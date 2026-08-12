#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TARGET=${TARGET:-x86_64-unknown-linux-musl}
OUT_DIR=${OUT_DIR:-$ROOT/dist}
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
if [[ "$CARGO_TARGET_DIR" != /* ]]; then
  CARGO_TARGET_DIR="$ROOT/$CARGO_TARGET_DIR"
fi
export CARGO_TARGET_DIR

case "$TARGET" in
  x86_64-unknown-linux-musl)
    DEB_ARCH=amd64
    ;;
  *)
    echo "unsupported Debian package target: $TARGET" >&2
    exit 2
    ;;
esac

for command in cargo dpkg-deb gzip install readelf sed; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command not found: $command" >&2
    exit 2
  fi
done

VERSION=${VERSION:-$(
  sed -n '/^\[package\]$/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" \
    | head -n1
)}
if [[ -z "$VERSION" ]]; then
  echo "failed to read package version from Cargo.toml" >&2
  exit 2
fi

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}
export CC_x86_64_unknown_linux_musl=${CC_x86_64_unknown_linux_musl:-musl-gcc}

for binary in iroh-sdwan iroh-sdwand; do
  cargo rustc \
    --manifest-path "$ROOT/Cargo.toml" \
    --locked \
    --release \
    --target "$TARGET" \
    --bin "$binary" \
    -- \
    -C link-self-contained=yes

  path="$CARGO_TARGET_DIR/$TARGET/release/$binary"
  if [[ ! -x "$path" ]]; then
    echo "build did not produce $path" >&2
    exit 1
  fi
  if readelf -l "$path" | grep -q 'Requesting program interpreter'; then
    echo "$path is dynamically linked; expected a fully static musl binary" >&2
    exit 1
  fi
done

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/iroh-sdwan-deb.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT
PACKAGE_ROOT="$WORK_DIR/iroh-sdwan"

install -d -m 0755 \
  "$PACKAGE_ROOT/DEBIAN" \
  "$PACKAGE_ROOT/usr/bin" \
  "$PACKAGE_ROOT/usr/lib/sysusers.d" \
  "$PACKAGE_ROOT/usr/lib/systemd/system" \
  "$PACKAGE_ROOT/usr/lib/sysctl.d" \
  "$PACKAGE_ROOT/usr/share/doc/iroh-sdwan/config" \
  "$PACKAGE_ROOT/usr/share/doc/iroh-sdwan/examples" \
  "$PACKAGE_ROOT/usr/share/doc/iroh-sdwan/docs"
install -d -m 0700 "$PACKAGE_ROOT/etc/iroh-sdwan"
install -m 0755 "$CARGO_TARGET_DIR/$TARGET/release/iroh-sdwan" "$PACKAGE_ROOT/usr/bin/iroh-sdwan"
install -m 0755 "$CARGO_TARGET_DIR/$TARGET/release/iroh-sdwand" "$PACKAGE_ROOT/usr/bin/iroh-sdwand"
sed 's|/usr/local/bin/|/usr/bin/|g' \
  "$ROOT/systemd/iroh-sdwan.service" \
  >"$PACKAGE_ROOT/usr/lib/systemd/system/iroh-sdwan.service"
chmod 0644 "$PACKAGE_ROOT/usr/lib/systemd/system/iroh-sdwan.service"
install -m 0644 \
  "$ROOT/systemd/iroh-sdwan.sysusers" \
  "$PACKAGE_ROOT/usr/lib/sysusers.d/iroh-sdwan.conf"
install -m 0644 \
  "$ROOT/systemd/90-iroh-sdwan.conf" \
  "$PACKAGE_ROOT/usr/lib/sysctl.d/90-iroh-sdwan.conf"
install -m 0644 "$ROOT/config/example.toml" \
  "$PACKAGE_ROOT/usr/share/doc/iroh-sdwan/examples/config.toml"
# 保留与仓库 docs/ 相同的相对链接结构，便于离线浏览已安装文档。
install -m 0644 "$ROOT/config/example.toml" \
  "$PACKAGE_ROOT/usr/share/doc/iroh-sdwan/config/example.toml"
install -m 0644 \
  "$ROOT/README.md" \
  "$ROOT/CONTRIBUTING.md" \
  "$ROOT/PLAN.md" \
  "$ROOT/LICENSE-APACHE" \
  "$ROOT/LICENSE-MIT" \
  "$PACKAGE_ROOT/usr/share/doc/iroh-sdwan/"
install -m 0644 "$ROOT"/docs/*.md "$PACKAGE_ROOT/usr/share/doc/iroh-sdwan/docs/"

cat >"$PACKAGE_ROOT/usr/share/doc/iroh-sdwan/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: iroh-sdwan

Files: *
Copyright: 2026 iroh-sdwan contributors
License: Apache-2.0 or MIT
 See /usr/share/doc/iroh-sdwan/LICENSE-APACHE and
 /usr/share/doc/iroh-sdwan/LICENSE-MIT for the complete license texts.
EOF

CHANGELOG_DATE=$(date --utc --date="@$SOURCE_DATE_EPOCH" --rfc-email)
{
  echo "iroh-sdwan ($VERSION) unstable; urgency=medium"
  echo
  echo "  * Automated musl release build."
  echo
  echo " -- iroh-sdwan maintainers <maintainers@iroh-sdwan.invalid>  $CHANGELOG_DATE"
} | gzip -9n >"$PACKAGE_ROOT/usr/share/doc/iroh-sdwan/changelog.Debian.gz"

cat >"$PACKAGE_ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/iroh-sdwan.conf >/dev/null
elif ! getent passwd iroh-sdwan >/dev/null 2>&1; then
    adduser --system --group --home /var/lib/iroh-sdwan --no-create-home iroh-sdwan >/dev/null
fi
install -d -o root -g iroh-sdwan -m 0750 /etc/iroh-sdwan
install -d -o iroh-sdwan -g iroh-sdwan -m 0700 /var/lib/iroh-sdwan
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
if command -v sysctl >/dev/null 2>&1; then
    sysctl --system >/dev/null 2>&1 || true
fi

exit 0
EOF

cat >"$PACKAGE_ROOT/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop iroh-sdwan.service >/dev/null 2>&1 || true
fi

exit 0
EOF

cat >"$PACKAGE_ROOT/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
EOF
chmod 0755 \
  "$PACKAGE_ROOT/DEBIAN/postinst" \
  "$PACKAGE_ROOT/DEBIAN/prerm" \
  "$PACKAGE_ROOT/DEBIAN/postrm"

INSTALLED_SIZE=$(du -sk "$PACKAGE_ROOT" | cut -f1)
cat >"$PACKAGE_ROOT/DEBIAN/control" <<EOF
Package: iroh-sdwan
Version: $VERSION
Section: net
Priority: optional
Architecture: $DEB_ARCH
Maintainer: iroh-sdwan maintainers <maintainers@iroh-sdwan.invalid>
Installed-Size: $INSTALLED_SIZE
Depends: adduser, iproute2, procps
Description: Demand-aware SD-WAN data plane using iroh and FlowRouter
 iroh-sdwan provides an unprivileged control CLI and a capability-bounded
 daemon. The daemon builds encrypted peer tunnels, exchanges bounded mesh
 presence, and uses FlowRouter to route node and LAN prefixes. Both executables are
 statically linked against musl; host routing utilities come from Debian packages.
EOF

(
  cd "$PACKAGE_ROOT"
  find etc usr -type f -print0 \
    | sort -z \
    | xargs -0 md5sum >DEBIAN/md5sums
)

mkdir -p "$OUT_DIR"
PACKAGE="$OUT_DIR/iroh-sdwan_${VERSION}_${DEB_ARCH}.deb"
rm -f "$PACKAGE"
dpkg-deb --root-owner-group --build "$PACKAGE_ROOT" "$PACKAGE"

dpkg-deb --info "$PACKAGE" >/dev/null
dpkg-deb --contents "$PACKAGE" >/dev/null
echo "$PACKAGE"

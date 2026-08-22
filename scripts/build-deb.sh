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
    TARGET_CC_VAR=CC_x86_64_unknown_linux_musl
    DEFAULT_TARGET_CC=musl-gcc
    ;;
  aarch64-unknown-linux-musl)
    DEB_ARCH=arm64
    TARGET_CC_VAR=CC_aarch64_unknown_linux_musl
    # Native arm64 runners expose musl-gcc under the generic name. Cross
    # builders can override this with CC_aarch64_unknown_linux_musl.
    DEFAULT_TARGET_CC=musl-gcc
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
if [[ -z "${!TARGET_CC_VAR:-}" ]]; then
  printf -v "$TARGET_CC_VAR" '%s' "$DEFAULT_TARGET_CC"
  export "$TARGET_CC_VAR"
fi

for binary in ironet ironetd; do
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

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ironet-deb.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT
PACKAGE_ROOT="$WORK_DIR/ironet"

install -d -m 0755 \
  "$PACKAGE_ROOT/DEBIAN" \
  "$PACKAGE_ROOT/usr/bin" \
  "$PACKAGE_ROOT/usr/lib/sysusers.d" \
  "$PACKAGE_ROOT/usr/lib/systemd/system" \
  "$PACKAGE_ROOT/usr/lib/sysctl.d" \
  "$PACKAGE_ROOT/usr/share/polkit-1/rules.d" \
  "$PACKAGE_ROOT/usr/share/doc/ironet/config" \
  "$PACKAGE_ROOT/usr/share/doc/ironet/examples" \
  "$PACKAGE_ROOT/usr/share/doc/ironet/docs"
install -d -m 0700 "$PACKAGE_ROOT/etc/ironet"
install -m 0755 "$CARGO_TARGET_DIR/$TARGET/release/ironet" "$PACKAGE_ROOT/usr/bin/ironet"
install -m 0755 "$CARGO_TARGET_DIR/$TARGET/release/ironetd" "$PACKAGE_ROOT/usr/bin/ironetd"
sed 's|/usr/local/bin/|/usr/bin/|g' \
  "$ROOT/systemd/ironet.service" \
  >"$PACKAGE_ROOT/usr/lib/systemd/system/ironet.service"
chmod 0644 "$PACKAGE_ROOT/usr/lib/systemd/system/ironet.service"
install -m 0644 \
  "$ROOT/systemd/ironet.sysusers" \
  "$PACKAGE_ROOT/usr/lib/sysusers.d/ironet.conf"
install -m 0644 \
  "$ROOT/systemd/90-ironet.conf" \
  "$PACKAGE_ROOT/usr/lib/sysctl.d/90-ironet.conf"
install -m 0644 \
  "$ROOT/systemd/90-ironet-resolved.rules" \
  "$PACKAGE_ROOT/usr/share/polkit-1/rules.d/90-ironet-resolved.rules"
install -m 0644 "$ROOT/config/example.toml" \
  "$PACKAGE_ROOT/usr/share/doc/ironet/examples/config.toml"
# 保留与仓库 docs/ 相同的相对链接结构，便于离线浏览已安装文档。
install -m 0644 "$ROOT/config/example.toml" \
  "$PACKAGE_ROOT/usr/share/doc/ironet/config/example.toml"
install -m 0644 \
  "$ROOT/README.md" \
  "$ROOT/CONTRIBUTING.md" \
  "$ROOT/PLAN.md" \
  "$ROOT/LICENSE-APACHE" \
  "$ROOT/LICENSE-MIT" \
  "$PACKAGE_ROOT/usr/share/doc/ironet/"
install -m 0644 "$ROOT"/docs/*.md "$PACKAGE_ROOT/usr/share/doc/ironet/docs/"

cat >"$PACKAGE_ROOT/usr/share/doc/ironet/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: ironet

Files: *
Copyright: 2026 ironet contributors
License: Apache-2.0 or MIT
 See /usr/share/doc/ironet/LICENSE-APACHE and
 /usr/share/doc/ironet/LICENSE-MIT for the complete license texts.
EOF

CHANGELOG_DATE=$(date --utc --date="@$SOURCE_DATE_EPOCH" --rfc-email)
{
  echo "ironet ($VERSION) unstable; urgency=medium"
  echo
  echo "  * Automated musl release build."
  echo
  echo " -- ironet maintainers <maintainers@ironet.invalid>  $CHANGELOG_DATE"
} | gzip -9n >"$PACKAGE_ROOT/usr/share/doc/ironet/changelog.Debian.gz"

cat >"$PACKAGE_ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/ironet.conf >/dev/null
elif ! getent passwd ironet >/dev/null 2>&1; then
    adduser --system --group --home /var/lib/ironet --no-create-home ironet >/dev/null
fi
install -d -o root -g ironet -m 0750 /etc/ironet
install -d -o ironet -g ironet -m 0700 /var/lib/ironet
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
    systemctl stop ironet.service >/dev/null 2>&1 || true
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
Package: ironet
Version: $VERSION
Section: net
Priority: optional
Architecture: $DEB_ARCH
Maintainer: ironet maintainers <maintainers@ironet.invalid>
Installed-Size: $INSTALLED_SIZE
Depends: adduser, dbus, iproute2, iptables, polkitd, procps, systemd-resolved
Description: QUIC SD-WAN data plane using Ironet Protocol V2
 ironet provides an unprivileged control CLI and a capability-bounded
 daemon. The daemon builds encrypted peer tunnels, exchanges bounded mesh
 presence, and uses immutable V2 route-label snapshots for node and LAN prefixes. Both executables are
 statically linked against musl; host routing utilities come from Debian packages.
EOF

(
  cd "$PACKAGE_ROOT"
  find etc usr -type f -print0 \
    | sort -z \
    | xargs -0 md5sum >DEBIAN/md5sums
)

mkdir -p "$OUT_DIR"
PACKAGE="$OUT_DIR/ironet_${VERSION}_${DEB_ARCH}.deb"
rm -f "$PACKAGE"
dpkg-deb --root-owner-group --build "$PACKAGE_ROOT" "$PACKAGE"

dpkg-deb --info "$PACKAGE" >/dev/null
dpkg-deb --contents "$PACKAGE" >/dev/null
echo "$PACKAGE"

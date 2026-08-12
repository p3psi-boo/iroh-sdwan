#!/usr/bin/env bash
set -euo pipefail

PACKAGE=${1:?usage: tests/deployment/package.sh PACKAGE.deb}
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

dpkg-deb --info "$PACKAGE" >/dev/null
dpkg-deb --extract "$PACKAGE" "$ROOT"

for binary in iroh-sdwan iroh-sdwand; do
  path="$ROOT/usr/bin/$binary"
  test -x "$path"
  if readelf -l "$path" | grep -q 'Requesting program interpreter'; then
    echo "$binary is dynamically linked" >&2
    exit 1
  fi
done
test -f "$ROOT/usr/lib/systemd/system/iroh-sdwan.service"
test -f "$ROOT/usr/lib/sysusers.d/iroh-sdwan.conf"
test -f "$ROOT/usr/lib/sysctl.d/90-iroh-sdwan.conf"
test -f "$ROOT/usr/share/doc/iroh-sdwan/examples/config.toml"
test -f "$ROOT/usr/share/doc/iroh-sdwan/config/example.toml"
test -f "$ROOT/usr/share/doc/iroh-sdwan/docs/README.md"
test -f "$ROOT/usr/share/doc/iroh-sdwan/docs/快速开始.md"
test -f "$ROOT/usr/share/doc/iroh-sdwan/CONTRIBUTING.md"
test -f "$ROOT/usr/share/doc/iroh-sdwan/PLAN.md"
test "$(stat -c %a "$ROOT/etc/iroh-sdwan")" = 700

SERVICE="$ROOT/usr/lib/systemd/system/iroh-sdwan.service"
grep -q '^User=iroh-sdwan$' "$SERVICE"
grep -q '^Group=iroh-sdwan$' "$SERVICE"
grep -q '^ExecStart=/usr/bin/iroh-sdwand ' "$SERVICE"
grep -q '^ExecReload=/usr/bin/iroh-sdwan reload ' "$SERVICE"
grep -q '^CapabilityBoundingSet=CAP_NET_ADMIN$' "$SERVICE"
grep -q '^NoNewPrivileges=true$' "$SERVICE"
grep -q '^ProtectSystem=strict$' "$SERVICE"
grep -q '^RuntimeDirectoryMode=0770$' "$SERVICE"
# 使用最小依赖集合验证已打包 unit。--root 会将默认依赖和 /bin/sh
# 也解析到解包目录，因此为纯包布局测试提供对应的占位文件。
install -d "$ROOT/bin" "$ROOT/usr/lib/systemd/system"
install -m 0755 /bin/sh "$ROOT/bin/sh"
cat >"$ROOT/usr/lib/systemd/system/sysinit.target" <<'EOF'
[Unit]
Description=Test sysinit target
EOF
cat >"$ROOT/usr/lib/systemd/system/network-online.target" <<'EOF'
[Unit]
Description=Test network target
EOF
cat >"$ROOT/usr/lib/systemd/system/systemd-sysctl.service" <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/true
EOF
systemd-analyze verify --root="$ROOT" usr/lib/systemd/system/iroh-sdwan.service

dpkg-deb --ctrl-tarfile "$PACKAGE" \
  | tar -xOf - ./postinst \
  | grep -q 'systemd-sysusers'
echo "Debian package and systemd deployment test passed"

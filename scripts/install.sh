#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PREFIX=${PREFIX:-/usr/local}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
SYSUSERS_DIR=${SYSUSERS_DIR:-/etc/sysusers.d}
SYSCTL_DIR=${SYSCTL_DIR:-/etc/sysctl.d}
CONFIG_DIR=${CONFIG_DIR:-/etc/iroh-sdwan}
STATE_DIR=${STATE_DIR:-/var/lib/iroh-sdwan}

if [[ $EUID -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

cd "$ROOT"
cargo build --locked --release
install -D -m 0755 target/release/iroh-sdwan "$PREFIX/bin/iroh-sdwan"
install -D -m 0755 target/release/iroh-sdwand "$PREFIX/bin/iroh-sdwand"
sed "s|/usr/local/bin/|$PREFIX/bin/|g" systemd/iroh-sdwan.service \
  | install -D -m 0644 /dev/stdin "$SYSTEMD_DIR/iroh-sdwan.service"
install -D -m 0644 systemd/iroh-sdwan.sysusers "$SYSUSERS_DIR/iroh-sdwan.conf"
install -D -m 0644 systemd/90-iroh-sdwan.conf "$SYSCTL_DIR/90-iroh-sdwan.conf"
if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers "$SYSUSERS_DIR/iroh-sdwan.conf"
elif ! getent passwd iroh-sdwan >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "$STATE_DIR" --shell /usr/sbin/nologin iroh-sdwan
fi
install -d -o root -g iroh-sdwan -m 0750 "$CONFIG_DIR"
install -d -o iroh-sdwan -g iroh-sdwan -m 0700 "$STATE_DIR"

sysctl --system >/dev/null
systemctl daemon-reload
echo "installed $PREFIX/bin/iroh-sdwan"
echo "installed $PREFIX/bin/iroh-sdwand"
echo "next: initialise or install $CONFIG_DIR/config.toml, then run:"
echo "  systemctl enable --now iroh-sdwan"

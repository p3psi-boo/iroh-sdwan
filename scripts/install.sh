#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PREFIX=${PREFIX:-/usr/local}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
SYSUSERS_DIR=${SYSUSERS_DIR:-/etc/sysusers.d}
SYSCTL_DIR=${SYSCTL_DIR:-/etc/sysctl.d}
CONFIG_DIR=${CONFIG_DIR:-/etc/ironet}
STATE_DIR=${STATE_DIR:-/var/lib/ironet}

if [[ $EUID -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

cd "$ROOT"
cargo build --locked --release
install -D -m 0755 target/release/ironet "$PREFIX/bin/ironet"
install -D -m 0755 target/release/ironetd "$PREFIX/bin/ironetd"
sed "s|/usr/local/bin/|$PREFIX/bin/|g" systemd/ironet.service \
  | install -D -m 0644 /dev/stdin "$SYSTEMD_DIR/ironet.service"
install -D -m 0644 systemd/ironet.sysusers "$SYSUSERS_DIR/ironet.conf"
install -D -m 0644 systemd/90-ironet.conf "$SYSCTL_DIR/90-ironet.conf"
if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers "$SYSUSERS_DIR/ironet.conf"
elif ! getent passwd ironet >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "$STATE_DIR" --shell /usr/sbin/nologin ironet
fi
install -d -o root -g ironet -m 0750 "$CONFIG_DIR"
install -d -o ironet -g ironet -m 0700 "$STATE_DIR"

sysctl --system >/dev/null
systemctl daemon-reload
echo "installed $PREFIX/bin/ironet"
echo "installed $PREFIX/bin/ironetd"
echo "next: initialise or install $CONFIG_DIR/config.toml, then run:"
echo "  systemctl enable --now ironet"

#!/usr/bin/env bash
set -euo pipefail

PREFIX=${PREFIX:-/usr/local}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
SYSCTL_DIR=${SYSCTL_DIR:-/etc/sysctl.d}
SYSUSERS_DIR=${SYSUSERS_DIR:-/etc/sysusers.d}

if [[ $EUID -ne 0 ]]; then
  echo "uninstall.sh must run as root" >&2
  exit 1
fi

systemctl disable --now iroh-sdwan 2>/dev/null || true
rm -f \
  "$SYSTEMD_DIR/iroh-sdwan.service" \
  "$SYSCTL_DIR/90-iroh-sdwan.conf" \
  "$SYSUSERS_DIR/iroh-sdwan.conf" \
  "$PREFIX/bin/iroh-sdwan" \
  "$PREFIX/bin/iroh-sdwand"
sysctl --system >/dev/null
systemctl daemon-reload
echo "binary and service removed; configuration and identity were preserved"

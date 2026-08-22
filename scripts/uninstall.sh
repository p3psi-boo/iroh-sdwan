#!/usr/bin/env bash
set -euo pipefail

PREFIX=${PREFIX:-/usr/local}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
SYSCTL_DIR=${SYSCTL_DIR:-/etc/sysctl.d}
SYSUSERS_DIR=${SYSUSERS_DIR:-/etc/sysusers.d}
POLKIT_RULES_DIR=${POLKIT_RULES_DIR:-/etc/polkit-1/rules.d}

if [[ $EUID -ne 0 ]]; then
  echo "uninstall.sh must run as root" >&2
  exit 1
fi

systemctl disable --now ironet 2>/dev/null || true
rm -f \
  "$SYSTEMD_DIR/ironet.service" \
  "$SYSCTL_DIR/90-ironet.conf" \
  "$SYSUSERS_DIR/ironet.conf" \
  "$POLKIT_RULES_DIR/90-ironet-resolved.rules" \
  "$PREFIX/bin/ironet" \
  "$PREFIX/bin/ironetd"
sysctl --system >/dev/null
systemctl daemon-reload
echo "binary and service removed; configuration and identity were preserved"

#!/bin/bash
# Removes portmon: the service, the nftables counting table and /opt/portmon.
# Config (/etc/portmon) and traffic history (/var/lib/portmon) are kept unless PM_PURGE=1.
set -e
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
systemctl disable --now portmon >/dev/null 2>&1 || true
rm -f /etc/systemd/system/portmon.service
systemctl daemon-reload
nft delete table inet portmon 2>/dev/null || true
rm -rf /opt/portmon
if [ "${PM_PURGE:-0}" = 1 ]; then
  rm -rf /etc/portmon /var/lib/portmon
  echo "portmon removed, with its config and history"
else
  echo "portmon removed; config and history kept in /etc/portmon and /var/lib/portmon (PM_PURGE=1 deletes them)"
fi

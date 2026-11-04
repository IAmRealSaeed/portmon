#!/bin/bash
# Removes portmon: the service, the nftables counting table, /opt/portmon and the `portmon` command.
# Config (/etc/portmon) and traffic history (/var/lib/portmon) are kept unless PM_PURGE=1, which also deletes
# the Let's Encrypt certificate it had (its renewal needs the Cloudflare token that goes with the config).
set -e
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
DOMAIN=$(python3 -c "import json; print(json.load(open('/etc/portmon/config.json')).get('domain') or '')" 2>/dev/null || true)
systemctl disable --now portmon >/dev/null 2>&1 || true
rm -f /etc/systemd/system/portmon.service
systemctl daemon-reload
nft delete table inet portmon 2>/dev/null || true
rm -f /usr/local/bin/portmon
rm -rf /opt/portmon
if [ "${PM_PURGE:-0}" = 1 ]; then
  if [ -n "$DOMAIN" ] && command -v certbot >/dev/null; then
    certbot delete --non-interactive --cert-name "$DOMAIN" >/dev/null 2>&1 || true
  fi
  rm -rf /etc/portmon /var/lib/portmon
  echo "portmon removed, with its config, history and certificate"
else
  echo "portmon removed; config and history kept in /etc/portmon and /var/lib/portmon (PM_PURGE=1 deletes them)"
fi

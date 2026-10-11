#!/bin/bash
# portmon installer — per-port traffic dashboard for a Debian/Ubuntu server. Run as root.
#
#   curl -fsSL https://raw.githubusercontent.com/IAmRealSaeed/portmon/main/install.sh | sudo bash
#   or, from a clone:  sudo ./install.sh
#
# Env: PM_PASSWORD (first install: asked on the terminal if unset, >= 8 chars; on an upgrade leave it unset to keep the
# current password), PM_PORT (default 8800), PM_AUTOADD (default 1: on the first install watch every public TCP
# listener except ssh/dns/the dashboard itself), PM_SRC (folder holding portmon.py and fonts/; default: next to this
# script, else downloaded from PM_REPO_RAW).
# Re-running upgrades the app and keeps the data, groups and settings.
set -e
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
REPO_RAW=${PM_REPO_RAW:-https://raw.githubusercontent.com/IAmRealSaeed/portmon/main}
if [ -z "${PM_SRC:-}" ] && [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "$(dirname "${BASH_SOURCE[0]}")/portmon.py" ]; then
  PM_SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fi

apt_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" >/dev/null 2>&1 || {
    apt-get update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" >/dev/null; }
}

HAVE_PW=$(python3 -c "import json; print(1 if json.load(open('/etc/portmon/config.json')).get('password_hash') else 0)" 2>/dev/null || echo 0)
if [ -z "${PM_PASSWORD:-}" ] && [ "$HAVE_PW" != 1 ] && { : </dev/tty; } 2>/dev/null; then
  read -rsp "dashboard password (>= 8 chars): " PM_PASSWORD </dev/tty; echo >/dev/tty
fi
if [ -n "${PM_PASSWORD:-}" ]; then [ ${#PM_PASSWORD} -ge 8 ] || { echo "the password must be at least 8 characters"; exit 1; }
elif [ "$HAVE_PW" != 1 ]; then echo "PM_PASSWORD is required on the first install"; exit 1; fi
PORT=${PM_PORT:-8800}
if ss -Htln "( sport = :$PORT )" | grep -q . && ! systemctl is-active --quiet portmon; then echo "port $PORT is already in use"; exit 1; fi

command -v nft >/dev/null || apt_install nftables
# The nftables *service* would load /etc/nftables.conf ("flush ruleset") — portmon only needs the nft command.
systemctl is-active --quiet nftables && echo "note: nftables.service was already active here; left as it was"
command -v python3 >/dev/null || apt_install python3
command -v openssl >/dev/null || apt_install openssl
command -v curl >/dev/null || apt_install curl ca-certificates

install -d -m 755 /opt/portmon /opt/portmon/fonts
install -d -m 700 /etc/portmon /var/lib/portmon
fetch() {  # fetch <path in repo> <destination>
  if [ -n "${PM_SRC:-}" ]; then cp "$PM_SRC/$1" "$2"; else curl -fsSL "$REPO_RAW/$1" -o "$2"; fi
}
fetch portmon.py /opt/portmon/portmon.py.new
python3 -c "import ast,sys; ast.parse(open('/opt/portmon/portmon.py.new').read())"
mv /opt/portmon/portmon.py.new /opt/portmon/portmon.py; chmod 755 /opt/portmon/portmon.py
for f in Vazirmatn-Regular.woff2 Vazirmatn-Bold.woff2; do fetch "fonts/$f" "/opt/portmon/fonts/$f"; done

if [ ! -f /etc/portmon/key.pem ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes -subj "/CN=portmon" \
    -keyout /etc/portmon/key.pem -out /etc/portmon/cert.pem >/dev/null 2>&1
  chmod 600 /etc/portmon/key.pem
fi
PORT=$PORT python3 - <<'PY'
import json, os
p = "/etc/portmon/config.json"
cfg = json.load(open(p)) if os.path.exists(p) else {}
cfg.update({"port": int(os.environ["PORT"]), "tls_cert": "/etc/portmon/cert.pem", "tls_key": "/etc/portmon/key.pem",
            "db": "/var/lib/portmon/portmon.db", "fonts": "/opt/portmon/fonts"})
cfg.setdefault("listen", "0.0.0.0"); cfg.setdefault("interval", 60); cfg.setdefault("utc_offset_minutes", 210)
json.dump(cfg, open(p, "w"), ensure_ascii=False, indent=2); os.chmod(p, 0o600)
PY
if [ -n "${PM_PASSWORD:-}" ]; then printf '%s\n' "$PM_PASSWORD" | python3 /opt/portmon/portmon.py --set-password >/dev/null; fi

FIRST=0; [ -f /var/lib/portmon/portmon.db ] || FIRST=1
if [ "$FIRST" = 1 ] && [ "${PM_AUTOADD:-1}" = 1 ]; then
  PORT=$PORT python3 - <<'PY'
import os, re, sqlite3, subprocess, time
skip = {22, 53, int(os.environ["PORT"])}
out = subprocess.run(["ss", "-Htlnp"], capture_output=True, text=True).stdout
ports = {}
for line in out.splitlines():
    f = line.split()
    m = re.match(r"^(.*):(\d+)$", f[3]) if len(f) > 3 else None
    if not m or m.group(1) in ("[::1]",) or m.group(1).startswith("127."):
        continue
    p = int(m.group(2))
    if p in skip:
        continue
    proc = re.search(r'\(\("([^"]+)"', line)
    ports[p] = proc.group(1) if proc else ""
os.makedirs("/var/lib/portmon", exist_ok=True)
c = sqlite3.connect("/var/lib/portmon/portmon.db")
c.execute("CREATE TABLE IF NOT EXISTS ports (port INTEGER PRIMARY KEY, label TEXT DEFAULT '', group_id INTEGER, added_at INTEGER)")
c.executemany("INSERT OR IGNORE INTO ports (port, label, group_id, added_at) VALUES (?, ?, NULL, ?)",
              [(p, n, int(time.time())) for p, n in sorted(ports.items())])
c.commit()
print(f"watching {len(ports)} listening ports: {sorted(ports)}")
PY
fi

cat > /etc/systemd/system/portmon.service <<'UNIT'
[Unit]
Description=portmon — per-port traffic dashboard
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/portmon/portmon.py --config /etc/portmon/config.json
Restart=always
RestartSec=3
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable portmon >/dev/null 2>&1
systemctl restart portmon
sleep 3
echo "service: $(systemctl is-active portmon) | listening :$PORT: $(ss -Htln "( sport = :$PORT )" | grep -c .) | nft table: $(nft list tables 2>/dev/null | grep -c 'inet portmon')"
echo "login page: $(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:$PORT/login)"
journalctl -u portmon -n 2 --no-pager -o cat
echo "open https://<server-ip>:$PORT  (self-signed certificate: accept the browser warning once)"

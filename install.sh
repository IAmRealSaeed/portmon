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
# PM_DOMAIN (a name whose A record points at this server): a Let's Encrypt certificate for it instead of the
# self-signed one, so the browser trusts the page and offers to save the password; setting it agrees to Let's
# Encrypt's terms. PM_CF_TOKEN (a Cloudflare API token that may edit that zone's DNS; asked on the terminal if unset):
# the name is proven through DNS and nothing has to reach this server; left empty, it is proven on port 80, which
# must then be free and reachable from the internet. PM_EMAIL (optional): where Let's Encrypt writes about the
# certificate. certbot renews it by itself and restarts portmon.
# Re-running upgrades the app and keeps the data, groups and settings, the domain and its certificate too.
set -e
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
REPO_RAW=${PM_REPO_RAW:-https://raw.githubusercontent.com/IAmRealSaeed/portmon/main}
if [ -z "${PM_SRC:-}" ] && [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "$(dirname "${BASH_SOURCE[0]}")/portmon.py" ]; then
  PM_SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fi

# On a terminal every download draws a bar (name, how far, how big) and every package says it is being installed;
# piped into a log it all stays quiet, as before.
TTY=0; [ -t 2 ] && TTY=1
draw() {  # draw <label> <percent>
  local w=28 f i bar=""
  f=$(( $2 * w / 100 ))
  for ((i = 0; i < w; i++)); do if [ "$i" -lt "$f" ]; then bar+="#"; else bar+="."; fi; done
  printf '\r  %-24s [%s] %3d%%' "$1" "$bar" "$2" >&2
}
human() { local b; b=$(stat -c %s "$1" 2>/dev/null || echo 0); if [ "$b" -ge 1048576 ]; then echo "$((b / 1048576)) MB"; else echo "$(( (b + 1023) / 1024 )) KB"; fi; }
# Some links (Iran's to raw.githubusercontent.com among them) now and then hold a connection open and send nothing.
# Without limits curl waits for ever; with these, a try that brings no byte for 15 s is dropped and tried again.
NET=(--connect-timeout 15 --speed-limit 1 --speed-time 15 --max-time 180 --retry 4 --retry-delay 1)
download() {  # download <url> <file> <label>
  if [ "$TTY" != 1 ]; then curl -fsSL "${NET[@]}" "$1" -o "$2"; return; fi
  local tok rc
  draw "$3" 0
  # curl redraws its own bar with \r; only its percentage is taken, and drawn beside the file's name
  curl -fL --progress-bar "${NET[@]}" "$1" -o "$2" 2>&1 | while IFS= read -r -d $'\r' tok || [ -n "$tok" ]; do
    if [[ $tok == *"Will retry"* ]]; then printf '\r  %-24s %-36s' "$3" "no answer, trying again ..." >&2
    elif [[ $tok =~ ([0-9]+)(\.[0-9]+)?%[[:space:]]*$ ]]; then draw "$3" "${BASH_REMATCH[1]}"; fi
  done
  rc=${PIPESTATUS[0]}
  if [ "$rc" = 0 ]; then draw "$3" 100; printf '  %s\n' "$(human "$2")" >&2; else printf '  failed (curl %s)\n' "$rc" >&2; fi
  return "$rc"
}

apt_install() {
  [ "$TTY" = 1 ] && echo "installing $* ..." >&2
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" >/dev/null 2>&1 || {
    apt-get update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" >/dev/null; }
}

CF_INI=/etc/portmon/cloudflare.ini
le_issue() {  # le_issue <domain>: a Let's Encrypt certificate, renewed by certbot's own timer
  local d=$1 how acct
  command -v certbot >/dev/null || apt_install certbot || return 1
  if [ -n "${PM_CF_TOKEN:-}" ]; then
    (umask 077; printf 'dns_cloudflare_api_token = %s\n' "$PM_CF_TOKEN" > "$CF_INI")
  fi
  if [ -s "$CF_INI" ]; then
    python3 -c "import certbot_dns_cloudflare" 2>/dev/null || apt_install python3-certbot-dns-cloudflare || return 1
    how="--dns-cloudflare --dns-cloudflare-credentials $CF_INI --dns-cloudflare-propagation-seconds 30"
  else
    how="--standalone"
  fi
  if [ -n "${PM_EMAIL:-}" ]; then acct="-m $PM_EMAIL --no-eff-email"; else acct="--register-unsafely-without-email"; fi
  echo "getting a Let's Encrypt certificate for $d ..."
  # The hook runs on every renewal; on a first install the service does not exist yet, hence «|| true».
  # shellcheck disable=SC2086
  if certbot certonly --non-interactive --agree-tos $acct $how -d "$d" --keep-until-expiring \
      --deploy-hook "systemctl restart portmon || true" >/tmp/portmon-certbot.log 2>&1; then
    return 0
  fi
  echo "warning: no certificate for $d; the last lines of certbot's log:"
  tail -n 8 /tmp/portmon-certbot.log
  return 1
}

HAVE_PW=$(python3 -c "import json; print(1 if json.load(open('/etc/portmon/config.json')).get('password_hash') else 0)" 2>/dev/null || echo 0)
if [ -z "${PM_PASSWORD:-}" ] && [ "$HAVE_PW" != 1 ] && { : </dev/tty; } 2>/dev/null; then
  read -rsp "dashboard password (>= 8 chars): " PM_PASSWORD </dev/tty; echo >/dev/tty
fi
if [ -n "${PM_PASSWORD:-}" ]; then [ ${#PM_PASSWORD} -ge 8 ] || { echo "the password must be at least 8 characters"; exit 1; }
elif [ "$HAVE_PW" != 1 ]; then echo "PM_PASSWORD is required on the first install"; exit 1; fi
# An upgrade keeps the port it had; until 2.3 it went back to 8800 unless PM_PORT was given again.
OLD_PORT=$(python3 -c "import json; print(json.load(open('/etc/portmon/config.json')).get('port') or '')" 2>/dev/null || true)
PORT=${PM_PORT:-${OLD_PORT:-8800}}
# Taken is fine only when it is portmon itself, staying on the port it already has.
if ss -Htln "( sport = :$PORT )" | grep -q . && ! { [ "$PORT" = "$OLD_PORT" ] && systemctl is-active --quiet portmon; }; then
  echo "port $PORT is already in use"; exit 1
fi

# Chrome never offers to save a password on a page with a certificate error, and a self-signed certificate is one.
OLD_DOMAIN=$(python3 -c "import json; print(json.load(open('/etc/portmon/config.json')).get('domain') or '')" 2>/dev/null || true)
DOMAIN=$(printf '%s' "${PM_DOMAIN:-$OLD_DOMAIN}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
if [ -n "${PM_DOMAIN:-}" ]; then
  printf '%s' "$DOMAIN" | grep -Eq '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$' || { echo "PM_DOMAIN is not a domain name: $PM_DOMAIN"; exit 1; }
  if [ -z "${PM_CF_TOKEN:-}" ] && [ ! -s "$CF_INI" ] && { : </dev/tty; } 2>/dev/null; then
    read -rsp "Cloudflare API token for $DOMAIN (empty: prove it on port 80 instead): " PM_CF_TOKEN </dev/tty; echo >/dev/tty
  fi
  if [ -z "${PM_CF_TOKEN:-}" ] && [ ! -s "$CF_INI" ] && ss -Htln "( sport = :80 )" | grep -q .; then
    echo "port 80 is in use here: give PM_CF_TOKEN to get the certificate through Cloudflare's DNS instead"; exit 1
  fi
fi

command -v nft >/dev/null || apt_install nftables
# The nftables *service* would load /etc/nftables.conf ("flush ruleset") — portmon only needs the nft command.
systemctl is-active --quiet nftables && echo "note: nftables.service was already active here; left as it was"
command -v python3 >/dev/null || apt_install python3
command -v openssl >/dev/null || apt_install openssl
command -v curl >/dev/null || apt_install curl ca-certificates

install -d -m 755 /opt/portmon /opt/portmon/fonts
install -d -m 700 /etc/portmon /var/lib/portmon
fetch() {  # fetch <path in repo> <destination>
  # Written beside it and moved over it, so a script that is running from there (the menu) is never edited
  # under its feet; and the menu's own reinstall reads from where it writes, which is then nothing to copy.
  if [ -n "${PM_SRC:-}" ]; then
    [ "$PM_SRC/$1" -ef "$2" ] && return 0
    cp "$PM_SRC/$1" "$2.new"
  else
    download "$REPO_RAW/$1" "$2.new" "$(basename "$1")" || { rm -f "$2.new"; from_release; }
  fi
  mv -f "$2.new" "$2"
}
# When a file will not come through even after the retries: the release build, which carries every file inside
# itself, comes from another GitHub host and is one download. It runs in place of this script.
RELEASE_URL=${PM_RELEASE_URL:-https://github.com/IAmRealSaeed/portmon/releases/latest/download/install_portmon.sh}
from_release() {
  local f
  echo "raw.githubusercontent.com keeps failing from here; taking the release build instead (one file, all inside):" >&2
  f=$(mktemp /tmp/install_portmon.XXXXXX)
  if ! download "$RELEASE_URL" "$f" install_portmon.sh; then
    echo "that did not come through either. Download install_portmon.sh from" >&2
    echo "https://github.com/IAmRealSaeed/portmon/releases/latest on another machine, copy it here and run: bash install_portmon.sh" >&2
    exit 1
  fi
  export PM_PASSWORD PM_CF_TOKEN PM_DOMAIN PM_PORT PM_EMAIL PM_AUTOADD   # what was typed here is not asked twice
  exec bash "$f"
}
[ -z "${PM_SRC:-}" ] && [ "$TTY" = 1 ] && [ -z "${PM_DL_HEADED:-}" ] && echo "downloading from GitHub:" >&2   # the menu printed it
fetch portmon.py /opt/portmon/portmon.py.new
python3 -c "import ast,sys; ast.parse(open('/opt/portmon/portmon.py.new').read())"
mv /opt/portmon/portmon.py.new /opt/portmon/portmon.py; chmod 755 /opt/portmon/portmon.py
for f in Vazirmatn-Regular.woff2 Vazirmatn-Medium.woff2; do fetch "fonts/$f" "/opt/portmon/fonts/$f"; done
# The menu (`portmon`) and what it runs: kept here, so a new certificate or port needs no GitHub.
for f in install.sh uninstall.sh cli.sh; do fetch "$f" "/opt/portmon/$f"; done
chmod 755 /opt/portmon/install.sh /opt/portmon/uninstall.sh /opt/portmon/cli.sh
ln -sfn /opt/portmon/cli.sh /usr/local/bin/portmon

if [ ! -f /etc/portmon/key.pem ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes -subj "/CN=portmon" \
    -keyout /etc/portmon/key.pem -out /etc/portmon/cert.pem >/dev/null 2>&1
  chmod 600 /etc/portmon/key.pem
fi
TLS_CERT=/etc/portmon/cert.pem TLS_KEY=/etc/portmon/key.pem
if [ -n "$DOMAIN" ]; then
  # Asked for now: issued (or kept, while it is far from expiring). Remembered from before: used as it is.
  if [ -n "${PM_DOMAIN:-}" ]; then le_issue "$DOMAIN" || true; fi
  LIVE=/etc/letsencrypt/live/$DOMAIN
  # A new name that could not be had does not throw away the one that works.
  if [ ! -s "$LIVE/fullchain.pem" ] && [ -n "$OLD_DOMAIN" ] && [ "$OLD_DOMAIN" != "$DOMAIN" ] \
      && [ -s "/etc/letsencrypt/live/$OLD_DOMAIN/fullchain.pem" ]; then
    echo "keeping the certificate for $OLD_DOMAIN"
    DOMAIN=$OLD_DOMAIN LIVE=/etc/letsencrypt/live/$OLD_DOMAIN
  fi
  if [ -s "$LIVE/fullchain.pem" ] && [ -s "$LIVE/privkey.pem" ]; then
    TLS_CERT=$LIVE/fullchain.pem TLS_KEY=$LIVE/privkey.pem
  else
    echo "warning: no certificate for $DOMAIN in $LIVE; the dashboard stays on its self-signed one"
    DOMAIN=""
  fi
fi
PORT=$PORT TLS_CERT=$TLS_CERT TLS_KEY=$TLS_KEY DOMAIN=$DOMAIN python3 - <<'PY'
import json, os
p = "/etc/portmon/config.json"
cfg = json.load(open(p)) if os.path.exists(p) else {}
cfg.update({"port": int(os.environ["PORT"]), "tls_cert": os.environ["TLS_CERT"], "tls_key": os.environ["TLS_KEY"],
            "domain": os.environ["DOMAIN"], "db": "/var/lib/portmon/portmon.db", "fonts": "/opt/portmon/fonts"})
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
if [ -n "$DOMAIN" ]; then
  # Without -k: the page must come back over a certificate a browser accepts for this name.
  code=$(curl -s -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:$PORT:127.0.0.1" "https://$DOMAIN:$PORT/login" || true)
  echo "certificate for $DOMAIN: $([ "$code" = 200 ] && echo accepted || echo "NOT accepted (login page: $code)")"
  echo "open https://$DOMAIN:$PORT  (its A record must point here, DNS only: Cloudflare's proxy does not carry port $PORT)"
else
  echo "open https://<server-ip>:$PORT  (self-signed certificate: accept the browser warning once)"
fi
echo "manage it with: portmon  (update, SSL certificate, password, port, restart, status, logs, uninstall)"

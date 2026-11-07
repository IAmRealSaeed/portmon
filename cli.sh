#!/bin/bash
# portmon — the menu on the server, installed as /usr/local/bin/portmon.
#
#   portmon             the menu
#   portmon <action>    update | ssl | password | port | restart | status | log | uninstall
#
# Each action runs once and exits: update and ssl run the installer, which replaces this very file.
REPO_RAW=${PM_REPO_RAW:-https://raw.githubusercontent.com/IAmRealSaeed/portmon/main}
APP=/opt/portmon
CFG=/etc/portmon/config.json
[ "$(id -u)" = 0 ] || { echo "run as root: sudo portmon"; exit 1; }
if [ -t 1 ]; then G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' B=$'\e[1m' N=$'\e[0m'; else G='' R='' Y='' B='' N=''; fi

cfg() { python3 -c "import json, sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]) or '')" "$CFG" "$1" 2>/dev/null; }
version() { sed -n 's/^VERSION = "\(.*\)"$/\1/p' "$APP/portmon.py" 2>/dev/null; }
server_ip() { ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}'; }
address() { local d; d=$(cfg domain); echo "https://${d:-$(server_ip)}:$(cfg port)"; }
state() {
  if systemctl is-active --quiet portmon; then echo "${G}running${N}"; else echo "${R}stopped${N}"; fi
}
cert_line() {
  local c d end
  c=$(cfg tls_cert) d=$(cfg domain)
  [ -n "$c" ] || { echo "${Y}none, plain HTTP${N}"; return; }
  end=$(openssl x509 -enddate -noout -in "$c" 2>/dev/null | cut -d= -f2)
  if [ -n "$d" ]; then echo "${G}Let's Encrypt${N} for $d, until $end (renews by itself)"
  else echo "${Y}self-signed${N}: the browser warns and Chrome will not save the password (menu 2 fixes that)"; fi
}
installed() { [ -f "$APP/install.sh" ] || { echo "$APP/install.sh is missing: run «portmon update» to get it back"; exit 1; }; }
# the same download bar as the installer's (install.sh draws the rest of the files)
draw() {
  local w=28 f i bar=""
  f=$(( $2 * w / 100 ))
  for ((i = 0; i < w; i++)); do if [ "$i" -lt "$f" ]; then bar+="#"; else bar+="."; fi; done
  printf '\r  %-24s [%s] %3d%%' "$1" "$bar" "$2" >&2
}
# a try that brings no byte for 15 s is dropped and tried again (see install.sh)
NET=(--connect-timeout 15 --speed-limit 1 --speed-time 15 --max-time 180 --retry 4 --retry-delay 1)
RELEASE_URL=${PM_RELEASE_URL:-https://github.com/IAmRealSaeed/portmon/releases/latest/download/install_portmon.sh}
download() {  # download <url> <file> <label>
  [ -t 2 ] || { curl -fsSL "${NET[@]}" "$1" -o "$2"; return; }
  local tok rc
  draw "$3" 0
  curl -fL --progress-bar "${NET[@]}" "$1" -o "$2" 2>&1 | while IFS= read -r -d $'\r' tok || [ -n "$tok" ]; do
    if [[ $tok == *"Will retry"* ]]; then printf '\r  %-24s %-36s' "$3" "no answer, trying again ..." >&2
    elif [[ $tok =~ ([0-9]+)(\.[0-9]+)?%[[:space:]]*$ ]]; then draw "$3" "${BASH_REMATCH[1]}"; fi
  done
  rc=${PIPESTATUS[0]}
  if [ "$rc" = 0 ]; then draw "$3" 100; printf '  %s KB\n' "$(( ($(stat -c %s "$2") + 1023) / 1024 ))" >&2; else printf '\n' >&2; fi
  return "$rc"
}

do_update() {
  local dir rc
  dir=$(mktemp -d) || exit 1
  echo "downloading from GitHub:"
  if ! download "$REPO_RAW/install.sh" "$dir/install.sh" install.sh; then
    # raw.githubusercontent.com would not answer: the release build is another host and carries everything
    echo "raw.githubusercontent.com keeps failing from here; taking the release build instead (one file, all inside):"
    if download "$RELEASE_URL" "$dir/install_portmon.sh" install_portmon.sh; then
      bash "$dir/install_portmon.sh"; rc=$?
      rm -rf "$dir"
      exit $rc
    fi
    rm -rf "$dir"
    echo "${R}GitHub is not reachable from this server.${N} Take install_portmon.sh from"
    echo "https://github.com/IAmRealSaeed/portmon/releases/latest, copy it here and run: bash install_portmon.sh"
    exit 1
  fi
  # From an empty folder, so the installer downloads everything else rather than look beside itself.
  PM_SRC='' PM_DL_HEADED=1 bash "$dir/install.sh"; rc=$?
  rm -rf "$dir"
  exit $rc
}

do_ssl() {
  local d
  installed
  echo "A Let's Encrypt certificate: the browser stops warning and Chrome offers to save the password."
  echo "First give the name an A record pointing at ${B}$(server_ip)${N}; on Cloudflare keep it ${B}DNS only${N}"
  echo "(grey cloud), because Cloudflare's proxy does not carry port $(cfg port)."
  read -rp "domain (e.g. pm.example.com): " d
  [ -n "$d" ] || { echo "nothing changed"; exit 0; }
  PM_SRC=$APP PM_DOMAIN=$d bash "$APP/install.sh"
  exit $?
}

do_password() {
  local p
  read -rsp "new dashboard password (at least 8 characters): " p; echo
  [ ${#p} -ge 8 ] || { echo "${R}at least 8 characters${N}; nothing changed"; exit 1; }
  printf '%s\n' "$p" | python3 "$APP/portmon.py" --config "$CFG" --set-password >/dev/null || exit 1
  systemctl restart portmon
  echo "${G}password changed${N}; signed-in browsers stay signed in"
}

do_port() {
  local p
  installed
  read -rp "new dashboard port (now $(cfg port)): " p
  case $p in ''|*[!0-9]*) echo "nothing changed"; exit 0 ;; esac
  [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || { echo "${R}a port is 1 to 65535${N}"; exit 1; }
  PM_SRC=$APP PM_PORT=$p bash "$APP/install.sh" || exit 1
  echo "if a firewall (ufw, the datacenter's) guards this server, open port $p there"
}

do_restart() {
  systemctl restart portmon
  sleep 2
  echo "portmon: $(state)"
}

do_status() {
  echo "${B}portmon $(version)${N}: $(state)"
  echo "address:     $(address)"
  echo "certificate: $(cert_line)"
  echo "watching:    $(python3 -c "import sqlite3; print(sqlite3.connect('file:/var/lib/portmon/portmon.db?mode=ro', uri=True).execute('SELECT COUNT(*) FROM ports').fetchone()[0])" 2>/dev/null || echo '?') ports"
}

do_log() {
  echo "(Ctrl+C to leave)"
  journalctl -u portmon -n 50 -f --no-pager
}

do_uninstall() {
  local a k purge=0 tmp
  read -rp "remove portmon from this server? [y/N] " a
  case $a in y|Y|yes) ;; *) echo "nothing changed"; exit 0 ;; esac
  read -rp "keep the settings and traffic history, for a later install? [Y/n] " k
  case $k in n|N|no) purge=1 ;; esac
  [ -f "$APP/uninstall.sh" ] || { echo "$APP/uninstall.sh is missing"; exit 1; }
  # A copy: the original is inside the folder it deletes.
  tmp=$(mktemp) && cp "$APP/uninstall.sh" "$tmp" || exit 1
  PM_PURGE=$purge bash "$tmp"; rm -f "$tmp"
}

menu() {
  echo
  echo "  ${B}portmon $(version)${N}  $(state)"
  echo "  $(address)"
  echo "  certificate: $(cert_line)"
  echo
  echo "  1) Update portmon"
  echo "  2) Get an SSL certificate for a domain"
  echo "  3) Change the password"
  echo "  4) Change the port"
  echo "  5) Restart"
  echo "  6) Status"
  echo "  7) Logs"
  echo "  8) Uninstall"
  echo "  0) Exit"
  echo
  read -rp "  choose: " c
  case $c in
    1) do_update ;; 2) do_ssl ;; 3) do_password ;; 4) do_port ;; 5) do_restart ;; 6) do_status ;; 7) do_log ;;
    8) do_uninstall ;; *) exit 0 ;;
  esac
}

case "${1:-}" in
  '') menu ;;
  update) do_update ;; ssl) do_ssl ;; password) do_password ;; port) do_port ;; restart) do_restart ;;
  status) do_status ;; log|logs) do_log ;; uninstall) do_uninstall ;;
  *) echo "usage: portmon [update|ssl|password|port|restart|status|log|uninstall]"; exit 1 ;;
esac

#!/usr/bin/env python3
"""portmon — per-port traffic and server resources for a tunnel server, with a Persian web dashboard.

Counting (nftables, table `inet portmon`): for every watched port P, the bytes of connections whose ORIGINAL destination
port is P — client->server as upload (rx), server->client as download (tx). Input counts the original direction,
output the reply direction, forward both, so a relay's own upstream connection is never counted, even when it reuses
the same port number. The rules only count; they never accept or drop anything. Bytes are network bytes (IP + TCP/UDP
headers included), so they run a few percent above what a VPN panel shows for the same traffic.

Every `interval` seconds the counters are read, turned into deltas and stored in SQLite (minutes for 3 days, hours and
days for ever; hours and days cut at Tehran time), together with a server sample (CPU, RAM, load, network, disk,
connections; kept 7 days). A port can belong to several groups; a group's total is the sum of its ports, and every
"all ports" total counts each port once. The dashboard (stdlib HTTP server, optional TLS, password login) shows usage
per group and port for any range, per-day/per-hour charts, live rates, server resources, and manages groups/ports.

Beside the ports it keeps the main interface's own byte counts per hour and day ("server inbound"): what a provider
that meters traffic sees, tunnels' overhead and unwatched ports included. And every interval it looks at who is
connected to the listening ports: a port nobody watches that several addresses use is pointed out on the dashboard.

Usage: portmon.py [--config /etc/portmon/config.json]      (python3 >= 3.8, stdlib only, needs `nft`)
       portmon.py --set-password                            (reads the password from stdin, stores a PBKDF2 hash)
"""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

VERSION = "2.5"
DEFAULTS = {"listen": "0.0.0.0", "port": 8800, "interval": 60, "utc_offset_minutes": 210, "db": "/var/lib/portmon/portmon.db",
            "tls_cert": "", "tls_key": "", "password_hash": "", "secret": "", "title": "مصرف پورت‌ها",
            "fonts": "/opt/portmon/fonts"}
PALETTE = ["#4f8cff", "#f5a524", "#3ccf91", "#ef5da8", "#a78bfa", "#22c3d6", "#ff7a45", "#9ccc3c", "#e85d5d", "#c9a227",
           "#5c6bc0", "#26a69a"]
TABLE = "portmon"
LOCK = threading.Lock()
CFG = {}
LIVE = {"ts": 0, "interval": 60, "ports": {}}
SYS = {"prev_cpu": None, "prev_net": None, "prev_ts": 0, "now": {}}
SCAN = {"ts": 0, "ports": {}, "flagged": set()}   # listening port -> {conns, peers, process, unit} at the last look
LOGIN_FAILS = {}
PEER_MIN = 3   # a port that many distinct addresses use is someone's service, not a tunnel's own listener (1 far end)
SSH_NAMES = {"sshd", "ssh", "dropbear"}


# ------------------------------------------------------------------ config / time / auth
def load_config(path):
    cfg = dict(DEFAULTS)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    if not cfg.get("secret"):
        cfg["secret"] = secrets.token_hex(32)
        save_config(path, cfg)
    cfg["_path"] = path
    return cfg


def save_config(path, cfg):
    data = {k: v for k, v in cfg.items() if not k.startswith("_")}
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def local_now(ts=None):
    off = dt.timedelta(minutes=int(CFG.get("utc_offset_minutes", 210)))
    return dt.datetime.fromtimestamp(ts if ts is not None else time.time(), dt.timezone.utc) + off


def hash_password(pw, salt=None, rounds=240000):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, rounds)
    return f"pbkdf2${rounds}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def check_password(pw, stored):
    try:
        _, rounds, salt, dk = stored.split("$")
        got = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(rounds))
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


# ------------------------------------------------------------------ database
def db():
    c = sqlite3.connect(CFG["db"], timeout=30)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    os.makedirs(os.path.dirname(CFG["db"]), exist_ok=True)
    with db() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, color TEXT, sort INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS ports (port INTEGER PRIMARY KEY, label TEXT DEFAULT '', group_id INTEGER, added_at INTEGER);
        CREATE TABLE IF NOT EXISTS port_groups (port INTEGER, group_id INTEGER, PRIMARY KEY (port, group_id));
        CREATE TABLE IF NOT EXISTS usage_min (ts INTEGER, port INTEGER, rx INTEGER, tx INTEGER, PRIMARY KEY (ts, port));
        CREATE TABLE IF NOT EXISTS usage_hour (hour TEXT, port INTEGER, rx INTEGER, tx INTEGER, PRIMARY KEY (hour, port));
        CREATE TABLE IF NOT EXISTS usage_day (day TEXT, port INTEGER, rx INTEGER, tx INTEGER, PRIMARY KEY (day, port));
        CREATE TABLE IF NOT EXISTS state (port INTEGER PRIMARY KEY, rx_last INTEGER, tx_last INTEGER);
        CREATE TABLE IF NOT EXISTS sys_min (ts INTEGER PRIMARY KEY, cpu REAL, mem_used INTEGER, mem_total INTEGER,
            swap_used INTEGER, swap_total INTEGER, load1 REAL, net_rx REAL, net_tx REAL, disk_used INTEGER, disk_total INTEGER,
            tcp INTEGER, ct_count INTEGER, ct_max INTEGER);
        CREATE TABLE IF NOT EXISTS nic_hour (hour TEXT PRIMARY KEY, rx INTEGER, tx INTEGER, secs REAL);
        CREATE TABLE IF NOT EXISTS nic_day (day TEXT PRIMARY KEY, rx INTEGER, tx INTEGER, secs REAL);
        CREATE TABLE IF NOT EXISTS nic_state (id INTEGER PRIMARY KEY CHECK (id = 1), boot TEXT, iface TEXT, rx INTEGER,
            tx INTEGER, ts REAL);
        CREATE TABLE IF NOT EXISTS seen_ports (port INTEGER PRIMARY KEY, conns INTEGER, peers INTEGER, process TEXT,
            unit TEXT, first_seen INTEGER, last_seen INTEGER);
        CREATE TABLE IF NOT EXISTS ignored_ports (port INTEGER PRIMARY KEY, at INTEGER);
        """)
        # v1 kept one group per port in ports.group_id: carry it over once
        if not c.execute("SELECT 1 FROM port_groups LIMIT 1").fetchone():
            c.execute("INSERT OR IGNORE INTO port_groups (port, group_id) SELECT port, group_id FROM ports WHERE group_id IS NOT NULL")
            c.execute("UPDATE ports SET group_id = NULL")
        # first run of a version that keeps the interface's totals: rebuild them from the rates already sampled
        if not c.execute("SELECT 1 FROM nic_day LIMIT 1").fetchone() and not c.execute("SELECT 1 FROM nic_state").fetchone():
            nic_backfill(c)


# ------------------------------------------------------------------ nftables
def nft(args, stdin=None):
    r = subprocess.run(["nft"] + args, input=stdin, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError("nft: " + (r.stderr or r.stdout).strip()[:300])
    return r.stdout


def watched_ports():
    with db() as c:
        return [r["port"] for r in c.execute("SELECT port FROM ports ORDER BY port")]


def build_table(ports):
    """Replace the counting table atomically (counters start from zero)."""
    lines = [f"table inet {TABLE} {{}}", f"delete table inet {TABLE}", f"table inet {TABLE} {{"]
    for p in ports:
        lines += [f"  counter rx_{p} {{}}", f"  counter tx_{p} {{}}"]
    hooks = (("pm_in", "input", ("original",)), ("pm_out", "output", ("reply",)), ("pm_fwd", "forward", ("original", "reply")))
    for name, hook, dirs in hooks:
        lines.append(f"  chain {name} {{ type filter hook {hook} priority -150; policy accept;")
        for p in ports:
            for d in dirs:
                # nft needs the l4 protocol before proto-dst; it then lists the port as hex "[invalid type]",
                # but matches it correctly (checked against real traffic).
                lines.append(f"    ct direction {d} meta l4proto {{ tcp, udp }} ct original proto-dst {p} "
                             f"counter name {'rx' if d == 'original' else 'tx'}_{p}")
        lines.append("  }")
    lines.append("}")
    nft(["-f", "-"], "\n".join(lines) + "\n")


def read_counters():
    out = json.loads(nft(["-j", "list", "counters", "table", "inet", TABLE]))
    vals = {}
    for item in out.get("nftables", []):
        c = item.get("counter")
        if c and c.get("table") == TABLE:
            vals[c["name"]] = int(c.get("bytes", 0))
    return vals


# ------------------------------------------------------------------ server resources
def main_iface():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    return parts[0]
    except OSError:
        pass
    return None


def read_int(path):
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip()
    except OSError:
        return ""


def nic_add(c, t0, t1, rx, tx):
    """Spread rx/tx bytes moved between t0 and t1 over the local hours (and days) they fall in, in proportion to
    time, so a gap after a restart lands where it happened. Rounding never loses or invents a byte."""
    span, t, done_rx, done_tx = t1 - t0, t0, 0, 0
    while t < t1:
        loc = local_now(t)
        e = min(t1, t + 3600 - (loc.minute * 60 + loc.second + loc.microsecond / 1e6))
        if e <= t:   # float edge at an exact boundary
            e = min(t1, t + 1)
        f = (e - t0) / span
        prx, ptx = round(rx * f) - done_rx, round(tx * f) - done_tx
        done_rx += prx
        done_tx += ptx
        hour, day = loc.strftime("%Y-%m-%d %H"), loc.strftime("%Y-%m-%d")
        for tbl, key, val in (("nic_hour", "hour", hour), ("nic_day", "day", day)):
            c.execute(f"INSERT INTO {tbl} ({key}, rx, tx, secs) VALUES (?, ?, ?, ?) ON CONFLICT({key}) DO UPDATE SET "
                      f"rx = rx + excluded.rx, tx = tx + excluded.tx, secs = secs + excluded.secs", (val, prx, ptx, e - t))
        t = e


def nic_bank(iface, rx, tx, now, boot):
    """Store the main interface's growth since the last reading. The reading is kept in the database, so restarting
    portmon (an upgrade) loses nothing; a reboot, a counter that went back or another interface start a new baseline."""
    with db() as c:
        st = c.execute("SELECT boot, iface, rx, tx, ts FROM nic_state WHERE id = 1").fetchone()
        c.execute("INSERT OR REPLACE INTO nic_state (id, boot, iface, rx, tx, ts) VALUES (1, ?, ?, ?, ?, ?)",
                  (boot, iface, rx, tx, now))
        if (st and st["boot"] == boot and st["iface"] == iface and rx >= st["rx"] and tx >= st["tx"]
                and now > st["ts"]):
            nic_add(c, st["ts"], now, rx - st["rx"], tx - st["tx"])


def nic_backfill(c):
    """Interface totals for the time before they were kept, from the per-sample rates (sys_min, 7 days)."""
    prev = None
    gap = 3 * max(60, int(CFG.get("interval", 60)))
    for r in c.execute("SELECT ts, net_rx, net_tx FROM sys_min ORDER BY ts").fetchall():
        if prev is not None and r["net_rx"] is not None and r["net_tx"] is not None and 0 < r["ts"] - prev <= gap:
            nic_add(c, prev, r["ts"], r["net_rx"] * (r["ts"] - prev), r["net_tx"] * (r["ts"] - prev))
        prev = r["ts"]


def sys_sample():
    """One server sample (CPU% over the last interval, RAM, swap, load, main-interface rate, disk, connections)."""
    now = time.time()
    with open("/proc/stat") as f:
        cpu = [int(x) for x in f.readline().split()[1:9]]
    total, idle = sum(cpu), cpu[3] + cpu[4]
    cpu_pct = None
    if SYS["prev_cpu"]:
        pt, pi = SYS["prev_cpu"]
        dtot = total - pt
        cpu_pct = round(100.0 * (dtot - (idle - pi)) / dtot, 1) if dtot > 0 else 0.0
    SYS["prev_cpu"] = (total, idle)
    mem = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            mem[k] = int(v.split()[0]) * 1024
    iface = main_iface()
    rx = tx = None
    if iface:
        with open("/proc/net/dev") as f:
            for line in f:
                if line.strip().startswith(iface + ":"):
                    vals = line.split(":", 1)[1].split()
                    rx, tx = int(vals[0]), int(vals[8])
    net_rx = net_tx = None
    if rx is not None and SYS["prev_net"] and SYS["prev_net"][0] == iface:
        el = max(1.0, now - SYS["prev_ts"])
        net_rx = max(0.0, (rx - SYS["prev_net"][1]) / el)
        net_tx = max(0.0, (tx - SYS["prev_net"][2]) / el)
    SYS["prev_net"] = (iface, rx, tx) if rx is not None else None
    SYS["prev_ts"] = now
    if rx is not None:
        if "boot" not in SYS:
            SYS["boot"] = boot_id()
        try:
            nic_bank(iface, rx, tx, now, SYS["boot"])
        except sqlite3.Error as e:
            print(f"nic: {e}", flush=True)
    st = os.statvfs("/")
    tcp = None
    try:
        with open("/proc/net/sockstat") as f:
            m = re.search(r"TCP: inuse (\d+)", f.read())
            tcp = int(m.group(1)) if m else None
    except OSError:
        pass
    s = {"ts": int(now), "cpu": cpu_pct, "mem_used": mem.get("MemTotal", 0) - mem.get("MemAvailable", 0),
         "mem_total": mem.get("MemTotal", 0), "swap_used": mem.get("SwapTotal", 0) - mem.get("SwapFree", 0),
         "swap_total": mem.get("SwapTotal", 0), "load1": float(open("/proc/loadavg").read().split()[0]),
         "net_rx": net_rx, "net_tx": net_tx, "disk_used": (st.f_blocks - st.f_bfree) * st.f_frsize,
         "disk_total": st.f_blocks * st.f_frsize, "tcp": tcp,
         "ct_count": read_int("/proc/sys/net/netfilter/nf_conntrack_count"),
         "ct_max": read_int("/proc/sys/net/netfilter/nf_conntrack_max")}
    SYS["now"] = dict(s, iface=iface)
    if cpu_pct is not None:
        with db() as c:
            c.execute("INSERT OR REPLACE INTO sys_min VALUES (:ts, :cpu, :mem_used, :mem_total, :swap_used, :swap_total, :load1, "
                      ":net_rx, :net_tx, :disk_used, :disk_total, :tcp, :ct_count, :ct_max)", s)


def top_processes(n=8):
    """CPU% per process over half a second, plus resident memory."""
    hz = os.sysconf("SC_CLK_TCK")

    def snap():
        out = {}
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/stat") as f:
                    raw = f.read()
                name = raw[raw.index("(") + 1:raw.rindex(")")]
                rest = raw[raw.rindex(")") + 2:].split()
                out[pid] = (name, int(rest[11]) + int(rest[12]), int(rest[21]) * os.sysconf("SC_PAGE_SIZE"))
            except (OSError, ValueError, IndexError):
                continue
        return out
    a = snap()
    time.sleep(0.5)
    b = snap()
    rows = []
    for pid, (name, ticks, rss) in b.items():
        if pid in a:
            rows.append({"pid": int(pid), "name": name, "cpu": round(100.0 * (ticks - a[pid][1]) / hz / 0.5, 1), "rss": rss})
    rows.sort(key=lambda r: (r["cpu"], r["rss"]), reverse=True)
    return rows[:n]


def system_report(hours):
    since = int(time.time()) - hours * 3600
    with db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM sys_min WHERE ts >= ? ORDER BY ts", (since,))]
    step = max(1, len(rows) // 360)   # at most ~360 points per chart
    hist = []
    for i in range(0, len(rows), step):
        chunk = rows[i:i + step]
        avg = lambda k: (sum(r[k] for r in chunk if r[k] is not None) / max(1, sum(1 for r in chunk if r[k] is not None)))
        hist.append({"ts": chunk[-1]["ts"], "cpu": round(avg("cpu"), 1),
                     "mem": round(100.0 * avg("mem_used") / max(1, chunk[-1]["mem_total"]), 1),
                     "load": round(avg("load1"), 2), "rx": avg("net_rx"), "tx": avg("net_tx")})
    try:
        with open("/proc/uptime") as f:
            uptime = int(float(f.read().split()[0]))
    except OSError:
        uptime = None
    try:
        osname = re.search(r'PRETTY_NAME="([^"]+)"', open("/etc/os-release").read()).group(1)
    except (OSError, AttributeError):
        osname = ""
    peak = {k: max((r[k] for r in rows if r[k] is not None), default=None) for k in ("cpu", "net_rx", "net_tx")}
    return {"now": SYS["now"], "history": hist, "peak": peak, "top": top_processes(),
            "info": {"host": socket.gethostname(), "os": osname, "kernel": os.uname().release, "cores": os.cpu_count(),
                     "uptime": uptime, "load": open("/proc/loadavg").read().split()[:3]}}


# ------------------------------------------------------------------ collector
def record(deltas, now):
    """deltas: {port: (rx, tx)} — added to the minute, hour and day buckets (local time for hour/day)."""
    if not deltas:
        return
    ts = int(now) // 60 * 60
    loc = local_now(now)
    hour, day = loc.strftime("%Y-%m-%d %H"), loc.strftime("%Y-%m-%d")
    with db() as c:
        for p, (rx, tx) in deltas.items():
            if not rx and not tx:
                continue
            for tbl, key, val in (("usage_min", "ts", ts), ("usage_hour", "hour", hour), ("usage_day", "day", day)):
                c.execute(f"INSERT INTO {tbl} ({key}, port, rx, tx) VALUES (?, ?, ?, ?) "
                          f"ON CONFLICT({key}, port) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx", (val, p, rx, tx))


def sample(rebuild=False):
    """Read the counters, store the growth since the last read, refresh the live rates. With rebuild=True the
    table is (re)made afterwards and the baselines reset — used at start and whenever the watched ports change."""
    now = time.time()
    with LOCK:
        ports = watched_ports()
        deltas = {}
        try:
            vals = read_counters()
        except (RuntimeError, ValueError, OSError):
            vals = None
        with db() as c:
            last = {r["port"]: (r["rx_last"], r["tx_last"]) for r in c.execute("SELECT * FROM state")}
            if vals is not None:
                for p in ports:
                    if f"rx_{p}" not in vals:
                        continue
                    rx, tx = vals[f"rx_{p}"], vals[f"tx_{p}"]
                    lrx, ltx = last.get(p, (0, 0))
                    drx = rx - lrx if rx >= lrx else rx   # a reset counter starts again from zero
                    dtx = tx - ltx if tx >= ltx else tx
                    deltas[p] = (drx, dtx)
                    c.execute("INSERT OR REPLACE INTO state (port, rx_last, tx_last) VALUES (?, ?, ?)", (p, rx, tx))
        record(deltas, now)
        elapsed = max(1.0, now - LIVE["ts"]) if LIVE["ts"] else float(CFG["interval"])
        LIVE.update({"ts": now, "interval": elapsed,
                     "ports": {p: {"rx_bps": d[0] / elapsed, "tx_bps": d[1] / elapsed} for p, d in deltas.items()}})
        healthy = vals is not None and all(f"rx_{p}" in vals and f"tx_{p}" in vals for p in ports)
        if rebuild or not healthy:
            build_table(ports)
            with db() as c:
                c.execute("DELETE FROM state")
                c.executemany("INSERT INTO state (port, rx_last, tx_last) VALUES (?, 0, 0)", [(p,) for p in ports])


def prune():
    """Minutes go after 3 days and server samples after 7; hours and days are kept for ever (a few MB a year),
    so a window of chosen hours works however far back it lies."""
    cut_min = int(time.time()) - 3 * 86400
    with db() as c:
        c.execute("DELETE FROM usage_min WHERE ts < ?", (cut_min,))
        c.execute("DELETE FROM sys_min WHERE ts < ?", (int(time.time()) - 7 * 86400,))
        c.execute("DELETE FROM seen_ports WHERE last_seen < ?", (int(time.time()) - 7 * 86400,))


def collector():
    for fn in (lambda: sample(rebuild=True), sys_sample, scan_ports):
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — the loop below retries
            print(f"collector start: {type(e).__name__}: {e}", flush=True)
    n = 0
    while True:
        time.sleep(max(5, int(CFG["interval"])) - (time.time() % 1))
        for fn in (sample, sys_sample, scan_ports):
            try:
                fn()
            except Exception as e:  # noqa: BLE001 — keep counting whatever happens
                print(f"collector: {type(e).__name__}: {e}", flush=True)
        n += 1
        if n % 60 == 0:
            try:
                prune()
            except Exception as e:  # noqa: BLE001
                print(f"prune: {e}", flush=True)


# ------------------------------------------------------------------ reports
def listening_ports():
    try:
        out = subprocess.run(["ss", "-Htulnp"], capture_output=True, text=True).stdout
    except OSError:
        return []
    seen = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        m = re.search(r"^(.*):(\d+)$", parts[4])
        if not m or m.group(1).startswith("127.") or m.group(1) in ("[::1]",):
            continue
        port = int(m.group(2))
        proc = re.search(r'\(\("([^"]+)"', line)
        e = seen.setdefault(port, {"port": port, "proto": set(), "process": proc.group(1) if proc else ""})
        e["proto"].add(parts[0])
    with db() as c:
        ignored = {r["port"] for r in c.execute("SELECT port FROM ignored_ports")}
    out = []
    for v in sorted(seen.values(), key=lambda x: x["port"]):
        s = SCAN["ports"].get(v["port"], {})
        out.append(dict(v, proto="/".join(sorted(v["proto"])), conns=s.get("conns", 0), peers=s.get("peers", 0),
                        unit=s.get("unit", ""), ignored=v["port"] in ignored))
    return out


def parse_listeners(text):
    """`ss -Htlnp` -> {port: (process, pid)}: TCP listeners on public addresses (loopback ones serve no users)."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        m = re.search(r"^(.*):(\d+)$", parts[3]) if len(parts) > 3 else None
        if not m or m.group(1).startswith("127.") or m.group(1) == "[::1]" or "%lo" in m.group(1):
            continue
        proc = re.search(r'\(\("([^"]+)",pid=(\d+)', line)
        out.setdefault(int(m.group(2)), (proc.group(1), int(proc.group(2))) if proc else ("", None))
    return out


def parse_established(text, ports):
    """`ss -Htn state established` -> {local port: (connections, distinct peer addresses)} for the given ports."""
    conns, peers = {}, {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            lp = int(parts[2].rsplit(":", 1)[1])
        except (IndexError, ValueError):
            continue
        if lp not in ports:
            continue
        ip = parts[3].rsplit(":", 1)[0].strip("[]")
        ip = ip[7:] if ip.startswith("::ffff:") else ip
        conns[lp] = conns.get(lp, 0) + 1
        peers.setdefault(lp, set()).add(ip)
    return {p: (n, len(peers[p])) for p, n in conns.items()}


def unit_of(pid):
    """The systemd service a process runs in: tunnel tools often rename their process, the unit keeps its name."""
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            m = re.search(r"/([^/\s]+)\.service", f.read())
        return m.group(1) if m else ""
    except (OSError, TypeError):
        return ""


def scan_ports():
    """Who is connected to the listening ports now. A port nobody watches that PEER_MIN or more addresses use is
    remembered in seen_ports with what it had at the last look, so the dashboard can point at it while it is quiet
    too. A tunnel's own listener has one far end and is never flagged; neither is SSH, which scanners crowd."""
    run = lambda *a: subprocess.run(list(a), capture_output=True, text=True).stdout
    try:
        lis = parse_listeners(run("ss", "-Htlnp"))
        est = parse_established(run("ss", "-Htn", "state", "established"), set(lis))
    except OSError:
        return
    now = int(time.time())
    info = {}
    for port, (proc, pid) in lis.items():
        n, peers = est.get(port, (0, 0))
        info[port] = {"conns": n, "peers": peers, "process": proc, "unit": unit_of(pid) if pid else ""}
    watched, flagged = set(watched_ports()), set()
    with db() as c:
        for port, i in info.items():
            if (port in watched or port == int(CFG["port"]) or i["peers"] < PEER_MIN
                    or i["process"] in SSH_NAMES or i["unit"] in SSH_NAMES):
                continue
            flagged.add(port)
            c.execute("INSERT INTO seen_ports (port, conns, peers, process, unit, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?) "
                      "ON CONFLICT(port) DO UPDATE SET conns = excluded.conns, peers = excluded.peers, "
                      "process = excluded.process, unit = excluded.unit, last_seen = excluded.last_seen",
                      (port, i["conns"], i["peers"], i["process"], i["unit"], now, now))
    SCAN.update(ts=now, ports=info, flagged=flagged)


def unwatched(hours=24):
    """Ports someone used in the last `hours` that nobody watches and nobody chose to ignore, busiest first."""
    with db() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT port, conns, peers, process, unit, first_seen, last_seen FROM seen_ports WHERE last_seen >= ? "
            "AND port NOT IN (SELECT port FROM ports) AND port NOT IN (SELECT port FROM ignored_ports) "
            "ORDER BY peers DESC, port", (int(time.time()) - hours * 3600,))]
    for r in rows:
        r["active"] = r["port"] in SCAN.get("flagged", ())   # busy at the last look, not only earlier
    return rows


def day_start(day):
    """Epoch of a local day's first second."""
    off = dt.timedelta(minutes=int(CFG.get("utc_offset_minutes", 210)))
    return (dt.datetime.fromisoformat(day).replace(tzinfo=dt.timezone.utc) - off).timestamp()


def hour_key(day, h):
    """The usage_hour key of hour h (0..24) of a local day; hour 24 is the next day's 00."""
    d = dt.date.fromisoformat(day) + dt.timedelta(days=h // 24)
    return f"{d.isoformat()} {h % 24:02d}"


def key_start(key):
    """Epoch of the first second of a local hour key."""
    return day_start(key[:10]) + int(key[11:13]) * 3600


def nic_cover(r, first, start, end):
    """Totals plus whether the stretch start..end (up to now) was all counted."""
    want = max(0.0, min(time.time(), end) - start)
    missing = want - r["secs"]
    return {"rx": r["rx"], "tx": r["tx"], "since": first,
            "partial": bool(want) and missing > max(3 * max(60, int(CFG.get("interval", 60))), 0.02 * want)}


NIC_SUM = "SELECT COALESCE(SUM(rx), 0) AS rx, COALESCE(SUM(tx), 0) AS tx, COALESCE(SUM(secs), 0) AS secs FROM "


def nic_report(day_from, day_to):
    """The main interface's bytes over a range of days, and whether all of the range (up to now) was counted."""
    with db() as c:
        r = c.execute(NIC_SUM + "nic_day WHERE day BETWEEN ? AND ?", (day_from, day_to)).fetchone()
        first = c.execute("SELECT MIN(day) AS d FROM nic_day").fetchone()["d"]
    return nic_cover(r, first, day_start(day_from), day_start(day_to) + 86400)


def nic_window(lo, hi):
    """The same over hour keys lo (included) .. hi (left out)."""
    with db() as c:
        r = c.execute(NIC_SUM + "nic_hour WHERE hour >= ? AND hour < ?", (lo, hi)).fetchone()
        first = c.execute("SELECT MIN(day) AS d FROM nic_day").fetchone()["d"]
    return nic_cover(r, first, key_start(lo), key_start(hi))


def layout():
    with db() as c:
        groups = [dict(r) for r in c.execute("SELECT id, name, color, sort FROM groups ORDER BY sort, id")]
        ports = [dict(r) for r in c.execute("SELECT port, label, added_at FROM ports ORDER BY port")]
        links = c.execute("SELECT port, group_id FROM port_groups").fetchall()
    of_port = {}
    for r in links:
        of_port.setdefault(r["port"], []).append(r["group_id"])
    for p in ports:
        p["groups"] = sorted(of_port.get(p["port"], []))
    return groups, ports


def scope_ports(ports, group):
    if group in (None, "", "all"):
        return [p["port"] for p in ports]
    gid = int(group)
    return [p["port"] for p in ports if gid in p["groups"]]


def report(day_from, day_to, group=None, hour_from=0, hour_to=24):
    """Usage over whole days (day_from..day_to, from usage_day, kept for ever), or over a window that starts at
    hour_from of day_from and ends at hour_to of day_to (from usage_hour, also kept for ever). A window of up to 48
    hours is charted hour by hour, a longer one day by day."""
    groups, ports = layout()
    in_scope = set(scope_ports(ports, group))
    whole = hour_from == 0 and hour_to == 24
    with db() as c:
        if whole:
            rows = c.execute("SELECT day AS k, port, rx, tx FROM usage_day WHERE day BETWEEN ? AND ?", (day_from, day_to)).fetchall()
            nic_rows = c.execute("SELECT day AS k, rx FROM nic_day WHERE day BETWEEN ? AND ?", (day_from, day_to)).fetchall()
        else:
            lo, hi = hour_key(day_from, hour_from), hour_key(day_to, hour_to)
            if lo >= hi:
                raise ValueError("the window ends before it starts")
            rows = c.execute("SELECT hour AS k, port, rx, tx FROM usage_hour WHERE hour >= ? AND hour < ?", (lo, hi)).fetchall()
            nic_rows = c.execute("SELECT hour AS k, rx FROM nic_hour WHERE hour >= ? AND hour < ?", (lo, hi)).fetchall()
    if whole:
        unit, nic = "day", nic_report(day_from, day_to)
        d0, d1 = dt.date.fromisoformat(day_from), dt.date.fromisoformat(day_to)
        keys = [(d0 + dt.timedelta(days=i)).isoformat() for i in range((d1 - d0).days + 1)]
    else:
        t0, t1 = key_start(lo), key_start(hi)
        hours = [local_now(t).strftime("%Y-%m-%d %H") for t in range(int(t0), int(t1), 3600)]
        unit, nic = ("hour" if t1 - t0 <= 48 * 3600 else "day"), nic_window(lo, hi)
        keys = hours if unit == "hour" else sorted({h[:10] for h in hours})
    bucket = (lambda k: k[:10]) if unit == "day" else (lambda k: k)
    per_port, per_key, nic_by = {}, {}, {}
    for r in rows:
        a = per_port.setdefault(r["port"], [0, 0])
        a[0] += r["rx"]; a[1] += r["tx"]
        b = per_key.setdefault(bucket(r["k"]), {}).setdefault(r["port"], [0, 0])
        b[0] += r["rx"]; b[1] += r["tx"]
    for r in nic_rows:
        nic_by[bucket(r["k"])] = nic_by.get(bucket(r["k"]), 0) + r["rx"]
    live = LIVE["ports"]
    port_rows = {p["port"]: dict(p, rx=per_port.get(p["port"], [0, 0])[0], tx=per_port.get(p["port"], [0, 0])[1],
                                 live=live.get(p["port"], {"rx_bps": 0, "tx_bps": 0})) for p in ports}
    out_groups = []
    for g in groups:
        gp = [port_rows[p["port"]] for p in ports if g["id"] in p["groups"]]
        out_groups.append(dict(g, ports=[x["port"] for x in gp], rx=sum(x["rx"] for x in gp), tx=sum(x["tx"] for x in gp),
                               live=sum(x["live"]["rx_bps"] + x["live"]["tx_bps"] for x in gp)))
    ungrouped = [p["port"] for p in ports if not p["groups"]]
    days = [dict(series_point(k, per_key.get(k, {}), in_scope, groups, ports), nic=nic_by.get(k)) for k in keys]
    tot_rx = sum(port_rows[p]["rx"] for p in in_scope)
    tot_tx = sum(port_rows[p]["tx"] for p in in_scope)
    return {"from": day_from, "to": day_to, "hour_from": hour_from, "hour_to": hour_to, "unit": unit,
            "now_hour": local_now().strftime("%Y-%m-%d %H"), "scope": group or "all", "groups": out_groups,
            "ports": list(port_rows.values()), "ungrouped": ungrouped, "days": days, "total": {"rx": tot_rx, "tx": tot_tx},
            "nic": nic, "unwatched": unwatched(),
            "live": {"rx_bps": sum(live.get(p, {}).get("rx_bps", 0) for p in in_scope),
                     "tx_bps": sum(live.get(p, {}).get("tx_bps", 0) for p in in_scope), "interval": LIVE["interval"],
                     "ts": LIVE["ts"]}}


def series_point(key, per_port, in_scope, groups, ports):
    """One chart point: the scope's total (each port once), each group's total, and the scope's biggest ports."""
    tot = sum(rx + tx for p, (rx, tx) in per_port.items() if p in in_scope)
    bygroup = {}
    for g in groups:
        bygroup[str(g["id"])] = sum(rx + tx for p, (rx, tx) in per_port.items()
                                    if any(x["port"] == p and g["id"] in x["groups"] for x in ports))
    top = sorted(((p, rx + tx) for p, (rx, tx) in per_port.items() if p in in_scope), key=lambda x: -x[1])[:6]
    return {"key": key, "total": tot, "groups": bygroup, "top": top}


def hourly(day, group=None):
    groups, ports = layout()
    in_scope = set(scope_ports(ports, group))
    with db() as c:
        rows = c.execute("SELECT hour, port, rx, tx FROM usage_hour WHERE hour LIKE ?", (day + " %",)).fetchall()
        nic_hours = {r["hour"][-2:]: r["rx"] for r in c.execute("SELECT hour, rx FROM nic_hour WHERE hour LIKE ?", (day + " %",))}
    per_hour = {f"{h:02d}": {} for h in range(24)}
    for r in rows:
        per_hour[r["hour"][-2:]][r["port"]] = (r["rx"], r["tx"])
    return {"day": day, "hours": [dict(series_point(h, pp, in_scope, groups, ports), nic=nic_hours.get(h))
                                  for h, pp in per_hour.items()]}


# ------------------------------------------------------------------ changes
def change_group(b):
    act = b.get("action")
    with db() as c:
        if act == "add":
            name = str(b.get("name", "")).strip()[:40]
            if not name:
                raise ValueError("نام گروه خالی است.")
            used = {r["color"] for r in c.execute("SELECT color FROM groups")}
            color = str(b.get("color") or next((x for x in PALETTE if x not in used), PALETTE[len(used) % len(PALETTE)]))[:9]
            c.execute("INSERT INTO groups (name, color, sort) VALUES (?, ?, (SELECT COALESCE(MAX(sort), 0) + 1 FROM groups))", (name, color))
        elif act == "edit":
            if "name" in b and not str(b["name"]).strip():
                raise ValueError("نام گروه خالی است.")
            c.execute("UPDATE groups SET name = COALESCE(?, name), color = COALESCE(?, color) WHERE id = ?",
                      (str(b["name"]).strip()[:40] if "name" in b else None, str(b["color"])[:9] if "color" in b else None, int(b["id"])))
        elif act == "delete":
            c.execute("DELETE FROM port_groups WHERE group_id = ?", (int(b["id"]),))
            c.execute("DELETE FROM groups WHERE id = ?", (int(b["id"]),))
        else:
            raise ValueError("action?")
    return {"ok": True}


def change_port(b):
    act = b.get("action")
    port = int(b.get("port", 0))
    if not 1 <= port <= 65535:
        raise ValueError("شمارهٔ پورت درست نیست.")
    gids = sorted({int(x) for x in (b.get("groups") or []) if str(x).strip().isdigit()})
    rebuild = False
    if act in ("ignore", "unignore"):   # the dashboard's «unwatched port» notice for this port: hide it / bring it back
        with db() as c:
            if act == "ignore":
                c.execute("INSERT OR REPLACE INTO ignored_ports (port, at) VALUES (?, ?)", (port, int(time.time())))
            else:
                c.execute("DELETE FROM ignored_ports WHERE port = ?", (port,))
        return {"ok": True}
    if act == "delete":
        sample()   # bank what this port counted since the last sample before it leaves the table
    with db() as c:
        valid = {r["id"] for r in c.execute("SELECT id FROM groups")}
        gids = [g for g in gids if g in valid]
        if act == "add":
            if c.execute("SELECT 1 FROM ports WHERE port = ?", (port,)).fetchone():
                raise ValueError("این پورت از قبل زیر نظر است.")
            c.execute("INSERT INTO ports (port, label, added_at) VALUES (?, ?, ?)", (port, str(b.get("label", ""))[:300], int(time.time())))
            rebuild = True
        elif act == "edit":
            if "label" in b:
                c.execute("UPDATE ports SET label = ? WHERE port = ?", (str(b.get("label", ""))[:300], port))
        elif act == "delete":
            c.execute("DELETE FROM ports WHERE port = ?", (port,))
            c.execute("DELETE FROM port_groups WHERE port = ?", (port,))
            c.execute("DELETE FROM state WHERE port = ?", (port,))
            if b.get("purge"):
                for t in ("usage_min", "usage_hour", "usage_day"):
                    c.execute(f"DELETE FROM {t} WHERE port = ?", (port,))
            rebuild = True
        else:
            raise ValueError("action?")
        if act in ("add", "edit") and "groups" in b:
            c.execute("DELETE FROM port_groups WHERE port = ?", (port,))
            c.executemany("INSERT INTO port_groups (port, group_id) VALUES (?, ?)", [(port, g) for g in gids])
    if rebuild:
        try:
            sample(rebuild=True)   # store what the old table counted, then remake it with the new port list
        except RuntimeError as e:
            raise ValueError(f"شمارش این پورت راه نیفتاد: {e}")
    return {"ok": True}


# ------------------------------------------------------------------ web
def sign(value):
    return hmac.new(CFG["secret"].encode(), value.encode(), hashlib.sha256).hexdigest()


def make_session():
    exp = str(int(time.time()) + 14 * 86400)
    return exp + "." + sign(exp)


def session_ok(cookie):
    try:
        exp, sig = cookie.split(".")
        return hmac.compare_digest(sig, sign(exp)) and int(exp) > time.time()
    except (ValueError, AttributeError):
        return False


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "portmon"
    sys_version = ""

    def log_message(self, fmt, *args):
        return

    def cookie(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "pm":
                return v
        return ""

    def authed(self):
        return session_ok(self.cookie())

    def send(self, code, body, ctype="application/json; charset=utf-8", headers=()):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def page(self, html, code=200, err=""):
        return self.send(code, html.replace("{{TITLE}}", CFG["title"]).replace("<!--ERR-->", err), "text/html; charset=utf-8")

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path.startswith("/font/"):
            name = os.path.basename(u.path)
            path = os.path.join(CFG["fonts"], name)
            if re.fullmatch(r"[A-Za-z-]+\.woff2", name) and os.path.exists(path):
                with open(path, "rb") as f:
                    return self.send(200, f.read(), "font/woff2", [("Cache-Control", "max-age=31536000")])
            return self.send(404, {"error": "not found"})
        if u.path == "/login":
            return self.page(LOGIN_HTML)
        if u.path == "/logout":
            return self.send(302, "", headers=[("Location", "/login"), ("Set-Cookie", "pm=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict")])
        if not self.authed():
            if u.path.startswith("/api/"):
                return self.send(401, {"error": "login"})
            return self.send(302, "", headers=[("Location", "/login")])
        if u.path == "/":
            return self.page(APP_HTML)
        try:
            if u.path == "/api/report":
                today = local_now().date().isoformat()
                f, t = q.get("from", today), q.get("to", today)
                dt.date.fromisoformat(f); dt.date.fromisoformat(t)
                fh, th = int(q.get("fh", 0)), int(q.get("th", 24))   # the window's first hour, and the hour it ends at
                if not (0 <= fh <= 23 and 1 <= th <= 24):
                    raise ValueError("hour")
                if f > t and fh == 0 and th == 24:
                    f, t = t, f
                return self.send(200, report(f, t, q.get("group"), fh, th))
            if u.path == "/api/hourly":
                day = q.get("day", local_now().date().isoformat())
                dt.date.fromisoformat(day)
                return self.send(200, hourly(day, q.get("group")))
            if u.path == "/api/system":
                return self.send(200, system_report(max(1, min(168, int(q.get("hours", 24))))))
            if u.path == "/api/config":
                groups, ports = layout()
                return self.send(200, {"groups": groups, "ports": ports, "listening": listening_ports(), "palette": PALETTE,
                                       "today": local_now().date().isoformat(), "host": socket.gethostname(),
                                       "version": VERSION, "dashboard_port": int(CFG["port"])})
        except ValueError:
            return self.send(400, {"error": "bad request"})
        return self.send(404, {"error": "not found"})

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/login":
            ip = self.client_address[0]
            fails = [t for t in LOGIN_FAILS.get(ip, []) if t > time.time() - 600]
            if len(fails) >= 8:
                return self.page(LOGIN_HTML, 429, "تلاش زیاد؛ ده دقیقهٔ دیگر امتحان کنید.")
            n = int(self.headers.get("Content-Length") or 0)
            pw = urllib.parse.parse_qs(self.rfile.read(min(n, 4096)).decode(errors="replace")).get("password", [""])[0]
            if CFG.get("password_hash") and check_password(pw, CFG["password_hash"]):
                LOGIN_FAILS.pop(ip, None)
                secure = "; Secure" if CFG.get("tls_cert") else ""
                return self.send(302, "", headers=[("Location", "/"), ("Set-Cookie", f"pm={make_session()}; Max-Age=1209600; Path=/; HttpOnly; SameSite=Strict{secure}")])
            LOGIN_FAILS[ip] = fails + [time.time()]
            return self.page(LOGIN_HTML, 401, "رمز اشتباه است.")
        if not self.authed() or self.headers.get("X-PM") != "1":
            return self.send(401, {"error": "login"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            b = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
        except ValueError:
            return self.send(400, {"error": "bad json"})
        try:
            if u.path == "/api/group":
                return self.send(200, change_group(b))
            if u.path == "/api/port":
                return self.send(200, change_port(b))
            if u.path == "/api/password":
                if not check_password(str(b.get("old", "")), CFG.get("password_hash", "")):
                    return self.send(400, {"error": "رمز فعلی درست نیست."})
                new = str(b.get("new", ""))
                if len(new) < 8:
                    return self.send(400, {"error": "رمز جدید حداقل ۸ کاراکتر باشد."})
                CFG["password_hash"] = hash_password(new)
                save_config(CFG["_path"], CFG)
                return self.send(200, {"ok": True})
        except (ValueError, KeyError, sqlite3.IntegrityError) as e:
            return self.send(400, {"error": str(e)})
        return self.send(404, {"error": "not found"})


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    tls = None

    def finish_request(self, request, client_address):
        if self.tls is not None:
            request.settimeout(30)
            try:
                request = self.tls.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                return
            request.settimeout(None)
        self.RequestHandlerClass(request, client_address, self)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/etc/portmon/config.json")
    ap.add_argument("--set-password", action="store_true")
    a = ap.parse_args()
    CFG.update(load_config(a.config))
    if a.set_password:
        pw = sys.stdin.readline().rstrip("\n")
        if len(pw) < 8:
            sys.exit("password must be at least 8 characters")
        CFG["password_hash"] = hash_password(pw)
        save_config(a.config, CFG)
        print("password saved")
        return
    init_db()
    LIVE["interval"] = float(CFG["interval"])
    threading.Thread(target=collector, daemon=True).start()
    srv = Server((CFG["listen"], int(CFG["port"])), Handler)
    if CFG.get("tls_cert") and CFG.get("tls_key"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CFG["tls_cert"], CFG["tls_key"])
        srv.tls = ctx
    print(f"portmon {VERSION} on {CFG['listen']}:{CFG['port']} ({'https' if CFG.get('tls_cert') else 'http'}), "
          f"{len(watched_ports())} ports watched", flush=True)
    srv.serve_forever()


# ------------------------------------------------------------------ pages
# Graphite surfaces and three text roles; colour belongs to the data (each group's own, download and upload)
# and to one signature: the link light beside a live rate, which blinks once per new sample and goes grey when
# the collector has stopped.
FONT_CSS = r"""@font-face{font-family:Vazirmatn;src:url(/font/Vazirmatn-Regular.woff2) format('woff2');font-weight:400;font-display:swap}
@font-face{font-family:Vazirmatn;src:url(/font/Vazirmatn-Medium.woff2) format('woff2');font-weight:500;font-display:swap}"""

THEME_CSS = r""":root{color-scheme:dark;--bg0:#0f0f10;--bg:#141415;--card:#19191b;--raised:#232325;--hover:rgba(237,237,237,.04);
--line:rgba(237,237,237,.08);--line2:rgba(237,237,237,.14);--t1:#ededed;--t2:#a1a1a6;--t3:#85858b;--sel:#ededed;--onsel:#141415;
--c1:#6ea8fe;--dn:#4cc38a;--upc:#d9a24a;--live:#4cc38a;--warn:#d9a24a;--bad:#e5484d;--shadow:0 8px 24px rgba(0,0,0,.4);
--ease:cubic-bezier(.22,1,.36,1)}
@media (prefers-color-scheme: light){:root{color-scheme:light;--bg0:#f4f4f5;--bg:#fafafa;--card:#fff;--raised:#f4f4f5;--hover:rgba(23,23,23,.03);
--line:rgba(23,23,23,.08);--line2:rgba(23,23,23,.16);--t1:#171717;--t2:#525252;--t3:#737373;--sel:#171717;--onsel:#fff;
--c1:#2f6fd6;--dn:#16936a;--upc:#b7791f;--live:#16a34a;--warn:#b7791f;--bad:#dc2626;--shadow:0 8px 24px rgba(0,0,0,.08)}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--t1);font:400 14px/1.6 Vazirmatn,Tahoma,sans-serif}
b,strong,h1,h2{font-weight:500}
button,input,select,textarea{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--t1);outline-offset:2px}
.btn{height:36px;padding:0 16px;border-radius:8px;border:1px solid var(--line2);background:var(--raised);color:var(--t1);cursor:pointer;
  display:inline-flex;align-items:center;justify-content:center;gap:8px;white-space:nowrap;
  transition:background-color .15s var(--ease),border-color .15s var(--ease),transform .15s var(--ease)}
.btn:hover{border-color:var(--t3)}.btn:active{transform:scale(.98)}
.btn.pri{background:var(--sel);border-color:var(--sel);color:var(--onsel)}.btn.pri:hover{opacity:.9}
.btn.del{background:none;border-color:transparent;color:var(--bad)}.btn.del:hover{background:var(--hover)}
.btn.sm{height:28px;padding:0 10px;font-size:13px}
input,select,textarea{height:36px;padding:0 12px;border-radius:8px;border:1px solid var(--line2);background:var(--raised);
  transition:border-color .15s var(--ease)}
input:hover,textarea:hover{border-color:var(--t3)}
textarea{height:auto;padding:8px 12px;line-height:1.6}"""

LOGIN_HTML = r"""<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}} — ورود</title><style>""" + FONT_CSS + THEME_CSS + r"""
body{min-height:100vh;display:grid;place-items:center;padding:16px}
form{width:min(360px,100%);background:var(--card);border:1px solid var(--line);border-radius:16px;padding:32px 24px 24px;display:grid;gap:8px}
h1{margin:0 0 16px;font-size:18px;line-height:1.3}label{font-size:13px;color:var(--t2)}input{height:40px}
.err{color:var(--bad);font-size:13px;min-height:20px}.btn{height:40px}
</style></head><body><form method="post" action="/login"><h1>{{TITLE}}</h1><label for="pw">رمز ورود</label>
<input type="text" name="username" value="portmon" autocomplete="username" hidden>
<input id="pw" type="password" name="password" autocomplete="current-password" autofocus required>
<div class="err" role="alert"><!--ERR--></div><button class="btn pri">ورود</button></form></body></html>"""

APP_HTML = r"""<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title><style>""" + FONT_CSS + THEME_CSS + r"""
.top{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:32px;height:56px;padding:0 24px;background:var(--bg0);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:baseline;gap:12px;min-width:0}.brand b{font-size:16px;white-space:nowrap}
.brand span{font-size:12px;color:var(--t3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tabs{display:flex;gap:24px;height:100%}
.tabs button{height:100%;padding:0;border:0;border-bottom:2px solid transparent;background:none;color:var(--t2);cursor:pointer;
  transition:color .15s var(--ease),border-color .15s var(--ease)}
.tabs button:hover{color:var(--t1)}.tabs button.on{color:var(--t1);border-bottom-color:var(--t1)}
.out{margin-inline-start:auto;font-size:13px;color:var(--t2);text-decoration:none}.out:hover{color:var(--t1)}
main{max-width:1440px;margin:0 auto;padding:24px;display:grid;grid-template-columns:minmax(0,1fr);gap:24px}
section{display:grid;grid-template-columns:minmax(0,1fr);gap:16px;min-width:0}
.tools{display:flex;flex-wrap:wrap;align-items:center;gap:12px 16px}
.seg{display:inline-flex;gap:2px;padding:2px;border-radius:10px;background:var(--raised);max-width:100%;overflow-x:auto}
.seg button{height:28px;padding:0 12px;border:0;border-radius:8px;background:none;color:var(--t2);cursor:pointer;white-space:nowrap;
  transition:background-color .15s var(--ease),color .15s var(--ease)}
.seg button:hover{color:var(--t1)}.seg button.on{background:var(--sel);color:var(--onsel)}
.custom{display:flex;flex-wrap:wrap;align-items:center;gap:8px;color:var(--t3);font-size:13px}.custom input{height:32px;padding:0 8px;min-width:0;flex:1 1 128px}.custom .btn{height:32px}
.custom select{height:32px;padding:0 8px;flex:none;font-variant-numeric:tabular-nums;cursor:pointer}
.custom .pair{display:flex;align-items:center;gap:8px;flex:1 1 240px;min-width:0}.custom .pair label{flex:none;min-width:16px}
.scopes{display:flex;flex-wrap:wrap;align-items:center;gap:8px}.scopes>span{font-size:13px;color:var(--t3);margin-inline-end:4px}
.chip{height:32px;padding:0 12px;border-radius:8px;border:1px solid var(--line);background:none;color:var(--t2);cursor:pointer;
  display:inline-flex;align-items:center;gap:8px;transition:background-color .15s var(--ease),color .15s var(--ease),border-color .15s var(--ease)}
.chip:hover{color:var(--t1);background:var(--hover)}.chip.on{background:var(--raised);border-color:var(--line2);color:var(--t1)}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex:none}
.q{display:inline-flex;align-items:baseline;gap:4px;white-space:nowrap}.q small{font-size:12px;color:var(--t3)}
.kpis,.cards{display:grid;gap:12px}.kpis{grid-template-columns:minmax(0,1.3fr) repeat(3,minmax(0,1fr)) minmax(0,1.3fr)}.cards{grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
.alerts{display:grid;gap:8px}.alerts:empty{display:none}
.alert{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;padding:12px 16px;border-radius:12px;
  border:1px solid color-mix(in srgb,var(--warn) 35%,var(--line));background:color-mix(in srgb,var(--warn) 7%,var(--card))}
.alert>.ic{color:var(--warn);flex:none}.alert .txt{flex:1;min-width:220px;display:grid;gap:2px}
.alert .txt b{font-size:14px}.alert .txt span{font-size:12px;color:var(--t2)}.alert .acts{display:flex;gap:8px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;min-width:0}
.kpi .k{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--t2)}
.kpi .v{display:flex;align-items:baseline;gap:8px;margin-top:8px;font-size:28px;line-height:1.2;font-weight:500;font-variant-numeric:tabular-nums;white-space:nowrap}
.kpi.main .v{font-size:32px}.kpi .v .q small{font-size:14px}.kpi .v .ic{align-self:center;color:var(--t3)}
.kpi .s{margin-top:4px;font-size:12px;color:var(--t3);font-variant-numeric:tabular-nums}.kpi .s .ic{vertical-align:-2px}
.meter{height:4px;border-radius:2px;background:var(--raised);margin-top:12px;overflow:hidden}
.meter i{display:block;height:100%;border-radius:2px;background:var(--t3)}.kpi.warn .meter i{background:var(--warn)}.kpi.bad .meter i{background:var(--bad)}
.led{width:8px;height:8px;border-radius:50%;background:var(--t3);opacity:.5;flex:none}.led.on{background:var(--live);opacity:1}
.led.blink{animation:blink .9s var(--ease) 1}@keyframes blink{30%{opacity:.15}}
.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;overflow:hidden;min-width:0}
.ph{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px 16px;padding:16px 20px}
.ph h2{margin:0;font-size:15px;line-height:1.4}.ph>div:first-child{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 12px}
.sub,.cap{font-size:12px;color:var(--t3)}.cap{margin:0;padding:0 20px 12px;line-height:1.7}
.legend{display:flex;flex-wrap:wrap;gap:4px 16px;font-size:12px;color:var(--t2)}.legend span{display:inline-flex;align-items:center;gap:8px}
.chart{padding:0 12px 12px}.chart svg{display:block;width:100%;direction:ltr}
.plot text{font:11px Vazirmatn,Tahoma,sans-serif;fill:var(--t3)}
.empty{padding:24px 20px;color:var(--t3);font-size:13px}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th{height:36px;padding:0 16px;font-size:12px;font-weight:400;color:var(--t3);text-align:right;border-top:1px solid var(--line);border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:12px 16px;text-align:right;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:middle}
tbody tr:last-child td{border-bottom:0}
tr.g{cursor:pointer}tr.g td{font-weight:500;transition:background-color .15s var(--ease)}tr.g:hover td{background:var(--hover)}
tr.g .ic{color:var(--t3);vertical-align:-3px;margin-inline-end:4px;transition:transform .2s var(--ease)}tr.g.open .ic{transform:rotate(-90deg)}
.gn{display:inline-flex;align-items:center;gap:8px}.cnt{font-size:12px;font-weight:400;color:var(--t3)}
tr.p td:first-child{padding-inline-start:52px}.pp{display:inline-flex;align-items:center;gap:8px}.pp .dot{width:6px;height:6px}
.desc{display:flex;align-items:center;gap:4px;max-width:360px;margin-top:2px;font-size:12px;color:var(--t3);white-space:normal;cursor:pointer}
.desc .ic{opacity:0;transition:opacity .15s var(--ease)}.desc:hover{color:var(--t2)}.desc:hover .ic{opacity:1}.desc.empty{color:var(--t3);opacity:.7}
tr.tot td{font-weight:500;background:var(--raised);border-bottom:0}
.share{display:inline-flex;align-items:center;gap:8px}.bar{width:56px;height:4px;border-radius:2px;background:var(--raised);overflow:hidden}
.bar i{display:block;height:100%;border-radius:2px}
.dim{color:var(--t2)}
.tip{position:fixed;z-index:9;display:none;min-width:180px;padding:12px;border-radius:10px;border:1px solid var(--line2);background:var(--raised);
  box-shadow:var(--shadow);font-size:13px;line-height:20px;pointer-events:none;font-variant-numeric:tabular-nums}
.tip b{display:block;margin-bottom:4px}.tip .r{display:flex;align-items:center;justify-content:space-between;gap:16px}
.tip .r span:first-child{display:inline-flex;align-items:center;gap:8px;color:var(--t2)}.tip .hd{margin-top:8px;color:var(--t3);font-size:12px}
.hide{display:none!important}
.sgrid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:16px}.sgrid .w4{grid-column:span 4}.sgrid .w2{grid-column:span 2}.sgrid .w3{grid-column:span 3}
td .pid{font-size:12px;color:var(--t3);margin-inline-start:8px;unicode-bidi:isolate}.nw{white-space:nowrap}
.mgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:16px;align-items:start}
.form{display:flex;flex-wrap:wrap;align-items:flex-end;gap:12px;padding:0 20px 16px}.form.col{flex-direction:column;align-items:stretch;gap:8px}
.field{display:grid;gap:4px}.field.grow{flex:1;min-width:180px}.field label,.lab{font-size:13px;color:var(--t2)}
input[type=color]{width:36px;padding:2px;cursor:pointer}
.row{display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:12px 20px;border-top:1px solid var(--line)}
.row .grow{flex:1;min-width:140px}.row .num{min-width:56px;font-variant-numeric:tabular-nums}.row .meta{font-size:13px;color:var(--t3)}
.gsel{display:flex;flex-wrap:wrap;gap:8px}
.gsel label{height:28px;padding:0 10px;border-radius:6px;border:1px solid var(--line);display:inline-flex;align-items:center;gap:8px;
  font-size:13px;color:var(--t2);cursor:pointer;transition:background-color .15s var(--ease),color .15s var(--ease)}
.gsel label.on{background:var(--raised);border-color:var(--line2);color:var(--t1)}.gsel input{width:14px;height:14px;margin:0;accent-color:var(--t1)}
.prow{display:grid;grid-template-columns:64px 1fr auto;gap:12px;align-items:start;padding:16px 20px;border-top:1px solid var(--line)}
.prow .num{padding-top:8px;font-weight:500}.prow textarea{width:100%;min-height:36px;resize:vertical}.prow>div{display:grid;gap:8px}
.toast{position:fixed;bottom:24px;left:24px;z-index:10;padding:12px 16px;border-radius:10px;border:1px solid var(--line2);background:var(--raised);
  box-shadow:var(--shadow);font-size:13px;opacity:0;transform:translateY(8px);pointer-events:none;transition:opacity .2s var(--ease),transform .2s var(--ease)}
.toast.show{opacity:1;transform:none}
@media (max-width:900px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.kpi.main{grid-column:span 2}.sgrid .w4,.sgrid .w2,.sgrid .w3{grid-column:1/-1}.mgrid{grid-template-columns:1fr}}
@media (max-width:640px){.top{flex-wrap:wrap;height:auto;gap:0 16px;padding:12px 16px 0}.brand{flex:1}.tabs{order:3;width:100%;height:44px;margin-top:8px;overflow-x:auto}
  main{padding:16px;gap:16px}.kpi{padding:12px 16px}.kpi .v{font-size:22px}.kpi.main .v{font-size:26px}.ph{padding:12px 16px}
  th{padding:0 10px}td{padding:10px}tr.p td:first-child{padding-inline-start:36px}.prow{grid-template-columns:48px 1fr;padding:12px 16px}
  .prow .btn{grid-column:2;justify-self:start}.form{padding:0 16px 16px}.row{padding:12px 16px}.cap{padding:0 16px 12px}.toast{left:16px;right:16px;bottom:16px}}
@media (prefers-reduced-motion: reduce){*{transition:none!important;animation:none!important}}
</style></head><body>
<header class="top"><div class="brand"><b>{{TITLE}}</b><span id="host"></span></div>
<nav class="tabs" aria-label="بخش‌ها"><button class="on" data-tab="rep">مصرف پورت‌ها</button><button data-tab="sys">منابع سرور</button><button data-tab="mgr">تنظیمات</button></nav>
<a class="out" href="/logout">خروج</a></header>
<main>
<section id="rep">
 <div class="tools">
  <div class="seg" id="ranges" aria-label="بازه"><button data-r="today">امروز</button><button data-r="yesterday">دیروز</button><button class="on" data-r="7">۷ روز</button><button data-r="30">۳۰ روز</button><button data-r="90">۹۰ روز</button></div>
  <div class="custom"><span class="pair"><label for="from">از</label><input type="date" id="from"><select id="fh" aria-label="ساعت شروع"></select></span><span class="pair"><label for="to">تا</label><input type="date" id="to"><select id="th" aria-label="ساعت پایان"></select></span><button class="btn" id="apply">نمایش</button></div>
 </div>
 <div class="scopes" id="scopes"></div>
 <div class="alerts" id="unw" role="status"></div>
 <div class="kpis">
  <div class="kpi main"><div class="k">مجموع</div><div class="v" id="c_tot">—</div><div class="s" id="c_tot_s"></div></div>
  <div class="kpi"><div class="k">دانلود کاربران</div><div class="v" id="c_tx">—</div></div>
  <div class="kpi"><div class="k">آپلود کاربران</div><div class="v" id="c_rx">—</div></div>
  <div class="kpi" title="هرچه کارت شبکهٔ سرور گرفته: همهٔ پورت‌ها و تونل‌ها، با سربارشان. دیتاسنتری که فقط ورودی را می‌شمارد همین را حساب می‌کند."><div class="k">ورودی سرور</div><div class="v" id="c_nic">—</div><div class="s" id="c_nic_s"></div></div>
  <div class="kpi"><div class="k"><i class="led" id="led"></i>سرعت همین الان</div><div class="v" id="c_live">—</div><div class="s" id="c_live_s"></div></div>
 </div>
 <div class="panel"><div class="ph"><div><h2 id="chart_title">مصرف روزانه</h2><span class="sub" id="range_lbl"></span></div><div class="legend" id="legend"></div></div><div class="chart" id="chart"></div></div>
 <div class="panel"><div class="ph"><h2>گروه‌ها و پورت‌ها</h2></div>
  <div class="scroll"><table><thead><tr><th>گروه / پورت</th><th>دانلود</th><th>آپلود</th><th>مجموع</th><th>سهم</th><th>الان</th></tr></thead><tbody id="tbl"></tbody></table></div></div>
</section>
<section id="sys" class="hide">
 <div class="tools"><div class="seg" aria-label="بازهٔ نمودار"><button data-h="1">۱ ساعت</button><button data-h="6">۶ ساعت</button><button class="on" data-h="24">۲۴ ساعت</button><button data-h="72">۳ روز</button><button data-h="168">۷ روز</button></div><span class="sub" id="sys_info"></span></div>
 <div class="cards" id="sys_cards"></div>
 <div class="sgrid">
  <div class="panel w4"><div class="ph"><h2>شبکه، کارت اصلی</h2><div class="legend"><span><i class="dot" style="background:var(--dn)"></i>دریافت</span><span><i class="dot" style="background:var(--upc)"></i>ارسال</span></div></div><div class="chart" id="ch_net"></div></div>
  <div class="panel w2"><div class="ph"><h2>پرمصرف‌ترین برنامه‌ها</h2></div><div class="scroll"><table><thead><tr><th>برنامه</th><th>پردازنده</th><th>رم</th></tr></thead><tbody id="top"></tbody></table></div></div>
  <div class="panel w3"><div class="ph"><h2>پردازنده</h2><span class="sub">درصد</span></div><div class="chart" id="ch_cpu"></div></div>
  <div class="panel w3"><div class="ph"><h2>رم</h2><span class="sub">درصد</span></div><div class="chart" id="ch_mem"></div></div>
 </div>
</section>
<section id="mgr" class="hide">
 <div class="mgrid">
  <div class="panel"><div class="ph"><h2>گروه‌ها</h2></div>
   <div class="form"><div class="field grow"><label for="g_name">گروه جدید</label><input id="g_name" placeholder="مثلاً آلمان"></div>
    <div class="field"><label for="g_color">رنگ</label><input id="g_color" type="color"></div><button class="btn pri" id="g_add">افزودن گروه</button></div>
   <div id="glist"></div></div>
  <div class="panel"><div class="ph"><h2>افزودن پورت</h2></div>
   <div class="form"><div class="field"><label for="p_port">پورت</label><input id="p_port" type="number" min="1" max="65535" inputmode="numeric" style="width:120px"></div>
    <div class="field grow"><label for="p_label">توضیح</label><input id="p_label" placeholder="مثلاً تانل اصلی به آلمان"></div></div>
   <div class="form col"><span class="lab">گروه‌ها، هر چندتا که لازم است</span><div class="gsel" id="p_groups"></div></div>
   <div class="form"><button class="btn pri" id="p_add">افزودن پورت</button></div>
   <div class="ph" style="border-top:1px solid var(--line)"><h2>پورت‌های باز روی سرور</h2></div>
   <p class="cap">پورت‌هایی که الان روی سرور گوش می‌دهند. «انتخاب» شماره را در فرم بالا می‌گذارد.</p><div id="llist"></div></div>
 </div>
 <div class="panel"><div class="ph"><h2>پورت‌های زیر نظر</h2><span class="sub">توضیح و گروه‌ها خودکار ذخیره می‌شوند</span></div><div id="plist"></div></div>
 <div class="panel"><div class="ph"><h2>تغییر رمز</h2></div>
  <div class="form"><div class="field"><label for="pw_old">رمز فعلی</label><input id="pw_old" type="password" autocomplete="current-password"></div>
   <div class="field"><label for="pw_new">رمز جدید</label><input id="pw_new" type="password" autocomplete="new-password" aria-describedby="pw_h"></div>
   <button class="btn pri" id="pw_btn">ذخیره</button></div><p class="cap" id="pw_h">رمز جدید دست‌کم ۸ نویسه</p></div>
</section>
</main><div class="tip" id="tip"></div><div class="toast" id="toast" role="status"></div>
<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const fa=(n,d)=>Number(n).toLocaleString('fa-IR',d==null?undefined:{maximumFractionDigits:d});
const fp=p=>Number(p).toLocaleString('fa-IR',{useGrouping:false});   /* a port number, never «۲٬۰۹۳» */
/* chart labels sit in an LTR drawing; an RTL isolate orders them as the page does: «GB ۱۰۰», «آبان ۵» */
const rl=t=>'\u2067'+t+'\u2069';
const IC={chev:'<path d="m15 18-6-6 6-6"/>',pen:'<path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/><path d="m15 5 4 4"/>',
  down:'<path d="M12 5v14"/><path d="m19 12-7 7-7-7"/>',up:'<path d="m5 12 7-7 7 7"/><path d="M12 19V5"/>',
  warn:'<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>'};
const ico=(k,s)=>`<svg class="ic" viewBox="0 0 24 24" width="${s||16}" height="${s||16}" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${IC[k]}</svg>`;
function unit(b){const u=['بایت','KB','MB','GB','TB','PB'];let i=0;b=Number(b)||0;while(b>=1024&&i<u.length-1){b/=1024;i++}
  return [b.toLocaleString('fa-IR',{maximumFractionDigits:(b>=100||i==0)?0:(b>=10?1:2)}),u[i]]}
function rateU(bps){const u=['bps','Kbps','Mbps','Gbps'];let i=0,v=(Number(bps)||0)*8;while(v>=1000&&i<u.length-1){v/=1000;i++}
  return [v.toLocaleString('fa-IR',{maximumFractionDigits:v>=100?0:1}),u[i]]}
const bytes=b=>Number(b)?unit(b).join(' '):'۰', rate=bps=>rateU(bps).join(' ');
const nb=b=>`<span class="nw">${bytes(b)}</span>`, nr=bps=>`<span class="nw">${rate(bps)}</span>`;
const Q=([n,u])=>`<span class="q"><span>${n}</span>${u?`<small>${u}</small>`:''}</span>`;
const QB=b=>Number(b)?Q(unit(b)):Q(['۰','']), QR=bps=>Q(rateU(bps));
const DF=o=>new Intl.DateTimeFormat('fa-IR-u-ca-persian',o), D=d=>new Date(d+'T12:00:00');
const jal=d=>DF({month:'short',day:'numeric'}).format(D(d));
const jalFull=d=>DF({weekday:'long',year:'numeric',month:'long',day:'numeric'}).format(D(d));
function jalRange(a,b){if(a==b)return jalFull(a);const f=DF({year:'numeric',month:'long',day:'numeric'});
  try{return f.formatRange(D(a),D(b))}catch(e){return f.format(D(a))+' تا '+f.format(D(b))}}
const clock=(ts,o)=>DF(Object.assign({hour:'2-digit',minute:'2-digit',timeZone:'Asia/Tehran'},o||{})).format(new Date(ts*1000));
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let CFG=null,OPEN=new Set(),RANGE='7',SCOPE='all',HOURS=24;const LAST={};
async function api(p,body){const r=await fetch(p,body?{method:'POST',headers:{'Content-Type':'application/json','X-PM':'1'},body:JSON.stringify(body)}:{});if(r.status==401){location='/login';throw 0}const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}
function toast(t){const e=$('#toast');e.textContent=t;e.classList.add('show');clearTimeout(e._t);e._t=setTimeout(()=>e.classList.remove('show'),2600)}
function addDays(iso,n){const d=new Date(iso+'T12:00:00Z');d.setUTCDate(d.getUTCDate()+n);return d.toISOString().slice(0,10)}
function rangeDates(r){const t=CFG.today;if(r=='today')return[t,t];if(r=='yesterday'){const y=addDays(t,-1);return[y,y]}return[addDays(t,-(Number(r)-1)),t]}
const G=id=>CFG.groups.find(g=>String(g.id)===String(id));
const gColor=id=>(G(id)||{}).color||'#85858b';
const pLabel=p=>{const x=CFG.ports.find(q=>q.port==p);return x&&x.label?x.label:''};
const width=el=>Math.max(280,Math.round($(el).clientWidth-24));
/* the link light: lit while samples keep coming, one blink for each new one, grey once the collector stops */
function led(el,ts,interval){if(!el)return;const age=Date.now()/1000-(ts||0),fresh=!!ts&&age<3*Math.max(60,interval||60);
  el.classList.toggle('on',fresh);el.title=ts?`آخرین نمونه ${fa(Math.max(0,Math.round(age/60)))} دقیقه پیش`:'هنوز نمونه‌ای نیست';
  if(fresh&&el._ts!==ts){el._ts=ts;el.classList.remove('blink');void el.offsetWidth;el.classList.add('blink')}}
function tipAt(e,h){const tip=$('#tip');tip.innerHTML=h;tip.style.display='block';const w=tip.offsetWidth,ht=tip.offsetHeight;
  tip.style.left=Math.max(8,Math.min(e.clientX+16,innerWidth-w-8))+'px';tip.style.top=Math.max(8,Math.min(e.clientY+16,innerHeight-ht-8))+'px'}
const tipOff=()=>$('#tip').style.display='none';

/* ---------------- usage report ---------------- */
function renderScopes(){
  const one=(s,label,c)=>`<button class="chip ${SCOPE==s?'on':''}" data-s="${s}">${c?`<i class="dot" style="background:${c}"></i>`:''}${label}</button>`;
  $('#scopes').innerHTML='<span>نمایش</span>'+one('all','همهٔ پورت‌ها')+CFG.groups.map(g=>one(String(g.id),esc(g.name),g.color)).join('');
  $$('#scopes [data-s]').forEach(b=>b.onclick=()=>{SCOPE=b.dataset.s;renderScopes();load()});
}
/* «۰۸:۰۰»: the hour pickers beside the dates; the end picker runs to ۲۴:۰۰, the end of its day */
const hh=h=>Number(h).toLocaleString('fa-IR',{minimumIntegerDigits:2})+':'+'۰۰';
$('#fh').innerHTML=[...Array(24).keys()].map(h=>`<option value="${h}">${hh(h)}</option>`).join('');
$('#th').innerHTML=[...Array(24).keys()].map(h=>`<option value="${h+1}"${h==23?' selected':''}>${hh(h+1)}</option>`).join('');
const jalDay=d=>DF({year:'numeric',month:'long',day:'numeric'}).format(D(d));
async function load(){
  const custom=RANGE=='custom';
  const [f,t]=custom?[$('#from').value,$('#to').value]:rangeDates(RANGE);
  const [fh,th]=custom?[Number($('#fh').value),Number($('#th').value)]:[0,24];
  $('#from').value=f;$('#to').value=t;$('#fh').value=fh;$('#th').value=th;
  const whole=fh==0&&th==24;
  if(!whole&&(f>t||(f==t&&fh>=th)))return toast('شروع بازه باید پیش از پایانش باشد');
  const sq=SCOPE=='all'?'':`&group=${SCOPE}`;
  const R=await api(`/api/report?from=${f}&to=${t}${sq}${whole?'':`&fh=${fh}&th=${th}`}`);
  $('#c_rx').innerHTML=QB(R.total.rx);$('#c_tx').innerHTML=QB(R.total.tx);$('#c_tot').innerHTML=QB(R.total.rx+R.total.tx);
  const g=SCOPE=='all'?null:G(SCOPE);
  $('#c_tot_s').textContent=g?`گروه «${g.name}»`:'هر پورت یک بار حساب شده';
  $('#c_live').innerHTML=ico('down',18)+QR(R.live.tx_bps);
  $('#c_live_s').innerHTML=`${ico('up',12)} ${rate(R.live.rx_bps)} آپلود`;
  led($('#led'),R.live.ts,R.live.interval);
  const N=R.nic;
  $('#c_nic').innerHTML=N.since?QB(N.rx):'—';
  $('#c_nic_s').innerHTML=!N.since?'از چند دقیقهٔ دیگر':(SCOPE=='all'?'':'کل سرور · ')+`خروجی ${nb(N.tx)}`
    +(N.partial?(N.since>f?` · ثبت از ${jal(N.since)}`:' · بخشی از بازه ثبت نشده'):'');
  renderUnwatched(R.unwatched);
  $('#range_lbl').textContent=whole?jalRange(f,t):f==t?`${jalFull(f)}، ساعت ${hh(fh)} تا ${hh(th)}`
    :`${jalDay(f)} ساعت ${hh(fh)} تا ${jalDay(t)} ساعت ${hh(th)}`;
  renderTable(R);
  if(whole&&f==t){const H=await api(`/api/hourly?day=${f}${sq}`);$('#chart_title').textContent='مصرف ساعتی';
    drawUsage(H.hours.map(x=>({lbl:fa(Number(x.key)),full:`ساعت ${fa(Number(x.key))} تا ${fa(Number(x.key)+1)}`,...x})))}
  else if(R.unit=='hour'){$('#chart_title').textContent='مصرف ساعتی';   /* a window of up to 48 hours */
    drawUsage(R.days.map((x,i)=>{const d=x.key.slice(0,10),h=Number(x.key.slice(11)),now=x.key==R.now_hour;
      return {lbl:f!=t&&(h==0||i==0)?jal(d):fa(h),full:`${jalFull(d)}، ساعت ${hh(h)} تا ${hh(h+1)}`+(now?'، تا این لحظه':''),now,...x}}))}
  else{$('#chart_title').textContent='مصرف روزانه';
    drawUsage(R.days.map(x=>({lbl:x.key==CFG.today?'امروز':jal(x.key),full:jalFull(x.key)+(x.key==CFG.today?'، تا این لحظه':''),now:x.key==CFG.today,...x})))}
}
function ago(ts){const m=Math.max(1,Math.round((Date.now()/1000-ts)/60));return m<60?`${fa(m)} دقیقه پیش`:`${fa(Math.round(m/60))} ساعت پیش`}
/* a port someone uses that nobody watches: its traffic reaches the provider's meter but not this page */
function renderUnwatched(list){
  $('#unw').innerHTML=(list||[]).map(u=>`<div class="alert">${ico('warn',20)}<div class="txt"><b>پورت ${fp(u.port)} کاربر دارد ولی زیر نظر نیست</b>`
    +`<span>${u.active?'الان':ago(u.last_seen)+':'} ${fa(u.conns)} اتصال از ${fa(u.peers)} آی‌پی${u.unit?` · سرویس ${esc(u.unit)}`:u.process?` · برنامهٔ ${esc(u.process)}`:''} · ترافیکش در آمار این صفحه نیست</span></div>`
    +`<div class="acts"><button class="btn sm pri" data-ua="${u.port}" data-ul="${esc(u.unit)}">زیر نظر بگیر</button><button class="btn sm" data-ui="${u.port}">نادیده بگیر</button></div></div>`).join('');
  $$('#unw [data-ua]').forEach(b=>b.onclick=()=>pick(b.dataset.ua,b.dataset.ul));
  $$('#unw [data-ui]').forEach(b=>b.onclick=()=>act('/api/port',{action:'ignore',port:b.dataset.ui}));
}
function pick(port,unit){$('[data-tab="mgr"]').click();$('#p_port').value=port;
  if(unit&&!$('#p_label').value)$('#p_label').value='سرویس '+unit;
  scrollTo({top:0,behavior:'smooth'});toast('گروهش را انتخاب کنید و «افزودن پورت» را بزنید')}
function renderTable(R){
  const P={};R.ports.forEach(p=>P[p.port]=p);
  const scopeTot=(R.total.rx+R.total.tx)||1;let h='';
  const share=(v,c)=>`<span class="share"><span class="bar"><i style="width:${Math.max(2,Math.round(100*v/scopeTot))}%;background:${c}"></i></span>${fa(Math.round(100*v/scopeTot))}٪</span>`;
  const portRow=(p,gid,color)=>{const pt=p.rx+p.tx;const others=p.groups.filter(x=>String(x)!==String(gid));
    return `<tr class="p ${OPEN.has(String(gid))||SCOPE!='all'?'':'hide'}" data-pg="${gid}"><td><span class="pp">پورت ${fp(p.port)}${others.map(o=>`<i class="dot" title="${esc((G(o)||{}).name)}" style="background:${gColor(o)}"></i>`).join('')}</span>`
      +`<span class="desc ${p.label?'':'empty'}" data-ed="${p.port}">${p.label?esc(p.label):'افزودن توضیح'}${ico('pen',12)}</span></td>`
      +`<td>${QB(p.tx)}</td><td>${QB(p.rx)}</td><td>${QB(pt)}</td><td>${share(pt,color)}</td><td class="dim">${rate(p.live.rx_bps+p.live.tx_bps)}</td></tr>`};
  const groupRow=(gid,name,color,n,tx,rx,live)=>`<tr class="g ${OPEN.has(gid)?'open':''}" data-g="${gid}"><td><span class="gn">${ico('chev')}<i class="dot" style="background:${color}"></i>${name}<span class="cnt">${fa(n)} پورت</span></span></td>`
      +`<td>${QB(tx)}</td><td>${QB(rx)}</td><td>${QB(tx+rx)}</td><td>${share(tx+rx,color)}</td><td class="dim">${rate(live)}</td></tr>`;
  const groups=SCOPE=='all'?R.groups:R.groups.filter(g=>String(g.id)===SCOPE);
  for(const g of groups){const gid=String(g.id);
    if(SCOPE=='all')h+=groupRow(gid,esc(g.name),g.color,g.ports.length,g.tx,g.rx,g.live);
    h+=g.ports.map(x=>P[x]).sort((a,b)=>(b.rx+b.tx)-(a.rx+a.tx)).map(p=>portRow(p,gid,g.color)).join('')}
  if(SCOPE=='all'&&R.ungrouped.length){const ug=R.ungrouped.map(x=>P[x]);
    h+=groupRow('none','بدون گروه','#85858b',ug.length,ug.reduce((a,p)=>a+p.tx,0),ug.reduce((a,p)=>a+p.rx,0),ug.reduce((a,p)=>a+p.live.rx_bps+p.live.tx_bps,0));
    h+=ug.sort((a,b)=>(b.rx+b.tx)-(a.rx+a.tx)).map(p=>portRow(p,'none','#85858b')).join('')}
  h+=`<tr class="tot"><td>${SCOPE=='all'?'کل، هر پورت یک بار':'کل گروه'}</td><td>${QB(R.total.tx)}</td><td>${QB(R.total.rx)}</td><td>${QB(R.total.rx+R.total.tx)}</td><td>۱۰۰٪</td><td>${rate(R.live.rx_bps+R.live.tx_bps)}</td></tr>`;
  $('#tbl').innerHTML=R.ports.length?h:'<tr><td colspan="6" class="empty">هنوز پورتی زیر نظر نیست؛ از «تنظیمات» اضافه کنید</td></tr>';
  $$('#tbl tr.g').forEach(tr=>tr.onclick=()=>{const g=tr.dataset.g;OPEN.has(g)?OPEN.delete(g):OPEN.add(g);tr.classList.toggle('open');$$(`#tbl tr[data-pg="${g}"]`).forEach(x=>x.classList.toggle('hide'))});
  $$('#tbl [data-ed]').forEach(e=>e.onclick=ev=>{ev.stopPropagation();const p=e.dataset.ed;const v=prompt(`توضیح پورت ${p}:`,pLabel(p));if(v!==null)act('/api/port',{action:'edit',port:p,label:v})});
}
function axis(max){let step=Math.pow(1024,Math.floor(Math.log(Math.max(max,1))/Math.log(1024)));const nice=[1,2,5,10,20,50,100,200,500,1000].map(m=>m*step).find(v=>v*4>=max)||max/4;return nice}
function drawUsage(items){
  LAST.usage=items;
  const W=width('#chart'),H=innerWidth<640?220:300,pl=4,pr=64,pt=12,pb=28,n=items.length||1,bw=(W-pl-pr)/n,barW=Math.max(2,Math.min(32,bw*.6));
  const multi=SCOPE=='all'&&CFG.groups.length>0,col=multi?'var(--t1)':(SCOPE=='all'?'var(--c1)':gColor(SCOPE));
  const vals=multi?items.flatMap(x=>[x.total,...Object.values(x.groups)]):items.map(x=>x.total);
  const nice=axis(Math.max(1,...vals)),top=nice*4,y=v=>pt+(H-pt-pb)*(1-v/top),xc=i=>W-pr-(i+.5)*bw;
  let s=`<svg class="plot" viewBox="0 0 ${W} ${H}" height="${H}" role="img" aria-label="${esc($('#chart_title').textContent)}">`
    +`<defs><pattern id="now" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><line x1="0" y1="0" x2="0" y2="5" stroke="${col}" stroke-width="2"/></pattern></defs>`
    +`<rect id="hov" y="${pt}" height="${H-pt-pb}" width="${bw}" fill="var(--t1)" opacity="0" rx="4"/>`;
  for(let i=0;i<=4;i++){const v=nice*i;s+=`<line x1="${pl}" x2="${W-pr}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line${i?'':'2'})"/><text x="${W-pr+12}" y="${y(v)+4}">${rl(bytes(v))}</text>`}
  const op=multi?.12:1;
  s+=items.map((it,i)=>`<rect x="${xc(i)-barW/2}" y="${y(it.total)}" width="${barW}" height="${Math.max(0,y(0)-y(it.total))}" fill="${it.now?'url(#now)':col}" opacity="${it.now?op*1.6:op}" rx="2"/>`).join('');
  if(multi)for(const g of CFG.groups){const pts=items.map((it,i)=>`${xc(i)},${y(it.groups[String(g.id)]||0)}`);
    s+=`<polyline points="${pts.join(' ')}" fill="none" stroke="${g.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
    if(n<=31)s+=items.map((it,i)=>`<circle cx="${xc(i)}" cy="${y(it.groups[String(g.id)]||0)}" r="3" fill="${g.color}" stroke="var(--card)" stroke-width="1.5"/>`).join('')}
  const every=Math.ceil(n/Math.max(4,Math.floor(W/64)));
  items.forEach((it,i)=>{s+=`<rect class="hit" data-i="${i}" x="${xc(i)-bw/2}" y="${pt}" width="${bw}" height="${H-pt-pb}" fill="transparent"/>`;
    if(i%every==0||it.now)s+=`<text x="${xc(i)}" y="${H-8}" text-anchor="middle"${it.now?' style="fill:var(--t1)"':''}>${rl(it.lbl)}</text>`});
  $('#chart').innerHTML=s+'</svg>';
  $('#legend').innerHTML=multi?CFG.groups.map(g=>`<span><i class="dot" style="background:${g.color}"></i>${esc(g.name)}</span>`).join('')+`<span><i class="dot" style="background:var(--t1);opacity:.25"></i>کل، هر پورت یک بار</span>`:'';
  const hov=$('#hov');
  $$('#chart .hit').forEach(r=>{r.onmousemove=e=>{const it=items[r.dataset.i];hov.setAttribute('x',r.getAttribute('x'));hov.setAttribute('opacity','.05');
    let h=`<b>${it.full}</b><div class="r"><span>مجموع</span>${bytes(it.total)}</div>`;
    if(it.nic!=null)h+=`<div class="r"><span>ورودی سرور</span>${bytes(it.nic)}</div>`;
    if(multi)h+=CFG.groups.filter(g=>it.groups[String(g.id)]).map(g=>`<div class="r"><span><i class="dot" style="background:${g.color}"></i>${esc(g.name)}</span>${bytes(it.groups[String(g.id)])}</div>`).join('');
    if(it.top&&it.top.length)h+='<div class="hd">پرمصرف‌ها</div>'+it.top.map(([p,v])=>`<div class="r"><span>پورت ${fp(p)}${pLabel(p)?' · '+esc(pLabel(p)).slice(0,28):''}</span>${bytes(v)}</div>`).join('');
    tipAt(e,h)};r.onmouseleave=()=>{tipOff();hov.setAttribute('opacity','0')}})
}

/* ---------------- server resources ---------------- */
function lineChart(el,hist,series,fmt,maxFixed,H){
  LAST[el]=[hist,series,fmt,maxFixed,H];
  const W=width(el),pl=4,pr=64,pt=12,pb=28;H=H||180;
  if(!hist.length){$(el).innerHTML='<div class="empty">هنوز داده‌ای نیست؛ چند دقیقه بعد سر بزنید</div>';return}
  const k=Math.max(1,Math.ceil(hist.length/Math.floor((W-pr)/4))),pts=[];   /* one point per ~4px: the shape, not the noise */
  for(let i=0;i<hist.length;i+=k){const c=hist.slice(i,i+k),o={ts:c[c.length-1].ts};for(const s of series)o[s.k]=c.reduce((a,h)=>a+(h[s.k]||0),0)/c.length;pts.push(o)}
  const t0=pts[0].ts,t1=pts[pts.length-1].ts||t0+1,x=ts=>W-pr-(W-pl-pr)*(t1==t0?0:(ts-t0)/(t1-t0));
  const max=maxFixed||Math.max(1e-9,...pts.flatMap(h=>series.map(s=>h[s.k]||0)))*1.15,y=v=>pt+(H-pt-pb)*(1-v/max);
  let s=`<svg class="plot" viewBox="0 0 ${W} ${H}" height="${H}">`;
  for(let i=0;i<=4;i++){const v=max*i/4;s+=`<line x1="${pl}" x2="${W-pr}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line${i?'':'2'})"/>${i%2==0?`<text x="${W-pr+12}" y="${y(v)+4}">${rl(fmt(v))}</text>`:''}`}
  for(const se of series){const line=pts.map(h=>`${x(h.ts)},${y(h[se.k]||0)}`).join(' ');
    s+=`<polygon points="${x(t0)},${y(0)} ${line} ${x(t1)},${y(0)}" fill="${se.c}" opacity=".08"/><polyline points="${line}" fill="none" stroke="${se.c}" stroke-width="1.75" stroke-linejoin="round"/>`}
  const long=HOURS>24;
  for(let i=0;i<4;i++){const ts=t0+(t1-t0)*i/3;s+=`<text x="${x(ts)}" y="${H-8}" text-anchor="${i==0?'end':i==3?'start':'middle'}">${rl(clock(ts,long?{month:'short',day:'numeric'}:{}))}</text>`}
  $(el).innerHTML=s+'</svg>';
}
function card(k,v,s,pct,lit){const tone=pct==null?'':pct>90?'bad':pct>70?'warn':'';
  return `<div class="kpi ${tone}"><div class="k">${lit?'<i class="led" id="led_sys"></i>':''}${k}</div><div class="v">${v}</div>${s?`<div class="s">${s}</div>`:''}${pct!=null?`<div class="meter"><i style="width:${Math.max(1,Math.min(100,pct))}%"></i></div>`:''}</div>`}
function dur(s){if(s==null)return'';const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?fa(d)+' روز ':'')+(h?fa(h)+' ساعت ':'')+(d?'':fa(m)+' دقیقه')}
async function loadSys(){
  const S=await api(`/api/system?hours=${HOURS}`),n=S.now||{},i=S.info;
  $('#sys_info').textContent=`${i.host} · ${i.os} · ${fa(i.cores)} هسته · روشن از ${dur(i.uptime)}پیش`;
  const memP=n.mem_total?100*n.mem_used/n.mem_total:null,dskP=n.disk_total?100*n.disk_used/n.disk_total:null,ctP=n.ct_max?100*n.ct_count/n.ct_max:null;
  const pc=v=>v!=null?fa(v,v<10?1:0)+'٪':'…';
  $('#sys_cards').innerHTML=
    card('پردازنده',pc(n.cpu),`بار ${i.load.map(x=>fa(x)).join(' / ')} · بیشینه ${S.peak.cpu!=null?fa(S.peak.cpu,0)+'٪':'—'}`,n.cpu)+
    card('رم',pc(memP),`${nb(n.mem_used)} از ${nb(n.mem_total)}${n.swap_total?` · سواپ ${nb(n.swap_used)}`:''}`,memP)+
    card('دیسک',pc(dskP),`${nb(n.disk_used)} از ${nb(n.disk_total)}`,dskP)+
    card('شبکه همین الان',n.net_rx!=null?ico('down',18)+QR(n.net_rx):'…',n.net_tx!=null?`${ico('up',12)} ${nr(n.net_tx)} · کارت ${esc(n.iface||'')}`:'',null,true)+
    card('اتصال‌ها',n.tcp!=null?fa(n.tcp):'—',ctP!=null?`ردیابی ${fa(n.ct_count)} از ${fa(n.ct_max)}`:'',ctP);
  led($('#led_sys'),n.ts,60);
  lineChart('#ch_net',S.history,[{k:'rx',c:'var(--dn)'},{k:'tx',c:'var(--upc)'}],v=>rate(v),0,innerWidth<640?200:260);
  lineChart('#ch_cpu',S.history,[{k:'cpu',c:'var(--t2)'}],v=>fa(Math.round(v))+'٪',100);
  lineChart('#ch_mem',S.history,[{k:'mem',c:'var(--t2)'}],v=>fa(Math.round(v))+'٪',100);
  $('#top').innerHTML=S.top.map(p=>`<tr><td><bdi>${esc(p.name)}</bdi><span class="pid">${fa(p.pid)}</span></td><td>${fa(p.cpu,1)}٪</td><td>${QB(p.rss)}</td></tr>`).join('');
}

/* ---------------- settings ---------------- */
async function loadCfg(){CFG=await api('/api/config');$('#host').textContent=`${CFG.host} · نسخهٔ ${CFG.version}`;$('#g_color').value=CFG.palette.find(c=>!CFG.groups.some(g=>g.color==c))||CFG.palette[0];renderScopes();renderMgr()}
function gsel(sel,name){return CFG.groups.map(g=>`<label class="${sel.includes(g.id)?'on':''}"><input type="checkbox" data-${name}="${g.id}" ${sel.includes(g.id)?'checked':''}><i class="dot" style="background:${g.color}"></i>${esc(g.name)}</label>`).join('')||'<span class="meta">اول یک گروه بسازید</span>'}
function renderMgr(){
  $('#glist').innerHTML=CFG.groups.map(g=>`<div class="row"><input type="color" value="${g.color}" data-gc="${g.id}" aria-label="رنگ ${esc(g.name)}"><input class="grow" value="${esc(g.name)}" data-gn="${g.id}" aria-label="نام گروه"><span class="meta">${fa(CFG.ports.filter(p=>p.groups.includes(g.id)).length)} پورت</span><button class="btn del sm" data-gd="${g.id}">حذف</button></div>`).join('')||'<div class="row meta">گروهی نیست</div>';
  $('#p_groups').innerHTML=gsel([],'ng');
  $('#plist').innerHTML=CFG.ports.map(p=>`<div class="prow"><span class="num">${fp(p.port)}</span><div><textarea data-pl="${p.port}" placeholder="توضیح این پورت" aria-label="توضیح پورت ${p.port}">${esc(p.label||'')}</textarea><div class="gsel">${gsel(p.groups,'pg-'+p.port)}</div></div><button class="btn del sm" data-pd="${p.port}">حذف</button></div>`).join('')||'<div class="row meta">پورتی زیر نظر نیست</div>';
  const watched=new Set(CFG.ports.map(p=>p.port));
  $('#llist').innerHTML=CFG.listening.filter(l=>l.port!==CFG.dashboard_port).map(l=>`<div class="row"><span class="num">${fp(l.port)}</span>`
    +`<span class="meta grow">${l.proto} · ${esc(l.unit?'سرویس '+l.unit:l.process)}${l.conns?` · ${fa(l.conns)} اتصال از ${fa(l.peers)} آی‌پی`:''}</span>`
    +(watched.has(l.port)?'<span class="meta">زیر نظر است</span>'
      :(l.ignored?`<span class="meta">هشدارش خاموش است</span><button class="btn sm" data-uu="${l.port}">روشن کن</button>`:'')
       +`<button class="btn sm" data-la="${l.port}" data-ll="${esc(l.unit)}">انتخاب</button>`)+'</div>').join('');
  $$('[data-gn]').forEach(e=>e.onchange=()=>act('/api/group',{action:'edit',id:e.dataset.gn,name:e.value}));
  $$('[data-gc]').forEach(e=>e.onchange=()=>act('/api/group',{action:'edit',id:e.dataset.gc,color:e.value}));
  $$('[data-gd]').forEach(e=>e.onclick=()=>confirm('گروه حذف شود؟ پورت‌ها و آمارشان می‌مانند.')&&act('/api/group',{action:'delete',id:e.dataset.gd}));
  $$('[data-pl]').forEach(e=>e.onchange=()=>act('/api/port',{action:'edit',port:e.dataset.pl,label:e.value}));
  CFG.ports.forEach(p=>$$(`[data-pg-${p.port}]`).forEach(cb=>cb.onchange=()=>{cb.closest('label').classList.toggle('on',cb.checked);act('/api/port',{action:'edit',port:p.port,groups:$$(`[data-pg-${p.port}]`).filter(x=>x.checked).map(x=>x.getAttribute(`data-pg-${p.port}`))})}));
  $$('[data-ng]').forEach(cb=>cb.onchange=()=>cb.closest('label').classList.toggle('on',cb.checked));
  $$('[data-pd]').forEach(e=>e.onclick=()=>{const p=e.dataset.pd;if(!confirm(`پورت ${p} از زیر نظر خارج شود؟`))return;const purge=confirm('آمار قبلی این پورت هم پاک شود؟ (انصراف = آمار بماند)');act('/api/port',{action:'delete',port:p,purge})});
  $$('[data-la]').forEach(e=>e.onclick=()=>{$('#p_port').value=e.dataset.la;if(e.dataset.ll&&!$('#p_label').value)$('#p_label').value='سرویس '+e.dataset.ll;$('#p_label').focus();scrollTo({top:0,behavior:'smooth'})});
  $$('[data-uu]').forEach(e=>e.onclick=()=>act('/api/port',{action:'unignore',port:e.dataset.uu}));
}
async function act(p,b){try{await api(p,b);toast('ذخیره شد');await loadCfg();await load()}catch(e){if(e)toast(e.message)}}
$('#g_add').onclick=()=>{const n=$('#g_name').value.trim();if(!n)return;act('/api/group',{action:'add',name:n,color:$('#g_color').value});$('#g_name').value=''};
$('#p_add').onclick=()=>{const p=$('#p_port').value;if(!p)return toast('شمارهٔ پورت را بنویسید');act('/api/port',{action:'add',port:p,label:$('#p_label').value,groups:$$('[data-ng]').filter(x=>x.checked).map(x=>x.dataset.ng)});$('#p_port').value='';$('#p_label').value=''};
$('#pw_btn').onclick=async()=>{try{await api('/api/password',{old:$('#pw_old').value,new:$('#pw_new').value});toast('رمز عوض شد');$('#pw_old').value=$('#pw_new').value=''}catch(e){if(e)toast(e.message)}};
let TAB='rep';
$$('[data-tab]').forEach(b=>b.onclick=()=>{TAB=b.dataset.tab;$$('[data-tab]').forEach(x=>x.classList.toggle('on',x==b));['rep','sys','mgr'].forEach(t=>$('#'+t).classList.toggle('hide',t!=TAB));if(TAB=='sys')loadSys()});
$$('#ranges [data-r]').forEach(b=>b.onclick=()=>{RANGE=b.dataset.r;$$('#ranges [data-r]').forEach(x=>x.classList.toggle('on',x==b));load()});
$$('[data-h]').forEach(b=>b.onclick=()=>{HOURS=Number(b.dataset.h);$$('[data-h]').forEach(x=>x.classList.toggle('on',x==b));loadSys()});
$('#apply').onclick=()=>{RANGE='custom';$$('#ranges [data-r]').forEach(x=>x.classList.remove('on'));load()};
let RT;addEventListener('resize',()=>{clearTimeout(RT);RT=setTimeout(()=>{if(TAB=='rep'&&LAST.usage)drawUsage(LAST.usage);
  if(TAB=='sys')['#ch_net','#ch_cpu','#ch_mem'].forEach(el=>LAST[el]&&lineChart(el,...LAST[el]))},150)});
(async()=>{await loadCfg();await load();setInterval(()=>{if(document.hidden)return;TAB=='sys'?loadSys():TAB=='rep'?load():0},60000)})();
</script></body></html>"""

if __name__ == "__main__":
    main()

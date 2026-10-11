#!/usr/bin/env python3
"""portmon — per-port traffic and server resources for a tunnel server, with a Persian web dashboard.

Counting (nftables, table `inet portmon`): for every watched port P, the bytes of connections whose ORIGINAL destination
port is P — client->server as upload (rx), server->client as download (tx). Input counts the original direction,
output the reply direction, forward both, so a relay's own upstream connection is never counted, even when it reuses
the same port number. The rules only count; they never accept or drop anything. Bytes are network bytes (IP + TCP/UDP
headers included), so they run a few percent above what a VPN panel shows for the same traffic.

Every `interval` seconds the counters are read, turned into deltas and stored in SQLite (minutes for 3 days, hours for
90 days, days forever; days cut at Tehran time), together with a server sample (CPU, RAM, load, network, disk,
connections; kept 7 days). A port can belong to several groups; a group's total is the sum of its ports, and every
"all ports" total counts each port once. The dashboard (stdlib HTTP server, optional TLS, password login) shows usage
per group and port for any range, per-day/per-hour charts, live rates, server resources, and manages groups/ports.

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

VERSION = "2.0"
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
LOGIN_FAILS = {}


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
        """)
        # v1 kept one group per port in ports.group_id: carry it over once
        if not c.execute("SELECT 1 FROM port_groups LIMIT 1").fetchone():
            c.execute("INSERT OR IGNORE INTO port_groups (port, group_id) SELECT port, group_id FROM ports WHERE group_id IS NOT NULL")
            c.execute("UPDATE ports SET group_id = NULL")


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
    cut_min = int(time.time()) - 3 * 86400
    cut_hour = local_now(time.time() - 90 * 86400).strftime("%Y-%m-%d %H")
    with db() as c:
        c.execute("DELETE FROM usage_min WHERE ts < ?", (cut_min,))
        c.execute("DELETE FROM usage_hour WHERE hour < ?", (cut_hour,))
        c.execute("DELETE FROM sys_min WHERE ts < ?", (int(time.time()) - 7 * 86400,))


def collector():
    for fn in (lambda: sample(rebuild=True), sys_sample):
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — the loop below retries
            print(f"collector start: {type(e).__name__}: {e}", flush=True)
    n = 0
    while True:
        time.sleep(max(5, int(CFG["interval"])) - (time.time() % 1))
        for fn in (sample, sys_sample):
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
    return [dict(v, proto="/".join(sorted(v["proto"]))) for v in sorted(seen.values(), key=lambda x: x["port"])]


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


def report(day_from, day_to, group=None):
    groups, ports = layout()
    in_scope = set(scope_ports(ports, group))
    with db() as c:
        rows = c.execute("SELECT day, port, rx, tx FROM usage_day WHERE day BETWEEN ? AND ?", (day_from, day_to)).fetchall()
    per_port, per_day = {}, {}
    for r in rows:
        a = per_port.setdefault(r["port"], [0, 0])
        a[0] += r["rx"]; a[1] += r["tx"]
        per_day.setdefault(r["day"], {})[r["port"]] = (r["rx"], r["tx"])
    live = LIVE["ports"]
    port_rows = {p["port"]: dict(p, rx=per_port.get(p["port"], [0, 0])[0], tx=per_port.get(p["port"], [0, 0])[1],
                                 live=live.get(p["port"], {"rx_bps": 0, "tx_bps": 0})) for p in ports}
    out_groups = []
    for g in groups:
        gp = [port_rows[p["port"]] for p in ports if g["id"] in p["groups"]]
        out_groups.append(dict(g, ports=[x["port"] for x in gp], rx=sum(x["rx"] for x in gp), tx=sum(x["tx"] for x in gp),
                               live=sum(x["live"]["rx_bps"] + x["live"]["tx_bps"] for x in gp)))
    ungrouped = [p["port"] for p in ports if not p["groups"]]
    days = []
    d0, d1 = dt.date.fromisoformat(day_from), dt.date.fromisoformat(day_to)
    for i in range((d1 - d0).days + 1):
        d = (d0 + dt.timedelta(days=i)).isoformat()
        pd = per_day.get(d, {})
        days.append(series_point(d, pd, in_scope, groups, ports))
    tot_rx = sum(port_rows[p]["rx"] for p in in_scope)
    tot_tx = sum(port_rows[p]["tx"] for p in in_scope)
    return {"from": day_from, "to": day_to, "scope": group or "all", "groups": out_groups, "ports": list(port_rows.values()),
            "ungrouped": ungrouped, "days": days, "total": {"rx": tot_rx, "tx": tot_tx},
            "live": {"rx_bps": sum(live.get(p, {}).get("rx_bps", 0) for p in in_scope),
                     "tx_bps": sum(live.get(p, {}).get("tx_bps", 0) for p in in_scope), "interval": LIVE["interval"]}}


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
    per_hour = {f"{h:02d}": {} for h in range(24)}
    for r in rows:
        per_hour[r["hour"][-2:]][r["port"]] = (r["rx"], r["tx"])
    return {"day": day, "hours": [series_point(h, pp, in_scope, groups, ports) for h, pp in per_hour.items()]}


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
                if f > t:
                    f, t = t, f
                return self.send(200, report(f, t, q.get("group")))
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
FONT_CSS = """@font-face{font-family:Vazirmatn;src:url(/font/Vazirmatn-Regular.woff2) format('woff2');font-weight:400;font-display:swap}
@font-face{font-family:Vazirmatn;src:url(/font/Vazirmatn-Bold.woff2) format('woff2');font-weight:700;font-display:swap}"""

THEME_CSS = """:root{--bg:#0f1218;--card:#171b23;--card2:#1d222c;--line:#262c38;--text:#e6e9ef;--muted:#8b93a3;--acc:#4f8cff;--up:#f5a524;--down:#3ccf91;--bad:#ff6b6b}
@media (prefers-color-scheme: light){:root{--bg:#f3f5f9;--card:#fff;--card2:#f7f8fb;--line:#dfe3ea;--text:#141821;--muted:#5d6676}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Vazirmatn,Tahoma,sans-serif;font-size:15px}"""

LOGIN_HTML = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}} — ورود</title><style>""" + FONT_CSS + THEME_CSS + """
body{min-height:100vh;display:grid;place-items:center}
form{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;width:min(340px,92vw);display:grid;gap:14px}
h1{margin:0;font-size:18px}input{font:inherit;padding:11px 12px;border-radius:9px;border:1px solid var(--line);background:var(--bg);color:var(--text)}
button{font:inherit;font-weight:700;padding:11px;border:0;border-radius:9px;background:var(--acc);color:#fff;cursor:pointer}.err{color:var(--bad);font-size:14px;min-height:1em}
</style></head><body><form method="post" action="/login"><h1>{{TITLE}}</h1><input type="password" name="password" placeholder="رمز ورود" autofocus required>
<div class="err"><!--ERR--></div><button>ورود</button></form></body></html>"""

APP_HTML = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title><style>""" + FONT_CSS + THEME_CSS + """
header{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;padding:12px 18px;border-bottom:1px solid var(--line);background:var(--card);position:sticky;top:0;z-index:5}
header h1{font-size:17px;margin:0}header .host{color:var(--muted);font-size:12px}a{color:var(--acc)}
main{max-width:1180px;margin:0 auto;padding:16px;display:grid;gap:16px}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.chip{font:inherit;padding:6px 13px;border-radius:999px;border:1px solid var(--line);background:var(--card);color:var(--text);cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:6px}
.chip.on{background:var(--acc);border-color:var(--acc);color:#fff}
.gchip{border-width:2px}.gchip.on{color:#fff}
input,select,textarea{font:inherit;padding:7px 10px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--text)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;position:relative;overflow:hidden}
.card .k{color:var(--muted);font-size:13px}.card .v{font-size:21px;font-weight:700;margin-top:6px;font-variant-numeric:tabular-nums}.card .s{color:var(--muted);font-size:12px;margin-top:4px}
.v.up{color:var(--up)}.v.down{color:var(--down)}
.meter{height:6px;border-radius:3px;background:var(--line);margin-top:10px;overflow:hidden}.meter i{display:block;height:100%;border-radius:3px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.panel h2{font-size:15px;margin:0;padding:12px 14px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th,td{padding:9px 12px;text-align:right;border-bottom:1px solid var(--line);white-space:nowrap}th{color:var(--muted);font-weight:400;font-size:13px}
tr.g{cursor:pointer}tr.g td{font-weight:700}tr.g td:first-child{border-right:5px solid var(--gc)}
tr.p td:first-child{padding-right:26px;border-right:5px solid var(--gc)}tr.p td{font-weight:400}
tr.tot td{font-weight:700;background:var(--card2)}
.desc{color:var(--muted);font-size:13px;white-space:normal;max-width:340px;display:inline-block;vertical-align:middle;cursor:pointer;border-bottom:1px dashed transparent}
.desc:hover{border-bottom-color:var(--muted)}.desc.empty{opacity:.55}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-left:6px;vertical-align:middle;flex:none}
.mini{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:3px;vertical-align:middle}
.share{display:inline-block;height:6px;border-radius:3px;vertical-align:middle;margin-left:6px}
.chart{padding:10px 8px 4px}.chart svg{width:100%;height:240px;display:block}.legend{display:flex;flex-wrap:wrap;gap:12px;padding:0 14px 12px;font-size:13px;color:var(--muted)}
.tip{position:fixed;pointer-events:none;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:13px;display:none;z-index:9;box-shadow:0 6px 24px #0006;line-height:1.7}
.hide{display:none!important}.muted{color:var(--muted)}
.mgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:16px}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line)}
.btn{font:inherit;padding:6px 11px;border-radius:8px;border:1px solid var(--line);background:var(--card2);color:var(--text);cursor:pointer}
.btn.pri{background:var(--acc);border-color:var(--acc);color:#fff}.btn.del{color:var(--bad)}
.gsel{display:flex;flex-wrap:wrap;gap:6px}.gsel label{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:999px;border:1px solid var(--line);cursor:pointer;font-size:13px}
.gsel input{margin:0}.gsel label.on{border-color:var(--gc);background:color-mix(in srgb,var(--gc) 18%,transparent)}
.prow{display:grid;grid-template-columns:70px 1fr auto;gap:8px;align-items:start;padding:10px 14px;border-bottom:1px solid var(--line)}
.prow textarea{width:100%;min-height:38px;resize:vertical}
.toast{position:fixed;bottom:16px;left:16px;background:var(--card);border:1px solid var(--line);padding:10px 14px;border-radius:10px;display:none;z-index:10}
@media (max-width:640px){.card .v{font-size:17px}th,td{padding:8px}.mgrid{grid-template-columns:1fr}.prow{grid-template-columns:60px 1fr}}
</style></head><body>
<header><div><h1>{{TITLE}}</h1><div class="host" id="host"></div></div>
<div class="bar"><button class="chip on" data-tab="rep">مصرف پورت‌ها</button><button class="chip" data-tab="sys">منابع سرور</button><button class="chip" data-tab="mgr">تنظیمات</button><a class="chip" href="/logout">خروج</a></div></header>
<main>
<section id="rep">
 <div class="bar" id="ranges">
  <button class="chip" data-r="today">امروز</button><button class="chip" data-r="yesterday">دیروز</button>
  <button class="chip on" data-r="7">۷ روز</button><button class="chip" data-r="30">۳۰ روز</button><button class="chip" data-r="90">۹۰ روز</button>
  <span class="muted">از</span><input type="date" id="from"><span class="muted">تا</span><input type="date" id="to"><button class="chip" id="apply">نمایش</button>
 </div>
 <div class="bar" id="scopes" style="margin-top:10px"></div>
 <div class="cards" style="margin-top:14px">
  <div class="card"><div class="k">دانلود کاربران</div><div class="v down" id="c_tx">—</div></div>
  <div class="card"><div class="k">آپلود کاربران</div><div class="v up" id="c_rx">—</div></div>
  <div class="card"><div class="k">مجموع</div><div class="v" id="c_tot">—</div><div class="s" id="c_tot_s"></div></div>
  <div class="card"><div class="k">سرعت همین الان</div><div class="v" id="c_live">—</div></div>
 </div>
 <div class="panel" style="margin-top:16px"><h2><span id="chart_title">مصرف روزانه</span><span class="muted" id="range_lbl" style="font-weight:400;font-size:13px"></span></h2><div class="chart" id="chart"></div><div class="legend" id="legend"></div></div>
 <div class="panel" style="margin-top:16px"><h2>گروه‌ها و پورت‌ها <span class="muted" style="font-size:12px;font-weight:400">روی گروه بزنید تا پورت‌هایش باز شود · روی توضیح بزنید تا ویرایش شود</span></h2>
  <div class="scroll"><table><thead><tr><th>گروه / پورت</th><th>دانلود</th><th>آپلود</th><th>مجموع</th><th>سهم</th><th>الان</th></tr></thead><tbody id="tbl"></tbody></table></div></div>
</section>
<section id="sys" class="hide">
 <div class="bar"><span class="muted">بازهٔ نمودار:</span><button class="chip" data-h="1">۱ ساعت</button><button class="chip" data-h="6">۶ ساعت</button><button class="chip on" data-h="24">۲۴ ساعت</button><button class="chip" data-h="72">۳ روز</button><button class="chip" data-h="168">۷ روز</button><span class="muted" id="sys_info" style="font-size:13px"></span></div>
 <div class="cards" style="margin-top:14px" id="sys_cards"></div>
 <div class="mgrid" style="margin-top:16px">
  <div class="panel"><h2>پردازنده (٪)</h2><div class="chart" id="ch_cpu"></div></div>
  <div class="panel"><h2>رم (٪)</h2><div class="chart" id="ch_mem"></div></div>
  <div class="panel"><h2>شبکه (کارت اصلی) <span class="muted" style="font-size:12px;font-weight:400"><span class="mini" style="background:var(--down)"></span>دریافت <span class="mini" style="background:var(--up)"></span>ارسال</span></h2><div class="chart" id="ch_net"></div></div>
  <div class="panel"><h2>پرمصرف‌ترین برنامه‌ها</h2><div class="scroll"><table><thead><tr><th>برنامه</th><th>پردازنده</th><th>رم</th></tr></thead><tbody id="top"></tbody></table></div></div>
 </div>
</section>
<section id="mgr" class="hide">
 <div class="mgrid">
  <div class="panel"><h2>گروه‌ها</h2><div id="glist"></div>
   <div class="row"><input id="g_name" placeholder="نام گروه جدید"><input id="g_color" type="color"><button class="btn pri" id="g_add">افزودن گروه</button></div></div>
  <div class="panel"><h2>افزودن پورت</h2>
   <div class="row"><input id="p_port" type="number" min="1" max="65535" placeholder="شمارهٔ پورت" style="width:130px"><input id="p_label" placeholder="توضیح (مثلاً: سرور آلمان، تانل اصلی)" style="flex:1;min-width:180px"></div>
   <div class="row"><span class="muted" style="font-size:13px">گروه‌ها (می‌شود چندتا را زد):</span><div class="gsel" id="p_groups"></div></div>
   <div class="row"><button class="btn pri" id="p_add">افزودن پورت</button></div>
   <h2 style="border-top:1px solid var(--line)">پورت‌های باز روی سرور</h2><div class="muted" style="padding:10px 14px 0;font-size:13px">پورت‌هایی که الان روی سرور گوش می‌دهند؛ «انتخاب» شماره را در فرم بالا می‌گذارد.</div><div id="llist"></div></div>
 </div>
 <div class="panel" style="margin-top:16px"><h2>پورت‌های زیر نظر <span class="muted" style="font-size:12px;font-weight:400">توضیح و گروه‌ها خودکار ذخیره می‌شوند</span></h2><div id="plist"></div></div>
 <div class="panel" style="margin-top:16px"><h2>تغییر رمز</h2><div class="row"><input id="pw_old" type="password" placeholder="رمز فعلی"><input id="pw_new" type="password" placeholder="رمز جدید (حداقل ۸)"><button class="btn pri" id="pw_btn">ذخیره</button></div></div>
</section>
</main><div class="tip" id="tip"></div><div class="toast" id="toast"></div>
<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const fa=n=>Number(n).toLocaleString('fa-IR');
function bytes(b){const u=['بایت','KB','MB','GB','TB','PB'];let i=0;b=Number(b)||0;while(b>=1024&&i<u.length-1){b/=1024;i++}return b.toLocaleString('fa-IR',{maximumFractionDigits:(b>=100||i==0)?0:(b>=10?1:2)})+' '+u[i]}
function rate(bps){const u=['bps','Kbps','Mbps','Gbps'];let i=0,v=(Number(bps)||0)*8;while(v>=1000&&i<u.length-1){v/=1000;i++}return v.toLocaleString('fa-IR',{maximumFractionDigits:v>=100?0:1})+' '+u[i]}
const jal=d=>new Intl.DateTimeFormat('fa-IR-u-ca-persian',{month:'short',day:'numeric'}).format(new Date(d+'T12:00:00'));
const jalFull=d=>new Intl.DateTimeFormat('fa-IR-u-ca-persian',{weekday:'short',year:'numeric',month:'long',day:'numeric'}).format(new Date(d+'T12:00:00'));
const clock=ts=>new Intl.DateTimeFormat('fa-IR-u-ca-persian',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',timeZone:'Asia/Tehran'}).format(new Date(ts*1000));
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let CFG=null,OPEN=new Set(),RANGE='7',SCOPE='all',HOURS=24;
async function api(p,body){const r=await fetch(p,body?{method:'POST',headers:{'Content-Type':'application/json','X-PM':'1'},body:JSON.stringify(body)}:{});if(r.status==401){location='/login';throw 0}const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}
function toast(t){const e=$('#toast');e.textContent=t;e.style.display='block';clearTimeout(e._t);e._t=setTimeout(()=>e.style.display='none',2600)}
function addDays(iso,n){const d=new Date(iso+'T12:00:00Z');d.setUTCDate(d.getUTCDate()+n);return d.toISOString().slice(0,10)}
function rangeDates(r){const t=CFG.today;if(r=='today')return[t,t];if(r=='yesterday'){const y=addDays(t,-1);return[y,y]}return[addDays(t,-(Number(r)-1)),t]}
const G=id=>CFG.groups.find(g=>String(g.id)===String(id));
const gColor=id=>(G(id)||{}).color||'#8a8f98';
const pLabel=p=>{const x=CFG.ports.find(q=>q.port==p);return x&&x.label?x.label:''};

/* ---------------- usage report ---------------- */
function renderScopes(){
  const all=`<button class="chip ${SCOPE=='all'?'on':''}" data-s="all">همهٔ پورت‌ها</button>`;
  $('#scopes').innerHTML='<span class="muted">نمایش:</span>'+all+CFG.groups.map(g=>`<button class="chip gchip ${SCOPE==String(g.id)?'on':''}" data-s="${g.id}" style="border-color:${g.color};${SCOPE==String(g.id)?'background:'+g.color:''}"><span class="dot" style="background:${SCOPE==String(g.id)?'#fff':g.color};margin:0"></span>${esc(g.name)}</button>`).join('');
  $$('#scopes [data-s]').forEach(b=>b.onclick=()=>{SCOPE=b.dataset.s;renderScopes();load()});
}
async function load(){
  const [f,t]=RANGE=='custom'?[$('#from').value,$('#to').value]:rangeDates(RANGE);
  $('#from').value=f;$('#to').value=t;
  const sq=SCOPE=='all'?'':`&group=${SCOPE}`;
  const R=await api(`/api/report?from=${f}&to=${t}${sq}`);
  $('#c_rx').textContent=bytes(R.total.rx);$('#c_tx').textContent=bytes(R.total.tx);$('#c_tot').textContent=bytes(R.total.rx+R.total.tx);
  const g=SCOPE=='all'?null:G(SCOPE);
  $('#c_tot_s').textContent=g?`گروه «${g.name}»`:'هر پورت یک بار حساب شده';
  $('#c_live').innerHTML=`<span style="color:var(--down)">↓ ${rate(R.live.tx_bps)}</span> <span style="color:var(--up);font-size:14px">↑ ${rate(R.live.rx_bps)}</span>`;
  $('#range_lbl').textContent=f==t?jalFull(f):`${jalFull(f)} تا ${jalFull(t)}`;
  renderTable(R);
  if(f==t){const H=await api(`/api/hourly?day=${f}${sq}`);$('#chart_title').textContent='مصرف ساعتی';drawUsage(H.hours.map(x=>({lbl:fa(Number(x.key)),full:`ساعت ${fa(Number(x.key))} تا ${fa(Number(x.key)+1)}`,...x})))}
  else{$('#chart_title').textContent='مصرف روزانه';drawUsage(R.days.map(x=>({lbl:jal(x.key),full:jalFull(x.key),...x})))}
}
function renderTable(R){
  const P={};R.ports.forEach(p=>P[p.port]=p);
  const scopeTot=(R.total.rx+R.total.tx)||1;let h='';
  const portRow=(p,gid,color)=>{const pt=p.rx+p.tx;const others=p.groups.filter(x=>String(x)!==String(gid));
    return `<tr class="p ${OPEN.has(String(gid))||SCOPE!='all'?'':'hide'}" data-pg="${gid}" style="--gc:${color}"><td>پورت ${fa(p.port)} ${others.map(o=>`<span class="mini" title="${esc((G(o)||{}).name)}" style="background:${gColor(o)}"></span>`).join('')}<br><span class="desc ${p.label?'':'empty'}" data-ed="${p.port}">${p.label?esc(p.label):'+ توضیح'}</span></td><td>${bytes(p.tx)}</td><td>${bytes(p.rx)}</td><td><b>${bytes(pt)}</b></td><td>${fa(Math.round(100*pt/scopeTot))}٪</td><td>${rate(p.live.rx_bps+p.live.tx_bps)}</td></tr>`};
  const groups=SCOPE=='all'?R.groups:R.groups.filter(g=>String(g.id)===SCOPE);
  for(const g of groups){const tot=g.rx+g.tx;const gid=String(g.id);
    if(SCOPE=='all')h+=`<tr class="g" data-g="${gid}" style="--gc:${g.color};background:color-mix(in srgb,${g.color} 10%,var(--card))"><td><span class="dot" style="background:${g.color}"></span>${esc(g.name)} <span class="muted" style="font-weight:400">(${fa(g.ports.length)} پورت)</span></td><td>${bytes(g.tx)}</td><td>${bytes(g.rx)}</td><td>${bytes(tot)}</td><td><span class="share" style="width:${Math.max(2,Math.round(60*tot/scopeTot))}px;background:${g.color}"></span>${fa(Math.round(100*tot/scopeTot))}٪</td><td>${rate(g.live)}</td></tr>`;
    h+=g.ports.map(x=>P[x]).sort((a,b)=>(b.rx+b.tx)-(a.rx+a.tx)).map(p=>portRow(p,gid,g.color)).join('')}
  if(SCOPE=='all'&&R.ungrouped.length){const ug=R.ungrouped.map(x=>P[x]);const rx=ug.reduce((a,p)=>a+p.rx,0),tx=ug.reduce((a,p)=>a+p.tx,0);
    h+=`<tr class="g" data-g="none" style="--gc:#8a8f98"><td><span class="dot" style="background:#8a8f98"></span>بدون گروه <span class="muted" style="font-weight:400">(${fa(ug.length)} پورت)</span></td><td>${bytes(tx)}</td><td>${bytes(rx)}</td><td>${bytes(rx+tx)}</td><td>${fa(Math.round(100*(rx+tx)/scopeTot))}٪</td><td>${rate(ug.reduce((a,p)=>a+p.live.rx_bps+p.live.tx_bps,0))}</td></tr>`;
    h+=ug.sort((a,b)=>(b.rx+b.tx)-(a.rx+a.tx)).map(p=>portRow(p,'none','#8a8f98')).join('')}
  h+=`<tr class="tot"><td>${SCOPE=='all'?'کل (هر پورت یک بار)':'کل گروه'}</td><td>${bytes(R.total.tx)}</td><td>${bytes(R.total.rx)}</td><td>${bytes(R.total.rx+R.total.tx)}</td><td>۱۰۰٪</td><td>${rate(R.live.rx_bps+R.live.tx_bps)}</td></tr>`;
  $('#tbl').innerHTML=R.ports.length?h:'<tr><td colspan="6" class="muted">هنوز پورتی زیر نظر نیست؛ از «تنظیمات» اضافه کنید.</td></tr>';
  $$('#tbl tr.g').forEach(tr=>tr.onclick=()=>{const g=tr.dataset.g;OPEN.has(g)?OPEN.delete(g):OPEN.add(g);$$(`#tbl tr[data-pg="${g}"]`).forEach(x=>x.classList.toggle('hide'))});
  $$('#tbl [data-ed]').forEach(e=>e.onclick=ev=>{ev.stopPropagation();const p=e.dataset.ed;const v=prompt(`توضیح پورت ${p}:`,pLabel(p));if(v!==null)act('/api/port',{action:'edit',port:p,label:v})});
}
function axis(max){let step=Math.pow(1024,Math.floor(Math.log(Math.max(max,1))/Math.log(1024)));const nice=[1,2,5,10,20,50,100,200,500,1000].map(m=>m*step).find(v=>v*4>=max)||max/4;return nice}
function drawUsage(items){
  const W=1000,H=240,pl=8,pr=62,pt=10,pb=26,n=items.length||1,bw=(W-pl-pr)/n;
  const multi=SCOPE=='all'&&CFG.groups.length>0;
  const vals=multi?items.flatMap(x=>[x.total,...Object.values(x.groups)]):items.map(x=>x.total);
  const nice=axis(Math.max(1,...vals)),top=nice*4,y=v=>pt+(H-pt-pb)*(1-v/top),xc=i=>W-pr-(i+.5)*bw;
  let s=`<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" font-family="Vazirmatn,Tahoma" font-size="11" style="direction:ltr">`;
  for(let i=0;i<=4;i++){const v=nice*i;s+=`<line x1="${pl}" x2="${W-pr}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)"/><text x="${W-pr+6}" y="${y(v)+4}" fill="var(--muted)">${bytes(v)}</text>`}
  if(multi){
    s+=items.map((it,i)=>`<rect x="${xc(i)-bw*.35}" y="${y(it.total)}" width="${bw*.7}" height="${Math.max(0,y(0)-y(it.total))}" fill="var(--muted)" opacity=".18" rx="2"/>`).join('');
    for(const g of CFG.groups){const pts=items.map((it,i)=>`${xc(i)},${y(it.groups[String(g.id)]||0)}`);
      s+=`<polyline points="${pts.join(' ')}" fill="none" stroke="${g.color}" stroke-width="2.4" stroke-linejoin="round"/>`;
      if(n<=45)s+=items.map((it,i)=>`<circle cx="${xc(i)}" cy="${y(it.groups[String(g.id)]||0)}" r="3" fill="${g.color}"/>`).join('')}
  }else{const c=SCOPE=='all'?'var(--acc)':gColor(SCOPE);s+=items.map((it,i)=>`<rect x="${xc(i)-bw*.35}" y="${y(it.total)}" width="${bw*.7}" height="${Math.max(0,y(0)-y(it.total))}" fill="${c}" rx="2"/>`).join('')}
  items.forEach((it,i)=>{s+=`<rect class="hit" data-i="${i}" x="${xc(i)-bw/2}" y="${pt}" width="${bw}" height="${H-pt-pb}" fill="transparent"/>`;
    if(n<=31||i%Math.ceil(n/31)==0)s+=`<text x="${xc(i)}" y="${H-8}" fill="var(--muted)" text-anchor="middle">${it.lbl}</text>`});
  $('#chart').innerHTML=s+'</svg>';
  $('#legend').innerHTML=multi?CFG.groups.map(g=>`<span><span class="dot" style="background:${g.color}"></span>${esc(g.name)}</span>`).join('')+`<span><span class="dot" style="background:var(--muted);opacity:.4"></span>کل (هر پورت یک بار)</span>`:'';
  const tip=$('#tip');$$('#chart .hit').forEach(r=>{r.onmousemove=e=>{const it=items[r.dataset.i];
    let h=`<b>${it.full}</b><br>مجموع: <b>${bytes(it.total)}</b>`;
    if(multi)h+='<br>'+CFG.groups.filter(g=>it.groups[String(g.id)]).map(g=>`<span class="dot" style="background:${g.color}"></span>${esc(g.name)}: ${bytes(it.groups[String(g.id)])}`).join('<br>');
    if(it.top&&it.top.length)h+='<br><span class="muted">پرمصرف‌ها:</span><br>'+it.top.map(([p,v])=>`پورت ${fa(p)}${pLabel(p)?' ('+esc(pLabel(p))+')':''}: ${bytes(v)}`).join('<br>');
    tip.innerHTML=h;tip.style.display='block';tip.style.left=Math.min(e.clientX+14,innerWidth-260)+'px';tip.style.top=(e.clientY+14)+'px'};r.onmouseleave=()=>tip.style.display='none'})
}

/* ---------------- server resources ---------------- */
function lineChart(el,hist,series,fmt,maxFixed){
  const W=1000,H=200,pl=8,pr=70,pt=10,pb=24,n=hist.length;if(!n){$(el).innerHTML='<div class="muted" style="padding:20px">هنوز داده‌ای نیست؛ چند دقیقه صبر کنید.</div>';return}
  const t0=hist[0].ts,t1=hist[n-1].ts||t0+1,x=ts=>pl+(W-pl-pr)*(t1==t0?1:(ts-t0)/(t1-t0));
  const max=maxFixed||Math.max(1e-9,...hist.flatMap(h=>series.map(s=>h[s.k]||0)))*1.15,y=v=>pt+(H-pt-pb)*(1-v/max);
  let s=`<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" font-family="Vazirmatn,Tahoma" font-size="11" style="direction:ltr;height:200px">`;
  for(let i=0;i<=4;i++){const v=max*i/4;s+=`<line x1="${pl}" x2="${W-pr}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)"/><text x="${W-pr+6}" y="${y(v)+4}" fill="var(--muted)">${fmt(v)}</text>`}
  for(const se of series){const pts=hist.map(h=>`${x(h.ts)},${y(h[se.k]||0)}`).join(' ');
    s+=`<polygon points="${x(t0)},${y(0)} ${pts} ${x(t1)},${y(0)}" fill="${se.c}" opacity=".12"/><polyline points="${pts}" fill="none" stroke="${se.c}" stroke-width="2"/>`}
  for(let i=0;i<5;i++){const ts=t0+(t1-t0)*i/4;s+=`<text x="${x(ts)}" y="${H-6}" fill="var(--muted)" text-anchor="${i==0?'start':i==4?'end':'middle'}">${clock(ts)}</text>`}
  $(el).innerHTML=s+'</svg>';
}
function card(k,v,s,pct,color){return `<div class="card"><div class="k">${k}</div><div class="v">${v}</div>${s?`<div class="s">${s}</div>`:''}${pct!=null?`<div class="meter"><i style="width:${Math.min(100,pct)}%;background:${color||(pct>85?'var(--bad)':pct>65?'var(--up)':'var(--down)')}"></i></div>`:''}</div>`}
function dur(s){if(s==null)return'';const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?fa(d)+' روز ':'')+(h?fa(h)+' ساعت ':'')+(d?'':fa(m)+' دقیقه')}
async function loadSys(){
  const S=await api(`/api/system?hours=${HOURS}`),n=S.now||{},i=S.info;
  $('#sys_info').textContent=`${i.host} · ${i.os} · ${fa(i.cores)} هسته · روشن از ${dur(i.uptime)} پیش`;
  const memP=n.mem_total?100*n.mem_used/n.mem_total:null,dskP=n.disk_total?100*n.disk_used/n.disk_total:null,ctP=n.ct_max?100*n.ct_count/n.ct_max:null;
  $('#sys_cards').innerHTML=
    card('پردازنده',n.cpu!=null?fa(n.cpu)+'٪':'…',`بار: ${i.load.map(x=>fa(x)).join(' / ')} · بیشینه در بازه: ${S.peak.cpu!=null?fa(S.peak.cpu)+'٪':'—'}`,n.cpu)+
    card('رم',memP!=null?fa(Math.round(memP))+'٪':'…',`${bytes(n.mem_used)} از ${bytes(n.mem_total)}${n.swap_total?` · سواپ ${bytes(n.swap_used)}`:''}`,memP)+
    card('دیسک',dskP!=null?fa(Math.round(dskP))+'٪':'…',`${bytes(n.disk_used)} از ${bytes(n.disk_total)}`,dskP)+
    card('شبکه همین الان',n.net_rx!=null?`<span style="color:var(--down)">↓ ${rate(n.net_rx)}</span>`:'…',n.net_tx!=null?`<span style="color:var(--up)">↑ ${rate(n.net_tx)}</span> · کارت ${esc(n.iface||'')}`:'',null)+
    card('اتصال‌ها',n.tcp!=null?fa(n.tcp):'—',ctP!=null?`ردیابی اتصال: ${fa(n.ct_count)} از ${fa(n.ct_max)}`:'',ctP);
  lineChart('#ch_cpu',S.history,[{k:'cpu',c:'var(--acc)'}],v=>fa(Math.round(v))+'٪',100);
  lineChart('#ch_mem',S.history,[{k:'mem',c:'#a78bfa'}],v=>fa(Math.round(v))+'٪',100);
  lineChart('#ch_net',S.history,[{k:'rx',c:'var(--down)'},{k:'tx',c:'var(--up)'}],v=>rate(v));
  $('#top').innerHTML=S.top.map(p=>`<tr><td>${esc(p.name)} <span class="muted" style="font-size:12px">#${fa(p.pid)}</span></td><td>${fa(p.cpu)}٪</td><td>${bytes(p.rss)}</td></tr>`).join('');
}

/* ---------------- settings ---------------- */
async function loadCfg(){CFG=await api('/api/config');$('#host').textContent=`${CFG.host} · نسخهٔ ${CFG.version}`;$('#g_color').value=CFG.palette.find(c=>!CFG.groups.some(g=>g.color==c))||CFG.palette[0];renderScopes();renderMgr()}
function gsel(sel,name){return CFG.groups.map(g=>`<label style="--gc:${g.color}" class="${sel.includes(g.id)?'on':''}"><input type="checkbox" data-${name}="${g.id}" ${sel.includes(g.id)?'checked':''}><span class="dot" style="background:${g.color};margin:0"></span>${esc(g.name)}</label>`).join('')||'<span class="muted" style="font-size:13px">اول یک گروه بسازید.</span>'}
function renderMgr(){
  $('#glist').innerHTML=CFG.groups.map(g=>`<div class="row" style="border-right:5px solid ${g.color}"><input type="color" value="${g.color}" data-gc="${g.id}"><input value="${esc(g.name)}" data-gn="${g.id}" style="flex:1;min-width:120px"><span class="muted">${fa(CFG.ports.filter(p=>p.groups.includes(g.id)).length)} پورت</span><button class="btn del" data-gd="${g.id}">حذف</button></div>`).join('')||'<div class="row muted">گروهی نیست.</div>';
  $('#p_groups').innerHTML=gsel([],'ng');
  $('#plist').innerHTML=CFG.ports.map(p=>`<div class="prow"><b style="padding-top:8px">${fa(p.port)}</b><div style="display:grid;gap:8px"><textarea data-pl="${p.port}" placeholder="توضیح این پورت">${esc(p.label||'')}</textarea><div class="gsel">${gsel(p.groups,'pg-'+p.port)}</div></div><button class="btn del" data-pd="${p.port}">حذف</button></div>`).join('')||'<div class="row muted">پورتی زیر نظر نیست.</div>';
  const watched=new Set(CFG.ports.map(p=>p.port));
  $('#llist').innerHTML=CFG.listening.filter(l=>l.port!==CFG.dashboard_port).map(l=>`<div class="row"><b style="min-width:60px">${fa(l.port)}</b><span class="muted">${l.proto} ${esc(l.process)}</span>${watched.has(l.port)?'<span class="muted">زیر نظر است</span>':`<button class="btn" data-la="${l.port}">انتخاب</button>`}</div>`).join('');
  $$('[data-gn]').forEach(e=>e.onchange=()=>act('/api/group',{action:'edit',id:e.dataset.gn,name:e.value}));
  $$('[data-gc]').forEach(e=>e.onchange=()=>act('/api/group',{action:'edit',id:e.dataset.gc,color:e.value}));
  $$('[data-gd]').forEach(e=>e.onclick=()=>confirm('گروه حذف شود؟ پورت‌ها و آمارشان می‌مانند.')&&act('/api/group',{action:'delete',id:e.dataset.gd}));
  $$('[data-pl]').forEach(e=>e.onchange=()=>act('/api/port',{action:'edit',port:e.dataset.pl,label:e.value}));
  CFG.ports.forEach(p=>$$(`[data-pg-${p.port}]`).forEach(cb=>cb.onchange=()=>{cb.closest('label').classList.toggle('on',cb.checked);act('/api/port',{action:'edit',port:p.port,groups:$$(`[data-pg-${p.port}]`).filter(x=>x.checked).map(x=>x.getAttribute(`data-pg-${p.port}`))})}));
  $$('[data-ng]').forEach(cb=>cb.onchange=()=>cb.closest('label').classList.toggle('on',cb.checked));
  $$('[data-pd]').forEach(e=>e.onclick=()=>{const p=e.dataset.pd;if(!confirm(`پورت ${p} از زیر نظر خارج شود؟`))return;const purge=confirm('آمار قبلی این پورت هم پاک شود؟ (انصراف = آمار بماند)');act('/api/port',{action:'delete',port:p,purge})});
  $$('[data-la]').forEach(e=>e.onclick=()=>{$('#p_port').value=e.dataset.la;$('#p_label').focus();scrollTo({top:0,behavior:'smooth'})});
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
(async()=>{await loadCfg();await load();setInterval(()=>{if(document.hidden)return;TAB=='sys'?loadSys():TAB=='rep'?load():0},60000)})();
</script></body></html>"""

if __name__ == "__main__":
    main()

"""portmon: the interface's own totals ("server inbound") and the notice for ports someone uses but nobody watches.

Runs anywhere with python3 (no nft, no root): the functions under test take their inputs as arguments or through
subprocess/unit_of, which the tests replace. Usage: python tools/portmon/tests/test_server_inbound_and_unwatched.py
"""
import importlib.util
import os
import sqlite3
import sys
import tempfile
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get("PORTMON_SRC", os.path.join(HERE, "..", "portmon.py"))


def load():
    spec = importlib.util.spec_from_file_location("portmon_under_test", SRC)
    pm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pm)
    return pm


class Base(unittest.TestCase):
    def setUp(self):
        self.pm = load()
        self.dir = tempfile.mkdtemp()
        self.pm.CFG.clear()
        self.pm.CFG.update(self.pm.DEFAULTS, db=os.path.join(self.dir, "pm.db"))
        self.pm.init_db()

    def rows(self, sql, *a):
        with self.pm.db() as c:
            return [dict(r) for r in c.execute(sql, a)]

    def local_hour_start(self, ts):
        """Epoch of the local (Tehran-offset) hour that contains ts."""
        loc = self.pm.local_now(ts)
        return ts - (loc.minute * 60 + loc.second + loc.microsecond / 1e6)


class NicTotals(Base):
    def test_bytes_split_over_the_hours_they_fell_in_and_none_lost(self):
        pm = self.pm
        h = self.local_hour_start(time.time() - 3 * 86400)
        t0, t1 = h + 3600 - 900, h + 3600 + 2700          # 15 min before an hour boundary, 45 min after
        rx, tx = 1_000_003, 2_000_001
        with pm.db() as c:
            pm.nic_add(c, t0, t1, rx, tx)
        hours = self.rows("SELECT hour, rx, tx, secs FROM nic_hour ORDER BY hour")
        self.assertEqual(len(hours), 2)
        self.assertEqual(sum(r["rx"] for r in hours), rx)
        self.assertEqual(sum(r["tx"] for r in hours), tx)
        self.assertAlmostEqual(hours[0]["rx"] / rx, 0.25, places=3)
        self.assertAlmostEqual(sum(r["secs"] for r in hours), t1 - t0, places=3)
        self.assertEqual(hours[0]["hour"], pm.local_now(t0).strftime("%Y-%m-%d %H"))
        self.assertEqual(sum(r["rx"] for r in self.rows("SELECT rx FROM nic_day")), rx)

    def test_a_day_ends_at_local_midnight(self):
        pm = self.pm
        start = pm.day_start(pm.local_now(time.time() - 5 * 86400).strftime("%Y-%m-%d"))
        with pm.db() as c:
            pm.nic_add(c, start - 600, start + 600, 1200, 0)
        days = self.rows("SELECT day, rx FROM nic_day ORDER BY day")
        self.assertEqual([d["rx"] for d in days], [600, 600])
        self.assertEqual(days[1]["day"], pm.local_now(start).strftime("%Y-%m-%d"))

    def test_bank_keeps_counting_across_a_restart_but_not_across_a_reboot(self):
        pm = self.pm
        now = time.time() - 7200
        pm.nic_bank("eth0", 10_000, 5_000, now, "boot-a")            # first reading: nothing to add yet
        self.assertEqual(self.rows("SELECT * FROM nic_day"), [])
        pm.nic_bank("eth0", 70_000, 9_000, now + 60, "boot-a")
        self.assertEqual(self.rows("SELECT SUM(rx) AS rx, SUM(tx) AS tx FROM nic_day")[0], {"rx": 60_000, "tx": 4_000})
        pm2 = load()                                                     # portmon restarted: state comes from the db
        pm2.CFG.update(pm.CFG)
        pm2.nic_bank("eth0", 130_000, 9_500, now + 1800, "boot-a")
        self.assertEqual(self.rows("SELECT SUM(rx) AS rx FROM nic_day")[0]["rx"], 120_000)
        pm2.nic_bank("eth0", 500, 100, now + 1900, "boot-b")             # rebooted: counters started again
        pm2.nic_bank("eth0", 400, 100, now + 1960, "boot-b")             # a counter that went back
        pm2.nic_bank("eth1", 9_999, 100, now + 2020, "boot-b")           # another interface
        self.assertEqual(self.rows("SELECT SUM(rx) AS rx FROM nic_day")[0]["rx"], 120_000)
        pm2.nic_bank("eth1", 10_999, 100, now + 2080, "boot-b")
        self.assertEqual(self.rows("SELECT SUM(rx) AS rx FROM nic_day")[0]["rx"], 121_000)

    def test_a_reboot_is_a_new_baseline_even_when_the_counters_came_back_higher(self):
        pm = self.pm
        now = time.time() - 3600
        pm.nic_bank("eth0", 1_000, 1_000, now, "boot-a")
        pm.nic_bank("eth0", 900_000, 900_000, now + 600, "boot-b")     # what moved around the reboot is unknown
        self.assertEqual(self.rows("SELECT * FROM nic_day"), [])
        pm.nic_bank("eth0", 901_000, 900_500, now + 660, "boot-b")
        self.assertEqual(self.rows("SELECT SUM(rx) AS rx, SUM(tx) AS tx FROM nic_day")[0], {"rx": 1_000, "tx": 500})

    def test_first_run_rebuilds_past_days_from_the_sampled_rates(self):
        pm = self.pm
        t = int(time.time()) - 86400
        with pm.db() as c:
            c.execute("DELETE FROM nic_day"); c.execute("DELETE FROM nic_hour"); c.execute("DELETE FROM nic_state")
            # ten samples a minute apart at 1000 B/s in, 10 B/s out; then a 2-hour hole; then one more
            for i in range(10):
                c.execute("INSERT INTO sys_min (ts, net_rx, net_tx) VALUES (?, ?, ?)", (t + 60 * i, None if i == 0 else 1000.0, 10.0))
            c.execute("INSERT INTO sys_min (ts, net_rx, net_tx) VALUES (?, ?, ?)", (t + 60 * 9 + 7200, 1000.0, 10.0))
        pm.init_db()
        got = self.rows("SELECT SUM(rx) AS rx, SUM(tx) AS tx, SUM(secs) AS secs FROM nic_day")[0]
        self.assertEqual(got["rx"], 9 * 60 * 1000)          # the first sample has no rate, the hole is not guessed
        self.assertEqual(got["tx"], 9 * 60 * 10)
        self.assertAlmostEqual(got["secs"], 9 * 60)
        pm.init_db()                                         # and only once
        self.assertEqual(self.rows("SELECT SUM(rx) AS rx FROM nic_day")[0]["rx"], 9 * 60 * 1000)

    def test_report_says_when_a_range_was_only_partly_counted(self):
        pm = self.pm
        today = pm.local_now().strftime("%Y-%m-%d")
        start = pm.day_start(today)
        with pm.db() as c:
            pm.nic_add(c, start, time.time(), 5_000, 50)
        r = pm.nic_report(today, today)
        self.assertEqual((r["rx"], r["tx"], r["since"], r["partial"]), (5_000, 50, today, False))
        week_ago = pm.local_now(time.time() - 6 * 86400).strftime("%Y-%m-%d")
        r = pm.nic_report(week_ago, today)
        self.assertTrue(r["partial"])
        self.assertEqual(r["since"], today)

    def test_report_and_hourly_carry_the_interface_figures(self):
        pm = self.pm
        today = pm.local_now().strftime("%Y-%m-%d")
        h = self.local_hour_start(time.time())
        with pm.db() as c:
            pm.nic_add(c, h, h + 60, 777, 1)
        R = pm.report(today, today)
        self.assertEqual(R["nic"]["rx"], 777)
        self.assertEqual(R["days"][-1]["nic"], 777)
        self.assertIn("unwatched", R)
        hk = pm.local_now(h).strftime("%H")
        H = pm.hourly(today)
        self.assertEqual({x["key"]: x["nic"] for x in H["hours"]}[hk], 777)
        self.assertEqual(sum(1 for x in H["hours"] if x["nic"] is not None), 1)


LISTEN = """LISTEN 0 4096 0.0.0.0:204 0.0.0.0:* users:(("6",pid=101,fd=11))
LISTEN 0 4096 0.0.0.0:1255 0.0.0.0:* users:(("6",pid=101,fd=10))
LISTEN 0 4096 *:3398 *:* users:(("6",pid=202,fd=11))
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=303,fd=3))
LISTEN 0 5 0.0.0.0:8800 0.0.0.0:* users:(("python3",pid=404,fd=3))
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=505,fd=14))
LISTEN 0 244 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=606,fd=5))
"""


def established(spec):
    """spec: [(local port, peer ip, how many connections)] -> ss -Htn state established text."""
    lines, n = [], 40000
    for port, ip, k in spec:
        for _ in range(k):
            n += 1
            peer = f"[::ffff:{ip}]:{n}" if ip.count(".") == 3 and n % 2 else f"{ip}:{n}"
            lines.append(f"0 0 [::ffff:88.0.0.1]:{port} {peer}" if n % 2 else f"0 0 88.0.0.1:{port} {peer}")
    return "\n".join(lines) + "\n"


class Unwatched(Base):
    def fake_ss(self, est_text):
        def run(args, capture_output=True, text=True, **kw):
            out = {"-Htlnp": LISTEN, "-Htn": est_text,   # the settings list asks with -u too: a Netid column first
                   "-Htulnp": "".join("tcp " + line + "\n" for line in LISTEN.splitlines())}.get(args[1], "")
            return types.SimpleNamespace(stdout=out, returncode=0)
        self.pm.subprocess.run = run
        self.pm.unit_of = lambda pid: {101: "relay-a", 202: "relay-b", 303: "ssh"}.get(pid, "")

    def test_parsers(self):
        pm = self.pm
        lis = pm.parse_listeners(LISTEN)
        self.assertEqual(sorted(lis), [22, 204, 1255, 3398, 8800])     # loopback listeners serve no users
        self.assertEqual(lis[204], ("6", 101))
        est = pm.parse_established(established([(204, "5.5.5.1", 3), (204, "5.5.5.2", 2), (1255, "9.9.9.9", 4),
                                                (999, "1.1.1.1", 1)]), set(lis))
        self.assertEqual(est, {204: (5, 2), 1255: (4, 1)})

    def test_a_used_port_nobody_watches_is_pointed_out_and_nothing_else(self):
        pm = self.pm
        with pm.db() as c:
            c.execute("INSERT INTO ports (port, label, added_at) VALUES (3398, '', 0)")
        users = [(204, f"5.5.5.{i}", 2) for i in range(1, 7)]               # six addresses: someone's service
        tunnel = [(1255, "9.9.9.9", 24)]                                       # one far end: a tunnel's listener
        ssh = [(22, f"7.7.7.{i}", 1) for i in range(1, 30)]                   # scanners on ssh
        dash = [(8800, f"6.6.6.{i}", 1) for i in range(1, 5)]                 # the dashboard itself
        watched = [(3398, f"4.4.4.{i}", 3) for i in range(1, 9)]              # already watched
        self.fake_ss(established(users + tunnel + ssh + dash + watched))
        pm.scan_ports()
        u = pm.unwatched()
        self.assertEqual([x["port"] for x in u], [204])
        self.assertEqual((u[0]["conns"], u[0]["peers"], u[0]["unit"], u[0]["active"]), (12, 6, "relay-a", True))
        self.assertEqual(pm.SCAN["ports"][1255]["peers"], 1)
        self.assertEqual(pm.SCAN["ports"][1255]["unit"], "relay-a")

    def test_a_port_with_fewer_than_the_minimum_of_addresses_is_not_flagged(self):
        pm = self.pm
        self.fake_ss(established([(204, f"5.5.5.{i}", 5) for i in range(1, pm.PEER_MIN)]))
        pm.scan_ports()
        self.assertEqual(pm.unwatched(), [])

    def test_quiet_now_still_shown_for_a_day_then_dropped(self):
        pm = self.pm
        self.fake_ss(established([(204, f"5.5.5.{i}", 1) for i in range(1, 6)]))
        pm.scan_ports()
        self.fake_ss("")                                                       # nobody connected now
        pm.scan_ports()
        u = pm.unwatched()
        self.assertEqual([(x["port"], x["peers"], x["active"]) for x in u], [(204, 5, False)])
        with pm.db() as c:
            c.execute("UPDATE seen_ports SET last_seen = last_seen - 2 * 86400")
        self.assertEqual(pm.unwatched(), [])

    def test_ignore_hides_it_unignore_brings_it_back_watching_ends_it(self):
        pm = self.pm
        self.fake_ss(established([(204, f"5.5.5.{i}", 1) for i in range(1, 6)]))
        pm.scan_ports()
        pm.change_port({"action": "ignore", "port": 204})
        self.assertEqual(pm.unwatched(), [])
        listed = {x["port"]: x for x in pm.listening_ports()}
        self.assertTrue(listed[204]["ignored"])
        self.assertEqual((listed[204]["conns"], listed[204]["peers"], listed[204]["unit"]), (5, 5, "relay-a"))
        pm.change_port({"action": "unignore", "port": 204})
        self.assertEqual([x["port"] for x in pm.unwatched()], [204])
        with pm.db() as c:                                                      # once watched, it is no longer news
            c.execute("INSERT INTO ports (port, label, added_at) VALUES (204, '', 0)")
        self.assertEqual(pm.unwatched(), [])
        pm.scan_ports()
        self.assertEqual(pm.unwatched(), [])


if __name__ == "__main__":
    unittest.main(verbosity=1)

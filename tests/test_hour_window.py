"""portmon: a report window that starts and ends at chosen hours (the hour pickers beside the dates).

Runs anywhere with python3. Usage: python tools/portmon/tests/test_hour_window.py   (PORTMON_SRC=<file> for another copy)
"""
import datetime as dt
import importlib.util
import os
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get("PORTMON_SRC", os.path.join(HERE, "..", "portmon.py"))


def load():
    spec = importlib.util.spec_from_file_location("portmon_under_test", SRC)
    pm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pm)
    return pm


class Window(unittest.TestCase):
    def setUp(self):
        pm = self.pm = load()
        pm.CFG.clear()
        pm.CFG.update(pm.DEFAULTS, db=os.path.join(tempfile.mkdtemp(), "pm.db"))
        pm.init_db()
        # a day ten days back and the day after it: port 200 moves (100*h) rx and (1000*h) tx in hour h of day 1,
        # port 601 the same plus one; day 2 repeats with 10_000 added. The day tables hold the same sums.
        self.d1 = pm.local_now(time.time() - 10 * 86400).strftime("%Y-%m-%d")
        self.d2 = (dt.date.fromisoformat(self.d1) + dt.timedelta(days=1)).isoformat()
        with pm.db() as c:
            c.execute("INSERT INTO ports (port, label, added_at) VALUES (200, '', 0), (601, '', 0)")
            c.execute("INSERT INTO groups (id, name, color, sort) VALUES (1, 'g', '#fff', 1)")
            c.execute("INSERT INTO port_groups (port, group_id) VALUES (601, 1)")
            for day, extra in ((self.d1, 0), (self.d2, 10_000)):
                for h in range(24):
                    for port, plus in ((200, 0), (601, 1)):
                        rx, tx = 100 * h + plus + extra, 1000 * h + plus + extra
                        c.execute("INSERT INTO usage_hour (hour, port, rx, tx) VALUES (?, ?, ?, ?)", (f"{day} {h:02d}", port, rx, tx))
                        c.execute("INSERT INTO usage_day (day, port, rx, tx) VALUES (?, ?, ?, ?) ON CONFLICT(day, port) DO "
                                  "UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx", (day, port, rx, tx))
                    c.execute("INSERT INTO nic_hour (hour, rx, tx, secs) VALUES (?, ?, ?, 3600)", (f"{day} {h:02d}", 7 * h, 1))

    def expect(self, cells):
        """Sum over (day, hour) cells for both ports, as the fixture lays them down."""
        rx = tx = 0
        for day, h in cells:
            extra = 0 if day == self.d1 else 10_000
            for plus in (0, 1):
                rx += 100 * h + plus + extra
                tx += 1000 * h + plus + extra
        return rx, tx

    def test_a_window_inside_one_day_counts_its_hours_only(self):
        R = self.pm.report(self.d1, self.d1, None, 8, 14)
        rx, tx = self.expect([(self.d1, h) for h in range(8, 14)])
        self.assertEqual((R["total"]["rx"], R["total"]["tx"]), (rx, tx))
        self.assertEqual(R["unit"], "hour")
        self.assertEqual([x["key"] for x in R["days"]], [f"{self.d1} {h:02d}" for h in range(8, 14)])
        self.assertEqual(R["nic"]["rx"], sum(7 * h for h in range(8, 14)))
        self.assertEqual([x["nic"] for x in R["days"]], [7 * h for h in range(8, 14)])

    def test_the_end_hour_24_takes_the_last_hour_of_the_day(self):
        R = self.pm.report(self.d1, self.d1, None, 20, 24)
        self.assertEqual((R["total"]["rx"], R["total"]["tx"]), self.expect([(self.d1, h) for h in range(20, 24)]))

    def test_a_window_across_midnight(self):
        R = self.pm.report(self.d1, self.d2, None, 22, 3)
        cells = [(self.d1, 22), (self.d1, 23)] + [(self.d2, h) for h in range(3)]
        self.assertEqual((R["total"]["rx"], R["total"]["tx"]), self.expect(cells))
        self.assertEqual(len(R["days"]), 5)
        self.assertEqual(R["days"][2]["key"], f"{self.d2} 00")

    def test_a_window_longer_than_two_days_is_charted_by_day(self):
        d3 = (dt.date.fromisoformat(self.d2) + dt.timedelta(days=1)).isoformat()
        self.assertEqual(self.pm.report(self.d1, d3, None, 12, 12)["unit"], "hour")    # exactly 48 hours
        R = self.pm.report(self.d1, d3, None, 12, 18)                                   # 54 hours
        self.assertEqual(R["unit"], "day")
        self.assertEqual([x["key"] for x in R["days"]], [self.d1, self.d2, d3])
        cells = [(self.d1, h) for h in range(12, 24)] + [(self.d2, h) for h in range(24)]
        self.assertEqual((R["total"]["rx"], R["total"]["tx"]), self.expect(cells))
        first = sum(a + b for a, b in [self.expect([(self.d1, h)]) for h in range(12, 24)])
        self.assertEqual(R["days"][0]["total"], first)       # the first day only from 12:00

    def test_groups_and_ports_follow_the_window(self):
        R = self.pm.report(self.d1, self.d1, "1", 8, 9)
        self.assertEqual((R["total"]["rx"], R["total"]["tx"]), (801, 8001))     # port 601 only, hour 8
        self.assertEqual({p["port"]: p["tx"] for p in R["ports"]}, {200: 8000, 601: 8001})
        self.assertEqual(R["days"][0]["groups"]["1"], 801 + 8001)

    def test_whole_days_are_what_they_were(self):
        R = self.pm.report(self.d1, self.d2)
        cells = [(d, h) for d in (self.d1, self.d2) for h in range(24)]
        self.assertEqual((R["total"]["rx"], R["total"]["tx"]), self.expect(cells))
        self.assertEqual((R["unit"], [x["key"] for x in R["days"]]), ("day", [self.d1, self.d2]))
        self.assertEqual(self.pm.report(self.d1, self.d2, None, 0, 24)["total"], R["total"])

    def test_a_window_that_ends_before_it_starts_is_refused(self):
        with self.assertRaises(ValueError):
            self.pm.report(self.d1, self.d1, None, 14, 8)
        with self.assertRaises(ValueError):
            self.pm.report(self.d2, self.d1, None, 3, 22)

    def test_hours_are_kept_for_ever_minutes_are_not(self):
        pm = self.pm
        old_day = pm.local_now(time.time() - 400 * 86400).strftime("%Y-%m-%d")
        old_ts = int(time.time()) - 400 * 86400
        with pm.db() as c:
            c.execute("INSERT INTO usage_hour (hour, port, rx, tx) VALUES (?, 200, 5, 50)", (f"{old_day} 09",))
            c.execute("INSERT INTO nic_hour (hour, rx, tx, secs) VALUES (?, 9, 1, 3600)", (f"{old_day} 09",))
            c.execute("INSERT INTO usage_min (ts, port, rx, tx) VALUES (?, 200, 1, 1)", (old_ts,))
        pm.prune()
        R = pm.report(old_day, old_day, None, 9, 10)
        self.assertEqual((R["total"]["rx"], R["total"]["tx"], R["nic"]["rx"]), (5, 50, 9))
        with pm.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM usage_min WHERE ts = ?", (old_ts,)).fetchone()[0], 0)

    def test_hour_keys(self):
        pm = self.pm
        self.assertEqual(pm.hour_key(self.d1, 24), f"{self.d2} 00")
        self.assertEqual(pm.key_start(pm.hour_key(self.d1, 5)) - pm.day_start(self.d1), 5 * 3600)


if __name__ == "__main__":
    unittest.main(verbosity=1)

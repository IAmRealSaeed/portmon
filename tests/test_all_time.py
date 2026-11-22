"""portmon: «همه» — the report over all time, and a long range charted by Persian month.

Runs anywhere with python3. Usage: python tools/portmon/tests/test_all_time.py   (PORTMON_SRC=<file> for another copy)
"""
import datetime as dt
import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get("PORTMON_SRC", os.path.join(HERE, "..", "portmon.py"))


def load():
    spec = importlib.util.spec_from_file_location("portmon_under_test", SRC)
    pm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pm)
    return pm


def days(a, b):
    d0, d1 = dt.date.fromisoformat(a), dt.date.fromisoformat(b)
    return [(d0 + dt.timedelta(days=i)).isoformat() for i in range((d1 - d0).days + 1)]


class Base(unittest.TestCase):
    def setUp(self):
        pm = self.pm = load()
        pm.CFG.clear()
        pm.CFG.update(pm.DEFAULTS, db=os.path.join(tempfile.mkdtemp(), "pm.db"))
        pm.init_db()


class Persian(Base):
    def test_calendar_facts(self):
        # Intl's «persian» calendar, which the pages use, says the same of these days (checked 2015..2045 in full).
        facts = {"2025-03-20": (1403, 12, 30), "2025-03-21": (1404, 1, 1), "2025-09-22": (1404, 6, 31),
                 "2025-09-23": (1404, 7, 1), "2026-03-20": (1404, 12, 29), "2026-03-21": (1405, 1, 1),
                 "2028-03-19": (1406, 12, 29), "2028-03-20": (1407, 1, 1), "2025-01-20": (1403, 11, 1)}
        for g, j in facts.items():
            self.assertEqual(self.pm.jalali(dt.date.fromisoformat(g)), j, g)


class FirstDay(Base):
    def test_a_fresh_install_starts_today(self):
        self.assertEqual(self.pm.first_day(), self.pm.local_now().date().isoformat())

    def test_the_first_counted_day_of_a_watched_port(self):
        with self.pm.db() as c:
            c.execute("INSERT INTO ports (port, label, added_at) VALUES (200, '', 0)")
            c.execute("INSERT INTO usage_day (day, port, rx, tx) VALUES ('2025-02-03', 200, 1, 1), ('2025-05-01', 200, 1, 1)")
            # a port no longer watched (its history kept) does not move the start: the report has no row for it
            c.execute("INSERT INTO usage_day (day, port, rx, tx) VALUES ('2024-12-01', 9999, 5, 5)")
        self.assertEqual(self.pm.first_day(), "2025-02-03")

    def test_the_interface_counts_too(self):
        with self.pm.db() as c:
            c.execute("INSERT INTO ports (port, label, added_at) VALUES (200, '', 0)")
            c.execute("INSERT INTO usage_day (day, port, rx, tx) VALUES ('2025-02-03', 200, 1, 1)")
            c.execute("INSERT INTO nic_day (day, rx, tx, secs) VALUES ('2025-01-28', 9, 9, 86400)")
        self.assertEqual(self.pm.first_day(), "2025-01-28")


class Monthly(Base):
    FROM, TO = "2025-01-10", "2025-06-30"   # 172 days: Dey 21 1403 .. Tir 9 1404

    def setUp(self):
        super().setUp()
        self.use = {}
        with self.pm.db() as c:
            c.execute("INSERT INTO groups (id, name, color, sort) VALUES (1, 'g1', '#fff', 1), (2, 'g2', '#000', 2)")
            c.execute("INSERT INTO ports (port, label, added_at) VALUES (200, '', 0), (601, '', 0), (2093, '', 0)")
            c.execute("INSERT INTO port_groups (port, group_id) VALUES (200, 1), (601, 1), (2093, 2)")
            for i, d in enumerate(days(self.FROM, self.TO)):
                for port, k in ((200, 3), (601, 5), (2093, 7)):
                    rx, tx = k * (i + 1), 1000 * k + i
                    self.use[(d, port)] = (rx, tx)
                    c.execute("INSERT INTO usage_day (day, port, rx, tx) VALUES (?, ?, ?, ?)", (d, port, rx, tx))
                c.execute("INSERT INTO nic_day (day, rx, tx, secs) VALUES (?, ?, 0, 86400)", (d, 11 * (i + 1)))

    def month_days(self, m):
        return [d for d in days(self.FROM, self.TO) if "%04d-%02d" % self.pm.jalali(dt.date.fromisoformat(d))[:2] == m]

    def test_a_long_range_is_charted_by_persian_month(self):
        R = self.pm.report(self.FROM, self.TO)
        self.assertEqual(R["unit"], "month")
        self.assertEqual([p["key"] for p in R["days"]],
                         ["1403-10", "1403-11", "1403-12", "1404-01", "1404-02", "1404-03", "1404-04"])

    def test_each_month_holds_exactly_its_days(self):
        R = self.pm.report(self.FROM, self.TO)
        for p in R["days"]:
            ds = self.month_days(p["key"])
            self.assertEqual((p["from"], p["to"]), (ds[0], ds[-1]), p["key"])
            self.assertEqual(p["total"], sum(sum(self.use[(d, port)]) for d in ds for port in (200, 601, 2093)), p["key"])
            self.assertEqual(p["groups"]["1"], sum(sum(self.use[(d, port)]) for d in ds for port in (200, 601)), p["key"])
            self.assertEqual(p["nic"], sum(11 * (days(self.FROM, self.TO).index(d) + 1) for d in ds), p["key"])
            want_top = sorted(((port, sum(sum(self.use[(d, port)]) for d in ds)) for port in (200, 601, 2093)),
                              key=lambda x: -x[1])
            self.assertEqual([list(x) for x in p["top"]], [list(x) for x in want_top], p["key"])

    def test_months_the_range_cuts_are_marked_partial(self):
        part = {p["key"]: p["part"] for p in self.pm.report(self.FROM, self.TO)["days"]}
        self.assertEqual(part, {"1403-10": True, "1403-11": False, "1403-12": False, "1404-01": False,
                                "1404-02": False, "1404-03": False, "1404-04": True})

    def test_the_totals_are_the_whole_range(self):
        R = self.pm.report(self.FROM, self.TO)
        self.assertEqual(R["total"]["rx"], sum(v[0] for v in self.use.values()))
        self.assertEqual(R["total"]["tx"], sum(v[1] for v in self.use.values()))
        self.assertEqual(sum(p["total"] for p in R["days"]), R["total"]["rx"] + R["total"]["tx"])

    def test_one_group_in_scope(self):
        R = self.pm.report(self.FROM, self.TO, "2")
        self.assertEqual(sum(p["total"] for p in R["days"]), sum(sum(v) for (d, port), v in self.use.items() if port == 2093))

    def test_ninety_days_stay_daily(self):
        to = days(self.FROM, self.TO)[89]
        R = self.pm.report(self.FROM, to)
        self.assertEqual(R["unit"], "day")
        self.assertEqual(len(R["days"]), 90)
        self.assertNotIn("part", R["days"][0])

    def test_the_cut_is_just_past_the_limit(self):
        ds = days(self.FROM, self.TO)
        self.assertEqual(self.pm.report(self.FROM, ds[self.pm.MONTHLY_AFTER_DAYS - 1])["unit"], "day")
        self.assertEqual(self.pm.report(self.FROM, ds[self.pm.MONTHLY_AFTER_DAYS])["unit"], "month")

    def test_all_time_starts_at_the_first_day(self):
        self.assertEqual(self.pm.first_day(), self.FROM)


if __name__ == "__main__":
    unittest.main()

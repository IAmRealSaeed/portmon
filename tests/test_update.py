"""portmon: updating from the dashboard — finding a newer release, and starting `portmon update` beside the service.

Runs anywhere with python3; the wrapper's own run needs bash and python3 on PATH and is skipped without them.
Usage: python tools/portmon/tests/test_update.py   (PORTMON_SRC=<file> for another copy)
"""
import email.message
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get("PORTMON_SRC", os.path.join(HERE, "..", "portmon.py"))


def load():
    spec = importlib.util.spec_from_file_location("portmon_under_test", SRC)
    pm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pm)
    return pm


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def redirect(url, code=302):
    h = email.message.Message()
    h["Location"] = url
    return urllib.error.HTTPError("https://github.com/x", code, "Found", h, None)


class Versions(unittest.TestCase):
    def setUp(self):
        self.pm = load()

    def test_numbers_not_text(self):
        newer = self.pm.is_newer
        self.assertTrue(newer("2.10", "2.9"))
        self.assertTrue(newer("v2.7", "2.6"))
        self.assertTrue(newer("2.5.1", "2.5"))
        self.assertTrue(newer("3.0", "2.99"))
        self.assertFalse(newer("2.6", "2.6"))
        self.assertFalse(newer("2.5", "2.6"))
        self.assertFalse(newer("", "2.6"))
        self.assertFalse(newer("latest", "2.6"))
        self.assertFalse(newer("2.7-rc1", "2.6"))

    def test_against_this_copy(self):
        v = self.pm.vtuple(self.pm.VERSION)
        self.assertIsNotNone(v)
        self.assertTrue(self.pm.is_newer(".".join(map(str, v[:-1] + (v[-1] + 1,)))))
        self.assertFalse(self.pm.is_newer(self.pm.VERSION))


class Lookup(unittest.TestCase):
    def setUp(self):
        self.pm = load()
        self.urlopen, self.opener = self.pm.urllib.request.urlopen, self.pm.urllib.request.build_opener

    def tearDown(self):
        self.pm.urllib.request.urlopen, self.pm.urllib.request.build_opener = self.urlopen, self.opener

    def fake(self, api=None, site=None):
        def urlopen(req, timeout=None):
            if api is None or isinstance(api, Exception):
                raise api or urllib.error.URLError("no route")
            return Resp(json.dumps(api).encode())

        class Opener:
            def open(self_, req, timeout=None):
                if isinstance(site, Exception):
                    raise site
                return Resp(b"<html>")
        self.pm.urllib.request.urlopen = urlopen
        self.pm.urllib.request.build_opener = lambda *a: Opener()

    def test_the_api_gives_tag_and_notes(self):
        self.fake(api={"tag_name": "v2.9", "body": "- new things", "html_url": "https://github.com/r/releases/tag/v2.9"})
        self.assertEqual(self.pm.latest_release(), ("v2.9", "- new things", "https://github.com/r/releases/tag/v2.9"))

    def test_without_the_api_the_latest_link_still_names_the_tag(self):
        self.fake(api=urllib.error.URLError("blocked"), site=redirect("https://github.com/IAmRealSaeed/portmon/releases/tag/v2.9"))
        self.assertEqual(self.pm.latest_release()[:2], ("v2.9", ""))

    def test_an_api_answer_without_a_version_falls_back(self):
        self.fake(api={"message": "rate limited"}, site=redirect("https://github.com/IAmRealSaeed/portmon/releases/tag/v3.0"))
        self.assertEqual(self.pm.latest_release()[0], "v3.0")

    def test_nothing_answers(self):
        self.fake(api=urllib.error.URLError("x"), site=urllib.error.URLError("y"))
        with self.assertRaises(OSError):
            self.pm.latest_release()

    def test_a_redirect_elsewhere_is_not_a_release(self):
        for where in ("https://github.com/login", "https://github.com/IAmRealSaeed/portmon/archive/v9.9",
                      "https://example.com/v9.9"):
            self.fake(api=urllib.error.URLError("x"), site=redirect(where))
            with self.assertRaises(OSError, msg=where):
                self.pm.latest_release()

    def test_a_failed_check_keeps_what_was_known(self):
        self.fake(api={"tag_name": "v9.1", "body": "n", "html_url": "u"})
        self.pm.check_update()
        self.assertEqual((self.pm.UPDATE["latest"], self.pm.UPDATE["error"]), ("9.1", ""))
        self.fake(api=urllib.error.URLError("x"), site=urllib.error.URLError("y"))
        self.pm.check_update()
        self.assertEqual(self.pm.UPDATE["latest"], "9.1")
        self.assertTrue(self.pm.UPDATE["error"])


class Start(unittest.TestCase):
    def setUp(self):
        pm = self.pm = load()
        self.dir = tempfile.mkdtemp()
        pm.CFG.clear()
        pm.CFG.update(pm.DEFAULTS, db=os.path.join(self.dir, "pm.db"))
        pm.APP_DIR = self.dir
        with open(os.path.join(self.dir, "cli.sh"), "w") as f:
            f.write("echo hi\n")
        v = pm.vtuple(pm.VERSION)
        self.next = ".".join(map(str, v[:-1] + (v[-1] + 1,)))
        pm.UPDATE.update(latest=self.next, notes="", url="", checked=1, error="")
        self.calls = []
        self.running = False
        self.real_run = subprocess.run

        def run(cmd, *a, **k):
            self.calls.append(cmd)
            if cmd[:2] == ["systemctl", "is-active"]:
                return subprocess.CompletedProcess(cmd, 0 if self.running else 3, "", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        pm.subprocess.run = run

    def tearDown(self):
        self.pm.subprocess.run = self.real_run

    def launched(self):
        return [c for c in self.calls if c[0] == "systemd-run"]

    def test_starts_portmon_update_as_its_own_unit(self):
        self.assertEqual(self.pm.start_update(self.next), {"ok": True})
        (cmd,) = self.launched()
        self.assertIn("--unit=portmon-update", cmd)
        self.assertIn("--collect", cmd)
        log, meta = self.pm.update_files()
        # the paths travel as arguments after the script, never inside it
        i = cmd.index("-c")
        self.assertEqual(cmd[i + 2:], ["portmon-update", os.path.join(self.dir, "cli.sh"), log, meta])
        self.assertNotIn(self.dir, cmd[i + 1])
        with open(meta) as f:
            m = json.load(f)
        self.assertEqual((m["from"], m["to"], m["rc"]), (self.pm.VERSION, self.next, None))

    def test_only_the_version_that_was_confirmed(self):
        with self.assertRaises(ValueError):
            self.pm.start_update("0.1")
        with self.assertRaises(ValueError):
            self.pm.start_update("")
        self.assertEqual(self.launched(), [])

    def test_nothing_newer_nothing_to_do(self):
        self.pm.UPDATE["latest"] = self.pm.VERSION
        with self.assertRaises(ValueError):
            self.pm.start_update(self.pm.VERSION)
        self.assertEqual(self.launched(), [])

    def test_never_two_at_once(self):
        self.running = True
        with self.assertRaises(ValueError):
            self.pm.start_update(self.next)
        self.assertEqual(self.launched(), [])

    def test_without_cli_sh_it_says_how_instead(self):
        os.remove(os.path.join(self.dir, "cli.sh"))
        with self.assertRaises(ValueError) as e:
            self.pm.start_update(self.next)
        self.assertIn("portmon update", str(e.exception))
        self.assertEqual(self.launched(), [])

    def test_a_refused_launch_is_reported(self):
        def run(cmd, *a, **k):
            if cmd[0] == "systemd-run":
                return subprocess.CompletedProcess(cmd, 1, "", "Unit portmon-update.service already exists.")
            return subprocess.CompletedProcess(cmd, 3, "", "")
        self.pm.subprocess.run = run
        with self.assertRaises(ValueError) as e:
            self.pm.start_update(self.next)
        self.assertIn("already exists", str(e.exception))

    def test_state_reads_the_last_attempt(self):
        self.pm.start_update(self.next)
        log, meta = self.pm.update_files()
        with open(log, "a") as f:
            f.write("".join(f"line {i}\n" for i in range(100)))
        with open(meta) as f:
            m = json.load(f)
        m["rc"] = 7
        with open(meta, "w") as f:
            json.dump(m, f)
        s = self.pm.update_state()
        self.assertEqual((s["current"], s["latest"], s["newer"], s["running"]), (self.pm.VERSION, self.next, True, False))
        self.assertEqual(s["last"]["rc"], 7)
        self.assertEqual(s["log"][-1], "line 99")
        self.assertLessEqual(len(s["log"]), 40)

    def test_the_wrapper_records_the_exit_code(self):
        bash, py3 = shutil.which("bash"), shutil.which("python3")
        if not bash or not py3 or os.name == "nt":
            self.skipTest("needs bash and python3 (a Linux box)")
        with open(os.path.join(self.dir, "cli.sh"), "w") as f:
            f.write('echo "updating: $1"; echo oops >&2; exit 5\n')
        self.pm.start_update(self.next)
        cmd = self.launched()[0]
        i = cmd.index("/bin/bash")
        self.real_run([bash] + cmd[i + 1:], check=True)
        log, meta = self.pm.update_files()
        with open(meta) as f:
            self.assertEqual(json.load(f)["rc"], 5)
        with open(log) as f:
            body = f.read()
        self.assertIn("updating: update", body)
        self.assertIn("oops", body)


if __name__ == "__main__":
    unittest.main()

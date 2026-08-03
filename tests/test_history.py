import json
import shutil
import tempfile
import unittest
from pathlib import Path

from netauditor import history
from netauditor.remediation import snippet_for


def host(name, ip, findings=(), config=""):
    return {"name": name, "host": ip, "group": "", "config": config,
            "findings": list(findings), "interfaces": [], "facts": {}}


def finding(code, severity="warning", interface=""):
    return {"code": code, "severity": severity, "interface": interface,
            "message": f"{code} on {interface or 'switch'}"}


class TestSnapshots(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_and_list(self):
        history.save_snapshot({"generated": "2026-08-01T10:00:00+10:00", "hosts": []},
                              self.tmp)
        history.save_snapshot({"generated": "2026-08-02T11:30:00+10:00", "hosts": []},
                              self.tmp)
        snaps = history.list_snapshots(self.tmp)
        self.assertEqual([p.name for p in snaps],
                         ["audit-20260801-100000.json", "audit-20260802-113000.json"])

    def test_keep_prunes_oldest(self):
        for day in range(1, 6):
            history.save_snapshot(
                {"generated": f"2026-08-0{day}T10:00:00+10:00", "hosts": []},
                self.tmp, keep=3)
        snaps = history.list_snapshots(self.tmp)
        self.assertEqual(len(snaps), 3)
        self.assertEqual(snaps[0].name, "audit-20260803-100000.json")

    def test_previous_snapshot_excludes_current(self):
        history.save_snapshot({"generated": "2026-08-01T10:00:00+10:00", "hosts": []},
                              self.tmp)
        history.save_snapshot({"generated": "2026-08-02T10:00:00+10:00", "hosts": []},
                              self.tmp)
        prev = history.previous_snapshot(self.tmp, before_stamp="20260802-100000")
        self.assertEqual(prev.name, "audit-20260801-100000.json")

    def test_no_snapshots(self):
        self.assertEqual(history.list_snapshots(self.tmp), [])
        self.assertIsNone(history.previous_snapshot(self.tmp))


class TestDiffAudits(unittest.TestCase):
    def setUp(self):
        self.old = {"hosts": [
            host("sw1", "10.0.0.1", [finding("UPLINK_PORTFAST", "critical", "Gi1/0/24"),
                                     finding("NO_NTP")]),
            host("sw2", "10.0.0.2", [finding("HALF_DUPLEX", "warning", "Gi1/0/3")]),
        ]}
        self.new = {"hosts": [
            host("sw1", "10.0.0.1", [finding("NO_NTP"),
                                     finding("DTP_ENABLED", "warning", "Gi1/0/5")]),
            host("sw2", "10.0.0.2", [finding("HALF_DUPLEX", "warning", "Gi1/0/3")]),
            host("sw3", "10.0.0.3", [finding("NO_NTP")]),
        ]}

    def test_fixed_and_added(self):
        delta = history.diff_audits(self.old, self.new)
        sw1 = next(s for s in delta["switches"] if s["name"] == "sw1")
        self.assertEqual([f["code"] for f in sw1["fixed"]], ["UPLINK_PORTFAST"])
        self.assertEqual([f["code"] for f in sw1["added"]], ["DTP_ENABLED"])
        self.assertEqual(sw1["still_open"], 1)

    def test_unchanged_switch_omitted(self):
        delta = history.diff_audits(self.old, self.new)
        self.assertNotIn("sw2", [s["name"] for s in delta["switches"]])

    def test_totals_and_new_switches(self):
        delta = history.diff_audits(self.old, self.new)
        self.assertEqual(delta["totals"], {"fixed": 1, "added": 1, "still_open": 2})
        self.assertEqual(delta["new_switches"], ["10.0.0.3"])
        self.assertEqual(delta["gone_switches"], [])

    def test_identical_audits(self):
        delta = history.diff_audits(self.old, self.old)
        self.assertEqual(delta["switches"], [])
        self.assertEqual(delta["totals"]["added"], 0)


class TestConfigDiff(unittest.TestCase):
    def test_config_diff_lines(self):
        old = {"hosts": [host("sw1", "10.0.0.1", config="hostname sw1\nntp server 10.0.0.9")]}
        new = {"hosts": [host("sw1", "10.0.0.1", config="hostname sw1\nntp server 10.1.1.1")]}
        lines = history.config_diff(old, new, "sw1")
        self.assertTrue(any(l.startswith("-ntp server 10.0.0.9") for l in lines))
        self.assertTrue(any(l.startswith("+ntp server 10.1.1.1") for l in lines))

    def test_no_change_no_diff(self):
        same = {"hosts": [host("sw1", "10.0.0.1", config="hostname sw1")]}
        self.assertEqual(history.config_diff(same, same, "sw1"), [])


class TestGitBackup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_configs(self):
        self.assertIn("no configs", history.backup_configs(self.tmp))

    @unittest.skipUnless(history.git_available(), "git not installed")
    def test_commits_and_detects_no_change(self):
        cfg = self.tmp / "configs"
        cfg.mkdir()
        (cfg / "sw1.cfg").write_text("hostname sw1\n", encoding="utf-8")
        first = history.backup_configs(self.tmp)
        self.assertIn("committed", first)
        self.assertTrue((cfg / ".git").is_dir())
        second = history.backup_configs(self.tmp)
        self.assertIn("no changes", second)
        (cfg / "sw1.cfg").write_text("hostname sw1\nntp server 10.0.0.1\n",
                                     encoding="utf-8")
        third = history.backup_configs(self.tmp)
        self.assertIn("committed", third)


class TestRemediation(unittest.TestCase):
    def test_interface_snippet_uses_port(self):
        snippet = snippet_for("UPLINK_PORTFAST", "Gi1/0/24")
        self.assertIn("interface Gi1/0/24", snippet)
        self.assertIn("no spanning-tree portfast", snippet)
        self.assertIn("write memory", snippet)

    def test_global_snippet(self):
        self.assertIn("ip ssh version 2", snippet_for("SSH_V1"))

    def test_placeholder_when_no_interface(self):
        self.assertIn("<interface>", snippet_for("ACCESS_NO_PORTFAST", ""))

    def test_no_snippet_for_investigation_codes(self):
        self.assertEqual(snippet_for("UNREACHABLE"), "")
        self.assertEqual(snippet_for("INTERFACE_ERRORS", "Gi1/0/3"), "")
        self.assertEqual(snippet_for("NOT_A_REAL_CODE"), "")

    def test_unsaved_changes_is_write_memory(self):
        self.assertEqual(snippet_for("UNSAVED_CHANGES"), "write memory")


if __name__ == "__main__":
    unittest.main()

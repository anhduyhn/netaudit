import json
import tempfile
import unittest
from pathlib import Path

from netauditor.inventory import Host
from netauditor.runner import (find_ghosts, merge_audit_hosts, prune_audit,
                               regenerate_reports, run_audit)


def entry(name, host, group="", marker=""):
    return {"name": name, "host": host, "group": group, "marker": marker,
            "findings": [], "interfaces": [], "config": "", "facts": {}}


class TestMergeAuditHosts(unittest.TestCase):
    def setUp(self):
        self.existing = [entry("sw1", "10.0.0.1", marker="old"),
                         entry("sw2", "10.0.0.2", marker="old"),
                         entry("sw3", "10.0.0.3", marker="old")]

    def test_replaces_matched_by_ip_keeps_others(self):
        fresh = [entry("sw2", "10.0.0.2", marker="new")]
        merged = merge_audit_hosts(self.existing, fresh)
        self.assertEqual([e["name"] for e in merged], ["sw1", "sw2", "sw3"])
        self.assertEqual([e["marker"] for e in merged], ["old", "new", "old"])

    def test_new_hosts_appended(self):
        fresh = [entry("sw9", "10.0.0.9", marker="new")]
        merged = merge_audit_hosts(self.existing, fresh)
        self.assertEqual(len(merged), 4)
        self.assertEqual(merged[-1]["name"], "sw9")

    def test_name_fallback_when_ip_changed(self):
        fresh = [entry("sw2", "10.99.99.99", marker="new")]
        merged = merge_audit_hosts(self.existing, fresh)
        self.assertEqual(len(merged), 3)
        sw2 = next(e for e in merged if e["name"] == "sw2")
        self.assertEqual(sw2["host"], "10.99.99.99")

    def test_old_duplicates_collapse(self):
        # rename+re-IP left two old identities; a fresh entry matching both dedupes
        existing = [entry("old-name", "10.0.0.5"), entry("sw5", "10.0.0.55")]
        fresh = [entry("sw5", "10.0.0.5", marker="new")]
        merged = merge_audit_hosts(existing, fresh)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["marker"], "new")


class TestRunAuditMerge(unittest.TestCase):
    """run_audit with zero hosts exercises the merge/write path without SSH."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        existing = {"generated": "2026-01-01T00:00:00",
                    "hosts": [entry("sw1", "10.0.0.1", group="sydenham")]}
        (self.tmp / "audit.json").write_text(json.dumps(existing), encoding="utf-8")

    def test_merge_keeps_existing_entries(self):
        audit, counts, _ = run_audit([], self.tmp)
        self.assertEqual(len(audit["hosts"]), 1)
        self.assertEqual(audit["hosts"][0]["name"], "sw1")
        self.assertEqual(counts["critical"], 0)  # scope counts: nothing audited
        on_disk = json.loads((self.tmp / "audit.json").read_text(encoding="utf-8"))
        self.assertEqual(len(on_disk["hosts"]), 1)

    def test_fresh_discards_existing(self):
        audit, _, _ = run_audit([], self.tmp, fresh=True)
        self.assertEqual(audit["hosts"], [])


class TestRegenerateReports(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        data = {"generated": "2026-08-03T10:00:00",
                "hosts": [dict(entry("sy1", "10.1.0.1", group="sydenham"),
                               findings=[{"code": "SSH_V1", "severity": "warning",
                                          "interface": "", "message": "no ssh v2"}]),
                          entry("sy2", "10.1.0.2", group="sydenham"),
                          entry("de1", "10.2.0.1", group="delahey")]}
        (self.tmp / "audit.json").write_text(json.dumps(data), encoding="utf-8")

    def test_regenerates_combined_and_per_campus(self):
        messages = regenerate_reports(self.tmp)
        self.assertTrue((self.tmp / "audit.html").exists())
        self.assertTrue((self.tmp / "sydenham.html").exists())
        self.assertTrue((self.tmp / "delahey.html").exists())
        self.assertTrue(any("sydenham.html" in m for m in messages))

    def test_per_campus_contains_only_its_switches(self):
        regenerate_reports(self.tmp)
        syd = (self.tmp / "sydenham.html").read_text(encoding="utf-8")
        self.assertIn("sy1", syd)
        self.assertNotIn("de1", syd)

    def test_fix_blocks_present_after_regeneration(self):
        regenerate_reports(self.tmp)
        for name in ("audit.html", "sydenham.html"):
            html = (self.tmp / name).read_text(encoding="utf-8")
            self.assertIn("class='fixblock'", html, name)
            self.assertIn("ip ssh version 2", html, name)

    def test_missing_audit_raises(self):
        with self.assertRaises(FileNotFoundError):
            regenerate_reports(self.tmp / "nope")


class TestPrune(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        data = {"generated": "2026-01-01T00:00:00",
                "hosts": [entry("sw1", "10.0.0.1"),
                          entry("sw2", "10.0.0.2"),
                          entry("ghost-sw", "10.0.0.99")]}
        (self.tmp / "audit.json").write_text(json.dumps(data), encoding="utf-8")
        self.inv = [Host(host="10.0.0.1", name="sw1"), Host(host="10.0.0.2")]

    def test_find_ghosts(self):
        hosts = json.loads((self.tmp / "audit.json").read_text())["hosts"]
        ghosts = find_ghosts(self.inv, hosts)
        self.assertEqual([g["name"] for g in ghosts], ["ghost-sw"])

    def test_dry_run_changes_nothing(self):
        names, messages = prune_audit(self.inv, self.tmp, apply=False)
        self.assertEqual(names, ["ghost-sw"])
        self.assertEqual(messages, [])
        on_disk = json.loads((self.tmp / "audit.json").read_text(encoding="utf-8"))
        self.assertEqual(len(on_disk["hosts"]), 3)

    def test_apply_removes_and_rewrites(self):
        names, messages = prune_audit(self.inv, self.tmp, apply=True)
        self.assertEqual(names, ["ghost-sw"])
        self.assertTrue(messages)
        on_disk = json.loads((self.tmp / "audit.json").read_text(encoding="utf-8"))
        self.assertEqual([h["name"] for h in on_disk["hosts"]], ["sw1", "sw2"])
        self.assertTrue((self.tmp / "audit.html").exists())

    def test_missing_audit_raises(self):
        with self.assertRaises(FileNotFoundError):
            prune_audit(self.inv, self.tmp / "nope")


if __name__ == "__main__":
    unittest.main()

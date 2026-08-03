import json
import os
import tempfile
import unittest
from pathlib import Path

from netauditor import cli

CONFIG_A = "spanning-tree mode rapid-pvst\nntp server 10.0.0.1\n"
CONFIG_B = "spanning-tree mode rapid-pvst\n"


def make_audit_json(tmpdir: Path) -> Path:
    hosts = [
        {"name": "sy-sw-1", "host": "10.1.0.11", "group": "sydenham", "config": CONFIG_A},
        {"name": "sy-sw-2", "host": "10.1.0.12", "group": "sydenham", "config": CONFIG_B},
        {"name": "de-sw-1", "host": "10.2.0.11", "group": "delahey", "config": CONFIG_A},
        {"name": "de-sw-2", "host": "10.2.0.12", "group": "delahey", "config": CONFIG_B},
        {"name": "lone-sw", "host": "10.3.0.11", "group": "kingspark", "config": CONFIG_A},
    ]
    path = tmpdir / "audit.json"
    path.write_text(json.dumps({"hosts": hosts}), encoding="utf-8")
    return path


class TestGroupHelpers(unittest.TestCase):
    def test_split_by_group(self):
        reports = [{"group": "sydenham"}, {"group": "sydenham"}, {"group": ""}]
        split = dict(cli._split_by_group(reports))
        self.assertEqual(len(split["sydenham"]), 2)
        self.assertEqual(len(split["ungrouped"]), 1)

    def test_split_without_groups_is_empty(self):
        self.assertEqual(cli._split_by_group([{"group": ""}, {}]), [])

    def test_group_filename_never_clobbers_combined_reports(self):
        self.assertEqual(cli._group_filename("Sydenham Campus", ".html"), "sydenham_campus.html")
        self.assertEqual(cli._group_filename("audit", ".html"), "group-audit.html")
        self.assertEqual(cli._group_filename("drift", ".drift.html"), "group-drift.drift.html")


class TestAnalyzePerGroupExport(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.src = make_audit_json(self.tmp)
        self.out = self.tmp / "out"

    def test_per_group_drift_reports_written(self):
        rc = cli.main(["analyze", str(self.src), "-o", str(self.out), "--tests", "stp"])
        self.assertIn(rc, (0, 1))
        self.assertTrue((self.out / "drift.html").exists())
        self.assertTrue((self.out / "sydenham.drift.html").exists())
        self.assertTrue((self.out / "delahey.drift.html").exists())
        # kingspark has one switch: no drift possible, no file
        self.assertFalse((self.out / "kingspark.drift.html").exists())
        # per-group report is scoped to its campus
        syd = (self.out / "sydenham.drift.html").read_text(encoding="utf-8")
        self.assertIn("campus: sydenham", syd)
        self.assertIn("sy-sw-1", syd)
        self.assertNotIn("de-sw-1", syd)

    def test_group_flag_scopes_combined_report(self):
        rc = cli.main(["analyze", str(self.src), "-o", str(self.out), "-g", "delahey"])
        self.assertIn(rc, (0, 1))
        drift = (self.out / "drift.html").read_text(encoding="utf-8")
        self.assertIn("de-sw-1", drift)
        self.assertNotIn("sy-sw-1", drift)


class TestPruneCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.out = self.tmp / "out"
        self.out.mkdir()
        (self.out / "audit.json").write_text(json.dumps({"hosts": [
            {"name": "sw1", "host": "10.1.0.11", "config": CONFIG_A,
             "findings": [], "interfaces": [], "facts": {}},
            {"name": "ghost-sw", "host": "10.9.9.9", "config": CONFIG_A,
             "findings": [], "interfaces": [], "facts": {}},
        ]}), encoding="utf-8")
        self.inv = self.tmp / "inv.yml"
        self.inv.write_text("hosts:\n  - host: 10.1.0.11\n    name: sw1\n",
                            encoding="utf-8")

    def test_dry_run_lists_but_keeps(self):
        rc = cli.main(["prune", "-i", str(self.inv), "-o", str(self.out)])
        self.assertEqual(rc, 0)
        data = json.loads((self.out / "audit.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["hosts"]), 2)

    def test_yes_removes(self):
        rc = cli.main(["prune", "-i", str(self.inv), "-o", str(self.out), "--yes"])
        self.assertEqual(rc, 0)
        data = json.loads((self.out / "audit.json").read_text(encoding="utf-8"))
        self.assertEqual([h["name"] for h in data["hosts"]], ["sw1"])


class TestImplicitStartup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.old_cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.old_cwd)

    def test_find_inventory_prefers_yml(self):
        (self.tmp / "inventory.txt").write_text("10.0.0.1\n", encoding="utf-8")
        (self.tmp / "inventory.yml").write_text("hosts:\n  - host: 10.0.0.1\n",
                                               encoding="utf-8")
        self.assertEqual(cli._find_inventory(self.tmp), str(self.tmp / "inventory.yml"))

    def test_find_inventory_empty_dir(self):
        self.assertEqual(cli._find_inventory(self.tmp), "")

    def test_resolve_explicit_wins(self):
        path, err = cli._resolve_inventory("explicit.yml")
        self.assertEqual(path, "explicit.yml")
        self.assertEqual(err, "")

    def test_resolve_errors_when_nothing_found(self):
        path, err = cli._resolve_inventory("")
        self.assertEqual(path, "")
        self.assertIn("inventory.yml", err)

    def test_bare_launch_without_anything_errors_cleanly(self):
        # no inventory, no out/audit.json, non-tty stdin: no UI, no hang
        rc = cli.main([])
        self.assertEqual(rc, 2)

    def test_status_autodetects_inventory(self):
        (self.tmp / "inventory.yml").write_text(
            "hosts:\n  - host: 127.0.0.1\n    port: 1\n", encoding="utf-8")
        rc = cli.main(["status", "--timeout", "1"])
        self.assertEqual(rc, 1)  # found the inventory, probed, port 1 is down


if __name__ == "__main__":
    unittest.main()

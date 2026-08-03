import unittest

from netauditor.inventory import Host
from netauditor.ui_data import ALL_ROW_NAME, build_rows, filter_findings


def audit_fixture():
    return {"hosts": [
        {"name": "sw1", "host": "10.0.0.1", "group": "sydenham",
         "findings": [
             {"code": "UPLINK_PORTFAST", "severity": "critical",
              "interface": "Gi1/0/24", "message": "portfast on uplink"},
             {"code": "NO_NTP", "severity": "warning", "interface": "", "message": "no ntp"},
         ],
         "interfaces": [{"interface": "Gi1/0/1"}], "config": "hostname sw1"},
        {"name": "sw2", "host": "10.0.0.2", "group": "delahey",
         "findings": [], "interfaces": [], "config": "hostname sw2"},
    ]}


class TestBuildRows(unittest.TestCase):
    def test_inventory_matched_by_ip(self):
        inv = [Host(host="10.0.0.1", name="inv-name", group="sydenham",
                    username="u", password="p")]
        rows = build_rows(inv, audit_fixture())
        merged = next(r for r in rows if r["host"] == "10.0.0.1")
        self.assertEqual(merged["critical"], 1)
        self.assertEqual(merged["config"], "hostname sw1")
        self.assertIsNotNone(merged["inv"])

    def test_audit_only_hosts_appended(self):
        rows = build_rows([], audit_fixture())
        names = {r["name"] for r in rows}
        self.assertIn("sw1", names)
        self.assertIn("sw2", names)

    def test_all_row_prepended_and_aggregates(self):
        rows = build_rows([], audit_fixture())
        self.assertEqual(rows[0]["name"], ALL_ROW_NAME)
        self.assertEqual(rows[0]["critical"], 1)
        self.assertEqual(rows[0]["warning"], 1)
        # aggregated findings carry their origin host
        self.assertEqual(rows[0]["findings"][0]["host"], "sw1")

    def test_no_findings_no_all_row(self):
        rows = build_rows([Host(host="10.9.9.9", username="u", password="p")], None)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["host"], "10.9.9.9")

    def test_inventory_matched_by_name(self):
        inv = [Host(host="192.168.99.1", name="sw2", username="u", password="p")]
        rows = build_rows(inv, audit_fixture())
        merged = next(r for r in rows if r["name"] == "sw2")
        self.assertEqual(merged["config"], "hostname sw2")
        # matched entry must not be duplicated as an audit-only row
        self.assertEqual(sum(1 for r in rows if r["config"] == "hostname sw2"), 1)


class TestFilterFindings(unittest.TestCase):
    FINDINGS = [
        {"code": "A", "severity": "warning", "host": "sw1", "message": "portfast missing"},
        {"code": "B", "severity": "critical", "host": "sw2", "message": "uplink loop"},
        {"code": "C", "severity": "info", "host": "sw1", "message": "vlan one"},
    ]

    def test_severity_filter(self):
        out = filter_findings(self.FINDINGS, severity="critical")
        self.assertEqual([f["code"] for f in out], ["B"])

    def test_query_filter(self):
        out = filter_findings(self.FINDINGS, query="portfast")
        self.assertEqual([f["code"] for f in out], ["A"])

    def test_sorted_by_severity(self):
        out = filter_findings(self.FINDINGS)
        self.assertEqual([f["severity"] for f in out], ["critical", "warning", "info"])


if __name__ == "__main__":
    unittest.main()

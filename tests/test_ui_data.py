import unittest

from netauditor.inventory import Host
from netauditor.ui_data import (ALL_ROW_NAME, aggregate_row, build_rows,
                                campuses, filter_findings)


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

    def test_no_aggregate_in_plain_rows(self):
        rows = build_rows([], audit_fixture())
        self.assertNotIn(ALL_ROW_NAME, [r["name"] for r in rows])
        self.assertEqual(len(rows), 2)

    def test_aggregate_row_combines_findings(self):
        rows = build_rows([], audit_fixture())
        agg = aggregate_row(rows)
        self.assertEqual(agg["name"], ALL_ROW_NAME)
        self.assertTrue(agg["is_aggregate"])
        self.assertEqual(agg["member_count"], 2)
        self.assertEqual(agg["critical"], 1)
        self.assertEqual(agg["warning"], 1)
        # aggregated findings carry their origin host
        self.assertEqual(agg["findings"][0]["host"], "sw1")

    def test_campuses_order_and_ungrouped(self):
        rows = build_rows([Host(host="10.9.9.9", username="u", password="p")],
                          audit_fixture())
        self.assertEqual(campuses(rows), ["sydenham", "delahey", ""])

    def test_inventory_only(self):
        rows = build_rows([Host(host="10.9.9.9", username="u", password="p")], None)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["host"], "10.9.9.9")

    def test_ghost_flag_only_with_inventory(self):
        inv = [Host(host="10.0.0.1", name="sw1")]
        rows = build_rows(inv, audit_fixture())
        by_name = {r["name"]: r for r in rows}
        self.assertFalse(by_name["sw1"]["ghost"])       # matched
        self.assertTrue(by_name["sw2"]["ghost"])        # audit-only = ghost
        # without an inventory nothing can be classified as a ghost
        rows = build_rows([], audit_fixture())
        self.assertFalse(any(r["ghost"] for r in rows))

    def test_hosts_for_scope(self):
        from netauditor.ui_data import hosts_for_scope
        inv = [Host(host="10.1.0.1", group="sydenham"),
               Host(host="10.2.0.1", group="delahey"),
               Host(host="10.9.0.1")]
        self.assertEqual(len(hosts_for_scope(inv, "All")), 3)
        self.assertEqual([h.host for h in hosts_for_scope(inv, "sydenham")],
                         ["10.1.0.1"])
        self.assertEqual([h.host for h in hosts_for_scope(inv, "ungrouped")],
                         ["10.9.0.1"])

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

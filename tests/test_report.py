import unittest

from netauditor import report


def minimal_audit():
    return {
        "generated": "2026-07-31T12:00:00",
        "tool_version": "0.1.0",
        "hosts": [{
            "host": "10.0.0.1", "name": "sw1", "group": "sydenham", "error": None,
            "facts": {"model": "WS-C2960X", "version": "15.2", "uptime": "1 week"},
            "stp": {"mode": "rapid-pvst"},
            "interfaces": [{
                "interface": "Gi1/0/1", "description": "AP", "status": "connected",
                "vlan": "10", "duplex": "a-full", "speed": "a-1000", "is_trunk": False,
                "is_uplink": False, "uplink_reason": "", "cdp_neighbors": [],
                "portfast": True, "portfast_source": "interface", "bpduguard": True,
                "input_errors": 0, "crc": 0, "late_collisions": 0, "config": [],
            }],
            "findings": [{"code": "X", "severity": "critical", "interface": "Gi1/0/1",
                          "message": "<script>alert(1)</script> boom"}],
            "config": "hostname sw1",
        }],
    }


def minimal_drift():
    return {
        "generated": "2026-07-31T12:00:00",
        "hosts": ["sw1", "sw2"],
        "tests_run": ["security"],
        "drift": {"hosts": ["sw1", "sw2"], "baseline": "sw1", "item_count": 1, "items": [{
            "header": "ntp server 10.0.0.1",
            "present_on": ["sw1"], "missing_on": ["sw2"],
            "variants": [{"hosts": ["sw1"], "is_baseline": True,
                          "children": [], "added": [], "removed": []}],
        }]},
        "findings": [{"code": "Y", "severity": "warning", "host": "sw2", "message": "warned"}],
    }


class TestAuditHtml(unittest.TestCase):
    def setUp(self):
        self.html = report.render_audit_html(minimal_audit())

    def test_has_filter_toolbar_and_script(self):
        self.assertIn("id='q'", self.html)
        self.assertIn("data-sev='critical'", self.html)
        self.assertIn("id='codesel'", self.html)
        self.assertIn("addEventListener", self.html)

    def test_tables_are_searchable_and_categorised(self):
        self.assertIn("data-cat='switches'", self.html)
        self.assertIn("data-cat='findings'", self.html)
        self.assertIn("data-cat='interfaces'", self.html)

    def test_findings_grouped_by_code(self):
        self.assertIn("class='findgroup' open", self.html)  # critical group starts open
        self.assertIn("data-code='X'", self.html)

    def test_campus_tagging(self):
        self.assertIn("id='groupsel'", self.html)
        self.assertIn("data-group='sydenham'", self.html)
        self.assertIn("<th>Campus</th>", self.html)
        self.assertIn("class='hostsection'", self.html)

    def test_untrusted_text_is_escaped(self):
        self.assertNotIn("<script>alert(1)</script>", self.html)
        self.assertIn("&lt;script&gt;", self.html)

    def test_no_unsaved_banner_without_finding(self):
        self.assertNotIn("class='banner-unsaved'", self.html)


class TestUnsavedBanner(unittest.TestCase):
    def test_banner_and_mark_present(self):
        audit = minimal_audit()
        audit["hosts"][0]["findings"].append(
            {"code": "UNSAVED_CHANGES", "severity": "warning", "interface": "",
             "message": "running differs from startup"})
        html = report.render_audit_html(audit)
        self.assertIn("class='banner-unsaved'", html)
        self.assertIn("1 switch(es) have UNSAVED", html)
        self.assertIn("sw1", html.split("class='banner-unsaved'")[1][:300])
        self.assertIn("class='unsaved-mark'", html)


class TestDriftHtml(unittest.TestCase):
    def setUp(self):
        self.html = report.render_drift_html(minimal_drift())

    def test_has_filter_toolbar_and_script(self):
        self.assertIn("id='q'", self.html)
        self.assertIn("addEventListener", self.html)

    def test_baseline_labelled(self):
        self.assertIn("baseline (sw1)", self.html)
        self.assertIn("baseline: sw1", self.html)

    def test_drift_cards_categorised(self):
        self.assertIn("data-cat='drift'", self.html)
        self.assertIn("data-cat='findings'", self.html)

    def test_drift_findings_grouped_by_code(self):
        self.assertIn("class='findgroup'", self.html)
        self.assertIn("data-code='Y'", self.html)


if __name__ == "__main__":
    unittest.main()

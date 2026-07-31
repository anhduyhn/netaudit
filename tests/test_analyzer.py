import unittest

from netauditor import analyzer

BASE_CONFIG = """\
version 15.2
service password-encryption
hostname {name}
spanning-tree mode rapid-pvst
vlan 10
 name STUDENTS
vlan 20
 name STAFF
ntp server 10.10.0.1
line vty 0 4
 transport input ssh
end
"""

DRIFTED_CONFIG = """\
version 15.2
hostname sw-access-2
spanning-tree mode pvst
vlan 10
 name STUDENTS
line vty 0 4
 transport input telnet ssh
snmp-server community public RO
ip http server
enable password letmein
end
"""


def make_configs():
    return {
        "sw-core-1": BASE_CONFIG.format(name="sw-core-1"),
        "sw-access-1": BASE_CONFIG.format(name="sw-access-1"),
        "sw-access-2": DRIFTED_CONFIG,
    }


class TestDrift(unittest.TestCase):
    def setUp(self):
        self.drift = analyzer.compute_drift(make_configs())
        self.by_header = {i["header"]: i for i in self.drift["items"]}

    def test_missing_lines_detected(self):
        self.assertIn("ntp server 10.10.0.1", self.by_header)
        self.assertEqual(self.by_header["ntp server 10.10.0.1"]["missing_on"], ["sw-access-2"])
        self.assertEqual(self.by_header["service password-encryption"]["missing_on"], ["sw-access-2"])

    def test_extra_lines_detected(self):
        self.assertIn("ip http server", self.by_header)
        self.assertEqual(self.by_header["ip http server"]["present_on"], ["sw-access-2"])

    def test_modified_block_children(self):
        item = self.by_header["line vty 0 4"]
        deviant = next(v for v in item["variants"] if v["hosts"] == ["sw-access-2"])
        self.assertIn("transport input telnet ssh", deviant["added"])
        self.assertIn("transport input ssh", deviant["removed"])

    def test_hostname_not_treated_as_drift(self):
        self.assertFalse(any(h.startswith("hostname") for h in self.by_header))

    def test_identical_configs_produce_no_drift(self):
        drift = analyzer.compute_drift({
            "a": BASE_CONFIG.format(name="a"),
            "b": BASE_CONFIG.format(name="b"),
        })
        self.assertEqual(drift["item_count"], 0)


class TestSuites(unittest.TestCase):
    def setUp(self):
        self.configs = make_configs()

    def codes(self, findings, host=None):
        return {f["code"] for f in findings if host is None or f["host"] == host}

    def test_security(self):
        findings = analyzer.test_security(self.configs)
        bad = self.codes(findings, "sw-access-2")
        self.assertIn("TELNET_ENABLED", bad)
        self.assertIn("SNMP_DEFAULT_COMMUNITY", bad)
        self.assertIn("HTTP_SERVER", bad)
        self.assertIn("ENABLE_PASSWORD", bad)
        self.assertIn("NO_PASSWORD_ENCRYPTION", bad)
        self.assertNotIn("TELNET_ENABLED", self.codes(findings, "sw-core-1"))

    def test_stp(self):
        findings = analyzer.test_stp(self.configs)
        codes = self.codes(findings)
        self.assertIn("STP_MODE_MISMATCH", codes)
        self.assertIn("NO_DETERMINISTIC_ROOT", codes)

    def test_vlans(self):
        findings = analyzer.test_vlans(self.configs)
        messages = " ".join(f["message"] for f in findings)
        self.assertIn("VLAN 20", messages)
        self.assertIn("sw-access-2", messages)

    def test_run_tests_all(self):
        findings, ran = analyzer.run_tests(self.configs, ["all"])
        self.assertEqual(set(ran), {"security", "stp", "vlans"})
        self.assertTrue(findings)

    def test_unknown_test_rejected(self):
        with self.assertRaises(ValueError):
            analyzer.run_tests(self.configs, ["nope"])


if __name__ == "__main__":
    unittest.main()

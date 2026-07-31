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


class TestNormalize(unittest.TestCase):
    def test_multiline_banner_skipped(self):
        cfg = ("hostname sw1\n"
               "banner motd ^C\n"
               "<> Authorised Users Only <>\n"
               "<> monitored for security reasons <>\n"
               "^C\n"
               "ntp server 10.0.0.1\n")
        norm = analyzer.normalize_config(cfg)
        self.assertNotIn("Authorised", norm)
        self.assertNotIn("^C", norm)
        self.assertIn("ntp server 10.0.0.1", norm)

    def test_banner_with_glued_delimiter(self):
        # exports often show 'banner motd ^CC' where ^C is the delimiter
        cfg = "banner motd ^CC\nKeep out\n^C\nntp server 10.0.0.1"
        norm = analyzer.normalize_config(cfg)
        self.assertNotIn("Keep out", norm)
        self.assertIn("ntp server 10.0.0.1", norm)

    def test_single_line_banner(self):
        cfg = "banner motd ^CAuthorised users only^C\nntp server 10.0.0.1"
        norm = analyzer.normalize_config(cfg)
        self.assertNotIn("Authorised", norm)
        self.assertIn("ntp server 10.0.0.1", norm)

    def test_mask_secrets(self):
        masked = analyzer.mask_secrets(
            "enable secret 9 $9$abcdef\n"
            "username admin privilege 15 secret 9 $9$xyz\n"
            "snmp-server community S3cr3tRW RW\n"
            "ntp server 10.0.0.1")
        self.assertNotIn("$9$abcdef", masked)
        self.assertNotIn("$9$xyz", masked)
        self.assertNotIn("S3cr3tRW", masked)
        self.assertIn("snmp-server community <redacted> RW", masked)
        self.assertIn("ntp server 10.0.0.1", masked)


class TestSecretAndBannerDrift(unittest.TestCase):
    def test_differing_hashes_are_not_drift(self):
        drift = analyzer.compute_drift({
            "a": "enable secret 9 $9$salted-one\nntp server 10.0.0.1",
            "b": "enable secret 9 $9$salted-two\nntp server 10.0.0.1",
        })
        self.assertEqual(drift["item_count"], 0)

    def test_no_hashes_leak_into_items(self):
        drift = analyzer.compute_drift({
            "a": "enable secret 9 $9$onlyhere\nntp server 10.0.0.1",
            "b": "ntp server 10.0.0.1",
        })
        headers = [i["header"] for i in drift["items"]]
        self.assertIn("enable secret 9 <redacted>", headers)
        self.assertNotIn("enable secret 9 $9$onlyhere", headers)

    def test_banner_lines_are_not_drift(self):
        drift = analyzer.compute_drift({
            "a": "banner motd ^C\n<> banner A <>\n^C\nntp server 10.0.0.1",
            "b": "banner motd ^C\n<> different banner B <>\n^C\nntp server 10.0.0.1",
        })
        self.assertEqual(drift["item_count"], 0)


class TestBaseline(unittest.TestCase):
    # Majority is "wrong" here: two switches lack ntp, only the golden one has it.
    CONFIGS = {
        "golden": "spanning-tree mode rapid-pvst\nntp server 10.0.0.1\n",
        "sw-a": "spanning-tree mode rapid-pvst\n",
        "sw-b": "spanning-tree mode rapid-pvst\nip http server\n",
    }

    def test_unknown_baseline_rejected(self):
        with self.assertRaises(ValueError):
            analyzer.compute_drift(self.CONFIGS, baseline="nope")

    def test_baseline_is_reference_even_against_majority(self):
        drift = analyzer.compute_drift(self.CONFIGS, baseline="golden")
        self.assertEqual(drift["baseline"], "golden")
        by_header = {i["header"]: i for i in drift["items"]}
        ntp = by_header["ntp server 10.0.0.1"]
        self.assertEqual(ntp["missing_on"], ["sw-a", "sw-b"])
        self.assertTrue(ntp["variants"][0]["is_baseline"])

    def test_extra_config_relative_to_baseline(self):
        drift = analyzer.compute_drift(self.CONFIGS, baseline="golden")
        by_header = {i["header"]: i for i in drift["items"]}
        item = by_header["ip http server"]
        self.assertIn("golden", item["missing_on"])
        self.assertEqual(item["present_on"], ["sw-b"])


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

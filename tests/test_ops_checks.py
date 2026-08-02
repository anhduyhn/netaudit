import unittest

from netauditor import checks, parsers

VTP_SERVER = """\
VTP Version capable             : 1 to 3
VTP version running             : 1
VTP Domain Name                 : school
VTP Pruning Mode                : Disabled
VTP Operating Mode              : Server
Configuration Revision          : 42
"""

VTP_TRANSPARENT = VTP_SERVER.replace(": Server", ": Transparent")

LOGGING = """\
Syslog logging: enabled (0 messages dropped, 0 messages rate-limited)
*Jul 30 08:12:33.120: %SW_MATM-4-MACFLAP_NOTIF: Host 001a.2b3c.4d5e in vlan 10 is flapping between port Gi1/0/5 and port GigabitEthernet1/0/24
*Jul 30 08:12:35.221: %SW_MATM-4-MACFLAP_NOTIF: Host 001a.2b3c.9999 in vlan 20 is flapping between port GigabitEthernet1/0/24 and port Gi1/0/5
*Jul 30 09:00:00.000: %SYS-5-CONFIG_I: Configured from console by admin on vty0
"""

RUNNING = "hostname sw1\nntp server 10.0.0.1\nsnmp-server community x RO\nend\n"
STARTUP_SAME = "Using 4096 out of 65536 bytes\nhostname sw1\nntp server 10.0.0.1\nsnmp-server community x RO\nend\n"
STARTUP_STALE = "Using 4096 out of 65536 bytes\nhostname sw1\nend\n"


def findings_for(outputs):
    outputs.setdefault("running_config", RUNNING)
    report = checks.build_host_report(
        {"host": "10.0.0.1", "name": "sw1", "error": None, "outputs": outputs})
    return {f["code"]: f for f in report["findings"]}


class TestUnsavedChanges(unittest.TestCase):
    def test_identical_configs_not_flagged(self):
        self.assertNotIn("UNSAVED_CHANGES", findings_for({"startup_config": STARTUP_SAME}))

    def test_stale_startup_flagged(self):
        f = findings_for({"startup_config": STARTUP_STALE})["UNSAVED_CHANGES"]
        self.assertEqual(f["severity"], "warning")
        self.assertIn("differs from startup-config", f["message"])

    def test_missing_startup_flagged(self):
        f = findings_for({"startup_config": "startup-config is not present"})["UNSAVED_CHANGES"]
        self.assertIn("No startup-config is saved", f["message"])

    def test_empty_collection_stays_quiet(self):
        self.assertNotIn("UNSAVED_CHANGES", findings_for({"startup_config": ""}))
        self.assertNotIn("UNSAVED_CHANGES", findings_for({}))

    def test_regenerated_self_signed_cert_is_not_unsaved_change(self):
        cert_block = ("crypto pki certificate chain TP-self-signed-1234567890\n"
                      " certificate self-signed 01\n"
                      "  30820229 30820192 A0030201 02020101 300D0609 2A864886 F70D0101\n"
                      "  05050030 2D312B30 29060355 04031322 494F532D 53656C66 2D536967\n"
                      "  quit\n")
        running = cert_block + RUNNING
        self.assertNotIn("UNSAVED_CHANGES",
                         findings_for({"running_config": running,
                                       "startup_config": STARTUP_SAME}))

    def test_diff_shows_example_lines_and_detail(self):
        f = findings_for({"startup_config": STARTUP_STALE})["UNSAVED_CHANGES"]
        self.assertIn("only in running:", f["message"])
        self.assertIn("ntp server 10.0.0.1", f["message"])
        self.assertIn("ntp server 10.0.0.1", f["detail"]["added"])
        self.assertEqual(f["detail"]["removed"], [])


class TestMacFlapping(unittest.TestCase):
    def test_parser_normalizes_ports(self):
        flaps = parsers.parse_mac_flaps(LOGGING)
        self.assertEqual(len(flaps), 2)
        self.assertEqual(flaps[0]["port_b"], "Gi1/0/24")

    def test_events_aggregated_per_port_pair(self):
        f = findings_for({"logging": LOGGING})["MAC_FLAPPING"]
        self.assertEqual(f["severity"], "critical")
        self.assertIn("2 event(s)", f["message"])
        self.assertIn("2 MAC(s)", f["message"])
        self.assertIn("10, 20", f["message"])
        self.assertIn("Gi1/0/5", f["message"])

    def test_clean_log_not_flagged(self):
        self.assertNotIn("MAC_FLAPPING", findings_for({"logging": "nothing interesting"}))


class TestVtp(unittest.TestCase):
    def test_server_mode_flagged(self):
        f = findings_for({"vtp_status": VTP_SERVER})["VTP_SERVER"]
        self.assertEqual(f["severity"], "warning")
        self.assertIn("domain school", f["message"])

    def test_transparent_mode_clean(self):
        self.assertNotIn("VTP_SERVER", findings_for({"vtp_status": VTP_TRANSPARENT}))
        self.assertNotIn("VTP_SERVER", findings_for({}))


if __name__ == "__main__":
    unittest.main()

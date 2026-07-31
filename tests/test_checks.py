import unittest

from netauditor import checks

import fixtures


def make_result():
    return {
        "host": "10.10.0.12",
        "name": "sw-access-1",
        "error": None,
        "outputs": {
            "version": fixtures.SHOW_VERSION,
            "interfaces_status": fixtures.SHOW_INT_STATUS,
            "interfaces": fixtures.SHOW_INTERFACES,
            "stp_summary": fixtures.SHOW_STP_SUMMARY,
            "stp_detail": fixtures.SHOW_STP_DETAIL,
            "cdp_neighbors": fixtures.SHOW_CDP_DETAIL,
            "running_config": fixtures.RUNNING_CONFIG,
        },
    }


class TestBuildHostReport(unittest.TestCase):
    def setUp(self):
        self.report = checks.build_host_report(make_result())
        self.codes = {(f["code"], f["interface"]) for f in self.report["findings"]}

    def test_uplink_portfast_flagged_critical(self):
        self.assertIn(("UPLINK_PORTFAST", "Gi1/0/24"), self.codes)
        f = next(f for f in self.report["findings"] if f["code"] == "UPLINK_PORTFAST")
        self.assertEqual(f["severity"], "critical")

    def test_errdisabled_flagged(self):
        self.assertIn(("ERRDISABLED", "Gi1/0/7"), self.codes)

    def test_stp_churn_critical(self):
        churn = [f for f in self.report["findings"] if f["code"] == "STP_CHURN"]
        self.assertEqual(len(churn), 1)
        self.assertEqual(churn[0]["severity"], "critical")
        self.assertIn("VLAN0010", churn[0]["message"])

    def test_access_port_without_protection_warned(self):
        self.assertIn(("ACCESS_NO_PORTFAST", "Gi1/0/3"), self.codes)
        self.assertIn(("ACCESS_NO_BPDUGUARD", "Gi1/0/3"), self.codes)

    def test_duplex_and_errors(self):
        self.assertIn(("HALF_DUPLEX", "Gi1/0/3"), self.codes)
        self.assertIn(("LATE_COLLISIONS", "Gi1/0/3"), self.codes)
        self.assertIn(("INTERFACE_ERRORS", "Gi1/0/3"), self.codes)

    def test_good_access_port_is_clean(self):
        gi1 = [f for f in self.report["findings"] if f["interface"] == "Gi1/0/1"]
        self.assertEqual(gi1, [])

    def test_uplink_detection(self):
        ifaces = {i["interface"]: i for i in self.report["interfaces"]}
        self.assertTrue(ifaces["Gi1/0/24"]["is_uplink"])
        self.assertIn("sw-core-1.school.local", ifaces["Gi1/0/24"]["cdp_neighbors"])
        self.assertFalse(ifaces["Gi1/0/1"]["is_uplink"])

    def test_unreachable_host(self):
        report = checks.build_host_report(
            {"host": "10.9.9.9", "name": "ghost", "error": "TimeoutError: no route"})
        self.assertEqual(report["findings"][0]["code"], "UNREACHABLE")
        self.assertEqual(report["findings"][0]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()

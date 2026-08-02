import unittest

from netauditor import parsers

import fixtures


class TestIfnames(unittest.TestCase):
    def test_long_to_short(self):
        self.assertEqual(parsers.short_ifname("GigabitEthernet1/0/24"), "Gi1/0/24")
        self.assertEqual(parsers.short_ifname("TenGigabitEthernet1/1/1"), "Te1/1/1")
        self.assertEqual(parsers.short_ifname("TwentyFiveGigE1/0/1"), "Twe1/0/1")
        self.assertEqual(parsers.short_ifname("Port-channel1"), "Po1")

    def test_short_stays_short(self):
        self.assertEqual(parsers.short_ifname("Gi1/0/1"), "Gi1/0/1")


class TestAges(unittest.TestCase):
    def test_hms(self):
        self.assertEqual(parsers.parse_age_seconds("00:04:33"), 273)

    def test_weeks_days(self):
        self.assertEqual(parsers.parse_age_seconds("5w4d"), 5 * 604800 + 4 * 86400)

    def test_garbage(self):
        self.assertIsNone(parsers.parse_age_seconds("never"))


class TestVersion(unittest.TestCase):
    def test_facts(self):
        facts = parsers.parse_version(fixtures.SHOW_VERSION)
        self.assertEqual(facts["hostname"], "sw-access-1")
        self.assertEqual(facts["model"], "WS-C2960X-24PS-L")
        self.assertEqual(facts["version"], "15.2(7)E7")
        self.assertEqual(facts["serial"], "FOC1234X0AB")


class TestInterfacesStatus(unittest.TestCase):
    def setUp(self):
        self.rows = {r["interface"]: r for r in
                     parsers.parse_interfaces_status(fixtures.SHOW_INT_STATUS)}

    def test_all_rows_parsed(self):
        self.assertEqual(len(self.rows), 6)

    def test_description_with_spaces(self):
        self.assertEqual(self.rows["Gi1/0/7"]["description"], "printer bay")
        self.assertEqual(self.rows["Gi1/0/7"]["status"], "err-disabled")

    def test_empty_description(self):
        self.assertEqual(self.rows["Gi1/0/2"]["description"], "")
        self.assertEqual(self.rows["Gi1/0/2"]["status"], "notconnect")

    def test_trunk(self):
        self.assertEqual(self.rows["Gi1/0/24"]["vlan"], "trunk")


class TestCounters(unittest.TestCase):
    def test_counters(self):
        counters = parsers.parse_interface_counters(fixtures.SHOW_INTERFACES)
        self.assertEqual(counters["Gi1/0/3"]["input_errors"], 512)
        self.assertEqual(counters["Gi1/0/3"]["crc"], 498)
        self.assertEqual(counters["Gi1/0/3"]["late_collisions"], 17)
        self.assertEqual(counters["Gi1/0/24"]["input_errors"], 0)


class TestStp(unittest.TestCase):
    def test_summary(self):
        s = parsers.parse_stp_summary(fixtures.SHOW_STP_SUMMARY)
        self.assertEqual(s["mode"], "rapid-pvst")
        self.assertFalse(s["portfast_default"])
        self.assertFalse(s["bpduguard_default"])

    def test_detail(self):
        vlans = {v["vlan"]: v for v in parsers.parse_stp_detail(fixtures.SHOW_STP_DETAIL)}
        self.assertEqual(vlans["VLAN0010"]["topology_changes"], 187)
        self.assertEqual(vlans["VLAN0010"]["from_port"], "Gi1/0/3")
        self.assertEqual(vlans["VLAN0010"]["last_change_seconds"], 273)
        self.assertEqual(vlans["VLAN0020"]["topology_changes"], 12)


class TestCdp(unittest.TestCase):
    def test_neighbors(self):
        neighbors = {n["local_interface"]: n
                     for n in parsers.parse_cdp_neighbors(fixtures.SHOW_CDP_DETAIL)}
        self.assertTrue(neighbors["Gi1/0/24"]["is_switch"])
        self.assertEqual(neighbors["Gi1/0/24"]["device_id"], "sw-core-1.school.local")
        self.assertFalse(neighbors["Gi1/0/1"]["is_switch"])  # AP is Trans-Bridge, not Switch


class TestInterfaceConfigs(unittest.TestCase):
    def test_blocks_and_attrs(self):
        blocks = parsers.parse_interface_configs(fixtures.RUNNING_CONFIG)
        self.assertIn("Gi1/0/1", blocks)
        attrs = parsers.interface_config_attrs(blocks["Gi1/0/1"])
        self.assertEqual(attrs["mode"], "access")
        self.assertTrue(attrs["portfast"])
        self.assertTrue(attrs["bpduguard"])
        self.assertEqual(attrs["access_vlan"], 10)
        uplink = parsers.interface_config_attrs(blocks["Gi1/0/24"])
        self.assertEqual(uplink["mode"], "trunk")
        self.assertTrue(uplink["portfast"])

    def test_trunk_and_routed_attrs(self):
        attrs = parsers.interface_config_attrs([
            "switchport mode trunk",
            "switchport trunk native vlan 999",
            "switchport trunk allowed vlan 10,20,30",
            "switchport nonegotiate",
        ])
        self.assertEqual(attrs["native_vlan"], 999)
        self.assertTrue(attrs["allowed_vlans"])
        self.assertTrue(attrs["nonegotiate"])
        routed = parsers.interface_config_attrs(["no switchport", "ip address 10.0.0.1 255.255.255.0"])
        self.assertTrue(routed["routed"])

    def test_line_blocks(self):
        blocks = parsers.parse_line_configs(fixtures.RUNNING_CONFIG)
        self.assertIn("line vty 0 4", blocks)
        self.assertIn("transport input ssh", blocks["line vty 0 4"])


if __name__ == "__main__":
    unittest.main()

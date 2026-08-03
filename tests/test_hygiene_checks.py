import unittest

from netauditor import checks

STATUS = """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1                      connected    1            auto   auto 10/100/1000BaseTX
Gi1/0/2                      notconnect   1            auto   auto 10/100/1000BaseTX
Gi1/0/3   good-port          connected    20         a-full a-1000 10/100/1000BaseTX
Gi1/0/23  tidy-uplink        connected    trunk      a-full a-1000 10/100/1000BaseTX
Gi1/0/24  sloppy-uplink      connected    trunk      a-full a-1000 10/100/1000BaseTX
"""

SLOPPY_CONFIG = """\
interface GigabitEthernet1/0/3
 switchport access vlan 20
 switchport mode access
 spanning-tree portfast
 spanning-tree bpduguard enable
!
interface GigabitEthernet1/0/23
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20
 switchport nonegotiate
!
interface GigabitEthernet1/0/24
 switchport mode trunk
!
line con 0
 exec-timeout 0 0
line vty 0 4
 transport input ssh
end
"""

CLEAN_CONFIG = """\
ip ssh version 2
ntp server 10.0.0.1
logging host 10.0.0.9
!
interface GigabitEthernet1/0/3
 switchport access vlan 20
 switchport mode access
 spanning-tree portfast
 spanning-tree bpduguard enable
!
interface GigabitEthernet1/0/23
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20
 switchport nonegotiate
!
line con 0
 exec-timeout 15 0
line vty 0 4
 access-class 10 in
 transport input ssh
end
"""


def report_for(config, status=STATUS):
    return checks.build_host_report({
        "host": "10.0.0.1", "name": "sw1", "error": None,
        "outputs": {"interfaces_status": status, "running_config": config},
    })


class TestSloppyConfig(unittest.TestCase):
    def setUp(self):
        self.report = report_for(SLOPPY_CONFIG)
        self.codes = {(f["code"], f["interface"]) for f in self.report["findings"]}
        self.by_code = {}
        for f in self.report["findings"]:
            self.by_code.setdefault(f["code"], []).append(f)

    def test_dtp_on_unconfigured_connected_port(self):
        self.assertIn(("DTP_ENABLED", "Gi1/0/1"), self.codes)
        # explicitly moded ports are fine
        self.assertNotIn(("DTP_ENABLED", "Gi1/0/3"), self.codes)
        self.assertNotIn(("DTP_ENABLED", "Gi1/0/23"), self.codes)

    def test_native_vlan_and_pruning_on_sloppy_trunk_only(self):
        self.assertIn(("NATIVE_VLAN_1", "Gi1/0/24"), self.codes)
        self.assertIn(("TRUNK_ALLOWS_ALL", "Gi1/0/24"), self.codes)
        self.assertNotIn(("NATIVE_VLAN_1", "Gi1/0/23"), self.codes)
        self.assertNotIn(("TRUNK_ALLOWS_ALL", "Gi1/0/23"), self.codes)

    def test_vlan1_aggregates(self):
        in_use = self.by_code["VLAN1_IN_USE"]
        self.assertEqual(len(in_use), 1)
        self.assertIn("Gi1/0/1", in_use[0]["message"])
        unused = self.by_code["UNUSED_PORT_OPEN"]
        self.assertEqual(len(unused), 1)
        self.assertIn("Gi1/0/2", unused[0]["message"])

    def test_management_hygiene(self):
        flat = {f["code"] for f in self.report["findings"]}
        self.assertIn("NO_EXEC_TIMEOUT", flat)
        self.assertIn("line con 0", self.by_code["NO_EXEC_TIMEOUT"][0]["message"])
        self.assertIn("VTY_NO_ACL", flat)
        self.assertIn("SSH_V1", flat)
        self.assertIn("NO_NTP", flat)
        self.assertIn("NO_LOGGING_HOST", flat)


class TestCleanConfig(unittest.TestCase):
    def test_clean_config_has_no_hygiene_findings(self):
        clean_status = "\n".join(l for l in STATUS.splitlines() if "1/0/24" not in l
                                 and not l.startswith(("Gi1/0/1 ", "Gi1/0/2 ")))
        report = report_for(CLEAN_CONFIG, clean_status)
        codes = {f["code"] for f in report["findings"]}
        for code in ("DTP_ENABLED", "NATIVE_VLAN_1", "TRUNK_ALLOWS_ALL", "VLAN1_IN_USE",
                     "UNUSED_PORT_OPEN", "NO_EXEC_TIMEOUT", "VTY_NO_ACL", "SSH_V1",
                     "NO_NTP", "NO_LOGGING_HOST"):
            self.assertNotIn(code, codes)


class TestErrorCounterLinkState(unittest.TestCase):
    STATUS = ("Port      Name               Status       Vlan       Duplex  Speed Type\n"
              "Gi1/0/10  live-port          connected    20         a-full  a-100 10/100/1000BaseTX\n"
              "Gi1/0/11  dead-port          notconnect   20           auto   auto 10/100/1000BaseTX\n")
    INTERFACES = """\
GigabitEthernet1/0/10 is up, line protocol is up (connected)
     2718 input errors, 2536 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions, 0 interface resets
     0 babbles, 0 late collision, 0 deferred
GigabitEthernet1/0/11 is down, line protocol is down (notconnect)
     900 input errors, 880 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions, 0 interface resets
     0 babbles, 0 late collision, 0 deferred
"""

    def setUp(self):
        report = checks.build_host_report({
            "host": "10.0.0.1", "name": "sw1", "error": None,
            "outputs": {"interfaces_status": self.STATUS,
                        "interfaces": self.INTERFACES,
                        "running_config": "interface GigabitEthernet1/0/10\n"
                                          " switchport mode access\n"
                                          " spanning-tree portfast\n"
                                          " spanning-tree bpduguard enable\n"
                                          "interface GigabitEthernet1/0/11\n"
                                          " switchport mode access\nend\n"}})
        self.by_code = {}
        for f in report["findings"]:
            self.by_code.setdefault(f["code"], []).append(f)

    def test_connected_port_is_a_warning(self):
        live = self.by_code["INTERFACE_ERRORS"]
        self.assertEqual(len(live), 1)
        self.assertEqual(live[0]["interface"], "Gi1/0/10")
        self.assertEqual(live[0]["severity"], "warning")

    def test_down_port_is_demoted_to_info(self):
        historic = self.by_code["INTERFACE_ERRORS_HISTORIC"]
        self.assertEqual(len(historic), 1)
        self.assertEqual(historic[0]["interface"], "Gi1/0/11")
        self.assertEqual(historic[0]["severity"], "info")
        self.assertIn("historical counters", historic[0]["message"])

    def test_down_port_not_flagged_as_live_error(self):
        self.assertNotIn("Gi1/0/11",
                         [f["interface"] for f in self.by_code["INTERFACE_ERRORS"]])

    def test_100m_hint_on_gigabit_port(self):
        self.assertIn("negotiated only 100M",
                      self.by_code["INTERFACE_ERRORS"][0]["message"])

    def test_counter_age_caveat_present(self):
        self.assertIn("cumulative since boot",
                      self.by_code["INTERFACE_ERRORS"][0]["message"])


class TestRoutedPortExempt(unittest.TestCase):
    def test_routed_port_not_flagged_for_dtp(self):
        status = ("Port      Name               Status       Vlan       Duplex  Speed Type\n"
                  "Gi1/0/48  l3-uplink          connected    routed     a-full a-1000 10/100/1000BaseTX\n")
        config = ("interface GigabitEthernet1/0/48\n"
                  " no switchport\n"
                  " ip address 10.0.12.1 255.255.255.252\n"
                  "end\n")
        report = report_for(config, status)
        codes = {f["code"] for f in report["findings"]}
        self.assertNotIn("DTP_ENABLED", codes)
        self.assertNotIn("NATIVE_VLAN_1", codes)


if __name__ == "__main__":
    unittest.main()

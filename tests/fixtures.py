"""Realistic Cisco IOS output samples shared by the test modules."""

SHOW_VERSION = """\
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E7, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2022 by Cisco Systems, Inc.

sw-access-1 uptime is 41 weeks, 3 days, 2 hours, 11 minutes
System returned to ROM by power-on

cisco WS-C2960X-24PS-L (APM86XXX) processor (revision A0) with 524288K bytes of memory.

Model number                    : WS-C2960X-24PS-L
System serial number            : FOC1234X0AB
"""

SHOW_INT_STATUS = """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   AP-Library         connected    10         a-full a-1000 10/100/1000BaseTX
Gi1/0/2                      notconnect   20           auto   auto 10/100/1000BaseTX
Gi1/0/3   Staff PC           connected    20         a-half  a-100 10/100/1000BaseTX
Gi1/0/7   printer bay        err-disabled 30           auto   auto 10/100/1000BaseTX
Gi1/0/24  UPLINK-CORE        connected    trunk      a-full a-1000 10/100/1000BaseTX
Po1       AGG-UPLINK         connected    trunk      a-full a-1000
"""

SHOW_INTERFACES = """\
GigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is 001a.2b3c.4d01 (bia 001a.2b3c.4d01)
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions, 1 interface resets
     0 babbles, 0 late collision, 0 deferred
GigabitEthernet1/0/3 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is 001a.2b3c.4d03 (bia 001a.2b3c.4d03)
  Half-duplex, 100Mb/s, media type is 10/100/1000BaseTX
     512 input errors, 498 CRC, 0 frame, 0 overrun, 0 ignored
     3 output errors, 120 collisions, 2 interface resets
     0 babbles, 17 late collision, 0 deferred
GigabitEthernet1/0/24 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is 001a.2b3c.4d18 (bia 001a.2b3c.4d18)
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions, 0 interface resets
     0 babbles, 0 late collision, 0 deferred
"""

SHOW_STP_SUMMARY = """\
Switch is in rapid-pvst mode
Root bridge for: none
Extended system ID           is enabled
Portfast Default             is disabled
PortFast BPDU Guard Default  is disabled
Portfast BPDU Filter Default is disabled
Loopguard Default            is disabled
EtherChannel misconfig guard is enabled
UplinkFast                   is disabled
BackboneFast                 is disabled

Name                   Blocking Listening Learning Forwarding STP Active
---------------------- -------- --------- -------- ---------- ----------
VLAN0010                     0         0        0          3          3
"""

SHOW_STP_DETAIL = """\
 VLAN0010 is executing the rstp compatible Spanning Tree protocol
  Bridge Identifier has priority 32768, sysid 10, address 001a.2b3c.4d00
  Configured hello time 2, max age 20, forward delay 15, transmit hold-count 6
  Current root has priority 4106, address 0011.2233.4455
  Root port is 24 (GigabitEthernet1/0/24), cost of root path is 4
  Topology change flag not set, detected flag not set
  Number of topology changes 187 last change occurred 00:04:33 ago
          from GigabitEthernet1/0/3
  Times:  hold 1, topology change 35, notification 2

 VLAN0020 is executing the rstp compatible Spanning Tree protocol
  Bridge Identifier has priority 32788, sysid 20, address 001a.2b3c.4d00
  Number of topology changes 12 last change occurred 5w4d ago
          from GigabitEthernet1/0/24
"""

SHOW_CDP_DETAIL = """\
-------------------------
Device ID: sw-core-1.school.local
Entry address(es):
  IP address: 10.10.0.11
Platform: cisco WS-C3850-24T,  Capabilities: Router Switch IGMP
Interface: GigabitEthernet1/0/24,  Port ID (outgoing port): GigabitEthernet1/0/1
Holdtime : 155 sec

-------------------------
Device ID: AP-LIB-01
Entry address(es):
  IP address: 10.10.30.5
Platform: cisco AIR-AP2802I-Z-K9,  Capabilities: Trans-Bridge
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet0
Holdtime : 121 sec
"""

RUNNING_CONFIG = """\
Building configuration...

Current configuration : 4096 bytes
!
version 15.2
service password-encryption
!
hostname sw-access-1
!
spanning-tree mode rapid-pvst
spanning-tree extend system-id
!
vlan 10
 name STUDENTS
vlan 20
 name STAFF
vlan 30
 name PRINTERS
!
interface GigabitEthernet1/0/1
 description AP-Library
 switchport access vlan 10
 switchport mode access
 spanning-tree portfast
 spanning-tree bpduguard enable
!
interface GigabitEthernet1/0/3
 description Staff PC
 switchport access vlan 20
 switchport mode access
!
interface GigabitEthernet1/0/24
 description UPLINK-CORE
 switchport mode trunk
 spanning-tree portfast
!
line vty 0 4
 transport input ssh
!
ntp server 10.10.0.1
end
"""

"""Copy-paste IOS remediation snippets per finding code.

Suggestions only - netauditor never writes configuration. Interface-scoped
snippets are rendered against the finding's own interface.
"""
from __future__ import annotations

_SAVE = "end\nwrite memory"


def _iface(body: str) -> "callable":
    def build(interface: str) -> str:
        port = interface or "<interface>"
        lines = "\n".join(f" {l}" for l in body.strip().splitlines())
        return f"configure terminal\ninterface {port}\n{lines}\n{_SAVE}"
    return build


def _global(body: str) -> "callable":
    def build(_interface: str) -> str:
        return f"configure terminal\n{body.strip()}\n{_SAVE}"
    return build


def _plain(body: str) -> "callable":
    def build(_interface: str) -> str:
        return body.strip()
    return build


SNIPPETS = {
    "UPLINK_PORTFAST": _iface("no spanning-tree portfast\nno spanning-tree portfast trunk"),
    "UPLINK_BPDUGUARD": _iface("no spanning-tree bpduguard enable\n"
                               "spanning-tree bpduguard disable"),
    "ACCESS_NO_PORTFAST": _iface("spanning-tree portfast"),
    "ACCESS_NO_BPDUGUARD": _iface("spanning-tree bpduguard enable"),
    "ERRDISABLED": _iface("shutdown\nno shutdown"),
    "DTP_ENABLED": _iface("switchport mode access\nswitchport nonegotiate"),
    "NATIVE_VLAN_1": _iface("switchport trunk native vlan <unused-vlan>"),
    "TRUNK_ALLOWS_ALL": _iface("switchport trunk allowed vlan <vlan-list>"),
    "HALF_DUPLEX": _iface("duplex auto\nspeed auto"),
    "UNUSED_PORT_OPEN": _iface("switchport access vlan <parking-vlan>\nshutdown"),

    "UNSAVED_CHANGES": _plain("write memory"),
    "NO_NTP": _global("ntp server <ntp-ip>"),
    "NO_LOGGING_HOST": _global("logging host <syslog-ip>"),
    "SSH_V1": _global("ip ssh version 2"),
    "NO_EXEC_TIMEOUT": _global("line con 0\n exec-timeout 15 0\nline vty 0 15\n"
                               " exec-timeout 15 0"),
    "VTY_NO_ACL": _global("ip access-list standard MGMT-ACCESS\n"
                          " permit <mgmt-subnet> <wildcard>\n"
                          "line vty 0 15\n access-class MGMT-ACCESS in"),
    "GLOBAL_BPDUFILTER": _global("no spanning-tree portfast bpdufilter default"),
    "EDGE_UNPROTECTED": _global("spanning-tree portfast bpduguard default"),
    "LEGACY_STP": _global("spanning-tree mode rapid-pvst"),
    "VTP_SERVER": _global("vtp mode transparent"),
    "TELNET_ENABLED": _global("line vty 0 15\n transport input ssh"),
    "HTTP_SERVER": _global("no ip http server\nip http secure-server"),
    "SNMP_DEFAULT_COMMUNITY": _global("no snmp-server community <old-community>\n"
                                      "snmp-server community <strong-string> RO <acl>"),
    "SNMP_RW": _global("no snmp-server community <rw-community> RW"),
    "NO_PASSWORD_ENCRYPTION": _global("service password-encryption"),
    "ENABLE_PASSWORD": _global("no enable password\nenable secret <strong-secret>"),
    "WEAK_USER_SECRET": _global("username <user> privilege <n> secret <strong-secret>"),
    "NO_DETERMINISTIC_ROOT": _global("spanning-tree vlan <vlan-list> root primary"),
    "STP_MODE_MISMATCH": _global("spanning-tree mode rapid-pvst"),
    "VLAN_INCONSISTENT": _global("vlan <id>\n name <name>"),
    "VLAN1_IN_USE": _iface("switchport access vlan <user-vlan>"),
    "STP_CHURN": _plain("! find the flapping port, then stabilise it:\n"
                        "show spanning-tree detail | include ieee|occurred\n"
                        "! on the offending edge port:\n"
                        "configure terminal\ninterface <port>\n spanning-tree portfast\n"
                        " spanning-tree bpduguard enable\n" + _SAVE),
    "MAC_FLAPPING": _plain("! trace the duplicated MAC, then remove the loop:\n"
                           "show mac address-table address <mac>\n"
                           "show interfaces status | include <port>"),
}

# Codes with no useful mechanical fix (investigate instead).
NO_SNIPPET = {"UNREACHABLE", "NO_CONFIG", "STP_CHURN_HISTORY", "STP_RECENT_CHANGE",
              "INTERFACE_ERRORS", "LATE_COLLISIONS"}


def snippet_for(code: str, interface: str = "") -> str:
    """Return an IOS snippet for a finding code, or '' when there isn't a sane one."""
    builder = SNIPPETS.get(code)
    if builder is None or code in NO_SNIPPET:
        return ""
    return builder(interface)

"""Regex parsers for Cisco IOS/IOS-XE show-command output.

Deliberately dependency-free (no TextFSM/ntc-templates) so the analyzer can run
anywhere; parsers are best-effort and return partial data on unexpected output.
"""
from __future__ import annotations

import re

# Long interface names first: matching is startswith-based, so more specific first.
_LONG_TO_SHORT = [
    ("TwentyFiveGigE", "Twe"),
    ("HundredGigE", "Hu"),
    ("FortyGigabitEthernet", "Fo"),
    ("TenGigabitEthernet", "Te"),
    ("TwoGigabitEthernet", "Tw"),
    ("AppGigabitEthernet", "Ap"),
    ("GigabitEthernet", "Gi"),
    ("FastEthernet", "Fa"),
    ("Ethernet", "Et"),
    ("Port-channel", "Po"),
]


def short_ifname(name: str) -> str:
    """Normalize interface names to the short form used by 'show interfaces status'."""
    name = name.strip()
    lowered = name.lower()
    for long, short in _LONG_TO_SHORT:
        if lowered.startswith(long.lower()):
            return short + name[len(long):]
    return name


def parse_age_seconds(text: str):
    """Parse IOS age strings: '03:12:33', '2d05h', '1w2d', '4y21w'. Returns seconds or None."""
    text = (text or "").strip().rstrip(",")
    m = re.fullmatch(r"(\d+):(\d{2}):(\d{2})", text)
    if m:
        h, mi, s = (int(g) for g in m.groups())
        return h * 3600 + mi * 60 + s
    unit_seconds = {"y": 31536000, "w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    total = 0
    matched = False
    for value, unit in re.findall(r"(\d+)([ywdhms])", text):
        total += int(value) * unit_seconds[unit]
        matched = True
    return total if matched else None


def parse_version(text: str) -> dict:
    facts = {}
    m = re.search(r"Version\s+([^,\s\]]+)", text)
    if m:
        facts["version"] = m.group(1)
    m = re.search(r"^(\S+)\s+uptime is\s+(.+)$", text, re.MULTILINE)
    if m:
        facts["hostname"] = m.group(1)
        facts["uptime"] = m.group(2).strip()
    m = re.search(r"[Mm]odel [Nn]umber\s*:\s*(\S+)", text)
    if not m:
        m = re.search(r"^cisco\s+(\S+)\s+\(", text, re.MULTILINE)
    if m:
        facts["model"] = m.group(1)
    m = re.search(r"[Ss]ystem [Ss]erial [Nn]umber\s*:\s*(\S+)", text)
    if m:
        facts["serial"] = m.group(1)
    return facts


_STATUS_RE = re.compile(
    r"^(?P<port>\S+)\s+(?P<name>.*?)\s*\s"
    r"(?P<status>connected|notconnect|err-disabled|disabled|inactive|suspended|monitoring)\s+"
    r"(?P<vlan>\S+)\s+(?P<duplex>\S+)\s+(?P<speed>\S+)(?:\s+(?P<type>.*))?$"
)


def parse_interfaces_status(text: str) -> "list[dict]":
    """Parse 'show interfaces status' into a list of interface dicts."""
    interfaces = []
    for line in (text or "").splitlines():
        if not line.strip() or line.lstrip().startswith("Port "):
            continue
        m = _STATUS_RE.match(line.rstrip())
        if not m:
            continue
        interfaces.append(
            {
                "interface": short_ifname(m.group("port")),
                "description": m.group("name").strip(),
                "status": m.group("status"),
                "vlan": m.group("vlan"),
                "duplex": m.group("duplex"),
                "speed": m.group("speed"),
                "media": (m.group("type") or "").strip(),
            }
        )
    return interfaces


_IF_HEADER_RE = re.compile(r"^(\S+) is (.+?), line protocol is (\S+)")


def parse_interface_counters(text: str) -> "dict[str, dict]":
    """Parse 'show interfaces' for error counters per interface (short-name keyed)."""
    counters = {}
    current = None
    for line in (text or "").splitlines():
        m = _IF_HEADER_RE.match(line)
        if m:
            current = {"input_errors": 0, "crc": 0, "output_errors": 0,
                       "collisions": 0, "late_collisions": 0}
            counters[short_ifname(m.group(1))] = current
            continue
        if current is None:
            continue
        m = re.search(r"(\d+) input errors, (\d+) CRC", line)
        if m:
            current["input_errors"] = int(m.group(1))
            current["crc"] = int(m.group(2))
            continue
        m = re.search(r"(\d+) output errors, (\d+) collisions", line)
        if m:
            current["output_errors"] = int(m.group(1))
            current["collisions"] = int(m.group(2))
            continue
        m = re.search(r"(\d+) late collision", line)
        if m:
            current["late_collisions"] = int(m.group(1))
    return counters


def parse_stp_summary(text: str) -> dict:
    summary = {"mode": None, "portfast_default": False, "bpduguard_default": False,
               "bpdufilter_default": False, "loopguard_default": False, "root_for": []}
    m = re.search(r"Switch is in (\S+) mode", text or "")
    if m:
        summary["mode"] = m.group(1)
    m = re.search(r"Root bridge for:\s*(.+)", text or "")
    if m:
        summary["root_for"] = [v.strip() for v in m.group(1).split(",") if v.strip()]

    def flag(pattern):
        fm = re.search(pattern, text or "", re.IGNORECASE)
        return bool(fm) and fm.group(1).lower() == "enabled"

    # Wording differs across IOS versions ('Portfast Default', 'PortFast Edge Default', ...)
    summary["portfast_default"] = flag(r"Port[Ff]ast(?:\s+Edge)?\s+Default\s+is\s+(\S+)")
    summary["bpduguard_default"] = flag(r"BPDU\s*Guard\s+Default\s+is\s+(\S+)")
    summary["bpdufilter_default"] = flag(r"BPDU\s*Filter\s+Default\s+is\s+(\S+)")
    summary["loopguard_default"] = flag(r"Loopguard\s+Default\s+is\s+(\S+)")
    return summary


_STP_VLAN_RE = re.compile(r"^\s*(VLAN\d+)\s+is executing", re.MULTILINE)
_STP_TC_RE = re.compile(
    r"Number of topology changes\s+(\d+)\s+last change occurred\s+(\S+?)(?:\s+ago)?\s*$"
    r"(?:\n\s*from\s+(\S+))?",
    re.MULTILINE,
)


def parse_stp_detail(text: str) -> "list[dict]":
    """Per-VLAN topology-change stats from 'show spanning-tree detail'."""
    vlans = []
    sections = _STP_VLAN_RE.split(text or "")
    # split() yields [pre, vlan1, body1, vlan2, body2, ...]
    for i in range(1, len(sections) - 1, 2):
        vlan, body = sections[i], sections[i + 1]
        m = _STP_TC_RE.search(body)
        if not m:
            continue
        last_change = m.group(2).rstrip(",")
        vlans.append(
            {
                "vlan": vlan,
                "topology_changes": int(m.group(1)),
                "last_change": last_change,
                "last_change_seconds": parse_age_seconds(last_change),
                "from_port": short_ifname(m.group(3)) if m.group(3) else None,
            }
        )
    return vlans


def parse_cdp_neighbors(text: str) -> "list[dict]":
    """Parse 'show cdp neighbors detail' into neighbor entries."""
    neighbors = []
    for block in re.split(r"^-{3,}\s*$", text or "", flags=re.MULTILINE):
        m = re.search(r"Device ID:\s*(\S+)", block)
        if not m:
            continue
        device_id = m.group(1)
        m = re.search(r"Interface:\s*([^,\s]+),\s*Port ID \(outgoing port\):\s*(\S+)", block)
        local_if = short_ifname(m.group(1)) if m else None
        remote_if = short_ifname(m.group(2)) if m else None
        caps_m = re.search(r"Capabilities:\s*(.+)", block)
        caps = caps_m.group(1).strip() if caps_m else ""
        platform_m = re.search(r"Platform:\s*([^,\n]+)", block)
        neighbors.append(
            {
                "device_id": device_id,
                "local_interface": local_if,
                "remote_interface": remote_if,
                "capabilities": caps,
                "platform": platform_m.group(1).strip() if platform_m else "",
                "is_switch": "Switch" in caps,
            }
        )
    return neighbors


def parse_interface_configs(config: str) -> "dict[str, list]":
    """Split running-config into per-interface config lines (short-name keyed)."""
    blocks = {}
    current = None
    for line in (config or "").splitlines():
        if line.startswith("interface "):
            current = short_ifname(line.split(None, 1)[1])
            blocks[current] = []
        elif current is not None:
            if line.startswith(" "):
                blocks[current].append(line.strip())
            elif line.strip() != "!":
                current = None
    return blocks


def interface_config_attrs(lines: "list[str]") -> dict:
    """Derive STP/switchport attributes from one interface's config lines."""
    attrs = {"mode": None, "portfast": None, "portfast_trunk": False,
             "bpduguard": None, "shutdown": False, "description": "",
             "access_vlan": None, "native_vlan": None, "allowed_vlans": False,
             "nonegotiate": False, "routed": False}
    for line in lines:
        if line.startswith("description "):
            attrs["description"] = line[len("description "):]
        elif line == "shutdown":
            attrs["shutdown"] = True
        elif line == "switchport mode trunk":
            attrs["mode"] = "trunk"
        elif line == "switchport mode access":
            attrs["mode"] = "access"
        elif line == "switchport nonegotiate":
            attrs["nonegotiate"] = True
        elif line == "no switchport":
            attrs["routed"] = True
        elif line.startswith("switchport access vlan "):
            try:
                attrs["access_vlan"] = int(line.rsplit(None, 1)[1])
            except ValueError:
                pass
        elif line.startswith("switchport trunk native vlan "):
            try:
                attrs["native_vlan"] = int(line.rsplit(None, 1)[1])
            except ValueError:
                pass
        elif line.startswith("switchport trunk allowed vlan"):
            attrs["allowed_vlans"] = True
        elif "spanning-tree portfast" in line:
            if line.endswith("disable"):
                attrs["portfast"] = False
            else:
                attrs["portfast"] = True
                if line.endswith("trunk"):
                    attrs["portfast_trunk"] = True
        elif "spanning-tree bpduguard" in line:
            attrs["bpduguard"] = line.endswith("enable")
    return attrs


def parse_vtp_status(text: str) -> dict:
    """Extract VTP operating mode and domain from 'show vtp status'."""
    mode = re.search(r"VTP Operating Mode\s*:\s*(.+)", text or "")
    domain = re.search(r"VTP Domain Name\s*:\s*(\S*)", text or "")
    return {
        "mode": mode.group(1).strip() if mode else None,
        "domain": domain.group(1).strip() if domain else "",
    }


_MACFLAP_RE = re.compile(
    r"Host (\S+) in vlan (\d+) is flapping between port (\S+) and port (\S+)")


def parse_mac_flaps(text: str) -> "list[dict]":
    """Extract %SW_MATM-4-MACFLAP_NOTIF events from 'show logging'."""
    flaps = []
    for m in _MACFLAP_RE.finditer(text or ""):
        flaps.append({
            "mac": m.group(1),
            "vlan": int(m.group(2)),
            "port_a": short_ifname(m.group(3)),
            "port_b": short_ifname(m.group(4)),
        })
    return flaps


def parse_line_configs(config: str) -> "dict[str, list]":
    """Split running-config into per-'line ...' blocks (console/VTY settings)."""
    blocks = {}
    current = None
    for line in (config or "").splitlines():
        if line.startswith("line "):
            current = line.strip()
            blocks[current] = []
        elif current is not None:
            if line.startswith(" "):
                blocks[current].append(line.strip())
            elif line.strip() != "!":
                current = None
    return blocks

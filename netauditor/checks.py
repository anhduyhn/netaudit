"""Health checks: turn raw command output into a structured per-host report with findings."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import parsers

SEVERITIES = ("critical", "warning", "info")

# Tunable thresholds
STP_CHURN_COUNT = 50            # topology changes considered "a lot"
STP_RECENT_SECONDS = 3600       # a change within the last hour counts as recent
ERROR_COUNTER_THRESHOLD = 100   # input errors / CRC before we flag the port


@dataclass
class Finding:
    code: str
    severity: str
    message: str
    interface: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {"code": self.code, "severity": self.severity,
             "interface": self.interface, "message": self.message}
        if self.detail:
            d["detail"] = self.detail
        return d


def build_host_report(result: dict) -> dict:
    """Parse one host's collected output and run all checks."""
    name = result.get("name") or result["host"]
    report = {
        "host": result["host"],
        "name": name,
        "group": result.get("group", ""),
        "error": result.get("error"),
        "command_errors": result.get("command_errors", {}),
        "facts": {},
        "stp": {},
        "interfaces": [],
        "findings": [],
        "config": "",
    }
    if result.get("error"):
        report["findings"] = [
            Finding("UNREACHABLE", "critical",
                    f"Could not audit {name}: {result['error']}").to_dict()
        ]
        return report

    out = result.get("outputs", {})
    report["facts"] = parsers.parse_version(out.get("version", ""))
    config = out.get("running_config", "")
    report["config"] = config

    stp_summary = parsers.parse_stp_summary(out.get("stp_summary", ""))
    stp_vlans = parsers.parse_stp_detail(out.get("stp_detail", ""))
    report["stp"] = dict(stp_summary, vlans=stp_vlans)

    status = parsers.parse_interfaces_status(out.get("interfaces_status", ""))
    counters = parsers.parse_interface_counters(out.get("interfaces", ""))
    cdp = parsers.parse_cdp_neighbors(out.get("cdp_neighbors", ""))
    iface_configs = parsers.parse_interface_configs(config)

    cdp_switches = {}
    for n in cdp:
        if n["is_switch"] and n["local_interface"]:
            cdp_switches.setdefault(n["local_interface"], []).append(n["device_id"])

    findings = []
    interfaces = []
    for entry in status:
        iface = _merge_interface(entry, counters, iface_configs, cdp_switches, stp_summary)
        interfaces.append(iface)
        findings.extend(_check_interface(iface))

    findings.extend(_check_global_stp(stp_summary))
    findings.extend(_check_stp_churn(stp_vlans))
    if not config:
        findings.append(Finding("NO_CONFIG", "warning",
                                "Running config could not be collected; drift analysis will skip this host."))

    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order.get(f.severity, 99), f.code, f.interface))
    report["interfaces"] = interfaces
    report["findings"] = [f.to_dict() for f in findings]
    return report


def _merge_interface(entry, counters, iface_configs, cdp_switches, stp_summary) -> dict:
    name = entry["interface"]
    cfg_lines = iface_configs.get(name, [])
    attrs = parsers.interface_config_attrs(cfg_lines)
    ctr = counters.get(name, {})

    is_trunk = entry["vlan"] == "trunk" or attrs["mode"] == "trunk"
    neighbors = cdp_switches.get(name, [])
    uplink_reasons = []
    if is_trunk:
        uplink_reasons.append("trunk")
    if neighbors:
        uplink_reasons.append("cdp:" + ",".join(neighbors))
    is_uplink = bool(uplink_reasons)

    # Effective portfast: explicit interface config wins; otherwise the global
    # 'portfast default' applies to non-trunk ports only.
    if attrs["portfast"] is not None:
        portfast = attrs["portfast"]
        portfast_source = "interface"
    elif stp_summary.get("portfast_default") and not is_trunk:
        portfast = True
        portfast_source = "global-default"
    else:
        portfast = False
        portfast_source = ""

    if attrs["bpduguard"] is not None:
        bpduguard = attrs["bpduguard"]
    else:
        bpduguard = bool(stp_summary.get("bpduguard_default")) and portfast

    return {
        "interface": name,
        "description": entry["description"] or attrs["description"],
        "status": entry["status"],
        "vlan": entry["vlan"],
        "duplex": entry["duplex"],
        "speed": entry["speed"],
        "is_trunk": is_trunk,
        "is_uplink": is_uplink,
        "uplink_reason": ";".join(uplink_reasons),
        "cdp_neighbors": neighbors,
        "portfast": portfast,
        "portfast_source": portfast_source,
        "bpduguard": bpduguard,
        "input_errors": ctr.get("input_errors", 0),
        "crc": ctr.get("crc", 0),
        "late_collisions": ctr.get("late_collisions", 0),
        "config": cfg_lines,
    }


def _check_interface(iface: dict) -> "list[Finding]":
    findings = []
    name = iface["interface"]

    if iface["status"] == "err-disabled":
        findings.append(Finding(
            "ERRDISABLED", "critical",
            f"{name} is err-disabled - a protection feature (BPDU guard, port-security, ...) shut it down; "
            "investigate the cause before re-enabling.", name))

    if iface["is_uplink"] and iface["portfast"]:
        who = f" (CDP neighbor: {', '.join(iface['cdp_neighbors'])})" if iface["cdp_neighbors"] else ""
        findings.append(Finding(
            "UPLINK_PORTFAST", "critical",
            f"PortFast is active on uplink {name}{who} - the port skips listening/learning, "
            "which can cause bridging loops and STP instability. Remove portfast from uplinks.",
            name, {"source": iface["portfast_source"]}))

    if iface["is_uplink"] and iface["bpduguard"]:
        findings.append(Finding(
            "UPLINK_BPDUGUARD", "critical",
            f"BPDU guard is enabled on uplink {name} - the first BPDU from the neighbor switch "
            "will err-disable this uplink and cut off everything behind it.", name))

    if not iface["is_uplink"] and iface["status"] == "connected":
        if not iface["portfast"]:
            findings.append(Finding(
                "ACCESS_NO_PORTFAST", "warning",
                f"Access port {name} has no PortFast - hosts wait ~30s for STP at link-up "
                "and each flap sends topology change notifications.", name))
        if not iface["bpduguard"]:
            findings.append(Finding(
                "ACCESS_NO_BPDUGUARD", "warning",
                f"Access port {name} has no BPDU guard - a rogue/mis-cabled switch plugged in "
                "here could trigger an STP reconvergence or loop.", name))

    if iface["duplex"].lstrip("a-").lower() == "half":
        findings.append(Finding(
            "HALF_DUPLEX", "warning",
            f"{name} is running half-duplex ({iface['duplex']}) - likely a duplex mismatch or legacy device.",
            name))

    if iface["late_collisions"] > 0:
        findings.append(Finding(
            "LATE_COLLISIONS", "warning",
            f"{name} has {iface['late_collisions']} late collisions - classic sign of a duplex mismatch.",
            name))

    if iface["input_errors"] >= ERROR_COUNTER_THRESHOLD or iface["crc"] >= ERROR_COUNTER_THRESHOLD:
        findings.append(Finding(
            "INTERFACE_ERRORS", "warning",
            f"{name} shows {iface['input_errors']} input errors / {iface['crc']} CRC errors - "
            "check cabling, SFPs and duplex.", name))

    return findings


def _check_global_stp(summary: dict) -> "list[Finding]":
    findings = []
    if summary.get("bpdufilter_default"):
        findings.append(Finding(
            "GLOBAL_BPDUFILTER", "warning",
            "Global 'BPDU Filter Default' is enabled - edge ports silently drop BPDUs, which can "
            "hide a loop instead of preventing it. Prefer BPDU guard."))
    if summary.get("portfast_default") and not summary.get("bpduguard_default"):
        findings.append(Finding(
            "EDGE_UNPROTECTED", "warning",
            "PortFast is enabled by default but BPDU guard default is off - edge ports come up fast "
            "but nothing stops a switch plugged into them."))
    mode = summary.get("mode")
    if mode == "pvst":
        findings.append(Finding(
            "LEGACY_STP", "info",
            "Switch runs legacy PVST+ - consider rapid-pvst for sub-second convergence."))
    return findings


def _check_stp_churn(vlans: "list[dict]") -> "list[Finding]":
    findings = []
    for v in vlans:
        count = v["topology_changes"]
        last = v["last_change_seconds"]
        recent = last is not None and last < STP_RECENT_SECONDS
        src = f" (last from {v['from_port']})" if v.get("from_port") else ""
        if count >= STP_CHURN_COUNT and recent:
            findings.append(Finding(
                "STP_CHURN", "critical",
                f"{v['vlan']}: {count} topology changes, last one {v['last_change']} ago{src} - "
                "active STP churn; every change flushes MAC tables and can cause network-wide flooding.",
                v.get("from_port") or "", v))
        elif count >= STP_CHURN_COUNT:
            findings.append(Finding(
                "STP_CHURN_HISTORY", "warning",
                f"{v['vlan']}: {count} accumulated topology changes{src} - a flapping edge port "
                "without PortFast is the usual culprit.", v.get("from_port") or "", v))
        elif recent:
            findings.append(Finding(
                "STP_RECENT_CHANGE", "warning",
                f"{v['vlan']}: topology changed {v['last_change']} ago{src}.",
                v.get("from_port") or "", v))
    return findings


def count_findings(reports: "list[dict]") -> "dict[str, int]":
    counts = {s: 0 for s in SEVERITIES}
    for r in reports:
        for f in r.get("findings", []):
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts

"""Config analyzer: cross-switch drift detection plus optional named test suites.

Input is either an audit.json produced by `netauditor audit` or a directory of
*.cfg / *.txt config exports (one file per switch, filename = switch name).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Volatile / host-identity lines that must not count as drift.
_VOLATILE_PREFIXES = (
    "Building configuration",
    "Current configuration",
    "Last configuration change",
    "NVRAM config last updated",
    "ntp clock-period",
    "Load for ",
    "Time source ",
)
# Top-level blocks excluded from drift comparison (host-specific by nature).
_EXCLUDED_HEADER_PREFIXES = (
    "hostname",
    "interface ",
    "crypto pki ",
    "quit",
    "license udi",
    "snmp-server chassis-id",
    "snmp-server location",
    "ip default-gateway",
    "switch ",          # stack provisioning
    "system mac",
    "end",
)


def load_configs(source) -> "dict[str, str]":
    """Return {switch_name: config_text} from an audit.json or a directory of config files."""
    source = Path(source)
    configs = {}
    if source.is_dir():
        audit_json = source / "audit.json"
        if audit_json.exists():
            return load_configs(audit_json)
        for f in sorted(source.glob("*")):
            if f.suffix.lower() in (".cfg", ".txt", ".conf") and f.is_file():
                configs[f.stem] = f.read_text(encoding="utf-8", errors="replace")
    elif source.suffix.lower() == ".json":
        data = json.loads(source.read_text(encoding="utf-8"))
        for h in data.get("hosts", []):
            if h.get("config"):
                configs[h.get("name") or h.get("host")] = h["config"]
    else:
        raise ValueError(f"analyze source must be an audit.json or a directory: {source}")
    return configs


def normalize_config(text: str) -> str:
    lines = []
    banner_delim = None
    for line in (text or "").splitlines():
        stripped = line.strip()
        if banner_delim is not None:
            # inside a banner block: its content lines are unindented and would
            # otherwise be mistaken for top-level config blocks
            if banner_delim in line:
                banner_delim = None
            continue
        if stripped.startswith("banner "):
            parts = stripped.split(None, 2)
            payload = parts[2] if len(parts) > 2 else ""
            if "\x03" in payload:
                delim = "\x03"
            elif payload.startswith("^C"):
                delim = "^C"
            else:
                delim = payload[:1] or "^C"
            if payload.count(delim) < 2:  # closing delimiter not on this line
                banner_delim = delim
            continue
        if not stripped or stripped == "!" or stripped.startswith("!"):
            continue
        if any(p in line for p in _VOLATILE_PREFIXES):
            continue
        lines.append(line.rstrip())
    return "\n".join(lines)


# Salted hashes differ between switches even for identical passwords, so they are
# pure false drift - and they don't belong in a report either.
_SECRET_RES = [
    (re.compile(r"^(\s*enable (?:secret|password)(?: level \d+)?(?: \d+)?) .+"), r"\1 <redacted>"),
    (re.compile(r"^(\s*username \S+ .*?(?:secret|password)(?: \d+)?) .+"), r"\1 <redacted>"),
    (re.compile(r"^(\s*snmp-server community) \S+(.*)$"), r"\1 <redacted>\2"),
    (re.compile(r"^(\s*snmp-server host \S+(?:\s+version \S+)?) \S+(.*)$"), r"\1 <redacted>\2"),
    (re.compile(r"^(\s*(?:tacacs-server|radius-server) .*?key(?: \d+)?) .+"), r"\1 <redacted>"),
    (re.compile(r"^(\s*key [07]) .+"), r"\1 <redacted>"),
    (re.compile(r"^(\s*key-string(?: \d+)?) .+"), r"\1 <redacted>"),
]


def mask_secrets(text: str) -> str:
    out = []
    for line in (text or "").splitlines():
        for rx, repl in _SECRET_RES:
            new = rx.sub(repl, line)
            if new != line:
                line = new
                break
        out.append(line)
    return "\n".join(out)


def parse_blocks(config: str) -> "dict[str, tuple]":
    """Split a normalized config into {top-level line: (child lines...)}."""
    blocks = {}
    current = None
    for line in config.splitlines():
        if not line.startswith(" "):
            current = line.strip()
            blocks.setdefault(current, [])
        elif current is not None:
            blocks[current].append(line.strip())
    return {header: tuple(children) for header, children in blocks.items()}


def _comparable(header: str) -> bool:
    lowered = header.lower()
    return not any(lowered.startswith(p) for p in _EXCLUDED_HEADER_PREFIXES)


def compute_drift(configs: "dict[str, str]", baseline: str = None) -> dict:
    """Compare top-level config blocks across switches.

    Without a baseline, the most common variant is the consensus and deviations
    are reported against it. With `baseline` set to a switch name, that switch's
    config is the reference: every difference is reported relative to it, which
    is the right model when one switch is known-good or the fleet has no majority.
    """
    parsed = {name: {h: c for h, c in
                     parse_blocks(mask_secrets(normalize_config(cfg))).items() if _comparable(h)}
              for name, cfg in configs.items()}
    hosts = sorted(parsed)
    if baseline is not None and baseline not in parsed:
        raise ValueError(
            f"baseline '{baseline}' is not among the loaded configs: {', '.join(hosts)}")
    all_headers = sorted({header for blocks in parsed.values() for header in blocks})

    items = []
    for header in all_headers:
        present = [h for h in hosts if header in parsed[h]]
        variants = {}
        for h in present:
            variants.setdefault(parsed[h][header], []).append(h)
        if len(present) == len(hosts) and len(variants) == 1:
            continue  # identical everywhere
        if baseline is not None:
            consensus_children = parsed[baseline].get(header, ())
            ranked = sorted(variants.items(),
                            key=lambda kv: (0 if baseline in kv[1] else 1, -len(kv[1]), kv[1]))
        else:
            ranked = sorted(variants.items(), key=lambda kv: (-len(kv[1]), kv[1]))
            consensus_children = ranked[0][0]
        items.append({
            "header": header,
            "present_on": present,
            "missing_on": [h for h in hosts if h not in present],
            "variants": [
                {
                    "hosts": hostlist,
                    "is_baseline": baseline is not None and baseline in hostlist,
                    "children": list(children),
                    "added": sorted(set(children) - set(consensus_children)),
                    "removed": sorted(set(consensus_children) - set(children)),
                }
                for children, hostlist in ranked
            ],
        })
    return {"hosts": hosts, "baseline": baseline, "item_count": len(items), "items": items}


# ------------------------------------------------------------------ test suites

def _finding(code, severity, host, message):
    return {"code": code, "severity": severity, "host": host, "message": message}


def test_security(configs: "dict[str, str]") -> "list[dict]":
    findings = []
    for host, cfg in sorted(configs.items()):
        lines = normalize_config(cfg).splitlines()
        stripped = [l.strip() for l in lines]

        for m in re.finditer(r"^line vty.*\n((?: .+\n?)*)", normalize_config(cfg), re.MULTILINE):
            block = m.group(1)
            tm = re.search(r"transport input\s+(.+)", block)
            if tm and ("telnet" in tm.group(1) or "all" in tm.group(1)):
                findings.append(_finding(
                    "TELNET_ENABLED", "critical", host,
                    f"VTY lines accept telnet ('transport input {tm.group(1).strip()}') - "
                    "credentials cross the network in cleartext. Use 'transport input ssh'."))
                break
        if "ip http server" in stripped:
            findings.append(_finding(
                "HTTP_SERVER", "warning", host,
                "Plain-HTTP management server is enabled ('ip http server') - disable it or use "
                "'ip http secure-server' only."))
        for line in stripped:
            m = re.match(r"snmp-server community\s+(\S+)(?:\s+(\S+))?", line)
            if m:
                community, mode = m.group(1), (m.group(2) or "RO").upper()
                if community.lower() in ("public", "private"):
                    findings.append(_finding(
                        "SNMP_DEFAULT_COMMUNITY", "critical", host,
                        f"SNMP community '{community}' ({mode}) is a well-known default - change it."))
                elif mode == "RW":
                    findings.append(_finding(
                        "SNMP_RW", "warning", host,
                        f"SNMP community with write access ({mode}) - full config control for "
                        "anyone who learns the string."))
        if "service password-encryption" not in stripped:
            findings.append(_finding(
                "NO_PASSWORD_ENCRYPTION", "warning", host,
                "'service password-encryption' is off - line passwords sit in the config in cleartext."))
        for line in stripped:
            if re.match(r"enable password\s", line):
                findings.append(_finding(
                    "ENABLE_PASSWORD", "warning", host,
                    "'enable password' in use - replace with 'enable secret' (proper hashing)."))
                break
        for line in stripped:
            if re.match(r"username \S+ (?:privilege \d+ )?password\s+[07]?\s", line):
                findings.append(_finding(
                    "WEAK_USER_SECRET", "warning", host,
                    "Local user uses 'password' (type 0/7, trivially reversible) - use "
                    "'username ... secret' instead."))
                break
    return findings


def test_stp(configs: "dict[str, str]") -> "list[dict]":
    findings = []
    modes = {}
    for host, cfg in sorted(configs.items()):
        m = re.search(r"^spanning-tree mode (\S+)", normalize_config(cfg), re.MULTILINE)
        modes[host] = m.group(1) if m else "pvst(default)"
    if len(set(modes.values())) > 1:
        detail = ", ".join(f"{h}={m}" for h, m in modes.items())
        findings.append(_finding(
            "STP_MODE_MISMATCH", "critical", "",
            f"Switches disagree on spanning-tree mode ({detail}) - mixed modes cause slow or "
            "asymmetric convergence."))
    priority_hosts = [h for h, cfg in sorted(configs.items())
                      if re.search(r"^spanning-tree vlan [\d,\-]+ priority \d+",
                                   normalize_config(cfg), re.MULTILINE)
                      or re.search(r"^spanning-tree vlan [\d,\-]+ root (?:primary|secondary)",
                                   normalize_config(cfg), re.MULTILINE)]
    if configs and not priority_hosts:
        findings.append(_finding(
            "NO_DETERMINISTIC_ROOT", "warning", "",
            "No switch sets an STP root priority - the root bridge is elected by lowest MAC, so "
            "any new/old switch can silently take over as root."))
    return findings


def test_vlans(configs: "dict[str, str]") -> "list[dict]":
    findings = []
    vlans_by_host = {}
    for host, cfg in sorted(configs.items()):
        vlans = set()
        for m in re.finditer(r"^vlan ([\d,\-]+)\s*$", normalize_config(cfg), re.MULTILINE):
            for part in m.group(1).split(","):
                if "-" in part:
                    lo, hi = part.split("-")
                    vlans.update(range(int(lo), int(hi) + 1))
                else:
                    vlans.add(int(part))
        vlans_by_host[host] = vlans
    all_vlans = set().union(*vlans_by_host.values()) if vlans_by_host else set()
    for vlan in sorted(all_vlans):
        missing = [h for h, v in vlans_by_host.items() if vlan not in v]
        if missing and len(missing) < len(vlans_by_host):
            findings.append(_finding(
                "VLAN_INCONSISTENT", "warning", "",
                f"VLAN {vlan} is not defined on: {', '.join(missing)} - traffic for it dies there."))
    return findings


TESTS = {
    "security": test_security,
    "stp": test_stp,
    "vlans": test_vlans,
}


def run_tests(configs: "dict[str, str]", names: "list[str]") -> "tuple[list, list]":
    """Run the named test suites; returns (findings, tests_run)."""
    if "all" in names:
        names = list(TESTS)
    findings, ran = [], []
    for name in names:
        fn = TESTS.get(name)
        if fn is None:
            raise ValueError(f"unknown test '{name}' (available: {', '.join(TESTS)}, all)")
        findings.extend(fn(configs))
        ran.append(name)
    seen, unique = set(), []
    for f in findings:
        key = (f["code"], f["host"], f["message"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique, ran

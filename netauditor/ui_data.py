"""Data layer for the terminal UI - pure helpers, no Textual imports."""
from __future__ import annotations

import json
from pathlib import Path

ALL_ROW_NAME = "= ALL SWITCHES ="
SEVERITY_CYCLE = ("all", "critical", "warning", "info")


def load_audit(path):
    """Load audit.json from a file or an output directory. Returns dict or None."""
    p = Path(path)
    if p.is_dir():
        p = p / "audit.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _row(name, host, group, inv=None, entry=None):
    findings = []
    for f in (entry or {}).get("findings", []):
        f = dict(f)
        f.setdefault("host", name)
        findings.append(f)
    counts = {"critical": 0, "warning": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "name": name,
        "host": host,
        "group": group,
        "critical": counts["critical"],
        "warning": counts["warning"],
        "info": counts["info"],
        "findings": findings,
        "interfaces": (entry or {}).get("interfaces", []),
        "config": (entry or {}).get("config", ""),
        "facts": (entry or {}).get("facts", {}),
        "error": (entry or {}).get("error"),
        "inv": inv,
    }


def build_rows(inv_hosts, audit) -> "list[dict]":
    """Merge inventory hosts with audit entries into display rows.

    Inventory rows adopt matching audit data (matched by IP, then by name);
    audit-only entries are appended; an aggregate ALL row is prepended when
    any findings exist.
    """
    audit_hosts = (audit or {}).get("hosts", [])
    by_ip = {a.get("host"): a for a in audit_hosts}
    by_name = {(a.get("name") or "").lower(): a for a in audit_hosts if a.get("name")}

    rows, matched = [], set()
    for h in inv_hosts:
        entry = by_ip.get(h.host) or by_name.get(h.display_name().lower())
        if entry is not None:
            matched.add(id(entry))
        rows.append(_row(h.display_name(), h.host, h.group, inv=h, entry=entry))
    for a in audit_hosts:
        if id(a) not in matched:
            rows.append(_row(a.get("name") or a.get("host"), a.get("host"),
                             a.get("group", ""), entry=a))

    all_findings = [f for r in rows for f in r["findings"]]
    if all_findings:
        combined = {
            "findings": all_findings,
            "interfaces": [],
            "config": "",
            "facts": {},
        }
        rows.insert(0, _row(ALL_ROW_NAME, "", "", entry=combined))
    return rows


def filter_findings(findings, severity="all", query="") -> "list[dict]":
    """Filter findings by severity and free-text query (case-insensitive)."""
    q = (query or "").strip().lower()
    out = []
    for f in findings:
        if severity != "all" and f.get("severity") != severity:
            continue
        if q:
            hay = " ".join(str(f.get(k, "")) for k in
                           ("host", "code", "interface", "message", "severity")).lower()
            if q not in hay:
                continue
        out.append(f)
    order = {"critical": 0, "warning": 1, "info": 2}
    out.sort(key=lambda f: (order.get(f.get("severity"), 9),
                            f.get("host", ""), f.get("code", "")))
    return out

"""Shared execution layer: run audits and drift analysis and write every output.

Both the CLI subcommands and the terminal UI go through these functions, so the
two entry points cannot drift apart in behaviour.
"""
from __future__ import annotations

import datetime
import json
import re
from pathlib import Path

from . import __version__, analyzer, checks, report


def _now() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def _safe_filename(name: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", name) or "switch"


def _group_filename(group: str, suffix: str) -> str:
    name = _safe_filename(group).lower()
    if name in ("audit", "drift"):  # don't clobber the combined reports
        name = f"group-{name}"
    return f"{name}{suffix}"


def _split_by_group(reports: "list[dict]") -> "list[tuple[str, list]]":
    """Split host reports by group; empty when no host carries a group name."""
    by = {}
    for r in reports:
        by.setdefault(r.get("group") or "", []).append(r)
    if not any(g for g in by):
        return []
    return sorted((g or "ungrouped", members) for g, members in by.items())


def _entry_keys(entry) -> "list[tuple]":
    keys = []
    host = entry.get("host") if isinstance(entry, dict) else entry.host
    name = entry.get("name") if isinstance(entry, dict) else entry.display_name()
    if host:
        keys.append(("ip", host))
    if name:
        keys.append(("name", str(name).lower()))
    return keys


def merge_audit_hosts(existing, fresh) -> "list[dict]":
    """Merge freshly audited host entries into an existing list.

    Fresh entries replace existing ones (matched by IP first, then by name);
    unmatched existing entries are kept in place; brand-new entries append.
    Two old entries matching the same fresh one collapse into it (dedupe after
    a rename or re-IP).
    """
    fresh_by_key = {}
    for entry in fresh:
        for key in _entry_keys(entry):
            fresh_by_key[key] = entry
    merged, used = [], set()
    for old in existing:
        replacement = None
        for key in _entry_keys(old):
            if key in fresh_by_key:
                replacement = fresh_by_key[key]
                break
        if replacement is None:
            merged.append(old)
        elif id(replacement) not in used:
            merged.append(replacement)
            used.add(id(replacement))
    for entry in fresh:
        if id(entry) not in used:
            merged.append(entry)
    return merged


def _load_existing_hosts(outdir: Path) -> "list[dict]":
    path = outdir / "audit.json"
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("hosts", [])
    except (OSError, ValueError):
        return []


def _write_audit_outputs(audit, outdir: Path, formats) -> "list[str]":
    outdir.mkdir(parents=True, exist_ok=True)
    reports = audit["hosts"]
    messages = []
    if "json" in formats:
        report.write_json(audit, outdir / "audit.json")
        messages.append(f"Wrote {outdir / 'audit.json'}")
    if "html" in formats:
        (outdir / "audit.html").write_text(report.render_audit_html(audit), encoding="utf-8")
        messages.append(f"Wrote {outdir / 'audit.html'}")
        for gname, ghosts in _split_by_group(reports):
            gpath = outdir / _group_filename(gname, ".html")
            gpath.write_text(report.render_audit_html(dict(audit, hosts=ghosts, scope=gname)),
                             encoding="utf-8")
            messages.append(f"Wrote {gpath}")
    return messages


def run_audit(hosts, outdir, formats=("json", "html"), workers=8, timeout=30,
              progress=None, fresh=False, snapshot=True, backup=True) -> "tuple[dict, dict, list]":
    """Collect, check, and write all audit outputs.

    By default the results MERGE into an existing audit.json, so a scoped run
    (one campus, one switch) updates just those entries and keeps the rest of
    the fleet's data. `fresh=True` discards previous results entirely.

    Returns (audit, severity_counts, messages); severity_counts cover only the
    hosts audited in this run.
    """
    from .collector import collect_all  # lazy: needs netmiko

    results = collect_all(hosts, workers=workers, timeout=timeout, progress=progress)
    reports = [checks.build_host_report(r) for r in results]
    outdir = Path(outdir)

    messages = []
    all_reports = reports
    if not fresh:
        existing = _load_existing_hosts(outdir)
        if existing:
            all_reports = merge_audit_hosts(existing, reports)
            kept = len(all_reports) - len(reports)
            if kept:
                messages.append(f"Merged: {len(reports)} switch(es) re-audited, "
                                f"{kept} kept from the previous audit")
    audit = {"generated": _now(), "tool_version": __version__, "hosts": all_reports}
    messages.extend(_write_audit_outputs(audit, outdir, formats))

    cfg_dir = outdir / "configs"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    for h in reports:
        if h["config"]:
            (cfg_dir / f"{_safe_filename(h['name'])}.cfg").write_text(h["config"],
                                                                      encoding="utf-8")
    messages.append(f"Wrote {sum(1 for h in reports if h['config'])} config export(s) "
                    f"to {cfg_dir}")

    if snapshot:
        from .history import save_snapshot
        path = save_snapshot(audit, outdir)
        if path:
            messages.append(f"Archived snapshot {path}")
    if backup:
        from .history import backup_configs
        messages.append(backup_configs(
            outdir, f"audit {audit['generated']}: {len(reports)} switch(es)"))
    return audit, checks.count_findings(reports), messages


def regenerate_reports(outdir, formats=("json", "html")) -> "list[str]":
    """Re-render every report from the existing audit.json / drift.json.

    Report files are build artefacts of the code that wrote them, so this
    refreshes them after an upgrade without re-auditing any switch.
    """
    outdir = Path(outdir)
    messages = []
    audit_path = outdir / "audit.json"
    if not audit_path.exists():
        raise FileNotFoundError(f"no audit.json in {outdir}")
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    messages.extend(_write_audit_outputs(audit, outdir, formats))

    drift_path = outdir / "drift.json"
    if drift_path.exists() and "html" in formats:
        drift = json.loads(drift_path.read_text(encoding="utf-8"))
        (outdir / "drift.html").write_text(report.render_drift_html(drift),
                                           encoding="utf-8")
        messages.append(f"Wrote {outdir / 'drift.html'}")
        groups = drift.get("groups") or {}
        for gname in sorted({g for g in groups.values() if g}):
            members = sorted(n for n, g in groups.items() if g == gname)
            if len(members) < 2:
                continue
            gitems = [i for i in (drift.get("drift") or {}).get("items", [])
                      if set(i.get("present_on", [])) & set(members)]
            gresult = dict(drift, hosts=members, group_filter=gname,
                           drift=dict(drift.get("drift") or {}, items=gitems),
                           findings=[f for f in drift.get("findings", [])
                                     if not f.get("host") or f.get("host") in members])
            gpath = outdir / _group_filename(gname, ".drift.html")
            gpath.write_text(report.render_drift_html(gresult), encoding="utf-8")
            messages.append(f"Wrote {gpath}")
    return messages


def find_ghosts(inv_hosts, audit_hosts) -> "list[dict]":
    """Audit entries with no matching inventory host (removed/renamed switches)."""
    inv_keys = set()
    for h in inv_hosts:
        inv_keys.update(_entry_keys(h))
    return [e for e in audit_hosts if not any(k in inv_keys for k in _entry_keys(e))]


def prune_audit(inv_hosts, outdir, formats=("json", "html"),
                apply=False) -> "tuple[list, list]":
    """Identify (and with apply=True remove) audit entries not in the inventory.

    Returns (ghost_names, messages). Raises FileNotFoundError when there is no
    audit.json to prune.
    """
    outdir = Path(outdir)
    path = outdir / "audit.json"
    if not path.exists():
        raise FileNotFoundError(f"no audit.json in {outdir}")
    data = json.loads(path.read_text(encoding="utf-8"))
    audit_hosts = data.get("hosts", [])
    ghosts = find_ghosts(inv_hosts, audit_hosts)
    names = [g.get("name") or g.get("host") for g in ghosts]
    if not apply or not ghosts:
        return names, []
    ghost_ids = {id(g) for g in ghosts}
    keep = [e for e in audit_hosts if id(e) not in ghost_ids]
    audit = dict(data, generated=_now(), hosts=keep)
    messages = _write_audit_outputs(audit, outdir, formats)
    return names, messages


def run_analyze(configs, groups, outdir, tests=(), baseline=None,
                formats=("json", "html"), group_filter="") -> "tuple[dict, list]":
    """Compute drift, run test suites, and write all analysis outputs.

    Returns (result, messages). Raises ValueError for unknown tests or a
    baseline that is not among the configs.
    """
    if len(configs) >= 2:
        drift = analyzer.compute_drift(configs, baseline=baseline)
    else:
        drift = {"hosts": sorted(configs), "baseline": baseline, "item_count": 0, "items": []}
    findings, tests_run = analyzer.run_tests(configs, list(tests))
    result = {
        "generated": _now(),
        "tool_version": __version__,
        "hosts": drift["hosts"],
        "groups": {n: groups.get(n, "") for n in configs},
        "group_filter": group_filter,
        "tests_run": tests_run,
        "drift": drift,
        "findings": findings,
    }

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    messages = []
    if "json" in formats:
        report.write_json(result, outdir / "drift.json")
        messages.append(f"Wrote {outdir / 'drift.json'}")
    if "html" in formats:
        (outdir / "drift.html").write_text(report.render_drift_html(result), encoding="utf-8")
        messages.append(f"Wrote {outdir / 'drift.html'}")
        group_names = sorted({g for g in (groups.get(n, "") for n in configs) if g})
        for gname in group_names:
            gconfigs = {n: c for n, c in configs.items() if groups.get(n, "") == gname}
            if len(gconfigs) < 2:
                messages.append(f"note: group '{gname}' has only {len(gconfigs)} config(s) - "
                                "skipping its per-group drift report")
                continue
            gbaseline = baseline if baseline in gconfigs else None
            gfindings, _ = analyzer.run_tests(gconfigs, list(tests))
            gresult = dict(result, hosts=sorted(gconfigs), group_filter=gname,
                           drift=analyzer.compute_drift(gconfigs, baseline=gbaseline),
                           findings=gfindings)
            gpath = outdir / _group_filename(gname, ".drift.html")
            gpath.write_text(report.render_drift_html(gresult), encoding="utf-8")
            messages.append(f"Wrote {gpath}")
    return result, messages

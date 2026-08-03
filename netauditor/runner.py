"""Shared execution layer: run audits and drift analysis and write every output.

Both the CLI subcommands and the terminal UI go through these functions, so the
two entry points cannot drift apart in behaviour.
"""
from __future__ import annotations

import datetime
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


def run_audit(hosts, outdir, formats=("json", "html"), workers=8, timeout=30,
              progress=None) -> "tuple[dict, dict, list]":
    """Collect, check, and write all audit outputs.

    Returns (audit, severity_counts, messages) where messages are the
    human-readable "Wrote ..." lines.
    """
    from .collector import collect_all  # lazy: needs netmiko

    results = collect_all(hosts, workers=workers, timeout=timeout, progress=progress)
    reports = [checks.build_host_report(r) for r in results]
    audit = {"generated": _now(), "tool_version": __version__, "hosts": reports}

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
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
    cfg_dir = outdir / "configs"
    cfg_dir.mkdir(exist_ok=True)
    for h in reports:
        if h["config"]:
            (cfg_dir / f"{_safe_filename(h['name'])}.cfg").write_text(h["config"],
                                                                      encoding="utf-8")
    messages.append(f"Wrote {sum(1 for h in reports if h['config'])} config export(s) "
                    f"to {cfg_dir}")
    return audit, checks.count_findings(reports), messages


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

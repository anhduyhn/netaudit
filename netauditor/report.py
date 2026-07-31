"""JSON and HTML report writers for audit and drift results."""
from __future__ import annotations

import html
import json
from pathlib import Path

_SEV_ORDER = {"critical": 0, "warning": 1, "info": 2}

_CSS = """
body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 24px;
       background: #f5f6f8; color: #1f2430; }
h1 { margin: 0 0 4px; font-size: 22px; }
h2 { margin: 32px 0 8px; font-size: 18px; border-bottom: 2px solid #d8dce3; padding-bottom: 4px; }
h3 { margin: 20px 0 6px; font-size: 15px; }
.meta { color: #667; font-size: 13px; margin-bottom: 20px; }
.tiles { display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0 8px; }
.tile { background: #fff; border: 1px solid #e2e5ea; border-radius: 8px; padding: 10px 18px; min-width: 110px; }
.tile .num { font-size: 24px; font-weight: 700; }
.tile .label { font-size: 12px; color: #667; text-transform: uppercase; letter-spacing: .04em; }
table { border-collapse: collapse; width: 100%; background: #fff; font-size: 13px;
        border: 1px solid #e2e5ea; border-radius: 8px; overflow: hidden; margin: 8px 0 16px; }
th { background: #eef0f4; text-align: left; padding: 7px 10px; font-size: 12px;
     text-transform: uppercase; letter-spacing: .03em; color: #445; }
td { padding: 6px 10px; border-top: 1px solid #eef0f4; vertical-align: top; }
tr:nth-child(even) td { background: #fafbfc; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: 11px;
         font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
.sev-critical { background: #fde3e3; color: #a11a1a; }
.sev-warning  { background: #fdf0d5; color: #8a5a00; }
.sev-info     { background: #dfeafd; color: #1c4f9c; }
.ok   { color: #1a7d3c; font-weight: 600; }
.bad  { color: #a11a1a; font-weight: 600; }
code, pre { font-family: 'Cascadia Code', Consolas, monospace; font-size: 12px; }
pre { background: #23272e; color: #dfe3ea; padding: 14px; border-radius: 8px; overflow-x: auto; }
details { margin: 8px 0 16px; }
summary { cursor: pointer; font-weight: 600; }
.diff-add { color: #1a7d3c; }
.diff-del { color: #a11a1a; text-decoration: line-through; }
.hostcard { background: #fff; border: 1px solid #e2e5ea; border-radius: 8px; padding: 14px 18px; margin: 12px 0; }
.small { font-size: 12px; color: #667; }
"""


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _page(title: str, body: str) -> str:
    return (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{_e(title)}</title><style>{_CSS}</style></head><body>{body}</body></html>")


def _badge(severity: str) -> str:
    return f"<span class='badge sev-{_e(severity)}'>{_e(severity)}</span>"


def _tiles(items) -> str:
    tiles = "".join(f"<div class='tile'><div class='num'>{_e(n)}</div>"
                    f"<div class='label'>{_e(label)}</div></div>" for label, n in items)
    return f"<div class='tiles'>{tiles}</div>"


def write_json(data: dict, path: Path) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- audit report

def render_audit_html(audit: dict) -> str:
    hosts = audit.get("hosts", [])
    all_findings = [(h, f) for h in hosts for f in h.get("findings", [])]
    counts = {"critical": 0, "warning": 0, "info": 0}
    for _, f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    body = [f"<h1>Switch audit report</h1>"
            f"<div class='meta'>Generated {_e(audit.get('generated'))} by netauditor "
            f"{_e(audit.get('tool_version'))}</div>"]
    body.append(_tiles([("Switches", len(hosts)),
                        ("Critical", counts["critical"]),
                        ("Warnings", counts["warning"]),
                        ("Info", counts["info"])]))

    # Fleet overview
    body.append("<h2>Fleet overview</h2><table><tr><th>Switch</th><th>Host</th><th>Model</th>"
                "<th>IOS</th><th>Uptime</th><th>STP mode</th><th>Critical</th><th>Warnings</th></tr>")
    for h in hosts:
        hc = sum(1 for f in h.get("findings", []) if f["severity"] == "critical")
        hw = sum(1 for f in h.get("findings", []) if f["severity"] == "warning")
        facts = h.get("facts", {})
        body.append(
            f"<tr><td><b>{_e(h['name'])}</b></td><td>{_e(h['host'])}</td>"
            f"<td>{_e(facts.get('model'))}</td><td>{_e(facts.get('version'))}</td>"
            f"<td>{_e(facts.get('uptime'))}</td><td>{_e(h.get('stp', {}).get('mode'))}</td>"
            f"<td class='{'bad' if hc else 'ok'}'>{hc}</td>"
            f"<td class='{'bad' if hw else 'ok'}'>{hw}</td></tr>")
    body.append("</table>")

    # All findings, most severe first
    body.append("<h2>Findings</h2>")
    if all_findings:
        all_findings.sort(key=lambda hf: (_SEV_ORDER.get(hf[1]["severity"], 9), hf[0]["name"]))
        body.append("<table><tr><th>Severity</th><th>Switch</th><th>Interface</th>"
                    "<th>Code</th><th>Message</th></tr>")
        for h, f in all_findings:
            body.append(f"<tr><td>{_badge(f['severity'])}</td><td>{_e(h['name'])}</td>"
                        f"<td><code>{_e(f.get('interface'))}</code></td>"
                        f"<td><code>{_e(f['code'])}</code></td><td>{_e(f['message'])}</td></tr>")
        body.append("</table>")
    else:
        body.append("<p class='ok'>No findings - clean audit.</p>")

    # Per-host detail
    for h in hosts:
        body.append(f"<h2>{_e(h['name'])} <span class='small'>({_e(h['host'])})</span></h2>")
        if h.get("error"):
            body.append(f"<div class='hostcard bad'>Unreachable: {_e(h['error'])}</div>")
            continue
        if h.get("interfaces"):
            body.append("<details><summary>Interfaces ("
                        f"{len(h['interfaces'])})</summary>"
                        "<table><tr><th>Port</th><th>Description</th><th>Status</th><th>VLAN</th>"
                        "<th>Duplex</th><th>Speed</th><th>Uplink</th><th>PortFast</th>"
                        "<th>BPDU guard</th><th>In errs / CRC</th></tr>")
            for i in h["interfaces"]:
                uplink = _e(i["uplink_reason"]) if i["is_uplink"] else "-"
                body.append(
                    f"<tr><td><code>{_e(i['interface'])}</code></td><td>{_e(i['description'])}</td>"
                    f"<td>{_e(i['status'])}</td><td>{_e(i['vlan'])}</td><td>{_e(i['duplex'])}</td>"
                    f"<td>{_e(i['speed'])}</td><td>{uplink}</td>"
                    f"<td>{'yes' if i['portfast'] else 'no'}</td>"
                    f"<td>{'yes' if i['bpduguard'] else 'no'}</td>"
                    f"<td>{i['input_errors']} / {i['crc']}</td></tr>")
            body.append("</table></details>")
        if h.get("config"):
            body.append(f"<details><summary>Running config</summary>"
                        f"<pre>{_e(h['config'])}</pre></details>")

    return _page("Switch audit report", "".join(body))


# ---------------------------------------------------------------- drift report

def render_drift_html(result: dict) -> str:
    items = result.get("drift", {}).get("items", [])
    baseline = result.get("drift", {}).get("baseline")
    findings = result.get("findings", [])
    counts = {"critical": 0, "warning": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    baseline_note = f" · baseline: {_e(baseline)}" if baseline else ""
    body = [f"<h1>Config drift &amp; analysis report</h1>"
            f"<div class='meta'>Generated {_e(result.get('generated'))} · "
            f"{len(result.get('hosts', []))} switches · tests: "
            f"{_e(', '.join(result.get('tests_run', [])) or 'none')}{baseline_note}</div>"]
    body.append(_tiles([("Switches", len(result.get("hosts", []))),
                        ("Drift items", len(items)),
                        ("Critical", counts["critical"]),
                        ("Warnings", counts["warning"])]))

    body.append("<h2>Analysis findings</h2>")
    if findings:
        findings = sorted(findings, key=lambda f: (_SEV_ORDER.get(f["severity"], 9), f.get("host", "")))
        body.append("<table><tr><th>Severity</th><th>Switch</th><th>Code</th><th>Message</th></tr>")
        for f in findings:
            body.append(f"<tr><td>{_badge(f['severity'])}</td><td>{_e(f.get('host'))}</td>"
                        f"<td><code>{_e(f['code'])}</code></td><td>{_e(f['message'])}</td></tr>")
        body.append("</table>")
    else:
        body.append("<p class='ok'>No findings from the requested tests.</p>")

    body.append("<h2>Config drift</h2>")
    if not items:
        body.append("<p class='ok'>No drift - all compared config sections are identical across switches.</p>")
    for item in items:
        body.append(f"<div class='hostcard'><h3><code>{_e(item['header'])}</code></h3>")
        if baseline and baseline in item["missing_on"]:
            body.append("<p class='bad'>Not on the baseline (extra config on the switches below)</p>")
        if item["missing_on"]:
            body.append(f"<p class='bad'>Missing on: {_e(', '.join(item['missing_on']))}</p>")
        for v, variant in enumerate(item["variants"]):
            if variant.get("is_baseline"):
                label = f"baseline ({baseline})"
            elif baseline:
                label = f"differs (variant {v + 1})"
            else:
                label = "consensus" if v == 0 else f"variant {v}"
            body.append(f"<p><b>{_e(label)}</b> - {_e(', '.join(variant['hosts']))}</p>")
            if variant["children"]:
                lines = []
                for line in variant["children"]:
                    cls = " class='diff-add'" if line in variant.get("added", []) else ""
                    lines.append(f"<span{cls}>{_e(line)}</span>")
                for line in variant.get("removed", []):
                    lines.append(f"<span class='diff-del'>{_e(line)}</span>")
                body.append("<pre>" + "\n".join(lines) + "</pre>")
            elif variant.get("removed"):
                body.append("<pre>" + "\n".join(
                    f"<span class='diff-del'>{_e(l)}</span>" for l in variant["removed"]) + "</pre>")
        body.append("</div>")

    return _page("Config drift report", "".join(body))

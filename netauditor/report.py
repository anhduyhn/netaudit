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
.toolbar { position: sticky; top: 0; z-index: 5; display: flex; gap: 8px; align-items: center;
           flex-wrap: wrap; background: rgba(245,246,248,.95); padding: 10px 0; }
.toolbar input { padding: 7px 12px; border: 1px solid #cdd2da; border-radius: 8px;
                 font-size: 13px; width: 280px; }
.toolbar select { padding: 7px 10px; border: 1px solid #cdd2da; border-radius: 8px;
                  font-size: 13px; background: #fff; max-width: 300px; }
.findgroup { background: #fff; border: 1px solid #e2e5ea; border-radius: 8px;
             padding: 8px 14px; margin: 8px 0; }
.findgroup summary { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.findgroup table { margin: 8px 0 4px; }
.count { color: #667; font-size: 12px; }
.chip { border: 1px solid #cdd2da; background: #fff; border-radius: 14px; padding: 4px 12px;
        font-size: 12px; cursor: pointer; }
.chip.active { background: #1f2430; color: #fff; border-color: #1f2430; }
.hidden { display: none !important; }
#matchcount { font-size: 12px; color: #667; }
"""

# Filters rows of table.searchable and .hostcard blocks by free text, severity
# chips (only elements that carry severity data), and the finding-code dropdown
# (only elements that carry data-code).
_FILTER_JS = """
(function () {
  var q = document.getElementById('q');
  if (!q) return;
  var chips = document.querySelectorAll('.chip');
  var codeSel = document.getElementById('codesel');
  var groupSel = document.getElementById('groupsel');
  var sev = 'all';

  if (codeSel) {
    var codes = {};
    document.querySelectorAll('[data-code]').forEach(function (el) {
      var c = el.getAttribute('data-code');
      codes[c] = (codes[c] || 0) + 1;
    });
    var names = Object.keys(codes).sort();
    names.forEach(function (c) {
      var o = document.createElement('option');
      o.value = c;
      o.textContent = c + ' (' + codes[c] + ')';
      codeSel.appendChild(o);
    });
    if (!names.length) codeSel.classList.add('hidden');
  }
  if (groupSel) {
    var groupNames = {};
    document.querySelectorAll('[data-group]').forEach(function (el) {
      var g = el.getAttribute('data-group');
      if (g) groupNames[g] = true;
    });
    var gs = Object.keys(groupNames).sort();
    gs.forEach(function (g) {
      var o = document.createElement('option');
      o.value = g;
      o.textContent = g;
      groupSel.appendChild(o);
    });
    if (!gs.length) groupSel.classList.add('hidden');
  }

  function targets() {
    var out = [];
    document.querySelectorAll('table.searchable tr, .hostcard').forEach(function (el) {
      if (el.tagName === 'TR' && el.querySelector('th')) return;  // keep header rows
      out.push(el);
    });
    return out;
  }
  function sevOf(el) {
    if (el.hasAttribute('data-sev')) return el.getAttribute('data-sev');
    var b = el.querySelector('.badge');
    var m = b && b.className.match(/sev-(\\w+)/);
    return m ? m[1] : null;
  }
  function apply() {
    var text = q.value.trim().toLowerCase();
    var code = codeSel ? codeSel.value : 'all';
    var grp = groupSel ? groupSel.value : 'all';
    if (text) document.querySelectorAll('details').forEach(function (d) { d.open = true; });
    var stats = {}, order = [];
    targets().forEach(function (el) {
      var holder = el.hasAttribute('data-cat') ? el : el.closest('[data-cat]');
      var cat = holder ? holder.getAttribute('data-cat') : 'items';
      if (!stats[cat]) { stats[cat] = { shown: 0, total: 0 }; order.push(cat); }
      // include the row's code in the haystack so searching a code matches its rows
      var hay = (el.textContent + ' ' + (el.getAttribute('data-code') || '')).toLowerCase();
      var okText = !text || hay.indexOf(text) !== -1;
      var s = sevOf(el);
      var okSev = sev === 'all' || s === null || s === sev;
      var elCode = el.getAttribute('data-code');
      var okCode = code === 'all' || !elCode || elCode === code;
      var gHolder = el.hasAttribute('data-group') ? el : el.closest('[data-group]');
      var g = gHolder ? gHolder.getAttribute('data-group') : null;
      var okGroup = grp === 'all' || !g || g === grp;
      stats[cat].total++;
      var show = okText && okSev && okCode && okGroup;
      el.classList.toggle('hidden', !show);
      if (show) stats[cat].shown++;
    });
    // a finding group disappears when none of its rows survive the filters
    document.querySelectorAll('.findgroup').forEach(function (g) {
      g.classList.toggle('hidden', !g.querySelector('tr:not(.hidden) td'));
    });
    // per-switch detail sections follow the campus selector
    document.querySelectorAll('.hostsection').forEach(function (hs) {
      var g = hs.getAttribute('data-group');
      hs.classList.toggle('hidden', grp !== 'all' && !!g && g !== grp);
    });
    document.getElementById('matchcount').textContent =
      (text || sev !== 'all' || code !== 'all' || grp !== 'all')
        ? order.map(function (c) { return c + ' ' + stats[c].shown + '/' + stats[c].total; }).join('  ·  ')
        : '';
  }
  q.addEventListener('input', apply);
  if (codeSel) codeSel.addEventListener('change', apply);
  if (groupSel) groupSel.addEventListener('change', apply);
  chips.forEach(function (c) {
    c.addEventListener('click', function () {
      chips.forEach(function (x) { x.classList.remove('active'); });
      c.classList.add('active');
      sev = c.getAttribute('data-sev');
      apply();
    });
  });
})();
"""

# Short human titles per finding code, shown in the group headers.
_CODE_TITLES = {
    "UNREACHABLE": "Switch could not be audited",
    "ERRDISABLED": "Port err-disabled",
    "UPLINK_PORTFAST": "PortFast on uplink",
    "UPLINK_BPDUGUARD": "BPDU guard on uplink",
    "STP_CHURN": "Active STP churn",
    "STP_CHURN_HISTORY": "Accumulated STP topology changes",
    "STP_RECENT_CHANGE": "Recent STP topology change",
    "ACCESS_NO_PORTFAST": "Access port without PortFast",
    "ACCESS_NO_BPDUGUARD": "Access port without BPDU guard",
    "HALF_DUPLEX": "Half-duplex link",
    "LATE_COLLISIONS": "Late collisions (duplex mismatch)",
    "INTERFACE_ERRORS": "High error counters",
    "GLOBAL_BPDUFILTER": "Global BPDU filter enabled",
    "EDGE_UNPROTECTED": "PortFast default without BPDU guard",
    "LEGACY_STP": "Legacy PVST+ mode",
    "NO_CONFIG": "Config not collected",
    "DTP_ENABLED": "Trunk negotiation (DTP) left on",
    "NATIVE_VLAN_1": "Trunk native VLAN is 1",
    "TRUNK_ALLOWS_ALL": "Trunk allows every VLAN",
    "VLAN1_IN_USE": "User ports on default VLAN 1",
    "UNUSED_PORT_OPEN": "Unused ports live on VLAN 1",
    "NO_EXEC_TIMEOUT": "Sessions never time out",
    "VTY_NO_ACL": "VTY lines without access-class",
    "SSH_V1": "SSH not pinned to version 2",
    "NO_NTP": "No NTP configured",
    "NO_LOGGING_HOST": "No syslog host configured",
    "UNSAVED_CHANGES": "Unsaved config changes",
    "MAC_FLAPPING": "MAC flapping (loop symptom)",
    "VTP_SERVER": "VTP server mode",
    "TELNET_ENABLED": "Telnet enabled on VTY lines",
    "HTTP_SERVER": "HTTP management server enabled",
    "SNMP_DEFAULT_COMMUNITY": "Well-known SNMP community",
    "SNMP_RW": "SNMP community with write access",
    "NO_PASSWORD_ENCRYPTION": "Password encryption disabled",
    "ENABLE_PASSWORD": "'enable password' instead of secret",
    "WEAK_USER_SECRET": "Weak local user password",
    "STP_MODE_MISMATCH": "STP mode mismatch across switches",
    "NO_DETERMINISTIC_ROOT": "No configured STP root bridge",
    "VLAN_INCONSISTENT": "VLAN missing on some switches",
}


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _page(title: str, body: str) -> str:
    return (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{_e(title)}</title><style>{_CSS}</style></head><body>{body}"
            f"<script>{_FILTER_JS}</script></body></html>")


def _toolbar(placeholder: str) -> str:
    return (f"<div class='toolbar'>"
            f"<input id='q' type='search' placeholder='{_e(placeholder)}'>"
            f"<button class='chip active' data-sev='all'>All</button>"
            f"<button class='chip' data-sev='critical'>Critical</button>"
            f"<button class='chip' data-sev='warning'>Warning</button>"
            f"<button class='chip' data-sev='info'>Info</button>"
            f"<select id='codesel'><option value='all'>All codes</option></select>"
            f"<select id='groupsel'><option value='all'>All campuses</option></select>"
            f"<span id='matchcount'></span></div>")


def _finding_groups(findings: "list[dict]", cols: "list[str]", row_fn) -> str:
    """Render findings as per-code collapsible groups, critical groups open."""
    groups = {}
    for f in findings:
        groups.setdefault((f["severity"], f["code"]), []).append(f)
    ordered = sorted(groups.items(),
                     key=lambda kv: (_SEV_ORDER.get(kv[0][0], 9), -len(kv[1]), kv[0][1]))
    out = []
    for (severity, code), items in ordered:
        title = _CODE_TITLES.get(code, "")
        title_html = f"<span>{_e(title)}</span>" if title else ""
        open_attr = " open" if severity == "critical" else ""
        out.append(f"<details class='findgroup'{open_attr}><summary>{_badge(severity)}"
                   f"<code>{_e(code)}</code>{title_html}"
                   f"<span class='count'>({len(items)})</span></summary>")
        out.append("<table class='searchable' data-cat='findings'><tr>"
                   + "".join(f"<th>{_e(c)}</th>" for c in cols) + "</tr>")
        out.extend(row_fn(f) for f in items)
        out.append("</table></details>")
    return "".join(out)


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

    scope_note = f" · campus: {_e(audit['scope'])}" if audit.get("scope") else ""
    body = [f"<h1>Switch audit report</h1>"
            f"<div class='meta'>Generated {_e(audit.get('generated'))} by netauditor "
            f"{_e(audit.get('tool_version'))}{scope_note}</div>"]
    body.append(_tiles([("Switches", len(hosts)),
                        ("Critical", counts["critical"]),
                        ("Warnings", counts["warning"]),
                        ("Info", counts["info"])]))
    body.append(_toolbar("Filter: switch, port, code, text..."))

    # Fleet overview
    any_groups = any(h.get("group") for h in hosts)
    campus_th = "<th>Campus</th>" if any_groups else ""
    body.append("<h2>Fleet overview</h2><table class='searchable' data-cat='switches'>"
                f"<tr><th>Switch</th>{campus_th}<th>Host</th><th>Model</th>"
                "<th>IOS</th><th>Uptime</th><th>STP mode</th><th>Critical</th><th>Warnings</th></tr>")
    for h in hosts:
        hc = sum(1 for f in h.get("findings", []) if f["severity"] == "critical")
        hw = sum(1 for f in h.get("findings", []) if f["severity"] == "warning")
        facts = h.get("facts", {})
        campus_td = f"<td>{_e(h.get('group'))}</td>" if any_groups else ""
        body.append(
            f"<tr data-group='{_e(h.get('group', ''))}'><td><b>{_e(h['name'])}</b></td>{campus_td}"
            f"<td>{_e(h['host'])}</td>"
            f"<td>{_e(facts.get('model'))}</td><td>{_e(facts.get('version'))}</td>"
            f"<td>{_e(facts.get('uptime'))}</td><td>{_e(h.get('stp', {}).get('mode'))}</td>"
            f"<td class='{'bad' if hc else 'ok'}'>{hc}</td>"
            f"<td class='{'bad' if hw else 'ok'}'>{hw}</td></tr>")
    body.append("</table>")

    # Findings grouped by code, most severe / most frequent first
    body.append("<h2>Findings</h2>")
    if all_findings:
        combined = sorted((dict(f, switch=h["name"], group=h.get("group", ""))
                           for h, f in all_findings),
                          key=lambda f: (f["switch"], f.get("interface") or ""))
        body.append(_finding_groups(
            combined,
            ["Switch", "Interface", "Message"],
            lambda f: (f"<tr data-sev='{_e(f['severity'])}' data-code='{_e(f['code'])}'"
                       f" data-group='{_e(f.get('group', ''))}'>"
                       f"<td>{_e(f['switch'])}</td><td><code>{_e(f.get('interface'))}</code></td>"
                       f"<td>{_e(f['message'])}</td></tr>")))
    else:
        body.append("<p class='ok'>No findings - clean audit.</p>")

    # Per-host detail
    for h in hosts:
        campus = f" · {_e(h['group'])}" if h.get("group") else ""
        body.append(f"<div class='hostsection' data-group='{_e(h.get('group', ''))}'>"
                    f"<h2>{_e(h['name'])} <span class='small'>({_e(h['host'])}{campus})</span></h2>")
        if h.get("error"):
            body.append(f"<div class='hostcard bad' data-cat='switches'>Unreachable: {_e(h['error'])}</div></div>")
            continue
        if h.get("interfaces"):
            body.append("<details><summary>Interfaces ("
                        f"{len(h['interfaces'])})</summary>"
                        "<table class='searchable' data-cat='interfaces'><tr><th>Port</th><th>Description</th><th>Status</th><th>VLAN</th>"
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
        body.append("</div>")

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
    if result.get("group_filter"):
        baseline_note += f" · campus: {_e(result['group_filter'])}"
    body = [f"<h1>Config drift &amp; analysis report</h1>"
            f"<div class='meta'>Generated {_e(result.get('generated'))} · "
            f"{len(result.get('hosts', []))} switches · tests: "
            f"{_e(', '.join(result.get('tests_run', [])) or 'none')}{baseline_note}</div>"]
    body.append(_tiles([("Switches", len(result.get("hosts", []))),
                        ("Drift items", len(items)),
                        ("Critical", counts["critical"]),
                        ("Warnings", counts["warning"])]))
    body.append(_toolbar("Filter: config line, switch, code, text..."))

    body.append("<h2>Analysis findings</h2>")
    if findings:
        findings = sorted(findings, key=lambda f: f.get("host") or "")
        body.append(_finding_groups(
            findings,
            ["Switch", "Message"],
            lambda f: (f"<tr data-sev='{_e(f['severity'])}' data-code='{_e(f['code'])}'>"
                       f"<td>{_e(f.get('host'))}</td><td>{_e(f['message'])}</td></tr>")))
    else:
        body.append("<p class='ok'>No findings from the requested tests.</p>")

    body.append("<h2>Config drift</h2>")
    if not items:
        body.append("<p class='ok'>No drift - all compared config sections are identical across switches.</p>")
    for item in items:
        body.append(f"<div class='hostcard' data-cat='drift'><h3><code>{_e(item['header'])}</code></h3>")
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

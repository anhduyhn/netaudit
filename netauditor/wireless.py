"""Trace problem Wi-Fi clients from the NPS RADIUS log to an access point and switch port.

Three sources are chained:

1. The NPS log (IAS format) names each client MAC, the account it used, the
   result of every login and the access point's radio MAC (Called-Station-Id).
   Clients that keep starting logins and never get an answer ("looping") or
   that are only ever rejected are the problem devices.
2. The wireless controller (Cisco AireOS) turns the radio MAC into the AP's
   name, model, location and wired MAC, and says whether the client is on the
   network right now and whether it is excluded (blocked).
3. The switches' MAC address tables turn the AP's wired MAC into the switch
   and port it is plugged into, using the audit data to skip uplinks.

Everything here is read-only: only 'show' commands are sent. Parsers are
regex-based and best-effort, like parsers.py.
"""
from __future__ import annotations

import concurrent.futures
import re
from collections import Counter
from datetime import datetime

# ------------------------------------------------------------------ MACs

_HEX12 = re.compile(r"[^0-9a-f]")


def norm_mac(value) -> str:
    """Any common MAC spelling -> 'aa:bb:cc:dd:ee:ff'; '' when it isn't one."""
    raw = _HEX12.sub("", str(value or "").lower())
    if len(raw) != 12:
        return ""
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


def is_random_mac(mac: str) -> bool:
    """Locally administered (randomised) MAC - usually a phone or tablet's private address."""
    mac = norm_mac(mac)
    return bool(mac) and mac[1] in "26ae"


_CALLED_RE = re.compile(r"^([0-9A-Fa-f]{2}(?:[-:.]?[0-9A-Fa-f]{2}){5})(?::(.*))?$")


def split_called_station(value: str) -> "tuple[str, str]":
    """'f4-db-e6-74-2c-a0:eduSTAR' -> ('f4:db:e6:74:2c:a0', 'eduSTAR')."""
    m = _CALLED_RE.match((value or "").strip())
    if not m:
        return "", ""
    return norm_mac(m.group(1)), (m.group(2) or "")


# ------------------------------------------------------------------ NPS log

PKT_REQUEST, PKT_ACCEPT, PKT_REJECT, PKT_CHALLENGE = "1", "2", "3", "11"
_SESSION_MAC_RE = re.compile(r"^[^/]+/([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})/")


def nps_date(day: datetime) -> str:
    """The IAS log's date spelling: M/D/YYYY with no leading zeros."""
    return f"{day.month}/{day.day}/{day.year}"


def nps_log_name(day: datetime) -> str:
    """Monthly IAS log file name, e.g. IN2611.log."""
    return f"IN{day:%y%m}.log"


def parse_nps_lines(lines, date: str = "") -> "dict[str, dict]":
    """Aggregate IAS-format NPS log lines per client MAC.

    date ('M/D/YYYY') limits it to one day; '' keeps every day in the input.
    Access-Accept/Reject records carry no Calling-Station-Id, so the client
    MAC also comes from the session id (attribute 44), which embeds it.
    """
    stats = {}
    for line in lines:
        parts = line.rstrip("\r\n").split(",")
        if len(parts) < 6:
            continue
        if date and parts[2] != date:
            continue
        attrs = {}
        for i in range(6, len(parts) - 1, 2):
            attrs.setdefault(parts[i], parts[i + 1])
        mac = norm_mac(attrs.get("31", ""))
        if not mac:
            m = _SESSION_MAC_RE.match(attrs.get("44", ""))
            mac = norm_mac(m.group(1)) if m else ""
        if not mac:
            continue
        e = stats.get(mac)
        if e is None:
            e = stats[mac] = {"mac": mac, "users": [], "requests": 0, "accepts": 0,
                              "rejects": 0, "reasons": Counter(), "ap_radio_mac": "",
                              "ssid": "", "nas_ip": "", "nas_name": "", "first": "",
                              "last": "", "date": parts[2]}
        pkt = attrs.get("4136", "")
        if pkt == PKT_REQUEST:
            e["requests"] += 1
            user = parts[1]
            if user and user not in e["users"]:
                e["users"].append(user)
            ap, ssid = split_called_station(attrs.get("30", ""))
            if ap:
                e["ap_radio_mac"], e["ssid"] = ap, ssid
            e["nas_ip"] = parts[0] or e["nas_ip"]
            e["nas_name"] = attrs.get("4128", "") or e["nas_name"]
            if not e["first"]:
                e["first"] = parts[3]
            e["last"] = parts[3]
        elif pkt == PKT_ACCEPT:
            e["accepts"] += 1
        elif pkt == PKT_REJECT:
            e["rejects"] += 1
            e["reasons"][attrs.get("4142", "?")] += 1
    return stats


def read_nps_log(path, date: str = "") -> "dict[str, dict]":
    """parse_nps_lines over a file, opened shared so a live NPS log can be read."""
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return parse_nps_lines(fh, date=date)


def find_problem_devices(stats: "dict[str, dict]", min_requests: int = 200,
                         min_rejects: int = 20) -> "list[dict]":
    """Clients that loop (many requests, never an answer) or are only ever rejected.

    A normal login is about 10 request/challenge rounds, so min_requests=200
    over a day is far beyond any real login. Devices that were accepted at
    least once are left out: their account and setup demonstrably work.
    """
    problems = []
    for e in stats.values():
        if e["accepts"]:
            continue
        if e["requests"] >= min_requests and not e["rejects"]:
            kind = "looping"
        elif e["rejects"] >= min_rejects:
            kind = "rejected"
        else:
            continue
        problems.append(dict(e, kind=kind, reasons=dict(e["reasons"])))
    order = {"looping": 0, "rejected": 1}
    problems.sort(key=lambda p: (order[p["kind"]], -p["requests"], -p["rejects"]))
    return problems


# NPS reason codes most likely to appear on a rejected device (subset).
REASON_TEXT = {
    "7": "domain does not exist",
    "8": "account does not exist",
    "16": "authentication failed (bad credentials)",
    "22": "client could not be authenticated (EAP)",
    "23": "certificate problem",
    "34": "account disabled",
    "48": "no matching network policy",
    "49": "no matching connection request policy",
    "65": "dial-in permission denied",
    "66": "authentication method not allowed",
    "262": "client certificate not trusted",
    "265": "certificate chain not trusted",
}


# ------------------------------------------------------------------ AireOS parsers

_MAC_PAT = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
_JOIN_RE = re.compile(rf"^\s*({_MAC_PAT})\s+({_MAC_PAT})\s+(\S+)\s+(\S+)\s+(.*?)\s*$")


def parse_ap_join_stats(text: str) -> "list[dict]":
    """'show ap join stats summary all': base radio MAC, wired MAC, AP name, IP, status."""
    aps = []
    for line in (text or "").splitlines():
        m = _JOIN_RE.match(line)
        if m:
            aps.append({"radio_mac": norm_mac(m.group(1)), "eth_mac": norm_mac(m.group(2)),
                        "name": m.group(3), "ip": m.group(4), "status": m.group(5)})
    return aps


_SUMMARY_RE = re.compile(
    rf"^(?P<name>\S+)\s+(?P<slots>\d+)\s+(?P<model>\S+)\s+(?P<mac>{_MAC_PAT})\s+"
    r"(?P<location>.*?)\s+(?P<country>[A-Z]{2}(?:-[A-Z]+)?)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<clients>\d+)")


def parse_ap_summary(text: str) -> "dict[str, dict]":
    """'show ap summary': model, wired MAC, location, IP, client count per AP name."""
    aps = {}
    for line in (text or "").splitlines():
        m = _SUMMARY_RE.match(line.strip())
        if m:
            aps[m.group("name")] = {"model": m.group("model"),
                                    "eth_mac": norm_mac(m.group("mac")),
                                    "location": m.group("location").strip(),
                                    "ip": m.group("ip"), "clients": int(m.group("clients"))}
    return aps


_DOTTED_RE = re.compile(r"^\s*(?P<key>[^.\n]+?)[\s:]*\.{2,}\s*(?P<val>.*?)\s*$")


def parse_client_detail(text: str):
    """'show client detail <mac>' -> dict, or None when the client isn't on the controller."""
    fields = {}
    for line in (text or "").splitlines():
        m = _DOTTED_RE.match(line)
        if m and m.group("key") not in fields:
            fields[m.group("key").strip()] = m.group("val")
    if not norm_mac(fields.get("Client MAC Address", "")):
        return None
    return {
        "ap_name": fields.get("AP Name", ""),
        "ap_mac": norm_mac(fields.get("AP MAC Address", "")),
        "state": fields.get("Client State", ""),
        "policy_state": fields.get("Policy Manager State", ""),
        "username": fields.get("Client Username", ""),
        "ip": fields.get("IP Address", ""),
        "ssid": fields.get("Wireless LAN Network Name (SSID)", ""),
    }


_EXCL_RE = re.compile(rf"^\s*({_MAC_PAT})\s+(.*?)\s*$")


def parse_exclusionlist(text: str) -> "dict[str, str]":
    """'show exclusionlist' -> {client MAC: the rest of its line (reason, time left)}."""
    out = {}
    for line in (text or "").splitlines():
        m = _EXCL_RE.match(line)
        if m:
            out[norm_mac(m.group(1))] = re.sub(r"\s{2,}", "  ", m.group(2))
    return out


# ------------------------------------------------------------------ IOS MAC table

_MACTABLE_RE = re.compile(
    r"^\s*(?P<vlan>\d+|All)\s+(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<type>\S+)\s+(?:\S+\s+)*?(?P<port>(?:[A-Za-z]+[\d/.:]+|CPU|Drop|Router))\s*$")


def parse_mac_table(text: str) -> "list[dict]":
    """IOS / IOS-XE 'show mac address-table [dynamic]' -> vlan, mac, type, port."""
    from .parsers import short_ifname

    entries = []
    for line in (text or "").splitlines():
        m = _MACTABLE_RE.match(line)
        if m:
            entries.append({"vlan": m.group("vlan"), "mac": norm_mac(m.group("mac")),
                            "type": m.group("type"), "port": short_ifname(m.group("port"))})
    return entries


# ------------------------------------------------------------------ correlation

def match_ap(radio_mac: str, aps: "list[dict]") -> "tuple[dict | None, str]":
    """Find the AP whose base radio MAC is radio_mac.

    Exact first. Otherwise an AP whose base MAC shares the first five octets
    and the top nibble of the last one: an AP's per-radio/per-SSID BSSIDs sit
    just above its base MAC. Returns (ap, 'exact' | 'approx' | '').
    """
    radio_mac = norm_mac(radio_mac)
    if not radio_mac:
        return None, ""
    for ap in aps:
        if ap["radio_mac"] == radio_mac:
            return ap, "exact"
    head, last = radio_mac[:14], int(radio_mac[15:], 16)
    for ap in aps:
        base = ap["radio_mac"]
        if base[:14] == head and (int(base[15:], 16) & 0xF0) == (last & 0xF0):
            return ap, "approx"
    return None, ""


def _uplink_ports(audit_hosts) -> "dict[str, set]":
    """Per switch name: ports the audit identified as uplinks (lower-cased names)."""
    out = {}
    for h in audit_hosts or []:
        name = (h.get("name") or "").lower()
        ups = {i["interface"] for i in h.get("interfaces", []) if i.get("is_uplink")}
        out[name] = ups
    return out


def _port_descriptions(audit_hosts) -> "dict[tuple, str]":
    return {((h.get("name") or "").lower(), i["interface"]): i.get("description", "")
            for h in audit_hosts or [] for i in h.get("interfaces", [])}


def locate_mac(mac: str, mac_tables: "dict[str, list]", audit_hosts=None):
    """The switch edge port where mac is learned, skipping uplinks and port-channels.

    Returns {'switch', 'port', 'vlan', 'description'} or None. Without audit
    data only port-channels count as uplinks, so a result may then be an
    upstream switch's uplink - the 'certain' flag says which case applies.
    """
    mac = norm_mac(mac)
    if not mac:
        return None
    uplinks = _uplink_ports(audit_hosts)
    descs = _port_descriptions(audit_hosts)
    fallback = None
    for switch, entries in sorted(mac_tables.items()):
        key = switch.lower()
        for e in entries:
            if e["mac"] != mac:
                continue
            port = e["port"]
            if port.startswith("Po") or port in uplinks.get(key, set()):
                fallback = fallback or {"switch": switch, "port": port, "vlan": e["vlan"],
                                        "description": descs.get((key, port), ""),
                                        "certain": False}
                continue
            return {"switch": switch, "port": port, "vlan": e["vlan"],
                    "description": descs.get((key, port), ""),
                    "certain": key in uplinks}
    return fallback


def build_trace(problems, aps=None, ap_summary=None, client_details=None,
                exclusions=None, mac_tables=None, audit_hosts=None) -> "list[dict]":
    """Join problem devices with controller and switch data into one row each."""
    aps = aps or []
    ap_summary = ap_summary or {}
    client_details = client_details or {}
    exclusions = exclusions or {}
    mac_tables = mac_tables or {}
    rows = []
    for p in problems:
        row = dict(p, random_mac=is_random_mac(p["mac"]), ap=None, switch=None,
                   live=client_details.get(p["mac"], "unknown"),
                   excluded=exclusions.get(p["mac"]))
        ap, how = match_ap(p.get("ap_radio_mac", ""), aps)
        if ap:
            info = dict(ap, match=how)
            info.update({k: v for k, v in ap_summary.get(ap["name"], {}).items()
                         if k in ("model", "location", "clients")})
            row["ap"] = info
            row["switch"] = locate_mac(ap["eth_mac"], mac_tables, audit_hosts)
        rows.append(row)
    return rows


def by_access_point(rows) -> "list[dict]":
    """Problem devices grouped per AP, busiest first - a walking list for a site visit."""
    groups = {}
    for r in rows:
        ap = r.get("ap")
        key = ap["name"] if ap else (r.get("ap_radio_mac") or "unknown AP")
        g = groups.setdefault(key, {"ap": key, "location": (ap or {}).get("location", ""),
                                    "switch": r.get("switch"), "devices": 0, "requests": 0,
                                    "macs": [], "group": r.get("group", "")})
        g["devices"] += 1
        g["requests"] += r["requests"]
        g["macs"].append(r["mac"])
    return sorted(groups.values(), key=lambda g: (-g["devices"], -g["requests"]))


# ------------------------------------------------------------------ collection (SSH)

CONTROLLER_COMMANDS = {
    "join_stats": "show ap join stats summary all",
    "ap_summary": "show ap summary",
    "exclusionlist": "show exclusionlist",
}


def collect_controller(host, client_macs, timeout: int = 60) -> dict:
    """Run the controller 'show' commands plus one 'show client detail' per problem MAC.

    Never raises; an error lands in result['error'].
    """
    from netmiko import ConnectHandler

    result = {"host": host.host, "name": host.display_name(), "group": host.group,
              "error": None, "outputs": {}, "client_detail": {}}
    device = {"device_type": host.device_type, "host": host.host, "username": host.username,
              "password": host.password, "port": host.port, "conn_timeout": 30}
    try:
        with ConnectHandler(**device) as conn:
            prompt = conn.find_prompt().strip("()#>* ")
            if not host.name and prompt:
                result["name"] = prompt
            for key, command in CONTROLLER_COMMANDS.items():
                try:
                    result["outputs"][key] = conn.send_command(command, read_timeout=timeout)
                except Exception as exc:
                    result["outputs"][key] = ""
                    result.setdefault("command_errors", {})[command] = str(exc)
            for mac in client_macs:
                try:
                    result["client_detail"][mac] = conn.send_command(
                        f"show client detail {mac}", read_timeout=timeout)
                except Exception as exc:
                    result.setdefault("command_errors", {})[f"show client detail {mac}"] = str(exc)
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def assign_groups(problems, controllers, default_group: str = "") -> None:
    """Tag each problem with its campus: the controller whose IP sent the request (NAS IP)."""
    by_ip = {c.host: c for c in controllers}
    only = controllers[0] if len(controllers) == 1 else None
    for p in problems:
        c = by_ip.get(p.get("nas_ip", "")) or only
        p["group"] = (c.group if c else "") or default_group
        p["controller"] = c.host if c else ""


def parse_saved_controller_output(text: str) -> dict:
    """AP data from controller CLI output saved to a file (no SSH).

    The file may hold 'show ap join stats summary all' (radio MAC -> AP name,
    the part that matters), 'show ap summary' (location, model) and
    'show exclusionlist', in any order and in one file or several: each
    parser only picks up the lines it recognises. Paging prompts copied along
    with the output ('--More-- or (q)uit') are dropped first.
    """
    text = re.sub(r"--More--\s*(?:or \(q\)uit)?", "", text or "")
    return {"aps": parse_ap_join_stats(text), "ap_summary": parse_ap_summary(text),
            "exclusions": parse_exclusionlist(text)}


def run_trace(problems, controllers, switches, outdir, offline: bool = False,
              skip_switches: bool = False, audit_hosts=None, workers: int = 8,
              timeout: int = 60, formats=("json", "html"), meta=None, progress=None,
              saved_outputs=None):
    """Collect controller + switch data for the problem devices, correlate, write outputs.

    offline reuses the controller/switch data cached in the previous trace.json
    (no SSH, so no live client state). saved_outputs ({file name: text}) supplies
    the AP list from saved controller output instead of logging in to the
    controller. Returns (trace dict, messages).
    """
    import json
    from pathlib import Path

    from . import __version__, report

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    say = progress or (lambda msg: None)
    messages = []
    cache_path = outdir / "trace.json"
    cache = {}
    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            cache = {}

    ctrl_data = {}      # host -> {name, group, error, aps, ap_summary, collected}
    client_details = {}
    exclusions = {}
    if saved_outputs:
        merged = {"aps": [], "ap_summary": {}}
        for fname, text in saved_outputs.items():
            got = parse_saved_controller_output(text)
            merged["aps"].extend(got["aps"])
            merged["ap_summary"].update(got["ap_summary"])
            exclusions.update(got["exclusions"])
            say(f"Saved controller output {fname}: {len(got['aps'])} APs with radio MACs, "
                f"{len(got['ap_summary'])} with locations")
        if not merged["aps"]:
            messages.append("saved controller output has no 'show ap join stats summary all' "
                            "lines - that command is what maps radio MACs to AP names")
        ctrl_data = {"saved": dict(merged, name="saved output", group="", error=None,
                                   source=sorted(saved_outputs),
                                   collected=datetime.now().astimezone().isoformat(
                                       timespec="seconds"))}
    elif offline:
        ctrl_data = cache.get("controllers", {})
        if not ctrl_data:
            messages.append("offline: no cached controller data - AP names unavailable "
                            "(run once without --offline, or pass --ap-list)")
    else:
        for c in controllers:
            macs = [p["mac"] for p in problems if p.get("controller") in ("", c.host)]
            say(f"Controller {c.display_name()} [{c.host}]: querying {len(macs)} client(s)...")
            res = collect_controller(c, macs, timeout=timeout)
            if res["error"]:
                messages.append(f"controller {res['name']} [{c.host}]: FAILED ({res['error']})")
                if c.host in cache.get("controllers", {}):
                    ctrl_data[c.host] = cache["controllers"][c.host]
                    messages.append("  using its cached AP list from the previous trace")
                continue
            outs = res["outputs"]
            ctrl_data[c.host] = {"name": res["name"], "group": c.group, "error": None,
                                 "aps": parse_ap_join_stats(outs.get("join_stats", "")),
                                 "ap_summary": parse_ap_summary(outs.get("ap_summary", "")),
                                 "collected": datetime.now().astimezone().isoformat(
                                     timespec="seconds")}
            exclusions.update(parse_exclusionlist(outs.get("exclusionlist", "")))
            for mac, text in res["client_detail"].items():
                client_details[mac] = parse_client_detail(text)
            say(f"  {len(ctrl_data[c.host]['aps'])} APs, "
                f"{sum(1 for v in res['client_detail'].values() if parse_client_detail(v))} "
                f"of the problem devices connected now")
            if not ctrl_data[c.host]["aps"]:
                messages.append(f"controller {res['name']}: no APs parsed from "
                                f"'{CONTROLLER_COMMANDS['join_stats']}' - check the output format")

    aps, ap_summary = [], {}
    for d in ctrl_data.values():
        aps.extend(d.get("aps", []))
        ap_summary.update(d.get("ap_summary", {}))

    mac_tables, mac_errors = {}, {}
    needs_ports = any(match_ap(p.get("ap_radio_mac", ""), aps)[0] for p in problems)
    if offline:
        mac_tables = cache.get("mac_tables", {})
    elif skip_switches or not needs_ports:
        pass
    else:
        groups = {p.get("group") for p in problems if p.get("group")}
        scope = [s for s in switches if not groups or s.group in groups]
        say(f"Reading MAC address tables from {len(scope)} switch(es)...")
        got = collect_mac_tables(scope, workers=workers, timeout=timeout,
                                 progress=lambda n, cnt, err: say(
                                     f"  {n}: {'FAILED (' + err + ')' if err else f'{cnt} MACs'}"))
        mac_tables, mac_errors = got["tables"], got["errors"]

    rows = build_trace(problems, aps, ap_summary, client_details if not offline else {},
                       exclusions, mac_tables, audit_hosts)
    trace = dict(meta or {})
    trace.update({
        "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "tool_version": __version__,
        "offline": offline,
        "devices": rows,
        "by_ap": by_access_point(rows),
        "controllers": ctrl_data,
        "mac_tables": mac_tables,
        "mac_table_errors": mac_errors,
    })
    if "json" in formats:
        report.write_json(trace, cache_path)
        messages.append(f"Wrote {cache_path}")
    if "html" in formats:
        html_path = outdir / "trace.html"
        html_path.write_text(report.render_trace_html(trace), encoding="utf-8")
        messages.append(f"Wrote {html_path}")
    return trace, messages


def collect_mac_tables(hosts, workers: int = 8, timeout: int = 60, progress=None) -> "dict":
    """'show mac address-table dynamic' from each switch -> {switch name: [entries]}, errors."""
    from netmiko import ConnectHandler

    def one(host):
        name = host.display_name()
        device = {"device_type": host.device_type, "host": host.host,
                  "username": host.username, "password": host.password,
                  "port": host.port, "conn_timeout": 30}
        if host.secret:
            device["secret"] = host.secret
        try:
            with ConnectHandler(**device) as conn:
                if host.secret:
                    conn.enable()
                prompt = conn.find_prompt().strip("#>* ")
                if not host.name and prompt:
                    name = prompt
                text = conn.send_command("show mac address-table dynamic", read_timeout=timeout)
            return name, parse_mac_table(text), None
        except Exception as exc:
            return name, [], f"{type(exc).__name__}: {exc}"

    tables, errors = {}, {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for name, entries, err in pool.map(one, hosts):
            if err:
                errors[name] = err
            else:
                tables[name] = entries
            if progress:
                progress(name, len(entries), err)
    return {"tables": tables, "errors": errors}

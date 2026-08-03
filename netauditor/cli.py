"""netauditor command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, analyzer
from .inventory import InventoryError, load_inventory
# Re-exported here for backwards compatibility (tests, external callers).
from .runner import _group_filename, _split_by_group, run_analyze, run_audit


def _parse_formats(value: str) -> "list[str]":
    formats = [f.strip().lower() for f in value.split(",") if f.strip()]
    bad = [f for f in formats if f not in ("json", "html")]
    if bad:
        raise argparse.ArgumentTypeError(f"unsupported format(s): {', '.join(bad)}")
    return formats or ["json", "html"]


def _filter_by_group(items, group_of, requested: str):
    """Filter items by comma-separated group names (case-insensitive).

    Returns (filtered_items, error_message). No requested groups means no filtering.
    """
    wanted = {g.strip().lower() for g in requested.split(",") if g.strip()}
    if not wanted:
        return items, None
    available = {group_of(i).lower() for i in items if group_of(i)}
    if not available:
        return items, "no campus/group information in the source (add groups to the inventory)"
    unknown = sorted(wanted - available)
    if unknown:
        return items, (f"unknown group(s): {', '.join(unknown)} "
                       f"(available: {', '.join(sorted(available))})")
    return [i for i in items if group_of(i).lower() in wanted], None


def cmd_audit(args) -> int:
    try:
        hosts = load_inventory(args.inventory, prompt_missing=not args.no_prompt)
    except InventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    hosts, err = _filter_by_group(hosts, lambda h: h.group, args.group)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    scope = f" in group(s) {args.group}" if args.group else ""
    print(f"Auditing {len(hosts)} switch(es){scope} with {args.workers} worker(s)...")

    def progress(result):
        state = f"FAILED ({result['error']})" if result.get("error") else "collected"
        print(f"  {result['name']} [{result['host']}]: {state}")

    _, counts, messages = run_audit(hosts, args.output, formats=args.formats,
                                    workers=args.workers, timeout=args.timeout,
                                    progress=progress)
    for line in messages:
        print(line)
    print(f"Findings: {counts['critical']} critical, {counts['warning']} warning, {counts['info']} info")
    return 1 if counts["critical"] else 0


def cmd_analyze(args) -> int:
    try:
        configs, groups = analyzer.load_configs(args.source)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.group:
        names, err = _filter_by_group(sorted(configs), lambda n: groups.get(n, ""), args.group)
        if err:
            print(f"error: {err}", file=sys.stderr)
            return 2
        configs = {n: c for n, c in configs.items() if n in set(names)}
    if args.hosts:
        wanted = [h.strip() for h in args.hosts.split(",") if h.strip()]
        unknown = [h for h in wanted if h not in configs]
        if unknown:
            print(f"error: unknown host(s) in --hosts: {', '.join(unknown)} "
                  f"(available: {', '.join(sorted(configs))})", file=sys.stderr)
            return 2
        configs = {name: cfg for name, cfg in configs.items() if name in wanted}
    if len(configs) < 1:
        print("error: no configs found in source", file=sys.stderr)
        return 2
    if len(configs) < 2:
        print("note: only one config found - drift needs 2+ switches; running tests only.")

    try:
        result, messages = run_analyze(configs, groups, args.output, tests=args.tests,
                                       baseline=args.baseline, formats=args.formats,
                                       group_filter=args.group or "")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for line in messages:
        print(line)
    criticals = sum(1 for f in result["findings"] if f["severity"] == "critical")
    print(f"Drift items: {result['drift']['item_count']}; "
          f"findings: {len(result['findings'])} ({criticals} critical)")
    return 1 if criticals else 0


def cmd_connect(args) -> int:
    try:
        hosts = load_inventory(args.inventory, prompt_missing=not args.no_prompt)
    except InventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    hosts, err = _filter_by_group(hosts, lambda h: h.group, args.group)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    from . import connect

    matches = connect.match_hosts(hosts, args.target)
    if not matches:
        print(f"error: nothing in the inventory matches '{args.target}'", file=sys.stderr)
        return 2
    chosen = matches[0] if len(matches) == 1 else connect.choose_host(matches)
    if chosen is None:
        return 2
    return connect.open_session(chosen)


def cmd_ui(args) -> int:
    hosts = []
    if args.inventory:
        try:
            hosts = load_inventory(args.inventory, prompt_missing=not args.no_prompt,
                                   require_credentials=False)
        except InventoryError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        hosts, err = _filter_by_group(hosts, lambda h: h.group, args.group)
        if err:
            print(f"error: {err}", file=sys.stderr)
            return 2

    from .ui_data import build_rows, load_audit

    audit = load_audit(args.output)
    if audit and args.group:
        wanted = {g.strip().lower() for g in args.group.split(",") if g.strip()}
        audit = dict(audit, hosts=[h for h in audit.get("hosts", [])
                                   if (h.get("group") or "").lower() in wanted])
    if not hosts and audit is None:
        print("error: nothing to show - pass -i <inventory> and/or -o <dir with audit.json>",
              file=sys.stderr)
        return 2

    try:
        from .ui import AuditUI
    except ImportError as exc:
        print(f"error: the dashboard needs the 'textual' package (pip install textual): {exc}",
              file=sys.stderr)
        return 2
    out = Path(args.output)
    outdir = out if out.is_dir() or not out.suffix else out.parent
    AuditUI(build_rows(hosts, audit), inv_hosts=hosts, outdir=outdir,
            generated=(audit or {}).get("generated", "")).run()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="netauditor",
        description="SSH switch auditor: port/STP health checks, config export, drift analysis.")
    parser.add_argument("--version", action="version", version=f"netauditor {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="SSH to every switch, run checks, export reports")
    p_audit.add_argument("-i", "--inventory", required=True, help="inventory file (YAML or plain text)")
    p_audit.add_argument("-o", "--output", default="out", help="output directory (default: out)")
    p_audit.add_argument("--formats", type=_parse_formats, default=["json", "html"],
                         help="comma-separated: json,html (default: both)")
    p_audit.add_argument("--workers", type=int, default=8, help="parallel SSH sessions (default: 8)")
    p_audit.add_argument("--timeout", type=int, default=30, help="per-command timeout seconds (default: 30)")
    p_audit.add_argument("-g", "--group", default="",
                         help="audit only these inventory groups/campuses, comma-separated "
                              "(default: all hosts)")
    p_audit.add_argument("--no-prompt", action="store_true",
                         help="never prompt for credentials (fail instead)")
    p_audit.set_defaults(func=cmd_audit)

    p_an = sub.add_parser("analyze", help="detect config drift between switches, run extra tests")
    p_an.add_argument("source", help="audit.json from an audit run, or a directory of *.cfg files")
    p_an.add_argument("-o", "--output", default="out", help="output directory (default: out)")
    p_an.add_argument("--formats", type=_parse_formats, default=["json", "html"],
                      help="comma-separated: json,html (default: both)")
    p_an.add_argument("--tests", default="",
                      help=f"extra test suites, comma-separated: {', '.join(analyzer.TESTS)}, all")
    p_an.add_argument("--baseline", default=None, metavar="SWITCH",
                      help="switch name whose config is the known-good reference; drift is "
                           "reported relative to it instead of the majority consensus")
    p_an.add_argument("-g", "--group", default="",
                      help="analyze only these groups/campuses, comma-separated "
                           "(default: all; requires an audit.json source with groups)")
    p_an.add_argument("--hosts", default="",
                      help="comma-separated switch names to compare (default: all in source)")
    p_an.set_defaults(func=cmd_analyze)

    p_conn = sub.add_parser("connect",
                            help="open a live SSH session to a switch using inventory credentials")
    p_conn.add_argument("target", nargs="?", default="",
                        help="switch name or IP (substring is fine); omit to pick from a list")
    p_conn.add_argument("-i", "--inventory", required=True,
                        help="inventory file (YAML or plain text)")
    p_conn.add_argument("-g", "--group", default="",
                        help="limit the candidates to these groups/campuses, comma-separated")
    p_conn.add_argument("--no-prompt", action="store_true",
                        help="never prompt for credentials (fail instead)")
    p_conn.set_defaults(func=cmd_connect)

    p_ui = sub.add_parser("ui", help="interactive terminal dashboard: audit browser + SSH")
    p_ui.add_argument("-i", "--inventory", default="",
                      help="inventory file (enables the SSH action)")
    p_ui.add_argument("-o", "--output", default="out",
                      help="audit output dir (or audit.json) to browse (default: out)")
    p_ui.add_argument("-g", "--group", default="",
                      help="show only these groups/campuses, comma-separated")
    p_ui.add_argument("--no-prompt", action="store_true",
                      help="never prompt for credentials (SSH action may be unavailable)")
    p_ui.set_defaults(func=cmd_ui)

    args = parser.parse_args(argv)
    if getattr(args, "tests", None) is not None and isinstance(args.tests, str):
        args.tests = [t.strip() for t in args.tests.split(",") if t.strip()]
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

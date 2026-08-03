"""Terminal command center (Textual), styled after dense ratatui-type dashboards:

status bar / campus tab strip / one full-width switch table / slim detail strip /
pipe-separated key hints. Enter drills into full-screen detail; audits and drift
checks run as background jobs with a live log screen.
"""
from __future__ import annotations

import datetime
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (Button, DataTable, Header, Input, Label, RichLog,
                             Static, Tab, TabbedContent, TabPane, Tabs)

from .ui_data import (ALL_ROW_NAME, SEVERITY_CYCLE, aggregate_row, build_rows,
                      campuses, filter_findings, load_drift)

_SEV_STYLE = {"critical": "bold red", "warning": "yellow", "info": "cyan"}
_UNGROUPED_LABEL = "ungrouped"


def _sev(severity: str) -> Text:
    return Text(severity, style=_SEV_STYLE.get(severity, ""))


def _hints(pairs) -> Text:
    text = Text()
    for i, (key, label) in enumerate(pairs):
        if i:
            text.append(" | ", style="dim")
        text.append(key, style="bold cyan")
        text.append(f" {label}", style="dim")
    return text


def _count(value: int, style: str) -> Text:
    return Text(str(value), style=style if value else "dim")


class HostTable(DataTable):
    """DataTable that gives left/right to campus switching instead of columns."""

    BINDINGS = [
        Binding("left", "app.prev_campus", "campus", show=False),
        Binding("right", "app.next_campus", "campus", show=False),
    ]


class CredentialsScreen(ModalScreen):
    """Prompt for SSH credentials when the inventory has none."""

    CSS = """
    CredentialsScreen { align: center middle; }
    #creds { width: 60; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #creds Button { margin: 1 2 0 0; }
    """

    def __init__(self, default_user: str = ""):
        super().__init__()
        self.default_user = default_user

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="creds"):
            yield Label("SSH credentials (applied to hosts without inline credentials)")
            yield Input(placeholder="username", value=self.default_user, id="cred-user")
            yield Input(placeholder="password", password=True, id="cred-pass")
            with Horizontal():
                yield Button("OK", variant="primary", id="cred-ok")
                yield Button("Cancel", id="cred-cancel")

    @on(Button.Pressed, "#cred-ok")
    def _ok(self, _event) -> None:
        self.dismiss((self.query_one("#cred-user", Input).value,
                      self.query_one("#cred-pass", Input).value))

    @on(Input.Submitted, "#cred-pass")
    def _submit(self, _event) -> None:
        self._ok(_event)

    @on(Button.Pressed, "#cred-cancel")
    def _cancel(self, _event) -> None:
        self.dismiss(None)


class DetailScreen(Screen):
    """Full-screen drill-in for one switch (or an aggregate scope)."""

    CSS = """
    #dheader { height: 2; padding: 0 1; border: round $secondary; }
    #dtabs { border: round $secondary; }
    #search { margin: 0 1; }
    #config { padding: 0 1; }
    #dhint { dock: bottom; height: 1; padding: 0 1; background: $surface; }
    """
    BINDINGS = [
        Binding("escape", "app.pop_screen", "back", show=False),
        Binding("f", "cycle_severity", "severity", show=False),
        Binding("slash", "focus_search", "search", show=False),
        Binding("s", "ssh", "ssh", show=False),
    ]

    def __init__(self, row: dict):
        super().__init__()
        self.row = row
        self.severity = "all"
        self.search_text = ""  # NB: must not be called "query" - that shadows Screen.query()

    def compose(self) -> ComposeResult:
        yield Static(id="dheader")
        with TabbedContent(id="dtabs"):
            with TabPane("Findings", id="tab-findings"):
                yield Input(placeholder="filter findings... ( / )", id="search")
                yield DataTable(id="findings")
            with TabPane("Interfaces", id="tab-interfaces"):
                yield DataTable(id="interfaces")
            with TabPane("Config", id="tab-config"):
                with VerticalScroll():
                    yield Static("", id="config")
        yield Static(_hints([("esc", "back"), ("tab", "next pane"), ("f", "severity"),
                             ("/", "find"), ("s", "ssh"), ("q", "quit")]), id="dhint")

    def on_mount(self) -> None:
        row = self.row
        findings = self.query_one("#findings", DataTable)
        findings.cursor_type = "row"
        findings.zebra_stripes = True
        findings.add_columns("Sev", "Switch", "Code", "Port", "Message")
        interfaces = self.query_one("#interfaces", DataTable)
        interfaces.cursor_type = "row"
        interfaces.zebra_stripes = True
        interfaces.add_columns("Port", "Description", "Status", "VLAN",
                               "Uplink", "PortFast", "BPDUguard", "Err/CRC")
        for i in row["interfaces"]:
            uplink = i.get("uplink_reason", "") if i.get("is_uplink") else ""
            interfaces.add_row(
                i.get("interface", ""), Text(str(i.get("description", ""))),
                i.get("status", ""), str(i.get("vlan", "")), Text(uplink),
                "yes" if i.get("portfast") else "no",
                "yes" if i.get("bpduguard") else "no",
                f"{i.get('input_errors', 0)}/{i.get('crc', 0)}")
        self.query_one("#config", Static).update(
            Text(row["config"] or "(no config collected)"))
        facts = row.get("facts") or {}
        header = Text()
        header.append(row["name"], style="bold cyan")
        if row.get("host"):
            header.append(f"  {row['host']}", style="dim")
        if row.get("group"):
            header.append(f"  campus:{row['group']}", style="blue")
        label = " ".join(str(v) for v in (facts.get("model"), facts.get("version")) if v)
        if label:
            header.append(f"  {label}")
        header.append(f"\n✗ {row['critical']} critical", style="bold red")
        header.append(f"  ! {row['warning']} warning", style="yellow")
        header.append(f"  · {row['info']} info", style="cyan")
        if row.get("error"):
            header.append(f"  UNREACHABLE: {row['error']}", style="bold red")
        self.query_one("#dheader", Static).update(header)
        self._refresh_findings()
        findings.focus()

    def action_cycle_severity(self) -> None:
        idx = SEVERITY_CYCLE.index(self.severity)
        self.severity = SEVERITY_CYCLE[(idx + 1) % len(SEVERITY_CYCLE)]
        self._refresh_findings()

    def action_focus_search(self) -> None:
        self.query_one("#dtabs", TabbedContent).active = "tab-findings"
        self.query_one("#search", Input).focus()

    def action_ssh(self) -> None:
        self.app.open_ssh(self.row)

    @on(Input.Changed, "#search")
    def _search_changed(self, event: Input.Changed) -> None:
        self.search_text = event.value
        self._refresh_findings()

    @on(Input.Submitted, "#search")
    def _search_done(self, _event) -> None:
        self.query_one("#findings", DataTable).focus()

    def _refresh_findings(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.clear()
        shown = filter_findings(self.row["findings"], self.severity, self.search_text)
        for f in shown:
            table.add_row(_sev(f.get("severity", "")), f.get("host", ""),
                          f.get("code", ""), f.get("interface", ""),
                          Text(str(f.get("message", ""))))
        self.query_one("#dtabs", TabbedContent).get_tab("tab-findings").label = \
            f"Findings [{self.severity}] {len(shown)}/{len(self.row['findings'])}"


class DriftScreen(Screen):
    """Full-screen drift results."""

    CSS = """
    #drheader { height: 1; padding: 0 1; }
    #drift { border: round $secondary; }
    #drhint { dock: bottom; height: 1; padding: 0 1; background: $surface; }
    """
    BINDINGS = [Binding("escape", "app.pop_screen", "back", show=False)]

    def __init__(self, result: dict):
        super().__init__()
        self.result = result or {}

    def compose(self) -> ComposeResult:
        yield Static(id="drheader")
        yield DataTable(id="drift")
        yield Static(_hints([("esc", "back"), ("q", "quit")]), id="drhint")

    def on_mount(self) -> None:
        items = (self.result.get("drift") or {}).get("items", [])
        findings = self.result.get("findings", [])
        criticals = sum(1 for f in findings if f["severity"] == "critical")
        header = Text("Config drift", style="bold cyan")
        header.append(f"  {len(items)} item(s)", style="yellow" if items else "green")
        header.append(f"  ·  {len(findings)} test finding(s) ({criticals} critical)",
                      style="red" if criticals else "dim")
        if self.result.get("generated"):
            header.append(f"  ·  {self.result['generated']}", style="dim")
        self.query_one("#drheader", Static).update(header)
        table = self.query_one("#drift", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("Config block", "Missing on", "Variants")
        for item in items:
            table.add_row(Text(item.get("header", "")),
                          Text(", ".join(item.get("missing_on", []))),
                          str(len(item.get("variants", []))))
        table.focus()


class LogScreen(Screen):
    """Job log; live-updates while a job is running."""

    CSS = """
    #log { border: round $secondary; }
    #lhint { dock: bottom; height: 1; padding: 0 1; background: $surface; }
    """
    BINDINGS = [Binding("escape", "app.pop_screen", "back", show=False)]

    def compose(self) -> ComposeResult:
        yield RichLog(id="log", wrap=True, highlight=False, markup=False)
        yield Static(_hints([("esc", "back"), ("q", "quit")]), id="lhint")

    def on_mount(self) -> None:
        log = self.query_one("#log", RichLog)
        log.border_title = "Job log"
        for line in self.app.log_lines:
            log.write(line)

    def append(self, line: str) -> None:
        self.query_one("#log", RichLog).write(line)


class AuditUI(App):
    """Main command-center screen."""

    TITLE = "netauditor"
    CSS = """
    #statusbar { dock: top; height: 3; border: round $accent; padding: 0 1; }
    #campustabs { dock: top; height: 2; }
    #hosts { height: 1fr; border: round $secondary; }
    #hostsearch { dock: bottom; display: none; height: 3; margin: 0 1; }
    #hostsearch.visible { display: block; }
    #detailstrip { dock: bottom; height: 4; border: round $secondary; padding: 0 1; }
    #hintbar { dock: bottom; height: 1; padding: 0 1; background: $surface; }
    """
    BINDINGS = [
        Binding("q", "quit", "quit", show=False, priority=False),
        Binding("enter", "open_detail", "detail", show=False),
        Binding("a", "audit", "audit", show=False),
        Binding("d", "drift", "drift", show=False),
        Binding("s", "ssh", "ssh", show=False),
        Binding("l", "show_log", "log", show=False),
        Binding("r", "reload", "reload", show=False),
        Binding("slash", "find", "find", show=False),
        Binding("escape", "clear_find", show=False),
    ]

    def __init__(self, rows, inv_hosts=None, outdir="out", generated=""):
        super().__init__()
        self.rows = rows
        self.inv_hosts = list(inv_hosts or [])
        self.outdir = Path(outdir)
        self.generated = generated
        self.campus = "All"
        self.host_filter = ""
        self.current_row = None
        self.log_lines: "list[str]" = []
        self.last_drift = None
        self._busy = False
        self._job_note = ""
        self._rowmap = {}

    # ------------------------------------------------------------- layout

    def compose(self) -> ComposeResult:
        yield Static(id="statusbar")
        names = [_UNGROUPED_LABEL if c == "" else c for c in campuses(self.rows)]
        yield Tabs(Tab("All", id="campus-all"),
                   *(Tab(n, id=f"campus-{i}") for i, n in enumerate(names)),
                   id="campustabs")
        yield HostTable(id="hosts")
        yield Input(placeholder="find switch... (esc clears)", id="hostsearch")
        yield Static(id="detailstrip")
        yield Static(_hints([("↑↓", "nav"), ("←→", "campus"), ("⏎", "detail"),
                             ("a", "audit"), ("d", "drift"), ("s", "ssh"),
                             ("l", "log"), ("/", "find"), ("r", "reload"),
                             ("q", "quit")]), id="hintbar")

    def on_mount(self) -> None:
        self._campus_names = ["All"] + [_UNGROUPED_LABEL if c == "" else c
                                        for c in campuses(self.rows)]
        tabs = self.query_one("#campustabs", Tabs)
        tabs.can_focus = False
        table = self.query_one("#hosts", HostTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.border_title = "Switches"
        table.add_columns("St", "Switch", "IP", "Campus", "Model", "IOS",
                          "Uptime", "C", "W")
        self.last_drift = load_drift(self.outdir)
        self._populate_hosts()
        self.set_interval(1.0, self._update_status)
        self._update_status()
        table.focus()

    # ------------------------------------------------------------- table

    def _visible_rows(self) -> "list[dict]":
        rows = self.rows
        if self.campus != "All":
            wanted = "" if self.campus == _UNGROUPED_LABEL else self.campus
            rows = [r for r in rows if (r.get("group") or "") == wanted]
        if self.host_filter:
            q = self.host_filter.lower()
            rows = [r for r in rows if q in r["name"].lower() or q in r["host"].lower()]
        return rows

    def _populate_hosts(self) -> None:
        table = self.query_one("#hosts", HostTable)
        table.clear()
        self._rowmap = {}
        scope = self._visible_rows()
        agg_name = ALL_ROW_NAME if self.campus == "All" else f"= {self.campus} ="
        agg = aggregate_row(scope, agg_name)
        self._rowmap["agg"] = agg
        table.add_row(Text("≡", style="bold"), Text(agg_name, style="bold"),
                      "", "", "", "", "",
                      _count(agg["critical"], "bold red"),
                      _count(agg["warning"], "yellow"), key="agg")
        if self.campus == "All":
            for campus in campuses(scope):
                label = _UNGROUPED_LABEL if campus == "" else campus
                members = [r for r in scope if (r.get("group") or "") == campus]
                key = f"sec:{label}"
                self._rowmap[key] = aggregate_row(members, f"= {label} =")
                table.add_row(Text("─", style="blue"),
                              Text(f"── {label} ──", style="bold blue"),
                              "", "", "", "", "", "", "", key=key)
                for r in members:
                    self._add_host_row(table, r)
        else:
            for r in scope:
                self._add_host_row(table, r)
        self.current_row = agg
        self._update_detailstrip()

    def _add_host_row(self, table, r) -> None:
        key = f"h:{id(r)}"
        self._rowmap[key] = r
        if r.get("error"):
            st = Text("✗", style="bold red")
            style = "red"
        elif r["critical"]:
            st = Text("✗", style="bold red")
            style = ""
        elif r["warning"]:
            st = Text("!", style="yellow")
            style = ""
        else:
            st = Text("●", style="green")
            style = ""
        facts = r.get("facts") or {}
        table.add_row(
            st,
            Text(r["name"], style=style or "bold"),
            Text(r["host"], style=style or ""),
            Text(r.get("group") or "", style=style or "blue"),
            Text(str(facts.get("model") or ""), style=style or ""),
            Text(str(facts.get("version") or ""), style=style or "dim"),
            Text(str(facts.get("uptime") or ""), style=style or "dim"),
            _count(r["critical"], "bold red"),
            _count(r["warning"], "yellow"),
            key=key)

    @on(DataTable.RowHighlighted, "#hosts")
    def _host_changed(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        row = self._rowmap.get(event.row_key.value)
        if row is not None:
            self.current_row = row
            self._update_detailstrip()

    @on(DataTable.RowSelected, "#hosts")
    def _host_selected(self, event: DataTable.RowSelected) -> None:
        self.action_open_detail()

    @on(Tabs.TabActivated, "#campustabs")
    def _campus_changed(self, event: Tabs.TabActivated) -> None:
        label = str(event.tab.label)
        self.campus = "All" if label == "All" else label
        self._populate_hosts()
        self._update_status()

    @on(Input.Changed, "#hostsearch")
    def _find_changed(self, event: Input.Changed) -> None:
        self.host_filter = event.value
        self._populate_hosts()

    @on(Input.Submitted, "#hostsearch")
    def _find_done(self, _event) -> None:
        self.query_one("#hosts", HostTable).focus()

    # ------------------------------------------------------------- status/detail

    def _update_status(self) -> None:
        rows = [r for r in self.rows]
        crit = sum(1 for r in rows if r["critical"] or r.get("error"))
        warn = sum(1 for r in rows if not r["critical"] and not r.get("error")
                   and r["warning"])
        clean = len(rows) - crit - warn
        text = Text()
        text.append("netauditor", style="bold cyan")
        text.append(f" | {len(rows)} switches | ", style="dim")
        text.append("● ", style="green")
        text.append(str(clean), style="green")
        text.append("  ✗ ", style="bold red")
        text.append(str(crit), style="bold red")
        text.append("  ! ", style="yellow")
        text.append(str(warn), style="yellow")
        text.append(f" | {datetime.datetime.now().strftime('%H:%M:%S')}", style="dim")
        if self._busy and self._job_note:
            text.append(f" | {self._job_note}", style="bold magenta")
        elif self.generated:
            text.append(f" | last audit {self.generated}", style="dim")
        else:
            text.append(" | no audit yet - press a", style="dim")
        if self.campus != "All":
            text.append(f" | campus: {self.campus}", style="blue")
        try:
            self.query_one("#statusbar", Static).update(text)
        except Exception:
            pass  # status bar not mounted (e.g. during shutdown)

    def _update_detailstrip(self) -> None:
        row = self.current_row
        strip = self.query_one("#detailstrip", Static)
        if row is None:
            strip.update("")
            return
        text = Text()
        text.append(row["name"], style="bold cyan")
        if row.get("host"):
            text.append(f"  ({row['host']})", style="dim")
        if row.get("group"):
            text.append(f"  campus:{row['group']}", style="blue")
        if row.get("is_aggregate"):
            text.append(f"  {row.get('member_count', 0)} switch(es)", style="dim")
        facts = row.get("facts") or {}
        label = " ".join(str(v) for v in (facts.get("model"), facts.get("version")) if v)
        if label:
            text.append(f"  {label}")
        text.append("\n")
        if row.get("error"):
            text.append(f"UNREACHABLE: {row['error']}", style="bold red")
        else:
            text.append(f"✗ {row['critical']} critical", style="bold red")
            text.append(f"   ! {row['warning']} warning", style="yellow")
            text.append(f"   · {row['info']} info", style="cyan")
            top = {}
            for f in row["findings"]:
                if f["severity"] in ("critical", "warning"):
                    top[f["code"]] = top.get(f["code"], 0) + 1
            if top:
                ranked = sorted(top.items(), key=lambda kv: -kv[1])[:4]
                text.append("   top: ", style="dim")
                text.append(", ".join(f"{c}({n})" for c, n in ranked), style="dim")
        strip.update(text)

    # ------------------------------------------------------------- actions

    def action_open_detail(self) -> None:
        if self.current_row is not None:
            self.push_screen(DetailScreen(self.current_row))

    def action_prev_campus(self) -> None:
        self.query_one("#campustabs", Tabs).action_previous_tab()

    def action_next_campus(self) -> None:
        self.query_one("#campustabs", Tabs).action_next_tab()

    def action_find(self) -> None:
        box = self.query_one("#hostsearch", Input)
        box.add_class("visible")
        box.focus()

    def action_clear_find(self) -> None:
        box = self.query_one("#hostsearch", Input)
        box.value = ""
        box.remove_class("visible")
        self.host_filter = ""
        self._populate_hosts()
        self.query_one("#hosts", HostTable).focus()

    def action_show_log(self) -> None:
        self.push_screen(LogScreen())

    def action_reload(self) -> None:
        from .ui_data import load_audit
        audit = load_audit(self.outdir)
        self._apply_audit(audit)
        self.last_drift = load_drift(self.outdir)
        self.notify("Reloaded results from disk.")

    def action_audit(self) -> None:
        if self._busy:
            self.notify("A job is already running - press l for the log.",
                        severity="warning")
            return
        if not self.inv_hosts:
            self.notify("No inventory loaded - start with -i <inventory> to run audits.",
                        severity="warning")
            return
        missing = [h for h in self.inv_hosts if not h.username or not h.password]
        if missing:
            default_user = next((h.username for h in self.inv_hosts if h.username), "")

            def with_creds(result) -> None:
                if not result:
                    return
                username, password = result
                for h in self.inv_hosts:
                    h.username = h.username or username
                    h.password = h.password or password
                self._start_audit()

            self.push_screen(CredentialsScreen(default_user), with_creds)
            return
        self._start_audit()

    def action_drift(self) -> None:
        if self._busy:
            self.notify("A job is already running - press l for the log.",
                        severity="warning")
            return
        if not (self.outdir / "audit.json").exists():
            self.notify("No audit.json yet - run an audit first (a).", severity="warning")
            return
        self._busy = True
        self._job_note = "drift check running..."
        self._show_log_screen()
        self._drift_worker()

    def action_ssh(self) -> None:
        self.open_ssh(self.current_row)

    def open_ssh(self, row) -> None:
        if not row:
            return
        if row.get("is_aggregate"):
            self.notify("Select a single switch to SSH.", severity="warning")
            return
        inv = row.get("inv")
        if inv is None:
            self.notify("No inventory entry for this host - SSH needs credentials "
                        "from the inventory.", severity="warning")
            return
        if not inv.username or not inv.password:
            self.notify("Inventory has no credentials for this host.", severity="warning")
            return
        from . import connect
        with self.suspend():
            connect.open_session(inv)
            try:
                input("\n[Enter] to return to the dashboard... ")
            except (EOFError, KeyboardInterrupt):
                pass

    # ------------------------------------------------------------- jobs

    def _show_log_screen(self) -> None:
        if not isinstance(self.screen, LogScreen):
            self.push_screen(LogScreen())

    def _start_audit(self) -> None:
        self._busy = True
        self._job_note = f"auditing 0/{len(self.inv_hosts)}..."
        self._show_log_screen()
        self._audit_worker(list(self.inv_hosts))

    @work(thread=True, exclusive=True, group="jobs")
    def _audit_worker(self, hosts) -> None:
        from .runner import run_audit

        done = {"n": 0}

        def progress(result):
            done["n"] += 1
            state = f"FAILED ({result['error']})" if result.get("error") else "collected"
            self.call_from_thread(self._log,
                                  f"  {result['name']} [{result['host']}]: {state}")
            self.call_from_thread(self._set_job_note,
                                  f"auditing {done['n']}/{len(hosts)}...")

        self.call_from_thread(self._log,
                              f"Audit started: {len(hosts)} switch(es) -> {self.outdir}")
        try:
            audit, counts, messages = run_audit(hosts, self.outdir, progress=progress)
        except Exception as exc:
            self.call_from_thread(self._job_failed, f"Audit failed: {exc}")
            return
        for line in messages:
            self.call_from_thread(self._log, line)
        self.call_from_thread(
            self._log, f"Audit done: {counts['critical']} critical, "
                       f"{counts['warning']} warning, {counts['info']} info.")
        self.call_from_thread(self._finish_audit, audit, counts)

    @work(thread=True, exclusive=True, group="jobs")
    def _drift_worker(self) -> None:
        from .analyzer import load_configs
        from .runner import run_analyze

        self.call_from_thread(self._log, f"Drift check started on {self.outdir} (tests: all)")
        try:
            configs, groups = load_configs(self.outdir)
            result, messages = run_analyze(configs, groups, self.outdir, tests=["all"])
        except Exception as exc:
            self.call_from_thread(self._job_failed, f"Drift check failed: {exc}")
            return
        for line in messages:
            self.call_from_thread(self._log, line)
        criticals = sum(1 for f in result["findings"] if f["severity"] == "critical")
        self.call_from_thread(
            self._log, f"Drift check done: {result['drift']['item_count']} drift item(s), "
                       f"{len(result['findings'])} finding(s) ({criticals} critical).")
        self.call_from_thread(self._finish_drift, result)

    def _set_job_note(self, note: str) -> None:
        self._job_note = note
        self._update_status()

    def _job_failed(self, message: str) -> None:
        self._busy = False
        self._job_note = ""
        self._log(message)
        self.notify(message, severity="error")

    def _finish_audit(self, audit, counts) -> None:
        self._busy = False
        self._job_note = ""
        self._apply_audit(audit)
        self.notify(f"Audit complete: {counts['critical']} critical, "
                    f"{counts['warning']} warning.")

    def _finish_drift(self, result) -> None:
        self._busy = False
        self._job_note = ""
        self.last_drift = result
        if isinstance(self.screen, LogScreen):
            self.pop_screen()
        self.push_screen(DriftScreen(result))

    # ------------------------------------------------------------- helpers

    def _log(self, line: str) -> None:
        self.log_lines.append(line)
        if isinstance(self.screen, LogScreen):
            self.screen.append(line)

    def _apply_audit(self, audit) -> None:
        self.rows = build_rows(self.inv_hosts, audit)
        self.generated = (audit or {}).get("generated", self.generated)
        self._populate_hosts()
        self._update_status()

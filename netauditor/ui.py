"""Terminal command center (Textual), styled after dense ratatui-type dashboards:

status bar / campus tab strip / one full-width switch table / slim detail strip /
pipe-separated key hints. Enter drills into full-screen detail; audits and drift
checks run as background jobs with a live log screen.
"""
from __future__ import annotations

import datetime
import time
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
                      campuses, filter_findings, hosts_for_scope, load_drift)

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


class ConfirmScreen(ModalScreen):
    """Yes/no confirmation; dismisses with True/False."""

    CSS = """
    ConfirmScreen { align: center middle; }
    #confirm { width: 70; height: auto; border: round $warning; padding: 1 2; background: $surface; }
    #confirm Button { margin: 1 2 0 0; }
    """
    BINDINGS = [Binding("escape", "cancel", show=False)]

    def __init__(self, message: str):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="confirm"):
            yield Label(self.message)
            with Horizontal():
                yield Button("Yes", variant="warning", id="confirm-yes")
                yield Button("Cancel", id="confirm-no")

    @on(Button.Pressed, "#confirm-yes")
    def _yes(self, _event) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#confirm-no")
    def _no(self, _event) -> None:
        self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


class DetailScreen(Screen):
    """Full-screen drill-in for one switch (or an aggregate scope)."""

    CSS = """
    #dheader { height: 2; padding: 0 1; border: round $secondary; }
    #dtabs { border: round $secondary; }
    #search { margin: 0 1; }
    #config { padding: 0 1; }
    #fix { height: auto; max-height: 10; padding: 0 1; border-top: solid $secondary; }
    #dhint { dock: bottom; height: 1; padding: 0 1; background: $surface; }
    """
    BINDINGS = [
        Binding("escape", "app.pop_screen", "back", show=False),
        Binding("f", "cycle_severity", "severity", show=False),
        Binding("slash", "focus_search", "search", show=False),
        Binding("s", "ssh", "ssh", show=False),
        Binding("a", "reaudit", "re-audit", show=False),
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
                yield Static(id="fix")
            with TabPane("Interfaces", id="tab-interfaces"):
                yield DataTable(id="interfaces")
            with TabPane("Config", id="tab-config"):
                with VerticalScroll():
                    yield Static("", id="config")
        yield Static(_hints([("esc", "back"), ("tab", "next pane"), ("f", "severity"),
                             ("/", "find"), ("s", "ssh"), ("a", "re-audit"),
                             ("q", "quit")]), id="dhint")

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
        if row.get("unsaved"):
            header.append("  ± UNSAVED CONFIG - lost at reboot", style="bold dark_orange")
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

    def action_reaudit(self) -> None:
        self.app.audit_single(self.row)

    @on(DataTable.RowHighlighted, "#findings")
    def _finding_changed(self, event: DataTable.RowHighlighted) -> None:
        self._update_fix(event.cursor_row)

    def _update_fix(self, index: int) -> None:
        from .remediation import snippet_for
        shown = filter_findings(self.row["findings"], self.severity, self.search_text)
        panel = self.query_one("#fix", Static)
        if not shown or index is None or index >= len(shown):
            panel.update("")
            return
        f = shown[index]
        snippet = snippet_for(f.get("code", ""), f.get("interface", ""))
        if not snippet:
            panel.update(Text("No mechanical fix for this finding - investigate.",
                              style="dim"))
            return
        text = Text()
        text.append(f"Suggested fix for {f.get('code', '')}", style="bold cyan")
        text.append("  (suggestion only - review before applying)\n", style="dim")
        text.append(snippet, style="green")
        panel.update(text)

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
        self._update_fix(0)


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


class ChangesScreen(Screen):
    """What changed since the previous audit snapshot."""

    CSS = """
    #chheader { height: 2; padding: 0 1; border: round $secondary; }
    #changes { border: round $secondary; }
    #chhint { dock: bottom; height: 1; padding: 0 1; background: $surface; }
    """
    BINDINGS = [Binding("escape", "app.pop_screen", "back", show=False)]

    def __init__(self, delta: dict, label: str):
        super().__init__()
        self.delta = delta or {}
        self.label = label

    def compose(self) -> ComposeResult:
        yield Static(id="chheader")
        yield DataTable(id="changes")
        yield Static(_hints([("esc", "back"), ("q", "quit")]), id="chhint")

    def on_mount(self) -> None:
        totals = self.delta.get("totals", {})
        header = Text("Changes since ", style="bold cyan")
        header.append(self.label, style="dim")
        header.append(f"\n✓ {totals.get('fixed', 0)} fixed", style="green")
        header.append(f"   + {totals.get('added', 0)} new", style="bold red")
        header.append(f"   = {totals.get('still_open', 0)} unchanged", style="dim")
        if self.delta.get("new_switches"):
            header.append(f"   new switches: {len(self.delta['new_switches'])}",
                          style="cyan")
        self.query_one("#chheader", Static).update(header)
        table = self.query_one("#changes", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("", "Switch", "Sev", "Code", "Port", "Message")
        for sw in self.delta.get("switches", []):
            for f in sw["fixed"]:
                table.add_row(Text("✓ fixed", style="green"), sw["name"],
                              _sev(f.get("severity", "")), f.get("code", ""),
                              f.get("interface", ""),
                              Text(str(f.get("message", ""))[:120]))
            for f in sw["added"]:
                table.add_row(Text("+ new", style="bold red"), sw["name"],
                              _sev(f.get("severity", "")), f.get("code", ""),
                              f.get("interface", ""),
                              Text(str(f.get("message", ""))[:120]))
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
    #unsavedbar { dock: top; height: 1; padding: 0 1; background: darkorange;
                  color: black; text-style: bold; display: none; }
    #unsavedbar.visible { display: block; }
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
        Binding("p", "prune", "prune", show=False),
        Binding("c", "changes", "changes", show=False),
        Binding("g", "generate_reports", "generate reports", show=False),
        Binding("w", "toggle_watch", "watch", show=False),
        Binding("slash", "find", "find", show=False),
        Binding("escape", "clear_find", show=False),
    ]

    def __init__(self, rows, inv_hosts=None, outdir="out", generated="",
                 probe_interval=15):
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
        # live reachability (watch mode)
        self.watch = bool(inv_hosts)
        self.probe_interval = max(5, int(probe_interval))
        self.probe_results: "dict[str, dict]" = {}
        self._probing = False
        self._next_scan_at = time.monotonic()

    # ------------------------------------------------------------- layout

    def compose(self) -> ComposeResult:
        yield Static(id="statusbar")
        yield Static(id="unsavedbar")
        names = [_UNGROUPED_LABEL if c == "" else c for c in campuses(self.rows)]
        yield Tabs(Tab("All", id="campus-all"),
                   *(Tab(n, id=f"campus-{i}") for i, n in enumerate(names)),
                   id="campustabs")
        yield HostTable(id="hosts")
        yield Input(placeholder="find switch... (esc clears)", id="hostsearch")
        yield Static(id="detailstrip")
        yield Static(_hints([("↑↓", "nav"), ("←→", "campus"), ("⏎", "detail"),
                             ("a", "audit scope"), ("d", "drift"), ("c", "changes"),
                             ("g", "reports"), ("s", "ssh"), ("w", "watch"),
                             ("l", "log"), ("/", "find"), ("p", "prune"),
                             ("r", "reload"), ("q", "quit")]),
                     id="hintbar")

    def on_mount(self) -> None:
        self._campus_names = ["All"] + [_UNGROUPED_LABEL if c == "" else c
                                        for c in campuses(self.rows)]
        tabs = self.query_one("#campustabs", Tabs)
        tabs.can_focus = False
        table = self.query_one("#hosts", HostTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.border_title = "Switches"
        for label, key in [("St", "st"), ("Switch", "switch"), ("IP", "ip"),
                           ("Campus", "campus"), ("Model", "model"), ("IOS", "ios"),
                           ("Audit", "audit"), ("ms", "ms"), ("Seen", "seen"),
                           ("Audited", "audited")]:
            table.add_column(label, key=key)
        self.last_drift = load_drift(self.outdir)
        self._populate_hosts()
        self._update_unsaved_banner()
        self.set_interval(1.0, self._tick)
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
                      "", "", "", "", self._audit_cell(agg), "", "", "", key="agg")
        if self.campus == "All":
            for campus in campuses(scope):
                label = _UNGROUPED_LABEL if campus == "" else campus
                members = [r for r in scope if (r.get("group") or "") == campus]
                key = f"sec:{label}"
                self._rowmap[key] = aggregate_row(members, f"= {label} =")
                table.add_row(Text("─", style="blue"),
                              Text(f"── {label} ──", style="bold blue"),
                              "", "", "", "", "", "", "", "", key=key)
                for r in members:
                    self._add_host_row(table, r)
        else:
            for r in scope:
                self._add_host_row(table, r)
        self.current_row = agg
        self._update_detailstrip()

    def _st_cell(self, r) -> Text:
        """Live reachability glyph when watch is on; audit-state glyph otherwise."""
        if r.get("ghost"):
            return Text("?", style="dim")
        if self.watch:
            pr = self.probe_results.get(r.get("host") or "")
            if pr is not None:
                return Text("●", style="green") if pr["ok"] else Text("✗", style="bold red")
            return Text("·", style="dim")  # not probed yet
        if r.get("error") or r["critical"]:
            return Text("✗", style="bold red")
        if r["warning"]:
            return Text("!", style="yellow")
        return Text("●", style="green")

    def _audit_cell(self, r) -> Text:
        """Audit flags: ✗n criticals, !n warnings, ● clean, - never audited."""
        if r.get("ghost"):
            return Text("stale", style="dim")
        if r.get("error"):
            return Text("unreach", style="bold red")
        if not r.get("audited_at") and not r["findings"]:
            return Text("-", style="dim")
        cell = Text()
        if r["critical"]:
            cell.append(f"✗{r['critical']} ", style="bold red")
        if r["warning"]:
            cell.append(f"!{r['warning']}", style="yellow")
        if not r["critical"] and not r["warning"]:
            cell.append("●", style="green")
        if r.get("unsaved"):
            cell.append(" ±", style="bold dark_orange")
        return cell

    def _probe_cells(self, r) -> "tuple[Text, Text]":
        pr = self.probe_results.get(r.get("host") or "")
        if not self.watch or pr is None:
            return Text("-", style="dim"), Text("-", style="dim")
        ms = Text(f"{pr['ms']}" if pr["ok"] else "-",
                  style="" if pr["ok"] else "red")
        seen = Text(pr.get("seen") or "-", style="dim")
        return ms, seen

    def _add_host_row(self, table, r) -> None:
        key = f"h:{id(r)}"
        self._rowmap[key] = r
        style = "dim" if r.get("ghost") else ("red" if r.get("error") else "")
        facts = r.get("facts") or {}
        audited = (r.get("audited_at") or "")[:16].replace("T", " ")
        ms, seen = self._probe_cells(r)
        table.add_row(
            self._st_cell(r),
            Text(r["name"], style=style or "bold"),
            Text(r["host"], style=style or ""),
            Text(r.get("group") or "", style=style or "blue"),
            Text(str(facts.get("model") or ""), style=style or ""),
            Text(str(facts.get("version") or ""), style=style or "dim"),
            self._audit_cell(r),
            ms, seen,
            Text(audited, style="dim"),
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

    # ------------------------------------------------------------- watch mode

    def action_toggle_watch(self) -> None:
        self.watch = not self.watch
        if self.watch:
            self._next_scan_at = time.monotonic()
            self.notify(f"Watch on - probing every {self.probe_interval}s.")
        else:
            self.notify("Watch off.")
        self._populate_hosts()
        self._update_status()

    def _tick(self) -> None:
        if self.watch and not self._probing and time.monotonic() >= self._next_scan_at:
            targets = [(r["host"], r["host"],
                        r["inv"].port if r.get("inv") else 22)
                       for r in self.rows if r.get("host") and not r.get("ghost")]
            if targets:
                self._probing = True
                self._probe_worker(targets)
        self._update_status()

    @work(thread=True, exclusive=True, group="probe")
    def _probe_worker(self, targets) -> None:
        from .probe import probe_all
        results = probe_all(targets, timeout=3.0)
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.call_from_thread(self._apply_probe, results, stamp)

    def _apply_probe(self, results, stamp) -> None:
        self._probing = False
        self._next_scan_at = time.monotonic() + self.probe_interval
        for host, ms in results.items():
            rec = self.probe_results.setdefault(host, {})
            rec["ok"] = ms is not None
            rec["ms"] = ms
            if ms is not None:
                rec["seen"] = stamp
        table = self.query_one("#hosts", HostTable)
        for key, row in self._rowmap.items():
            if not key.startswith("h:") or row.get("host") not in results:
                continue
            ms_cell, seen_cell = self._probe_cells(row)
            try:
                table.update_cell(key, "st", self._st_cell(row))
                table.update_cell(key, "ms", ms_cell)
                table.update_cell(key, "seen", seen_cell)
            except Exception:
                pass  # table repopulated mid-apply; next sweep catches up
        self._update_status()

    # ------------------------------------------------------------- status/detail

    def _update_status(self) -> None:
        ghosts = sum(1 for r in self.rows if r.get("ghost"))
        rows = [r for r in self.rows if not r.get("ghost")]
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
        text.append("  ? ", style="dim")
        text.append(str(ghosts), style="dim" if not ghosts else "bold magenta")
        if self.watch:
            probed = [self.probe_results.get(r["host"]) for r in rows if r.get("host")]
            up = sum(1 for p in probed if p and p["ok"])
            down = sum(1 for p in probed if p and not p["ok"])
            text.append(" | live ", style="dim")
            text.append(f"↑{up}", style="green")
            text.append(f" ↓{down}", style="bold red" if down else "dim")
            remaining = max(0, int(self._next_scan_at - time.monotonic()))
            text.append(" | scanning..." if self._probing else f" | next scan {remaining}s",
                        style="dim")
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

    def _update_unsaved_banner(self) -> None:
        affected = [r["name"] for r in self.rows
                    if r.get("unsaved") and not r.get("ghost")]
        banner = self.query_one("#unsavedbar", Static)
        if affected:
            names = ", ".join(affected[:6]) + (", ..." if len(affected) > 6 else "")
            banner.update(f"⚠ {len(affected)} switch(es) with UNSAVED config changes "
                          f"(lost at reboot): {names}")
            banner.add_class("visible")
        else:
            banner.remove_class("visible")

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
        if row.get("audited_at"):
            text.append(f"  audited {row['audited_at'][:16].replace('T', ' ')}",
                        style="dim")
        text.append("\n")
        if row.get("ghost"):
            text.append("NOT IN INVENTORY - removed or renamed switch; "
                        "press p to prune stale entries", style="bold magenta")
        elif row.get("error"):
            text.append(f"UNREACHABLE: {row['error']}", style="bold red")
        else:
            text.append(f"✗ {row['critical']} critical", style="bold red")
            text.append(f"   ! {row['warning']} warning", style="yellow")
            text.append(f"   · {row['info']} info", style="cyan")
            if row.get("unsaved"):
                text.append("   ± UNSAVED CONFIG", style="bold dark_orange")
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

    def action_generate_reports(self) -> None:
        """Re-render every HTML report from the stored audit data (no SSH)."""
        if self._busy:
            self.notify("A job is already running - press l for the log.",
                        severity="warning")
            return
        from .runner import regenerate_reports
        try:
            messages = regenerate_reports(self.outdir)
        except FileNotFoundError:
            self.notify("No audit.json yet - run an audit first (a).",
                        severity="warning")
            return
        except Exception as exc:
            self.notify(f"Report generation failed: {exc}", severity="error")
            return
        for line in messages:
            self._log(line)
        written = sum(1 for m in messages if m.startswith("Wrote"))
        self.notify(f"Regenerated {written} report file(s) in {self.outdir}.")

    def action_changes(self) -> None:
        from .history import (_stamp_from, diff_audits, load_snapshot,
                              previous_snapshot)
        from .ui_data import load_audit
        current = load_audit(self.outdir)
        if current is None:
            self.notify("No audit yet - press a to run one.", severity="warning")
            return
        prev_path = previous_snapshot(
            self.outdir, before_stamp=_stamp_from(current.get("generated", "")))
        if prev_path is None:
            self.notify("No earlier snapshot yet - this audit is the baseline.")
            return
        delta = diff_audits(load_snapshot(prev_path), current)
        self.push_screen(ChangesScreen(delta, prev_path.name))

    def action_reload(self) -> None:
        from .ui_data import load_audit
        audit = load_audit(self.outdir)
        self._apply_audit(audit)
        self.last_drift = load_drift(self.outdir)
        self.notify("Reloaded results from disk.")

    def action_audit(self) -> None:
        scope_hosts = hosts_for_scope(self.inv_hosts, self.campus,
                                      ungrouped_label=_UNGROUPED_LABEL)
        scope_label = "all campuses" if self.campus == "All" else self.campus
        self._request_audit(scope_hosts, scope_label)

    def audit_single(self, row) -> None:
        """Re-audit one switch (from the detail screen); merges into results."""
        if not row or row.get("is_aggregate"):
            self.notify("Select a single switch to re-audit.", severity="warning")
            return
        inv = row.get("inv")
        if inv is None:
            self.notify("Not in the inventory - nothing to connect with.",
                        severity="warning")
            return
        if isinstance(self.screen, DetailScreen):
            self.pop_screen()
        self._request_audit([inv], row["name"])

    def _request_audit(self, scope_hosts, scope_label) -> None:
        if self._busy:
            self.notify("A job is already running - press l for the log.",
                        severity="warning")
            return
        if not self.inv_hosts:
            self.notify("No inventory loaded - start with -i <inventory> to run audits.",
                        severity="warning")
            return
        if not scope_hosts:
            self.notify(f"No inventory hosts in scope '{scope_label}'.",
                        severity="warning")
            return
        missing = [h for h in scope_hosts if not h.username or not h.password]
        if missing:
            default_user = next((h.username for h in self.inv_hosts if h.username), "")

            def with_creds(result) -> None:
                if not result:
                    return
                username, password = result
                for h in self.inv_hosts:
                    h.username = h.username or username
                    h.password = h.password or password
                self._start_audit(scope_hosts, scope_label)

            self.push_screen(CredentialsScreen(default_user), with_creds)
            return
        self._start_audit(scope_hosts, scope_label)

    def action_prune(self) -> None:
        if self._busy:
            self.notify("A job is already running - press l for the log.",
                        severity="warning")
            return
        if not self.inv_hosts:
            self.notify("Pruning needs an inventory as the source of truth "
                        "(start with -i).", severity="warning")
            return
        ghost_rows = [r for r in self.rows if r.get("ghost")]
        if not ghost_rows:
            self.notify("No stale entries - audit data matches the inventory.")
            return
        names = ", ".join(r["name"] for r in ghost_rows[:8])
        if len(ghost_rows) > 8:
            names += ", ..."

        def confirmed(yes) -> None:
            if not yes:
                return
            from .runner import prune_audit
            try:
                removed, messages = prune_audit(self.inv_hosts, self.outdir, apply=True)
            except Exception as exc:
                self.notify(f"Prune failed: {exc}", severity="error")
                return
            for line in messages:
                self._log(line)
            from .ui_data import load_audit
            self._apply_audit(load_audit(self.outdir))
            self.notify(f"Pruned {len(removed)} stale entr(ies).")

        self.push_screen(ConfirmScreen(
            f"Remove {len(ghost_rows)} audit entr(ies) not in the inventory?\n\n"
            f"{names}\n\nReports will be regenerated without them."), confirmed)

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

    def _start_audit(self, scope_hosts, scope_label) -> None:
        self._busy = True
        self._job_note = f"auditing {scope_label} 0/{len(scope_hosts)}..."
        self._show_log_screen()
        self._audit_worker(list(scope_hosts), scope_label)

    @work(thread=True, exclusive=True, group="jobs")
    def _audit_worker(self, hosts, scope_label) -> None:
        from .runner import run_audit

        done = {"n": 0}

        def progress(result):
            done["n"] += 1
            state = f"FAILED ({result['error']})" if result.get("error") else "collected"
            self.call_from_thread(self._log,
                                  f"  {result['name']} [{result['host']}]: {state}")
            self.call_from_thread(self._set_job_note,
                                  f"auditing {scope_label} {done['n']}/{len(hosts)}...")

        self.call_from_thread(self._log,
                              f"Audit started: {len(hosts)} switch(es) "
                              f"[{scope_label}] -> {self.outdir}")
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
        self._update_unsaved_banner()
        self._update_status()

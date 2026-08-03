"""Terminal command center (Textual): run audits and drift checks, browse results, jump into SSH."""
from __future__ import annotations

from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (Button, DataTable, Footer, Header, Input, Label,
                             RichLog, Static, TabbedContent, TabPane)

from .ui_data import ALL_ROW_NAME, SEVERITY_CYCLE, build_rows, filter_findings, load_drift

_SEV_STYLE = {"critical": "bold red", "warning": "yellow", "info": "cyan"}


def _sev(severity: str) -> Text:
    return Text(severity, style=_SEV_STYLE.get(severity, ""))


def _sev_count(count: int, severity: str) -> Text:
    return Text(str(count), style=_SEV_STYLE[severity] if count else "dim")


class CredentialsScreen(ModalScreen):
    """Prompt for SSH credentials when the inventory has none."""

    CSS = """
    CredentialsScreen { align: center middle; }
    #creds { width: 60; height: auto; border: thick $accent; padding: 1 2; background: $surface; }
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


class AuditUI(App):
    """Hosts on the left; findings / interfaces / config / drift / log on the right."""

    TITLE = "netauditor"
    CSS = """
    #hosts { width: 42%; min-width: 44; border: solid $accent; }
    #tabs { border: solid $accent; }
    #search { margin: 0 1; }
    #config { padding: 0 1; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("a", "audit", "Run audit"),
        Binding("d", "drift", "Drift check"),
        Binding("s", "ssh", "SSH"),
        Binding("r", "reload", "Reload"),
        Binding("f", "cycle_severity", "Severity"),
        Binding("slash", "focus_search", "Search", key_display="/"),
        Binding("escape", "blur_search", show=False),
    ]

    def __init__(self, rows, inv_hosts=None, outdir="out"):
        super().__init__()
        self.rows = rows
        self.inv_hosts = list(inv_hosts or [])
        self.outdir = Path(outdir)
        self.current = rows[0] if rows else None
        self.severity = "all"
        self.query = ""
        self._busy = False

    # ------------------------------------------------------------- layout

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            yield DataTable(id="hosts")
            with TabbedContent(id="tabs"):
                with TabPane("Findings", id="tab-findings"):
                    yield Input(placeholder="filter findings... ( / )", id="search")
                    yield DataTable(id="findings")
                with TabPane("Interfaces", id="tab-interfaces"):
                    yield DataTable(id="interfaces")
                with TabPane("Config", id="tab-config"):
                    with VerticalScroll():
                        yield Static("", id="config")
                with TabPane("Drift", id="tab-drift"):
                    yield DataTable(id="drift")
                with TabPane("Log", id="tab-log"):
                    yield RichLog(id="log", wrap=True, highlight=False, markup=False)
        yield Footer()

    def on_mount(self) -> None:
        hosts = self.query_one("#hosts", DataTable)
        hosts.cursor_type = "row"
        hosts.zebra_stripes = True
        hosts.add_columns("Switch", "Host", "Campus", "C", "W")
        findings = self.query_one("#findings", DataTable)
        findings.cursor_type = "row"
        findings.zebra_stripes = True
        findings.add_columns("Sev", "Switch", "Code", "Port", "Message")
        interfaces = self.query_one("#interfaces", DataTable)
        interfaces.cursor_type = "row"
        interfaces.zebra_stripes = True
        interfaces.add_columns("Port", "Description", "Status", "VLAN",
                               "Uplink", "PortFast", "BPDUguard", "Err/CRC")
        drift = self.query_one("#drift", DataTable)
        drift.cursor_type = "row"
        drift.zebra_stripes = True
        drift.add_columns("Config block", "Missing on", "Variants")
        self._populate_hosts()
        self._populate_drift(load_drift(self.outdir))
        hosts.focus()
        self._refresh_detail()

    # ------------------------------------------------------------- events

    @on(DataTable.RowHighlighted, "#hosts")
    def _host_changed(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is not None and event.row_key.value is not None:
            self.current = self.rows[int(event.row_key.value)]
            self._refresh_detail()

    @on(Input.Changed, "#search")
    def _search_changed(self, event: Input.Changed) -> None:
        self.query = event.value
        self._refresh_findings()

    # ------------------------------------------------------------- actions

    def action_cycle_severity(self) -> None:
        idx = SEVERITY_CYCLE.index(self.severity)
        self.severity = SEVERITY_CYCLE[(idx + 1) % len(SEVERITY_CYCLE)]
        self._refresh_findings()

    def action_focus_search(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-findings"
        self.query_one("#search", Input).focus()

    def action_blur_search(self) -> None:
        self.query_one("#hosts", DataTable).focus()

    def action_reload(self) -> None:
        from .ui_data import load_audit
        self._apply_audit(load_audit(self.outdir))
        self._populate_drift(load_drift(self.outdir))
        self.notify("Reloaded results from disk.")

    def action_audit(self) -> None:
        if self._busy:
            self.notify("A job is already running - watch the Log tab.", severity="warning")
            return
        if not self.inv_hosts:
            self.notify("No inventory loaded - start the dashboard with -i <inventory> "
                        "to run audits.", severity="warning")
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
            self.notify("A job is already running - watch the Log tab.", severity="warning")
            return
        if not (self.outdir / "audit.json").exists():
            self.notify("No audit.json yet - run an audit first (a).", severity="warning")
            return
        self._busy = True
        self.query_one("#tabs", TabbedContent).active = "tab-log"
        self._drift_worker()

    def action_ssh(self) -> None:
        row = self.current
        if not row:
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

    def _start_audit(self) -> None:
        self._busy = True
        self.query_one("#tabs", TabbedContent).active = "tab-log"
        self._audit_worker(list(self.inv_hosts))

    @work(thread=True, exclusive=True, group="jobs")
    def _audit_worker(self, hosts) -> None:
        from .runner import run_audit

        def progress(result):
            state = f"FAILED ({result['error']})" if result.get("error") else "collected"
            self.call_from_thread(self._log, f"  {result['name']} [{result['host']}]: {state}")

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

    def _job_failed(self, message: str) -> None:
        self._busy = False
        self._log(message)
        self.notify(message, severity="error")

    def _finish_audit(self, audit, counts) -> None:
        self._busy = False
        self._apply_audit(audit)
        self.notify(f"Audit complete: {counts['critical']} critical, "
                    f"{counts['warning']} warning.")

    def _finish_drift(self, result) -> None:
        self._busy = False
        self._populate_drift(result)
        self.query_one("#tabs", TabbedContent).active = "tab-drift"
        self.notify(f"Drift check complete: {result['drift']['item_count']} item(s).")

    # ------------------------------------------------------------- rendering

    def _log(self, line: str) -> None:
        self.query_one("#log", RichLog).write(line)

    def _apply_audit(self, audit) -> None:
        self.rows = build_rows(self.inv_hosts, audit)
        self.current = self.rows[0] if self.rows else None
        self._populate_hosts()
        self._refresh_detail()

    def _populate_hosts(self) -> None:
        table = self.query_one("#hosts", DataTable)
        table.clear()
        for i, r in enumerate(self.rows):
            table.add_row(r["name"], r["host"], r["group"],
                          _sev_count(r["critical"], "critical"),
                          _sev_count(r["warning"], "warning"), key=str(i))

    def _populate_drift(self, result) -> None:
        table = self.query_one("#drift", DataTable)
        table.clear()
        items = ((result or {}).get("drift") or {}).get("items", [])
        for item in items:
            table.add_row(Text(item.get("header", "")),
                          Text(", ".join(item.get("missing_on", []))),
                          str(len(item.get("variants", []))))
        pane = self.query_one("#tabs", TabbedContent).get_tab("tab-drift")
        pane.label = f"Drift ({len(items)})" if items else "Drift"

    def _refresh_detail(self) -> None:
        row = self.current
        self._refresh_findings()
        interfaces = self.query_one("#interfaces", DataTable)
        interfaces.clear()
        config = self.query_one("#config", Static)
        if row is None:
            config.update("")
            return
        for i in row["interfaces"]:
            uplink = i.get("uplink_reason", "") if i.get("is_uplink") else ""
            interfaces.add_row(
                i.get("interface", ""), Text(str(i.get("description", ""))),
                i.get("status", ""), str(i.get("vlan", "")), Text(uplink),
                "yes" if i.get("portfast") else "no",
                "yes" if i.get("bpduguard") else "no",
                f"{i.get('input_errors', 0)}/{i.get('crc', 0)}")
        config.update(Text(row["config"] or "(no config collected)"))
        facts = row.get("facts") or {}
        label = " ".join(str(v) for v in (facts.get("model"), facts.get("version")) if v)
        self.sub_title = f"{row['name']}  {label}".strip()

    def _refresh_findings(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.clear()
        row = self.current
        if row is None:
            return
        shown = filter_findings(row["findings"], self.severity, self.query)
        for f in shown:
            table.add_row(_sev(f.get("severity", "")), f.get("host", ""),
                          f.get("code", ""), f.get("interface", ""),
                          Text(str(f.get("message", ""))))
        scope = "fleet" if row["name"] == ALL_ROW_NAME else row["name"]
        self.query_one("#tabs", TabbedContent).get_tab("tab-findings").label = \
            f"Findings [{self.severity}] {len(shown)}/{len(row['findings'])} - {scope}"

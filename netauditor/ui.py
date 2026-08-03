"""Terminal dashboard (Textual): browse audit results, drill into hosts, jump into SSH."""
from __future__ import annotations

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import DataTable, Footer, Header, Input, Static, TabbedContent, TabPane

from .ui_data import ALL_ROW_NAME, SEVERITY_CYCLE, filter_findings

_SEV_STYLE = {"critical": "bold red", "warning": "yellow", "info": "cyan"}


def _sev(severity: str) -> Text:
    return Text(severity, style=_SEV_STYLE.get(severity, ""))


class AuditUI(App):
    """Host list on the left; findings / interfaces / config tabs on the right."""

    TITLE = "netauditor"
    CSS = """
    #hosts { width: 42%; min-width: 44; border: solid $accent; }
    #tabs { border: solid $accent; }
    #search { margin: 0 1; }
    #config { padding: 0 1; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "ssh", "SSH to host"),
        Binding("f", "cycle_severity", "Severity filter"),
        Binding("slash", "focus_search", "Search", key_display="/"),
        Binding("escape", "blur_search", show=False),
    ]

    def __init__(self, rows):
        super().__init__()
        self.rows = rows
        self.current = rows[0] if rows else None
        self.severity = "all"
        self.query = ""

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
        yield Footer()

    def on_mount(self) -> None:
        hosts = self.query_one("#hosts", DataTable)
        hosts.cursor_type = "row"
        hosts.zebra_stripes = True
        hosts.add_columns("Switch", "Host", "Campus", "C", "W")
        for i, r in enumerate(self.rows):
            hosts.add_row(r["name"], r["host"], r["group"],
                          _sev_count(r["critical"], "critical"),
                          _sev_count(r["warning"], "warning"), key=str(i))
        findings = self.query_one("#findings", DataTable)
        findings.cursor_type = "row"
        findings.zebra_stripes = True
        findings.add_columns("Sev", "Switch", "Code", "Port", "Message")
        interfaces = self.query_one("#interfaces", DataTable)
        interfaces.cursor_type = "row"
        interfaces.zebra_stripes = True
        interfaces.add_columns("Port", "Description", "Status", "VLAN",
                               "Uplink", "PortFast", "BPDUguard", "Err/CRC")
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
        self.query_one("#search", Input).focus()

    def action_blur_search(self) -> None:
        self.query_one("#hosts", DataTable).focus()

    def action_ssh(self) -> None:
        row = self.current
        if not row:
            return
        inv = row.get("inv")
        if inv is None:
            self.notify("No inventory entry for this host - SSH needs "
                        "credentials from the inventory.", severity="warning")
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

    # ------------------------------------------------------------- rendering

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


def _sev_count(count: int, severity: str) -> Text:
    return Text(str(count), style=_SEV_STYLE[severity] if count else "dim")

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from netauditor import cli, report, wireless
from netauditor.inventory import load_controllers, load_inventory

DAY = "11/16/2026"
NAS = "10.0.8.5"


def _req(mac, user, ap, t, session="6afa7487"):
    dashed = mac.replace(":", "-")
    return (f"{NAS},{user},{DAY},{t},IAS,NPS01,4,{NAS},31,{dashed},30,{ap}:eduSTAR,"
            f"44,{session}/{mac}/7743,4128,WLC01,4154,Secure Wireless,4136,1,4142,0")


def _chal(mac, user, t, session="6afa7487"):
    return f"{NAS},{user},{DAY},{t},IAS,NPS01,44,{session}/{mac}/7743,4128,WLC01,4136,11,4142,0"


def _accept(mac, user, t):
    return f"{NAS},{user},{DAY},{t},IAS,NPS01,44,6afa0001/{mac}/1,4128,WLC01,4136,2,4142,0"


def _reject(mac, user, t, code):
    return f"{NAS},{user},{DAY},{t},IAS,NPS01,44,6afa0002/{mac}/2,4128,WLC01,4136,3,4142,{code}"


LOOPER = "fe:37:49:d4:49:6c"      # looping phone: requests + challenges, never an answer
GOOD = "f6:02:1e:2d:4a:9c"        # normal login: a few rounds then accepted
REJECTED = "14:ea:63:ee:6f:a7"    # projector with a dead account: only rejects
AP1 = "f4-db-e6-74-2c-a0"
AP2 = "6c-8b-d3-16-09-60"


def nps_lines():
    lines = []
    for i in range(30):
        t = f"09:{i // 60:02d}:{i % 60:02d}"
        lines += [_req(LOOPER, "daden8@schools.vic.edu.au", AP1, t), _chal(LOOPER, "daden8", t)]
    for i in range(10):
        lines += [_req(GOOD, "daden8@schools.vic.edu.au", AP2, "10:25:2" + str(i % 10)),
                  _chal(GOOD, "daden8", "10:25:24")]
    lines.append(_accept(GOOD, "daden8@schools.vic.edu.au", "10:25:24"))
    for i in range(5):
        lines += [_req(REJECTED, "8799-byod", AP2, f"14:05:4{i}"),
                  _reject(REJECTED, "8799-byod", f"14:05:4{i}", "8")]
    lines.append(_req(LOOPER, "daden8", AP1, "09:00:00").replace(DAY, "11/15/2026"))
    return lines


JOIN_STATS = """\
Number of APs.............................................. 3

Base Mac             AP EthernetMac       AP Name                   IP Address         Status
f4:db:e6:74:2c:a0    f4:db:e6:12:34:56    DE-AP-LIB-07              10.0.9.21          Joined
6c:8b:d3:16:09:60    6c:8b:d3:aa:bb:cc    DE-AP-S12                 10.0.9.22          Joined
00:27:e3:da:e2:e0    00:27:e3:00:00:01    DE-AP-GYM                 10.0.9.23          Not joined
"""

AP_SUMMARY = """\
Number of APs.................................... 2

Global AP User Name.............................. Not Configured
Global AP Dot1x User Name........................ Not Configured

AP Name             Slots  AP Model              Ethernet MAC       Location          Country  IP Address       Clients   DSE Location
------------------  -----  --------------------  -----------------  ----------------  -------  ---------------  --------  --------------
DE-AP-LIB-07         2     AIR-AP2802I-Z-K9      f4:db:e6:12:34:56  Library upstairs  AU       10.0.9.21        14        [0 ,0 ,0 ]
DE-AP-S12            2     AIR-AP2802I-Z-K9      6c:8b:d3:aa:bb:cc  S Block room 12   AU       10.0.9.22        9         [0 ,0 ,0 ]
"""

CLIENT_DETAIL = """\
Client MAC Address............................... fe:37:49:d4:49:6c
Client Username ................................. daden8@schools.vic.edu.au
Hostname: .......................................
AP MAC Address................................... f4:db:e6:74:2c:a0
AP Name.......................................... DE-AP-LIB-07
AP radio slot Id................................. 1
Client State..................................... Probing
Wireless LAN Id.................................. 1
Wireless LAN Network Name (SSID)................. eduSTAR
IP Address....................................... Unknown
Policy Manager State............................. 8021X_REQD
"""

CLIENT_MISSING = "Client not found."

EXCLUSIONS = """\
Excluded Clients

MAC Address             Description              Exclusion Reason        Time Remaining (in secs)
-----------             -----------              ----------------        ------------------------
14:ea:63:ee:6f:a7                                802.1X Failure          51
"""

MAC_TABLE_EDGE = """\
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 120    f4db.e612.3456    DYNAMIC     Gi1/0/17
 120    0011.2233.4455    DYNAMIC     Gi1/0/48
Total Mac Addresses for this criterion: 2
"""

MAC_TABLE_CORE = """\
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 120    f4db.e612.3456    DYNAMIC     Te1/1/3
 120    6c8b.d3aa.bbcc    DYNAMIC     Te1/1/1
"""

AUDIT_HOSTS = [
    {"name": "879902CSW01", "group": "delahey", "interfaces": [
        {"interface": "Te1/1/1", "is_uplink": True, "description": "Fibre to S block"},
        {"interface": "Te1/1/3", "is_uplink": True, "description": "Fibre to library"}]},
    {"name": "DE-SW-LIB-02", "group": "delahey", "interfaces": [
        {"interface": "Gi1/0/17", "is_uplink": False, "description": "AP-LIB-07"},
        {"interface": "Gi1/0/48", "is_uplink": True, "description": "TRUNK"}]},
]


class TestMacs(unittest.TestCase):
    def test_norm_mac_spellings(self):
        for raw in ("F4-DB-E6-74-2C-A0", "f4:db:e6:74:2c:a0", "f4db.e674.2ca0", "f4dbe6742ca0"):
            self.assertEqual(wireless.norm_mac(raw), "f4:db:e6:74:2c:a0")
        self.assertEqual(wireless.norm_mac("not a mac"), "")

    def test_random_mac(self):
        self.assertTrue(wireless.is_random_mac("fe:37:49:d4:49:6c"))
        self.assertFalse(wireless.is_random_mac("14:ea:63:ee:6f:a7"))

    def test_called_station(self):
        self.assertEqual(wireless.split_called_station("f4-db-e6-74-2c-a0:eduSTAR"),
                         ("f4:db:e6:74:2c:a0", "eduSTAR"))
        self.assertEqual(wireless.split_called_station("garbage"), ("", ""))


class TestNps(unittest.TestCase):
    def setUp(self):
        self.stats = wireless.parse_nps_lines(nps_lines(), date=DAY)

    def test_counts_per_client(self):
        loop = self.stats[LOOPER]
        self.assertEqual(loop["requests"], 30)   # the 11/15 line is filtered out
        self.assertEqual((loop["accepts"], loop["rejects"]), (0, 0))
        self.assertEqual(loop["ap_radio_mac"], "f4:db:e6:74:2c:a0")
        self.assertEqual(loop["nas_ip"], NAS)
        self.assertEqual(self.stats[GOOD]["accepts"], 1)   # MAC taken from the session id
        self.assertEqual(self.stats[REJECTED]["reasons"]["8"], 5)

    def test_all_days(self):
        self.assertEqual(wireless.parse_nps_lines(nps_lines())[LOOPER]["requests"], 31)

    def test_problem_devices(self):
        problems = wireless.find_problem_devices(self.stats, min_requests=20, min_rejects=5)
        self.assertEqual([(p["mac"], p["kind"]) for p in problems],
                         [(LOOPER, "looping"), (REJECTED, "rejected")])

    def test_accepted_devices_are_never_problems(self):
        problems = wireless.find_problem_devices(self.stats, min_requests=5, min_rejects=1)
        self.assertNotIn(GOOD, [p["mac"] for p in problems])

    def test_names(self):
        from datetime import datetime
        self.assertEqual(wireless.nps_date(datetime(2026, 1, 5)), "1/5/2026")
        self.assertEqual(wireless.nps_log_name(datetime(2026, 11, 16)), "IN2611.log")


class TestControllerParsers(unittest.TestCase):
    def test_join_stats(self):
        aps = wireless.parse_ap_join_stats(JOIN_STATS)
        self.assertEqual(len(aps), 3)
        self.assertEqual(aps[0], {"radio_mac": "f4:db:e6:74:2c:a0", "eth_mac": "f4:db:e6:12:34:56",
                                  "name": "DE-AP-LIB-07", "ip": "10.0.9.21", "status": "Joined"})
        self.assertEqual(aps[2]["status"], "Not joined")

    def test_ap_summary_keeps_location_spaces(self):
        aps = wireless.parse_ap_summary(AP_SUMMARY)
        self.assertEqual(aps["DE-AP-S12"]["location"], "S Block room 12")
        self.assertEqual(aps["DE-AP-LIB-07"]["clients"], 14)

    def test_client_detail(self):
        d = wireless.parse_client_detail(CLIENT_DETAIL)
        self.assertEqual(d["ap_name"], "DE-AP-LIB-07")
        self.assertEqual(d["policy_state"], "8021X_REQD")
        self.assertEqual(d["username"], "daden8@schools.vic.edu.au")
        self.assertIsNone(wireless.parse_client_detail(CLIENT_MISSING))

    def test_exclusionlist(self):
        ex = wireless.parse_exclusionlist(EXCLUSIONS)
        self.assertIn("802.1X Failure", ex[REJECTED])

    def test_mac_table(self):
        entries = wireless.parse_mac_table(MAC_TABLE_EDGE)
        self.assertEqual(entries[0], {"vlan": "120", "mac": "f4:db:e6:12:34:56",
                                      "type": "DYNAMIC", "port": "Gi1/0/17"})
        self.assertEqual(len(entries), 2)


class TestCorrelation(unittest.TestCase):
    def setUp(self):
        self.aps = wireless.parse_ap_join_stats(JOIN_STATS)
        self.tables = {"879902CSW01": wireless.parse_mac_table(MAC_TABLE_CORE),
                       "DE-SW-LIB-02": wireless.parse_mac_table(MAC_TABLE_EDGE)}

    def test_exact_and_approx_ap_match(self):
        self.assertEqual(wireless.match_ap("f4:db:e6:74:2c:a0", self.aps)[1], "exact")
        ap, how = wireless.match_ap("f4:db:e6:74:2c:af", self.aps)   # a BSSID just above the base
        self.assertEqual((ap["name"], how), ("DE-AP-LIB-07", "approx"))
        self.assertEqual(wireless.match_ap("00:11:22:33:44:55", self.aps), (None, ""))

    def test_locate_skips_uplinks(self):
        loc = wireless.locate_mac("f4:db:e6:12:34:56", self.tables, AUDIT_HOSTS)
        self.assertEqual((loc["switch"], loc["port"], loc["description"]),
                         ("DE-SW-LIB-02", "Gi1/0/17", "AP-LIB-07"))
        self.assertTrue(loc["certain"])

    def test_locate_falls_back_to_uplink(self):
        loc = wireless.locate_mac("6c:8b:d3:aa:bb:cc", self.tables, AUDIT_HOSTS)
        self.assertEqual((loc["switch"], loc["port"], loc["certain"]), ("879902CSW01", "Te1/1/1", False))

    def test_build_trace_and_by_ap(self):
        stats = wireless.parse_nps_lines(nps_lines(), date=DAY)
        problems = wireless.find_problem_devices(stats, 20, 5)
        rows = wireless.build_trace(
            problems, self.aps, wireless.parse_ap_summary(AP_SUMMARY),
            {LOOPER: wireless.parse_client_detail(CLIENT_DETAIL), REJECTED: None},
            wireless.parse_exclusionlist(EXCLUSIONS), self.tables, AUDIT_HOSTS)
        loop = rows[0]
        self.assertEqual(loop["ap"]["name"], "DE-AP-LIB-07")
        self.assertEqual(loop["ap"]["location"], "Library upstairs")
        self.assertEqual(loop["switch"]["port"], "Gi1/0/17")
        self.assertEqual(loop["live"]["policy_state"], "8021X_REQD")
        self.assertTrue(loop["random_mac"])
        self.assertIsNone(rows[1]["live"])
        self.assertIn("802.1X", rows[1]["excluded"])
        groups = wireless.by_access_point(rows)
        self.assertEqual({g["ap"] for g in groups}, {"DE-AP-LIB-07", "DE-AP-S12"})
        html = report.render_trace_html({"devices": rows, "by_ap": groups, "nps_logs": ["x"],
                                         "thresholds": {"min_requests": 20, "min_rejects": 5}})
        self.assertIn("DE-AP-LIB-07", html)
        self.assertIn("account does not exist", html)


class TestControllerInventory(unittest.TestCase):
    def test_controllers_kept_apart_from_switches(self):
        text = """
defaults:
  username: admin
  password: pw
  device_type: cisco_ios
groups:
  delahey:
    hosts:
      - host: 10.0.8.1
    controllers:
      - host: 10.0.8.5
        nps_host: nps01.example
controllers:
  - host: 10.0.10.5
    group: kingspark
"""
        with tempfile.TemporaryDirectory() as tmp:
            inv = Path(tmp) / "inventory.yml"
            inv.write_text(text, encoding="utf-8")
            switches = load_inventory(inv, prompt_missing=False)
            ctrls = load_controllers(inv, prompt_missing=False)
        self.assertEqual([s.host for s in switches], ["10.0.8.1"])
        self.assertEqual([(c.host, c.group, c.device_type) for c in ctrls],
                         [("10.0.10.5", "kingspark", "cisco_wlc_ssh"),
                          ("10.0.8.5", "delahey", "cisco_wlc_ssh")])
        self.assertEqual(ctrls[1].nps_host, "nps01.example")
        self.assertEqual(ctrls[1].username, "admin")

    def test_ap_list_controller_needs_no_credentials(self):
        text = "controllers:\n  - host: 10.0.8.5\n    group: delahey\n    ap_list: aps.txt\n"
        with tempfile.TemporaryDirectory() as tmp:
            inv = Path(tmp) / "inventory.yml"
            inv.write_text(text, encoding="utf-8")
            ctrls = load_controllers(inv, prompt_missing=False, require_credentials=True)
        self.assertEqual(Path(ctrls[0].ap_list), Path(tmp) / "aps.txt")   # relative to the inventory


def _inventory(folder: Path) -> Path:
    inv = folder / "inventory.yml"
    inv.write_text("groups:\n  delahey:\n    hosts:\n      - host: 10.0.8.1\n", encoding="utf-8")
    return inv


class TestTraceCli(unittest.TestCase):
    def test_offline_trace_from_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            log = tmp / "IN2611.log"
            log.write_text("\n".join(nps_lines()) + "\n", encoding="utf-8")
            out = tmp / "out"
            out.mkdir()
            (out / "audit.json").write_text(json.dumps({"hosts": AUDIT_HOSTS}), encoding="utf-8")
            (out / "trace.json").write_text(json.dumps({
                "controllers": {NAS: {"name": "WLC01", "group": "delahey", "error": None,
                                      "aps": wireless.parse_ap_join_stats(JOIN_STATS),
                                      "ap_summary": wireless.parse_ap_summary(AP_SUMMARY)}},
                "mac_tables": {"879902CSW01": wireless.parse_mac_table(MAC_TABLE_CORE),
                               "DE-SW-LIB-02": wireless.parse_mac_table(MAC_TABLE_EDGE)}}),
                encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                code = cli.main(["trace", "--nps-log", str(log), "--date", "2026-11-16",
                                 "--offline", "--min-requests", "20", "--min-rejects", "5",
                                 "-o", str(out), "-i", str(_inventory(tmp))])
            self.assertEqual(code, 1)   # a looping device was found
            text = buf.getvalue()
            self.assertIn("DE-AP-LIB-07", text)
            self.assertIn("DE-SW-LIB-02 Gi1/0/17", text)
            trace = json.loads((out / "trace.json").read_text(encoding="utf-8"))
            self.assertEqual(trace["devices"][0]["switch"]["port"], "Gi1/0/17")
            self.assertTrue((out / "trace.html").exists())

    def test_ap_list_names_without_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            log = tmp / "IN2611.log"
            log.write_text("\n".join(nps_lines()) + "\n", encoding="utf-8")
            saved = tmp / "wlc.txt"   # both commands pasted into one file, as a user would
            saved.write_text("(879902WLC01) >show ap join stats summary all\n" + JOIN_STATS
                             + "\n(879902WLC01) >show ap summary\n" + AP_SUMMARY, encoding="utf-8")
            out = tmp / "out"
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                code = cli.main(["trace", "--nps-log", str(log), "--date", "2026-11-16",
                                 "--ap-list", str(saved), "--no-switches", "--no-prompt",
                                 "--min-requests", "20", "--min-rejects", "5",
                                 "-o", str(out), "-i", str(_inventory(tmp))])
            self.assertEqual(code, 1)
            self.assertIn("3 APs with radio MACs, 2 with locations", buf.getvalue())
            trace = json.loads((out / "trace.json").read_text(encoding="utf-8"))
            names = {r["mac"]: (r["ap"] or {}).get("name") for r in trace["devices"]}
            self.assertEqual(names[LOOPER], "DE-AP-LIB-07")
            self.assertEqual(names[REJECTED], "DE-AP-S12")
            self.assertEqual(trace["devices"][0]["ap"]["location"], "Library upstairs")
            self.assertEqual(trace["devices"][0]["live"], "unknown")   # controller never contacted
            self.assertIn("AP names from wlc.txt", (out / "trace.html").read_text(encoding="utf-8"))
            # the saved AP list is cached, so a later --offline run still has names
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                cli.main(["trace", "--nps-log", str(log), "--date", "2026-11-16", "--offline",
                          "--min-requests", "20", "--min-rejects", "5",
                          "-o", str(out), "-i", str(_inventory(tmp))])
            self.assertIn("DE-AP-LIB-07", buf.getvalue())

    def test_ap_list_without_join_stats_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            log = tmp / "IN.log"
            log.write_text("\n".join(nps_lines()) + "\n", encoding="utf-8")
            saved = tmp / "summary-only.txt"
            saved.write_text(AP_SUMMARY, encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                cli.main(["trace", "--nps-log", str(log), "--date", "2026-11-16",
                          "--ap-list", str(saved), "--no-switches", "--min-requests", "20",
                          "-o", str(tmp / "out"), "-i", str(_inventory(tmp))])
            self.assertIn("show ap join stats summary all", buf.getvalue())

    def test_no_problems_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "IN.log"
            log.write_text(_accept(GOOD, "x", "10:00:00") + "\n", encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = cli.main(["trace", "--nps-log", str(log), "--date", "2026-11-16",
                                 "--offline", "-o", str(Path(tmp) / "out"),
                                 "-i", str(_inventory(Path(tmp)))])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()

# netauditor

SSH-based audit tool for Cisco IOS/IOS-XE switch fleets. It connects to every
switch in an inventory, checks port and spanning-tree health, flags likely
problems (PortFast on uplinks, BPDU guard gaps, STP churn, err-disabled ports,
duplex mismatches), exports each running config, and can then compare configs
across switches to detect drift.

## Quick start

Put a filled-in `inventory.yml` in a folder (copy
[examples/inventory.yml](examples/inventory.yml)) and run the tool from that
folder with no arguments:

```
netauditor
```

That pops the terminal command center with the inventory auto-loaded - live
reachability starts immediately, press `a` to run the first audit. The same
works for the standalone exe: put `netauditor.exe` and `inventory.yml` in one
folder and double-click the exe.

Every subcommand auto-detects `inventory.yml` / `inventory.yaml` /
`inventory.txt` in the current directory, so day-to-day none of them need
`-i`:

```
netauditor status          # is everything up?
netauditor audit           # full audit -> out/
netauditor analyze out     # config drift
netauditor connect sw-lib  # SSH into a switch
netauditor ui              # command center (same as bare "netauditor")
```

`-i <file>` still overrides the auto-detection everywhere.

## Install

```
pip install .
```

or for development:

```
pip install -r requirements.txt
```

Requires Python 3.9+. SSH connectivity uses [netmiko](https://github.com/ktbyers/netmiko);
the `analyze` subcommand works without any network access.

## Inventory

YAML (recommended - see [examples/inventory.yml](examples/inventory.yml)):

```yaml
defaults:
  username: audituser
  password: changeme

groups:                     # campus/site groups; audit one with -g sydenham
  sydenham:
    defaults:
      username: syd-audit   # optional per-group defaults override the global ones
    hosts:
      - host: 10.1.0.11
        name: sy-sw-core-1
      - host: 10.1.0.12
  delahey:
    hosts:
      - host: 10.2.0.11
        username: localadmin   # inline creds take priority over everything
        password: different

hosts:                      # ungrouped hosts are always audited
  - host: 10.9.0.14
  - host: 10.9.0.15
    group: kingspark        # a per-host group key also works
```

Plain text also works: one `ip[,username[,password]]` per line, with optional
INI-style `[campus]` section headers assigning the hosts below them to a group.

### Campus / site groups

Hosts can be grouped by campus, either with a `groups:` mapping (as above, with
optional per-group `defaults`), a per-host `group:` key, or `[section]` headers
in plain-text inventories. Both subcommands take `-g/--group` to operate on a
subset; no flag means everything:

```
netauditor audit -i inventory.yml -g sydenham
netauditor analyze out -g sydenham --tests all
```

`analyze -g` needs an `audit.json` source (raw `.cfg` directories carry no
group information). The audit report shows a campus column and gains a campus
dropdown in the filter toolbar, so a whole-fleet audit can still be read one
campus at a time.

When groups exist, per-campus HTML reports are written automatically next to
the combined ones: `audit` produces `<group>.html` for each campus (plus
`ungrouped.html` if some hosts have no group), and `analyze` produces
`<group>.drift.html` with drift computed only within that campus (groups with a
single switch are skipped). The JSON outputs stay combined.

Credential precedence: inline per-host → inventory `defaults` →
`NETAUDITOR_USERNAME` / `NETAUDITOR_PASSWORD` / `NETAUDITOR_SECRET` environment
variables → interactive prompt. Prefer the env vars or the prompt over putting
passwords in the file; if you must inline them, keep the inventory out of git
(the bundled `.gitignore` already ignores `inventory.*`).

## 1. Audit

```
netauditor audit -i inventory.yml -o out
```

Unsaved config changes get loud treatment everywhere: an amber banner at the
top of `audit.html` and the UI naming the affected switches, a `±` marker on
those switches in every table, and an `UNSAVED-CONFIG` tag in `status` output -
because "the switch reboots and the fix vanishes" is the most common way fleet
work silently unravels.

Scoped runs (`-g <campus>`, or a campus tab / single switch in the UI) **merge**
into the existing `audit.json`: audited entries are replaced, everything else
is kept, and each entry carries its own `audited_at` timestamp so mixed-age
data is visible (fleet overview and UI both show it). `--fresh` discards
previous results instead. Entries for switches no longer in the inventory are
flagged as stale rather than silently kept - remove them with:

```
netauditor prune -i inventory.yml -o out          # dry run: lists stale entries
netauditor prune -i inventory.yml -o out --yes    # remove and regenerate reports
```

Connects to every switch in parallel and runs:
`show version`, `show interfaces status`, `show interfaces`,
`show spanning-tree summary`, `show spanning-tree detail`,
`show cdp neighbors detail`, `show vtp status`, `show logging`,
`show running-config`, `show startup-config`.

Checks performed per switch:

| Code | Severity | Meaning |
|---|---|---|
| `UPLINK_PORTFAST` | critical | PortFast active on an uplink (trunk or CDP-detected switch neighbor) - loop risk |
| `UPLINK_BPDUGUARD` | critical | BPDU guard on an uplink - first neighbor BPDU err-disables the uplink |
| `ERRDISABLED` | critical | Port is err-disabled |
| `STP_CHURN` | critical | High topology-change count *and* a recent change - active STP churn |
| `MAC_FLAPPING` | critical | `%SW_MATM-4-MACFLAP` events in the log - loop or double-bridged device, aggregated per port pair |
| `UNREACHABLE` | critical | Switch could not be audited |
| `UNSAVED_CHANGES` | warning | Running config differs from startup-config (or none saved) - lost at reboot |
| `VTP_SERVER` | warning | VTP server mode - a higher-revision switch can wipe the VLAN database |
| `STP_CHURN_HISTORY` / `STP_RECENT_CHANGE` | warning | Accumulated or recent topology changes |
| `ACCESS_NO_PORTFAST` / `ACCESS_NO_BPDUGUARD` | warning | Unprotected access/edge ports |
| `HALF_DUPLEX` / `LATE_COLLISIONS` / `INTERFACE_ERRORS` | warning | Duplex mismatch signs and error counters |
| `GLOBAL_BPDUFILTER` / `EDGE_UNPROTECTED` | warning | Risky global STP defaults |
| `DTP_ENABLED` | warning | Port has no explicit switchport mode, so DTP can negotiate a trunk |
| `NATIVE_VLAN_1` / `TRUNK_ALLOWS_ALL` | warning | Trunk native VLAN left at 1 / trunk not pruned |
| `NO_EXEC_TIMEOUT` / `VTY_NO_ACL` / `SSH_V1` / `NO_NTP` | warning | Management-plane hygiene: sessions never expire, unrestricted VTY, SSH not pinned to v2, no time source |
| `VLAN1_IN_USE` / `UNUSED_PORT_OPEN` | info | Access traffic on default VLAN 1 / live unused ports (aggregated per switch) |
| `NO_LOGGING_HOST` | info | No syslog collector configured |
| `LEGACY_STP` | info | Legacy PVST+ mode |

Uplinks are identified from trunk mode/status **or** a CDP neighbor advertising
the Switch capability, so a mis-configured access port facing another switch is
still treated as an uplink.

Output (`out/`):

Findings come with **suggested IOS fixes**: each finding group in `audit.html`
has a collapsible "Suggested fix" block with a copy-paste snippet scoped to the
affected port, and the UI's detail screen shows the snippet for the selected
finding. They are suggestions only - netauditor never writes configuration.

- `audit.json` - full structured report (facts, interfaces, findings, configs)
- `audit.html` - self-contained report: fleet overview, findings grouped by
  code (critical groups expanded), per-switch interface tables, collapsible
  config exports. A sticky toolbar offers free-text search, severity chips,
  and a finding-code dropdown; the same toolbar appears in `drift.html`.
- `configs/<switch>.cfg` - one config export per switch

Exit code is `1` if any critical finding exists (usable in CI/cron), `2` on
usage errors, otherwise `0`.

Every audit also archives a timestamped snapshot under `out/history/` (the
newest 30 are kept) and git-commits `out/configs/` - a free per-switch config
history you can `git log` forever. Disable either with `--no-snapshot` /
`--no-backup`.

## 2. Diff (what changed since last time)

```
netauditor diff                             # vs the previous snapshot
netauditor diff --since 20260803            # vs a specific snapshot
netauditor diff --config DE-SW-LIB-02       # that switch's running-config diff
```

Answers "did the fixes take?": per switch it lists findings that are **FIXED**
(gone since the earlier audit), **NEW**, and how many are unchanged, plus
switches added to or missing from the fleet. Exit code 1 if anything new
appeared. The same view is `c` in the UI.

## 3. Analyze (config drift + extra tests)

```
netauditor analyze out/audit.json -o out --tests all
```

The source can be the `audit.json` from step 1, the output directory itself, or
any directory of `*.cfg` files. Drift detection compares top-level config
blocks across switches: the majority variant becomes the consensus and every
deviation is reported as missing / extra / modified lines per switch.
Host-specific lines (hostname, interfaces, certificates, stack provisioning,
SNMP location...) are excluded so they don't show up as false drift. Banner
blocks are skipped, and secrets (enable/username hashes, SNMP communities,
tacacs/radius keys) are redacted before comparison - salted hashes differ on
every switch even for identical passwords, so they would otherwise be pure
false drift, and they don't belong in a shareable report anyway.

### Baseline mode

Majority consensus is the wrong model when the fleet is small or heterogeneous
(e.g. one core switch plus several access switches - the core loses every
"vote"). If you have a known-good, properly configured switch, name it as the
baseline and every difference is reported relative to it:

```
netauditor analyze out -o out --baseline sw-access-1
```

Use `--hosts` to limit the comparison to switches that should look alike,
so a core switch's legitimate extras don't drown the report:

```
netauditor analyze out -o out --baseline sw-access-1 --hosts sw-access-1,sw-access-2,sw-access-3
```

Extra test suites via `--tests` (comma-separated, or `all`):

- `security` - telnet on VTY lines, `ip http server`, default/RW SNMP
  communities, missing `service password-encryption`, `enable password`,
  type 0/7 user passwords
- `stp` - spanning-tree mode mismatches between switches, no deterministic
  root bridge configured
- `vlans` - VLANs defined on some switches but missing on others

Outputs `drift.json` and `drift.html` in the same style as the audit report.

## 4. Connect (live SSH session)

```
netauditor connect sw-lib-02 -i inventory.yml
netauditor connect -i inventory.yml -g sydenham
```

Opens a real interactive SSH session to a switch using the credentials already
in the inventory - no separate PuTTY profile or password lookup. The target can
be a name, an IP, or any substring of either; with several matches (or no
target at all) you get a numbered list to pick from. Type `exit` on the switch
to end the session. Ctrl+C is passed through to the switch, and arrow keys /
history work as normal. Host keys are auto-accepted, same policy as the audit.

## 5. Status (quick reachability check)

```
netauditor status -i inventory.yml [-g sydenham]
```

One concurrent sweep: a bare TCP connect to each switch's SSH port (no login,
safe to run any time). Prints up/DOWN, connect latency, and - when audit output
exists - each switch's audit flags in a separate column. Exit code 1 if
anything is down, so it doubles as a cron-able dead-switch alarm. Reachability
and audit state are deliberately separate: "up" only means the management port
answers.

## 6. Command center (terminal UI)

```
netauditor
```

(bare invocation defaults to `ui`; the explicit form is
`netauditor ui [-i inventory.yml] [-o out]`)

An interactive terminal command center (built on
[Textual](https://github.com/Textualize/textual)), laid out like a dense
ratatui-style dashboard: a status bar (switch count, colored ●/✗/! state
summary, clock, last-audit time or live job progress), a campus tab strip, one
full-width switch table with campus section headers and a fleet aggregate row,
a slim detail strip for the selected switch, and a pipe-separated key-hint bar.
Unreachable switches show as red rows; Enter drills into a full-screen detail
view (findings / interfaces / config) and Esc comes back.

Keys:

| Key | Action |
|-----|--------|
| `↑↓` / `←→` | Navigate switches / switch campus tab. |
| `Enter` | Drill into the selected switch (or aggregate row) - findings, interfaces, config. `a` inside re-audits just that switch. |
| `a` | Audit the current scope: the whole inventory on the All tab, one campus on a campus tab. Results merge into the existing audit. Prompts for credentials in-app if the inventory has none. |
| `d` | Run the drift check + all test suites; results open in a drift screen. |
| `c` | Changes since the previous audit snapshot: what got fixed, what is new. |
| `p` | Prune stale entries (switches no longer in the inventory, shown dim with `?`) after a confirmation listing them. |
| `w` | Toggle watch mode (on by default with an inventory): TCP-probes every switch on an interval (`--interval`, default 15s). `St` shows live up/down, `ms`/`Seen` columns update, and the status bar shows `live ↑N ↓N | next scan Ns`. Audit flags stay in their own column. |
| `s` | Live SSH session on the selected switch; ending it returns to the dashboard. |
| `/` | Find switches by name/IP (Esc clears). In the detail screen: filter findings. |
| `f` | (detail screen) cycle the severity filter. |
| `l` | Show the job log. |
| `r` | Reload results from disk (e.g. after a CLI run). |
| `q` | Quit. |

Jobs write the same `audit.json`/`audit.html`/`drift.html`/per-campus files as
the CLI - the UI and CLI share one execution layer, so outputs are identical.
`-g` scopes everything to a campus. Both `-i` and `-o` are optional: with only
an inventory you get the host list, audit runs and SSH; with only audit output
you get the results browser and drift checks.

## Typical workflow

From the folder containing `inventory.yml` - interactive:

```
netauditor
```

or scripted (reports land in `out\`):

```
netauditor audit
netauditor analyze out --tests all
start out\audit.html
```

## Notes and limits

- Command set and parsers target Cisco IOS/IOS-XE. `device_type` is passed
  straight to netmiko, but the checks assume IOS-style output.
- Parsers are regex-based and best-effort: unrecognized lines are skipped
  rather than crashing the audit.
- Run it with a read-only account; the tool only issues `show` commands.

## Sharing the tool

Two options depending on the recipient:

**They have Python** - install straight from the repo (needs repo access):

```
pipx install git+https://github.com/anhduyhn/netaudit.git
```

(or `pip install git+...`). That puts a `netauditor` command on their PATH.

**They have nothing** - point them at the standalone Windows exe on the
[releases page](https://github.com/anhduyhn/netaudit/releases) (built and
attached automatically by CI whenever a `v*` tag is pushed:
`git tag v0.2.0 && git push origin v0.2.0`). To build it locally instead:

```
powershell -ExecutionPolicy Bypass -File packaging\build-exe.ps1
```

Either way you get `netauditor.exe` (~20 MB, no Python required). The
recipient experience is two files in one folder: the exe plus a filled-in
`inventory.yml` (start from [examples/inventory.yml](examples/inventory.yml)).
**Double-clicking the exe opens the command center** with the inventory
auto-loaded; terminal users get the same subcommands as the pip install
(`netauditor.exe status`, `netauditor.exe audit`, ...). Releases also include
`run-audit.bat` for the non-interactive path: it audits, analyzes, and opens
the HTML report without anyone touching the dashboard.

Notes: the exe is Windows-only (build on the OS you target); unsigned exes may
trigger a SmartScreen "unrecognized app" prompt on first run - "More info" >
"Run anyway"; never bundle a filled-in inventory (credentials) alongside a
shared exe - send the template and let recipients add their own.

## Development

```
python -m unittest discover -s tests
```

To keep `dist\netauditor.exe` automatically up to date, enable the bundled
pre-push hook once per clone:

```
git config core.hooksPath .githooks
```

From then on, any push whose commits touch `netauditor/`, `packaging/` or
`pyproject.toml` rebuilds the local exe first (a failing build blocks the
push). Doc-only pushes and tag pushes skip the rebuild - tags are built by the
release workflow on CI. Bypass once with `NETAUDITOR_SKIP_BUILD=1 git push`.

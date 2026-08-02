# netauditor

SSH-based audit tool for Cisco IOS/IOS-XE switch fleets. It connects to every
switch in an inventory, checks port and spanning-tree health, flags likely
problems (PortFast on uplinks, BPDU guard gaps, STP churn, err-disabled ports,
duplex mismatches), exports each running config, and can then compare configs
across switches to detect drift.

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
hosts:
  - host: 10.10.0.11
    name: sw-core-1
  - host: 10.10.0.13
    username: localadmin   # inline creds take priority over defaults
    password: different
```

Plain text also works: one `ip[,username[,password]]` per line, with optional
INI-style `[campus]` sections.

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

- `audit.json` - full structured report (facts, interfaces, findings, configs)
- `audit.html` - self-contained report: fleet overview, findings grouped by
  code (critical groups expanded), per-switch interface tables, collapsible
  config exports. A sticky toolbar offers free-text search, severity chips,
  and a finding-code dropdown; the same toolbar appears in `drift.html`.
- `configs/<switch>.cfg` - one config export per switch

Exit code is `1` if any critical finding exists (usable in CI/cron), `2` on
usage errors, otherwise `0`.

## 2. Analyze (config drift + extra tests)

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

## Typical workflow

```
netauditor audit -i inventory.yml -o out
netauditor analyze out -o out --tests all
start out\audit.html
```

## Notes and limits

- Command set and parsers target Cisco IOS/IOS-XE. `device_type` is passed
  straight to netmiko, but the checks assume IOS-style output.
- Parsers are regex-based and best-effort: unrecognized lines are skipped
  rather than crashing the audit.
- Run it with a read-only account; the tool only issues `show` commands.

## Development

```
python -m unittest discover -s tests
```

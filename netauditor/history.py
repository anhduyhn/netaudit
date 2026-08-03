"""Audit history: timestamped snapshots, finding deltas, and git-backed config backup.

Each audit archives its audit.json under out/history/audit-<stamp>.json, so
"what changed since last time" can be answered per switch and per finding.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

HISTORY_DIR = "history"
_STAMP_RE = re.compile(r"audit-(\d{8}-\d{6})\.json$")


def _stamp_from(generated: str) -> str:
    """2026-08-03T10:12:33+10:00 -> 20260803-101233 (sortable, filename safe)."""
    digits = re.sub(r"[^\d]", "", (generated or "").split("+")[0])
    return f"{digits[:8]}-{digits[8:14]}" if len(digits) >= 14 else "unknown"


def snapshot_dir(outdir) -> Path:
    return Path(outdir) / HISTORY_DIR


def save_snapshot(audit: dict, outdir, keep: int = 30) -> "Path | None":
    """Archive an audit under history/, pruning to the newest `keep` snapshots."""
    hist = snapshot_dir(outdir)
    hist.mkdir(parents=True, exist_ok=True)
    path = hist / f"audit-{_stamp_from(audit.get('generated', ''))}.json"
    path.write_text(json.dumps(audit, indent=2), encoding="utf-8")
    snaps = list_snapshots(outdir)
    for old in snaps[:-keep] if keep and len(snaps) > keep else []:
        try:
            old.unlink()
        except OSError:
            pass
    return path


def list_snapshots(outdir) -> "list[Path]":
    """Snapshot files, oldest first."""
    hist = snapshot_dir(outdir)
    if not hist.is_dir():
        return []
    return sorted((p for p in hist.glob("audit-*.json") if _STAMP_RE.search(p.name)),
                  key=lambda p: p.name)


def load_snapshot(path) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def previous_snapshot(outdir, before_stamp: str = "") -> "Path | None":
    """Newest snapshot older than `before_stamp` (or simply the newest)."""
    snaps = list_snapshots(outdir)
    if before_stamp:
        snaps = [p for p in snaps if p.name < f"audit-{before_stamp}.json"]
    return snaps[-1] if snaps else None


def _finding_key(f) -> tuple:
    return (f.get("code", ""), f.get("interface", ""))


def diff_audits(old: dict, new: dict) -> dict:
    """Per-switch finding delta between two audits.

    Returns {"switches": [{name, host, fixed, added, still_open, ...}],
             "totals": {fixed, added, still_open}, "new_switches", "gone_switches"}
    """
    def index(audit):
        out = {}
        for h in (audit or {}).get("hosts", []):
            key = h.get("host") or (h.get("name") or "").lower()
            if key:
                out[key] = h
        return out

    old_idx, new_idx = index(old), index(new)
    switches = []
    totals = {"fixed": 0, "added": 0, "still_open": 0}
    for key, new_host in new_idx.items():
        old_host = old_idx.get(key)
        if old_host is None:
            continue  # brand new switch: reported separately, not as "added findings"
        old_f = {_finding_key(f): f for f in old_host.get("findings", [])}
        new_f = {_finding_key(f): f for f in new_host.get("findings", [])}
        fixed = [old_f[k] for k in old_f.keys() - new_f.keys()]
        added = [new_f[k] for k in new_f.keys() - old_f.keys()]
        still = [new_f[k] for k in new_f.keys() & old_f.keys()]
        # fleet-wide still-open count includes switches that did not change
        totals["still_open"] += len(still)
        if not (fixed or added):
            continue
        order = {"critical": 0, "warning": 1, "info": 2}
        fixed.sort(key=lambda f: order.get(f.get("severity"), 9))
        added.sort(key=lambda f: order.get(f.get("severity"), 9))
        switches.append({
            "name": new_host.get("name") or new_host.get("host"),
            "host": new_host.get("host", ""),
            "group": new_host.get("group", ""),
            "fixed": fixed,
            "added": added,
            "still_open": len(still),
        })
        totals["fixed"] += len(fixed)
        totals["added"] += len(added)
    switches.sort(key=lambda s: (-len(s["added"]), s["name"]))
    return {
        "switches": switches,
        "totals": totals,
        "new_switches": sorted(set(new_idx) - set(old_idx)),
        "gone_switches": sorted(set(old_idx) - set(new_idx)),
    }


def config_diff(old: dict, new: dict, switch: str) -> "list[str]":
    """Unified-ish diff of one switch's running config between two audits."""
    import difflib

    def config_of(audit):
        for h in (audit or {}).get("hosts", []):
            if (h.get("name") or "").lower() == switch.lower() or h.get("host") == switch:
                return h.get("config", "")
        return ""

    old_cfg, new_cfg = config_of(old), config_of(new)
    if not old_cfg and not new_cfg:
        return []
    return [l for l in difflib.unified_diff(
        old_cfg.splitlines(), new_cfg.splitlines(),
        fromfile=f"{switch} (previous)", tofile=f"{switch} (current)", lineterm="")]


# ------------------------------------------------------------------ git backup

def git_available() -> bool:
    return shutil.which("git") is not None


def _git(args, cwd) -> "subprocess.CompletedProcess | None":
    try:
        return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                              text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None


def backup_configs(outdir, message: str = "netauditor config backup") -> str:
    """Commit out/configs into a local git repo. Returns a status message."""
    cfg_dir = Path(outdir) / "configs"
    if not cfg_dir.is_dir() or not any(cfg_dir.iterdir()):
        return "no configs to back up"
    if not git_available():
        return "git not found on PATH - skipping config backup"
    if not (cfg_dir / ".git").is_dir():
        init = _git(["init", "-q"], cfg_dir)
        if init is None or init.returncode != 0:
            return "could not initialise the config backup repo"
        _git(["config", "user.email", "netauditor@localhost"], cfg_dir)
        _git(["config", "user.name", "netauditor"], cfg_dir)
    _git(["add", "-A"], cfg_dir)
    status = _git(["status", "--porcelain"], cfg_dir)
    if status is not None and not status.stdout.strip():
        return "config backup: no changes since the last audit"
    commit = _git(["commit", "-q", "-m", message], cfg_dir)
    if commit is None or commit.returncode != 0:
        return "config backup: commit failed"
    changed = len([l for l in (status.stdout or "").splitlines() if l.strip()])
    return f"config backup: committed {changed} changed config(s) to {cfg_dir}"

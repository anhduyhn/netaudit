"""Inventory loading: YAML or plain-text host lists with global and per-host credentials.

Credential precedence (highest first):
  1. inline per-host username/password in the inventory
  2. inventory-wide defaults
  3. NETAUDITOR_USERNAME / NETAUDITOR_PASSWORD / NETAUDITOR_SECRET environment variables
  4. interactive prompt (once, applied to every host still missing credentials)
"""
from __future__ import annotations

import getpass
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

ENV_USERNAME = "NETAUDITOR_USERNAME"
ENV_PASSWORD = "NETAUDITOR_PASSWORD"
ENV_SECRET = "NETAUDITOR_SECRET"

YAML_SUFFIXES = {".yml", ".yaml", ".json"}


class InventoryError(Exception):
    pass


@dataclass
class Host:
    host: str
    name: str = ""
    username: str = ""
    password: str = ""
    secret: str = ""  # enable secret; optional
    device_type: str = "cisco_ios"
    port: int = 22
    group: str = ""  # campus/site; "" means ungrouped

    def display_name(self) -> str:
        return self.name or self.host


def load_inventory(path, prompt_missing: bool = True,
                   require_credentials: bool = True) -> "list[Host]":
    """Load an inventory file and return Host objects.

    With require_credentials (the default) every host must end up with a
    username and password; the UI passes False since credentials are only
    needed when an SSH session is actually opened.
    """
    path = Path(path)
    if not path.exists():
        raise InventoryError(f"inventory file not found: {path}")
    if path.suffix.lower() in YAML_SUFFIXES:
        hosts = _load_yaml(path)
    else:
        hosts = _load_plain(path)
    if not hosts:
        raise InventoryError(f"no hosts found in {path}")
    _apply_env(hosts)
    if prompt_missing:
        _prompt_missing(hosts)
    if require_credentials:
        missing = [h.host for h in hosts if not h.username or not h.password]
        if missing:
            raise InventoryError(
                "no credentials for: %s (set inventory defaults, inline creds, or %s/%s)"
                % (", ".join(missing), ENV_USERNAME, ENV_PASSWORD)
            )
    return hosts


def _load_yaml(path: Path) -> "list[Host]":
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if isinstance(data, list):  # bare list of hosts is also accepted
        data = {"hosts": data}
    if not isinstance(data, dict):
        raise InventoryError(f"{path}: expected a mapping with 'hosts' or 'groups'")
    defaults = data.get("defaults") or {}
    hosts = []

    def add(entry, group="", group_defaults=None):
        if isinstance(entry, str):
            entry = {"host": entry}
        if not isinstance(entry, dict) or not entry.get("host"):
            raise InventoryError(f"{path}: each host needs at least a 'host' address: {entry!r}")
        merged = dict(defaults)
        merged.update(group_defaults or {})
        merged.update({k: v for k, v in entry.items() if v is not None})
        hosts.append(
            Host(
                host=str(merged["host"]),
                name=str(merged.get("name", "") or ""),
                username=str(merged.get("username", "") or ""),
                password=str(merged.get("password", "") or ""),
                secret=str(merged.get("secret", "") or ""),
                device_type=str(merged.get("device_type", "cisco_ios") or "cisco_ios"),
                port=int(merged.get("port", 22) or 22),
                group=str(merged.get("group", group) or ""),
            )
        )

    entries = data.get("hosts")
    if entries is not None and not isinstance(entries, list):
        raise InventoryError(f"{path}: 'hosts' must be a list")
    for entry in entries or []:
        add(entry)

    groups = data.get("groups") or {}
    if not isinstance(groups, dict):
        raise InventoryError(f"{path}: 'groups' must be a mapping of group name to hosts")
    for gname, gdata in groups.items():
        if isinstance(gdata, list):
            gdata = {"hosts": gdata}
        if not isinstance(gdata, dict):
            raise InventoryError(f"{path}: group '{gname}' must be a list or mapping")
        for entry in gdata.get("hosts") or []:
            add(entry, group=str(gname), group_defaults=gdata.get("defaults") or {})
    return hosts


def _load_plain(path: Path) -> "list[Host]":
    """Plain text: one host per line, 'ip[,username[,password]]'.

    An INI-style '[groupname]' line starts a group; hosts below it belong to
    that group until the next section header.
    """
    hosts = []
    group = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            group = line[1:-1].strip()
            continue
        parts = [p.strip() for p in (line.split(",") if "," in line else line.split())]
        host = Host(host=parts[0], group=group)
        if len(parts) > 1:
            host.username = parts[1]
        if len(parts) > 2:
            host.password = parts[2]
        hosts.append(host)
    return hosts


def _apply_env(hosts: "list[Host]") -> None:
    env_user = os.environ.get(ENV_USERNAME, "")
    env_pass = os.environ.get(ENV_PASSWORD, "")
    env_secret = os.environ.get(ENV_SECRET, "")
    for h in hosts:
        h.username = h.username or env_user
        h.password = h.password or env_pass
        h.secret = h.secret or env_secret


def _prompt_missing(hosts: "list[Host]") -> None:
    if not sys.stdin.isatty():
        return
    if any(not h.username for h in hosts):
        user = input("SSH username (applies to hosts without inline credentials): ").strip()
        for h in hosts:
            h.username = h.username or user
    if any(not h.password for h in hosts):
        password = getpass.getpass("SSH password: ")
        for h in hosts:
            h.password = h.password or password

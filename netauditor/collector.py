"""SSH collection of show-command output from switches (netmiko)."""
from __future__ import annotations

import concurrent.futures

# Keyed outputs consumed by parsers/checks; order matters only for readability.
COMMANDS = {
    "version": "show version",
    "interfaces_status": "show interfaces status",
    "interfaces": "show interfaces",
    "stp_summary": "show spanning-tree summary",
    "stp_detail": "show spanning-tree detail",
    "cdp_neighbors": "show cdp neighbors detail",
    "running_config": "show running-config",
}


def collect_host(host, timeout: int = 30) -> dict:
    """Connect to one switch and run every audit command. Never raises; errors land in the result."""
    # Imported lazily so parsing/analysis (and tests) work without netmiko installed.
    from netmiko import ConnectHandler

    result = {"host": host.host, "name": host.display_name(), "error": None, "outputs": {}}
    device = {
        "device_type": host.device_type,
        "host": host.host,
        "username": host.username,
        "password": host.password,
        "port": host.port,
        "conn_timeout": timeout,
    }
    if host.secret:
        device["secret"] = host.secret
    try:
        with ConnectHandler(**device) as conn:
            if host.secret:
                conn.enable()
            prompt_name = conn.find_prompt().strip("#>* ")
            if not host.name and prompt_name:
                result["name"] = prompt_name
            for key, command in COMMANDS.items():
                read_timeout = max(timeout, 120) if key == "running_config" else timeout
                try:
                    result["outputs"][key] = conn.send_command(command, read_timeout=read_timeout)
                except Exception as exc:  # one failed command shouldn't kill the whole host
                    result["outputs"][key] = ""
                    result.setdefault("command_errors", {})[command] = str(exc)
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def collect_all(hosts, workers: int = 8, timeout: int = 30, progress=None) -> "list[dict]":
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(collect_host, h, timeout): h for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            results.append(res)
            if progress:
                progress(res)
    results.sort(key=lambda r: r["host"])
    return results

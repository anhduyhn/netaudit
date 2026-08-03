"""Cheap reachability probes: a TCP connect to the management (SSH) port.

"Up" means the port accepted a connection - no authentication, no session, so
it is safe to run frequently even against old switches. Latency is the TCP
connect time in milliseconds.
"""
from __future__ import annotations

import concurrent.futures
import socket
import time


def probe(host: str, port: int = 22, timeout: float = 3.0):
    """Return connect latency in ms, or None when unreachable."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError:
        return None
    return round((time.perf_counter() - start) * 1000)


def probe_all(targets, timeout: float = 3.0, workers: int = 32) -> dict:
    """Probe (key, host, port) targets concurrently. Returns {key: ms|None}."""
    targets = list(targets)
    results = {}
    if not targets:
        return results
    pool_size = min(workers, max(1, len(targets)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=pool_size) as pool:
        futures = {pool.submit(probe, host, port, timeout): key
                   for key, host, port in targets}
        for future in concurrent.futures.as_completed(futures):
            results[futures[future]] = future.result()
    return results

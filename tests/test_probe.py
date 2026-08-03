import socket
import tempfile
import unittest
from pathlib import Path

from netauditor import cli
from netauditor.probe import probe, probe_all


def open_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    return server, server.getsockname()[1]


def closed_port():
    """A port that was just released - connecting to it is refused."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class TestProbe(unittest.TestCase):
    def test_open_port_returns_latency(self):
        server, port = open_listener()
        try:
            ms = probe("127.0.0.1", port, timeout=2)
            self.assertIsNotNone(ms)
            self.assertGreaterEqual(ms, 0)
        finally:
            server.close()

    def test_closed_port_returns_none(self):
        self.assertIsNone(probe("127.0.0.1", closed_port(), timeout=2))

    def test_probe_all_maps_keys(self):
        server, port = open_listener()
        try:
            results = probe_all([("up", "127.0.0.1", port),
                                 ("down", "127.0.0.1", closed_port())], timeout=2)
        finally:
            server.close()
        self.assertIsNotNone(results["up"])
        self.assertIsNone(results["down"])

    def test_probe_all_empty(self):
        self.assertEqual(probe_all([]), {})


class TestStatusCommand(unittest.TestCase):
    def test_status_exit_codes_and_sweep(self):
        server, up_port = open_listener()
        down = closed_port()
        tmp = Path(tempfile.mkdtemp())
        inv = tmp / "inv.yml"
        inv.write_text(
            "hosts:\n"
            f"  - host: 127.0.0.1\n    name: up-sw\n    port: {up_port}\n"
            f"  - host: 127.0.0.1\n    name: down-sw\n    port: {down}\n",
            encoding="utf-8")
        try:
            rc = cli.main(["status", "-i", str(inv), "-o", str(tmp), "--timeout", "2"])
        finally:
            server.close()
        self.assertEqual(rc, 1)  # one switch down

    def test_status_all_up(self):
        server, up_port = open_listener()
        tmp = Path(tempfile.mkdtemp())
        inv = tmp / "inv.yml"
        inv.write_text(f"hosts:\n  - host: 127.0.0.1\n    port: {up_port}\n",
                       encoding="utf-8")
        try:
            rc = cli.main(["status", "-i", str(inv), "-o", str(tmp), "--timeout", "2"])
        finally:
            server.close()
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()

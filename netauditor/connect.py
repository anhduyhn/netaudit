"""Fast connector: open a live interactive SSH session using inventory credentials."""
from __future__ import annotations

import os
import shutil
import sys


def match_hosts(hosts, target) -> list:
    """Match a user-supplied target against the inventory.

    An exact IP or name match wins outright; otherwise a case-insensitive
    substring match against IP, name and group. An empty target matches all.
    """
    t = (target or "").strip().lower()
    if not t:
        return list(hosts)
    exact = [h for h in hosts if h.host.lower() == t or h.display_name().lower() == t]
    if exact:
        return exact[:1]
    return [h for h in hosts
            if t in h.host.lower() or t in h.display_name().lower() or t in h.group.lower()]


def choose_host(hosts):
    """Numbered picker for ambiguous / absent targets; returns a Host or None."""
    print(f"\n  #  {'name':<26} {'host':<16} group")
    for idx, h in enumerate(hosts, 1):
        print(f"{idx:>3}  {h.display_name():<26} {h.host:<16} {h.group}")
    if not sys.stdin.isatty():
        print("error: multiple matches; be more specific", file=sys.stderr)
        return None
    try:
        raw = input("\nConnect to #: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not raw.isdigit() or not (1 <= int(raw) <= len(hosts)):
        print("error: no such entry", file=sys.stderr)
        return None
    return hosts[int(raw) - 1]


def open_session(host) -> int:
    """SSH to the host and bridge the console to it until the session ends."""
    import paramiko

    print(f"Connecting to {host.display_name()} ({host.host}:{host.port}) "
          f"as {host.username} ...")
    client = paramiko.SSHClient()
    # Switch host keys are rarely curated and change on hardware swaps; accept
    # them like the audit (and typical network tooling) does.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host.host, port=host.port, username=host.username,
                       password=host.password, look_for_keys=False,
                       allow_agent=False, timeout=15)
    except Exception as exc:
        print(f"error: could not connect: {exc}", file=sys.stderr)
        return 2
    size = shutil.get_terminal_size((100, 30))
    chan = client.invoke_shell(term="xterm", width=size.columns, height=size.lines)
    print("Connected - type 'exit' to end the session.\n")
    try:
        if os.name == "nt":
            _shell_windows(chan)
        else:
            _shell_posix(chan)
    finally:
        try:
            chan.close()
            client.close()
        except Exception:
            pass
    print("\nSession closed.")
    return 0


# Windows console special keys (second byte after \x00/\xe0) -> ANSI sequences.
_WIN_KEYMAP = {
    "H": "\x1b[A",  # up
    "P": "\x1b[B",  # down
    "M": "\x1b[C",  # right
    "K": "\x1b[D",  # left
    "G": "\x1b[H",  # home
    "O": "\x1b[F",  # end
    "S": "\x7f",    # delete
}


def _shell_windows(chan):
    import msvcrt
    import threading
    import time

    def pump_output():
        while True:
            try:
                data = chan.recv(4096)
            except Exception:
                break
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.flush()

    writer = threading.Thread(target=pump_output, daemon=True)
    writer.start()
    while writer.is_alive():
        try:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):
                    ch = _WIN_KEYMAP.get(msvcrt.getwch(), "")
                if ch:
                    chan.send(ch.encode("utf-8"))
            else:
                time.sleep(0.02)
        except KeyboardInterrupt:
            chan.send(b"\x03")  # pass Ctrl+C through to the switch
        except Exception:
            break


def _shell_posix(chan):
    import select
    import socket
    import termios
    import tty

    old = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        chan.settimeout(0.0)
        while True:
            readable, _, _ = select.select([chan, sys.stdin], [], [])
            if chan in readable:
                try:
                    data = chan.recv(4096)
                except (socket.timeout, TimeoutError):
                    data = None
                if data == b"":
                    break
                if data:
                    sys.stdout.buffer.write(data)
                    sys.stdout.flush()
            if sys.stdin in readable:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    break
                chan.send(data)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)

"""In-browser VM/container consoles for team-server set-ups (#28).

A console is an interactive shell on a lab machine, bridged to the browser over a WebSocket. The server
forks a PTY and execs the engine's own exec command into the machine; bytes flow master-fd ↔ WebSocket.
No extra daemon, no agent on the guest beyond what the engine already uses.

Two pure, testable pieces and one runtime piece:
  - console_argv(engine, name, windows): the argv that opens an interactive shell on the machine.
  - ConsoleSession: forks the PTY, execs that argv, and exposes read/write/resize/close.

Engine coverage: Docker is fully interactive (`docker exec -it`). Tart and UTM run their exec under the
forked PTY — interactive where the tool forwards the tty; a graphical Windows console (noVNC) is a later
increment (see docs/implementation-plans/28-vm-consoles.md). Auth and name validation are the caller's
job (shikari.lab.web gates on _owns/_can_lab, the same as every other lab action).
"""
from __future__ import annotations

import fcntl
import os
import re
import signal
import struct
import termios
from typing import List, Optional

# Machine names follow the lab's own convention (shi-…, no spaces); be strict here too, since the name
# becomes an argv element — a belt-and-braces guard on top of the ownership check.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Try bash for a nicer prompt, fall back to sh; one string so it's a single exec argument.
_POSIX_SHELL = ["sh", "-lc", "exec bash 2>/dev/null || exec sh"]


def valid_name(name: str) -> bool:
    return bool(_NAME_RE.match(name or ""))


def console_argv(engine: str, name: str, windows: bool = False) -> List[str]:
    """The command that opens an interactive shell on `name`. Raises ValueError on a bad name/engine."""
    if not valid_name(name):
        raise ValueError(f"unsafe machine name: {name!r}")
    win_shell = ["powershell", "-NoLogo"]
    if engine == "docker":
        # -i keeps stdin open, -t allocates a tty inside the container (we already hold the outer PTY).
        return ["docker", "exec", "-it", name, *(win_shell if windows else _POSIX_SHELL)]
    if engine == "tart":
        return ["tart", "exec", name, *(win_shell if windows else _POSIX_SHELL)]
    if engine == "utm":
        # utmctl --cmd is variadic and must come last.
        return ["utmctl", "exec", "--hide", name, "--cmd", *(win_shell if windows else _POSIX_SHELL)]
    raise ValueError(f"unknown engine: {engine!r}")


class ConsoleSession:
    """A forked-PTY interactive session. Create it, then pump: read() the master fd, write() keystrokes,
    resize() on a terminal resize, close() when done. The fd is non-blocking so an async reader can poll
    it with loop.add_reader."""

    def __init__(self, argv: List[str], env: Optional[dict] = None):
        import pty

        self.argv = argv
        pid, fd = pty.fork()
        if pid == 0:  # child: become the shell
            try:
                environ = dict(os.environ, TERM="xterm-256color", **(env or {}))
                os.execvpe(argv[0], argv, environ)
            except Exception:  # noqa: BLE001 — exec failed; don't fall back into the parent's code
                os._exit(127)
        self.pid = pid
        self.fd = fd
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def read(self, size: int = 65536) -> bytes:
        """Non-blocking read of pending output; b'' when nothing is ready."""
        try:
            return os.read(self.fd, size)
        except (BlockingIOError, InterruptedError):
            return b""
        except OSError:
            return b""  # fd closed / child gone

    def write(self, data: bytes) -> None:
        try:
            os.write(self.fd, data)
        except OSError:
            pass

    def resize(self, rows: int, cols: int) -> None:
        rows = max(1, min(int(rows), 1000))
        cols = max(1, min(int(cols), 1000))
        try:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass

    def alive(self) -> bool:
        try:
            done, _ = os.waitpid(self.pid, os.WNOHANG)
            return done == 0
        except OSError:
            return False

    def close(self) -> None:
        for step in (lambda: os.kill(self.pid, signal.SIGHUP),
                     lambda: os.kill(self.pid, signal.SIGKILL),
                     lambda: os.close(self.fd),
                     lambda: os.waitpid(self.pid, os.WNOHANG)):
            try:
                step()
            except OSError:
                pass

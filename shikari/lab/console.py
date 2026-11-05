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
import secrets
import signal
import struct
import termios
import threading
import time
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


# ── Session registry: reconnect to a dropped console, and reap idle/abandoned PTYs (#28) ─────────────
IDLE_LIMIT = 1800        # close a session after this many seconds with no input or output
DETACH_GRACE = 300       # after the browser drops, keep the shell alive this long for a reconnect
RING_BYTES = 256 * 1024  # scrollback kept and replayed to a reconnecting client


class _Managed:
    """One live console: its PTY session, a capped scrollback ring, and liveness bookkeeping."""

    def __init__(self, sid: str, owner, engine: str, name: str, session: "ConsoleSession"):
        self.sid = sid
        self.owner = owner
        self.engine = engine
        self.name = name
        self.session = session
        self.buf = bytearray()
        self.attached = True
        self.last_activity = time.time()
        self.detached_at: Optional[float] = None

    def record(self, data: bytes) -> None:
        """Append output to the scrollback ring (trimmed to RING_BYTES) and mark activity."""
        self.buf += data
        if len(self.buf) > RING_BYTES:
            del self.buf[:len(self.buf) - RING_BYTES]
        self.last_activity = time.time()

    def touch(self) -> None:
        self.last_activity = time.time()

    def attach(self) -> None:
        self.attached = True
        self.detached_at = None
        self.touch()

    def detach(self) -> None:
        self.attached = False
        self.detached_at = time.time()

    def expired(self, now: float) -> bool:
        """Whether the reaper should close this: the shell exited, it's been idle too long, or the
        browser dropped and didn't come back within the grace window."""
        if not self.session.alive():
            return True
        if now - self.last_activity > IDLE_LIMIT:
            return True
        if not self.attached and self.detached_at is not None and now - self.detached_at > DETACH_GRACE:
            return True
        return False


class ConsoleRegistry:
    """Live console sessions so a dropped WebSocket can reconnect to the same shell, and idle or
    abandoned PTYs get reaped. Keyed by an unguessable session id; a reconnect must also match the
    original owner, engine and machine name."""

    def __init__(self):
        self._by_sid: dict = {}
        self._lock = threading.Lock()
        self._reaper: Optional[threading.Thread] = None

    def create(self, owner, engine: str, name: str, session: "ConsoleSession") -> str:
        sid = secrets.token_urlsafe(16)
        with self._lock:
            self._by_sid[sid] = _Managed(sid, owner, engine, name, session)
        self._ensure_reaper()
        return sid

    def get(self, sid: str, owner, engine: str, name: str) -> Optional[_Managed]:
        with self._lock:
            m = self._by_sid.get(sid)
        if m and m.owner == owner and m.engine == engine and m.name == name and m.session.alive():
            return m
        return None

    def drop(self, sid: str) -> None:
        with self._lock:
            m = self._by_sid.pop(sid, None)
        if m:
            m.session.close()

    def reap(self, now: Optional[float] = None) -> int:
        """Close and forget every expired session. Returns how many were reaped."""
        now = now or time.time()
        with self._lock:
            dead = [sid for sid, m in self._by_sid.items() if m.expired(now)]
            gone = [self._by_sid.pop(sid) for sid in dead]
        for m in gone:
            m.session.close()
        return len(gone)

    def count(self) -> int:
        with self._lock:
            return len(self._by_sid)

    def _ensure_reaper(self) -> None:
        if self._reaper and self._reaper.is_alive():
            return

        def loop():
            while True:
                time.sleep(15)
                try:
                    self.reap()
                except Exception:  # noqa: BLE001 — the reaper must never die
                    pass

        self._reaper = threading.Thread(target=loop, daemon=True, name="console-reaper")
        self._reaper.start()


REGISTRY = ConsoleRegistry()

"""Tests for the lab console argv/name helpers (#28).

Pure — no docker/tart/utm needed. The PTY runtime (ConsoleSession) and the WebSocket bridge need a real
engine and are exercised manually / in integration, not here.
"""
import pytest

from shikari.lab.console import console_argv, valid_name


def test_valid_name():
    assert valid_name("shi-cal-ubu24")
    assert valid_name("shi-win11")
    assert not valid_name("")
    assert not valid_name("has space")
    assert not valid_name("bad;rm -rf")      # no shell metacharacters
    assert not valid_name("-leadingdash")    # must start alphanumeric
    assert not valid_name("a" * 65)           # length cap


def test_docker_argv_is_interactive():
    argv = console_argv("docker", "shi-cal-ubu24")
    assert argv[:4] == ["docker", "exec", "-it", "shi-cal-ubu24"]
    assert argv[-1].startswith("exec bash")   # bash-with-sh-fallback


def test_tart_and_utm_posix():
    assert console_argv("tart", "shi-cal-mac15")[:3] == ["tart", "exec", "shi-cal-mac15"]
    utm = console_argv("utm", "shi-win11-lab")
    assert utm[:3] == ["utmctl", "exec", "--hide"]
    assert "--cmd" in utm                     # --cmd precedes the variadic command


def test_windows_uses_powershell():
    for engine in ("tart", "utm"):
        argv = console_argv(engine, "shi-win11", windows=True)
        assert "powershell" in argv
        assert "sh" not in argv


def test_bad_engine_and_name_raise():
    with pytest.raises(ValueError):
        console_argv("virtualbox", "shi-x")
    with pytest.raises(ValueError):
        console_argv("docker", "bad;name")


# ── Session registry: reconnect + reaping (#28) ──────────────────────────────────────────────────
import time as _time

from shikari.lab.console import (DETACH_GRACE, IDLE_LIMIT, RING_BYTES, ConsoleRegistry, _Managed)


class FakeSession:
    def __init__(self, alive=True):
        self._alive = alive
        self.closed = False
        self.fd = -1

    def alive(self):
        return self._alive

    def close(self):
        self.closed = True
        self._alive = False


def test_ring_buffer_caps_scrollback():
    m = _Managed("sid", 1, "docker", "shi-x", FakeSession())
    m.record(b"a" * (RING_BYTES + 5000))
    assert len(m.buf) == RING_BYTES          # trimmed to the cap
    m.record(b"TAIL")
    assert m.buf.endswith(b"TAIL")           # newest kept


def test_registry_reconnect_requires_owner_engine_name():
    reg = ConsoleRegistry()
    sid = reg.create(owner=7, engine="docker", name="shi-x", session=FakeSession())
    assert reg.get(sid, 7, "docker", "shi-x") is not None      # same identity reattaches
    assert reg.get(sid, 8, "docker", "shi-x") is None          # different owner
    assert reg.get(sid, 7, "tart", "shi-x") is None            # different engine
    assert reg.get(sid, 7, "docker", "other") is None          # different machine
    assert reg.get("nope", 7, "docker", "shi-x") is None       # unknown sid


def test_expired_rules():
    now = _time.time()
    m = _Managed("s", 1, "docker", "shi-x", FakeSession())
    assert not m.expired(now)                                  # fresh + attached + alive
    m.last_activity = now - IDLE_LIMIT - 1
    assert m.expired(now)                                      # idle too long
    m.last_activity = now
    m.detach()
    m.detached_at = now - DETACH_GRACE - 1
    assert m.expired(now)                                      # abandoned past the grace window
    dead = _Managed("d", 1, "docker", "shi-x", FakeSession(alive=False))
    assert dead.expired(now)                                   # shell exited


def test_reap_closes_and_removes_expired():
    reg = ConsoleRegistry()
    live = FakeSession()
    stale = FakeSession()
    s_live = reg.create(1, "docker", "a", live)
    s_stale = reg.create(1, "docker", "b", stale)
    # Make the second one idle-expired.
    reg._by_sid[s_stale].last_activity = _time.time() - IDLE_LIMIT - 1
    assert reg.reap() == 1
    assert stale.closed and not live.closed
    assert reg.get(s_live, 1, "docker", "a") is not None
    assert reg.get(s_stale, 1, "docker", "b") is None


def test_drop_closes_session():
    reg = ConsoleRegistry()
    s = FakeSession()
    sid = reg.create(1, "docker", "a", s)
    reg.drop(sid)
    assert s.closed
    assert reg.count() == 0

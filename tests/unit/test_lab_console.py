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

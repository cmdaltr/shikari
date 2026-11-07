"""Windows: the windowed app starts console programs with no console window of their own."""
import subprocess
import sys

import pytest

from shikari import desktop_app


@pytest.fixture
def windows(monkeypatch):
    seen = []
    monkeypatch.setattr(sys, "platform", "win32")
    for name, value in (("CREATE_NO_WINDOW", 0x08000000), ("CREATE_NEW_CONSOLE", 0x10), ("DETACHED_PROCESS", 0x8)):
        monkeypatch.setattr(subprocess, name, value, raising=False)
    monkeypatch.setattr(subprocess.Popen, "__init__", lambda self, *a, **k: seen.append(k.get("creationflags", 0)))
    monkeypatch.delattr(subprocess.Popen, "_shikari_no_window", raising=False)
    desktop_app.hide_console_windows()
    yield seen
    monkeypatch.delattr(subprocess.Popen, "_shikari_no_window", raising=False)


def test_console_programs_get_no_window(windows):
    subprocess.Popen(["git", "--version"])
    subprocess.Popen(["where", "docker"], creationflags=0x200)   # a caller's own flags are kept
    assert windows == [0x08000000, 0x200 | 0x08000000]


def test_a_detached_or_new_console_process_is_left_alone(windows):
    subprocess.Popen(["powershell"], creationflags=0x8 | 0x200)
    subprocess.Popen(["cmd"], creationflags=0x10)
    assert windows == [0x8 | 0x200, 0x10]

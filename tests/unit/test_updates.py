"""shikari.updates: is there a newer release, how often the app asks, and the install it hands over to."""
import json

import pytest

from shikari import updates

RELEASE = {"tag": "v2.1.0", "version": "2.1.0", "url": "https://github.com/cmdaltr/shikari/releases/tag/v2.1.0", "notes": ""}


@pytest.mark.parametrize("latest, current, newer", [
    ("2.1.0", "2.0.0", True),
    ("v2.0.1", "2.0.0", True),
    ("2.0.0", "2.0.0", False),
    ("2.0", "2.0.0", False),          # 2.0 == 2.0.0
    ("1.9.9", "2.0.0", False),
    ("2.10.0", "2.9.0", True),        # numbers, not strings
    ("v3.0.0-rc1", "2.9.0", True),
    ("", "2.0.0", False),
])
def test_is_newer(latest, current, newer):
    assert updates.is_newer(latest, current) is newer


@pytest.fixture
def github(monkeypatch):
    calls = []

    def latest_release(timeout=10):
        calls.append(1)
        return dict(RELEASE)
    monkeypatch.setattr(updates, "latest_release", latest_release)
    monkeypatch.delenv("SHIKARI_UPDATE_CHECK", raising=False)
    return calls


def test_asks_github_at_most_once_a_day(tmp_path, github):
    assert updates.daily_check(tmp_path, "2.0.0", now=1000)["tag"] == "v2.1.0"
    assert updates.daily_check(tmp_path, "2.0.0", now=1000 + 3600)["tag"] == "v2.1.0"   # from the cache
    assert len(github) == 1
    updates.daily_check(tmp_path, "2.0.0", now=1000 + updates.DAY)
    assert len(github) == 2


def test_nothing_when_already_on_the_latest(tmp_path, github):
    assert updates.daily_check(tmp_path, "2.1.0", now=1000) is None


def test_switched_off_never_asks(tmp_path, github, monkeypatch):
    updates.set_checks(tmp_path, False)
    assert updates.daily_check(tmp_path, "2.0.0", now=1000) is None
    updates.set_checks(tmp_path, True)
    monkeypatch.setenv("SHIKARI_UPDATE_CHECK", "0")
    assert updates.daily_check(tmp_path, "2.0.0", now=1000) is None
    assert github == []


def test_a_skipped_version_stays_quiet_but_a_later_one_shows(tmp_path, github, monkeypatch):
    updates.skip(tmp_path, "2.1.0")
    assert updates.daily_check(tmp_path, "2.0.0", now=1000) is None
    monkeypatch.setattr(updates, "latest_release", lambda timeout=10: {**RELEASE, "tag": "v2.2.0", "version": "2.2.0"})
    assert updates.daily_check(tmp_path, "2.0.0", now=1000 + updates.DAY)["version"] == "2.2.0"


def test_a_failed_check_is_quiet_and_waits_a_day(tmp_path, monkeypatch):
    calls = []

    def offline(timeout=10):
        calls.append(1)
        raise updates.UpdateError("couldn't reach GitHub")
    monkeypatch.setattr(updates, "latest_release", offline)
    assert updates.daily_check(tmp_path, "2.0.0", now=1000) is None
    assert updates.daily_check(tmp_path, "2.0.0", now=2000) is None
    assert len(calls) == 1
    assert "latest" not in json.loads((tmp_path / "update.json").read_text())


def test_installer_waits_for_the_app_then_installs_and_reopens(monkeypatch):
    monkeypatch.setattr(updates.sys, "platform", "darwin")
    cmd = updates.installer_command("/app/seed/install.sh", "v2.1.0", wait_pid=4242, log="/tmp/update.log")
    assert cmd[:2] == ["/bin/sh", "-c"]
    assert "kill -0 4242" in cmd[2] and "--version 'v2.1.0' --launch" in cmd[2] and "/tmp/update.log" in cmd[2]
    assert "--launch" not in updates.installer_command("/x/install.sh", "v2.1.0", launch=False)[2]

    monkeypatch.setattr(updates.sys, "platform", "win32")
    cmd = updates.installer_command(r"C:\app\seed\install.ps1", "v2.1.0", wait_pid=4242)
    assert cmd[0] == "powershell" and "Wait-Process -Id 4242" in cmd[-1] and "-Version 'v2.1.0' -Launch" in cmd[-1]


def test_a_private_repository_without_a_token_says_why(monkeypatch):
    from urllib.error import HTTPError

    def not_found(*a, **k):
        raise HTTPError("https://api.github.com", 404, "Not Found", {}, None)
    monkeypatch.setattr(updates, "token", lambda: None)
    monkeypatch.setattr(updates, "urlopen", not_found)
    with pytest.raises(updates.UpdateError, match="GH_TOKEN"):
        updates.latest_release()

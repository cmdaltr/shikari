"""The Edge window for Windows on ARM64 (shikari.desktop_edge)."""

import json
import urllib.request
from types import SimpleNamespace

import pytest

from shikari import desktop_edge


class FakeApp:
    def __init__(self):
        self.choice = None
        self.calls = []

    def connect(self, url):
        self.calls.append(("connect", url))
        return {"url": url} if url.startswith("https://") else {"error": "Not an address"}

    def use_local(self):
        self.calls.append(("local",))
        return {"url": "http://127.0.0.1:8000"}


def _post(url, body=b""):
    with urllib.request.urlopen(urllib.request.Request(url, data=body, method="POST")) as r:
        return json.load(r)


def test_chooser_serves_the_page_with_the_bridge_and_answers_posts():
    app = FakeApp()
    chooser = desktop_edge.Chooser(app)
    try:
        page = urllib.request.urlopen(chooser.url).read().decode()
        assert "window.pywebview" in page and "Connect to Shikari" in page
        assert _post(chooser.url + "connect", b"https://shikari.example.org") == {"url": "https://shikari.example.org"}
        assert _post(chooser.url + "connect", b"nope") == {"error": "Not an address"}
        assert _post(chooser.url + "local") == {"url": "http://127.0.0.1:8000"}
    finally:
        chooser.stop()


def test_chooser_ignores_other_paths():
    app = FakeApp()
    chooser = desktop_edge.Chooser(app)
    try:
        base = chooser.url.rsplit("/", 2)[0]
        with pytest.raises(urllib.error.HTTPError):
            _post(base + "/guess/connect", b"https://evil.example")
        assert app.calls == []
    finally:
        chooser.stop()


def test_wanted_only_on_windows_arm64(monkeypatch):
    monkeypatch.delenv("SHIKARI_WINDOW", raising=False)
    monkeypatch.setattr(desktop_edge.sys, "platform", "win32")
    monkeypatch.setattr(desktop_edge.platform, "machine", lambda: "ARM64")
    assert desktop_edge.wanted()
    monkeypatch.setattr(desktop_edge.platform, "machine", lambda: "AMD64")
    assert not desktop_edge.wanted()
    monkeypatch.setenv("SHIKARI_WINDOW", "edge")
    assert desktop_edge.wanted()
    monkeypatch.setattr(desktop_edge.sys, "platform", "darwin")
    assert not desktop_edge.wanted()


def test_local_choice_opens_the_local_server(monkeypatch, tmp_path):
    app = desktop_edge.EdgeApp.__new__(desktop_edge.EdgeApp)
    app.choice = SimpleNamespace(mode="local")
    app.log = tmp_path / "shikari.log"
    monkeypatch.setattr(app, "start_local", lambda: ("http://127.0.0.1:8000", None), raising=False)
    assert app.first_url() == ("http://127.0.0.1:8000", None)
    monkeypatch.setattr(app, "start_local", lambda: (None, "port in use"), raising=False)
    url, chooser = app.first_url()
    assert url.startswith("data:text/html,") and "port in use" in url and chooser is None


def test_edge_holds_is_false_without_a_lock(tmp_path):
    assert not desktop_edge.edge_holds(tmp_path)


def test_dotnet_root_needs_desktop_runtime_8_or_later(monkeypatch, tmp_path):
    for var in ("DOTNET_ROOT", "ProgramFiles", "LOCALAPPDATA"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DOTNET_ROOT", str(tmp_path))
    shared = tmp_path / "shared" / "Microsoft.WindowsDesktop.App"
    (shared / "6.0.36").mkdir(parents=True)
    assert desktop_edge.dotnet_root() is None
    (shared / "8.0.11").mkdir()
    assert desktop_edge.dotnet_root() == tmp_path


def test_use_dotnet_falls_back_to_edge(monkeypatch, tmp_path):
    monkeypatch.setenv("SHIKARI_WINDOW", "edge")
    assert not desktop_edge.use_dotnet(tmp_path)
    monkeypatch.delenv("SHIKARI_WINDOW")
    monkeypatch.setattr(desktop_edge, "dotnet_root", lambda: None)
    assert not desktop_edge.use_dotnet(tmp_path)

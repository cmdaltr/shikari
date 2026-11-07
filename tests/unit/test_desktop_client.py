"""The desktop app's choice of server: IT's setting, SHIKARI_SERVER, the user's, or ask."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from shikari import desktop_client as client


@pytest.fixture(autouse=True)
def no_policy(monkeypatch):
    monkeypatch.setattr(client, "managed_url", lambda: None)
    monkeypatch.delenv("SHIKARI_SERVER", raising=False)


def test_nothing_set_asks(tmp_path):
    assert client.resolve(tmp_path) is None


def test_it_setting_wins_and_is_locked(tmp_path, monkeypatch):
    monkeypatch.setattr(client, "managed_url", lambda: "https://shikari.corp.example")
    monkeypatch.setenv("SHIKARI_SERVER", "local")
    client.save(tmp_path, client.Choice("local"))
    choice = client.resolve(tmp_path)
    assert (choice.mode, choice.url, choice.managed) == ("server", "https://shikari.corp.example", True)


def test_environment_beats_saved_choice(tmp_path, monkeypatch):
    client.save(tmp_path, client.Choice("server", "https://old.example"))
    monkeypatch.setenv("SHIKARI_SERVER", "local")
    assert client.resolve(tmp_path).mode == "local"
    monkeypatch.setenv("SHIKARI_SERVER", "https://new.example")
    choice = client.resolve(tmp_path)
    assert (choice.mode, choice.url, choice.managed) == ("server", "https://new.example", False)


def test_saved_choice_round_trips(tmp_path):
    client.save(tmp_path, client.Choice("server", "https://shikari.corp.example"))
    assert client.resolve(tmp_path).url == "https://shikari.corp.example"
    client.save(tmp_path, client.Choice("local"))
    assert client.resolve(tmp_path).mode == "local"


def test_corrupt_saved_choice_asks(tmp_path):
    client.saved_path(tmp_path).write_text("{not json")
    assert client.resolve(tmp_path) is None


@pytest.mark.parametrize("typed, expected", [
    ("shikari.corp.example", "https://shikari.corp.example"),
    ("https://shikari.corp.example/", "https://shikari.corp.example"),
    ("https://shikari.corp.example:8443/shikari/", "https://shikari.corp.example:8443/shikari"),
    ("http://localhost:8000", "http://localhost:8000"),
    ("http://127.0.0.1:8000/", "http://127.0.0.1:8000"),
])
def test_normalise(typed, expected):
    assert client.normalise(typed) == expected


@pytest.mark.parametrize("typed", ["", "   ", "ftp://shikari.corp.example", "http://shikari.corp.example"])
def test_normalise_rejects(typed):
    with pytest.raises(ValueError):
        client.normalise(typed)


def test_plain_http_allowed_when_it_or_env_set_it():
    assert client.normalise("http://shikari.corp.example", allow_http=True) == "http://shikari.corp.example"


def _serve(body, status=200):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.mark.parametrize("body, ok", [
    (json.dumps({"status": "ok", "app": "shikari"}), True),
    (json.dumps({"status": "ok"}), True),                    # a server older than the desktop app
    (json.dumps({"status": "ok", "app": "grafana"}), False),
    ("<html>a login page</html>", False),
])
def test_probe(body, ok):
    server, url = _serve(body)
    try:
        assert client.probe(url, timeout=5)[0] is ok
    finally:
        server.shutdown()


def test_probe_unreachable():
    ok, message = client.probe("http://127.0.0.1:9", timeout=2)
    assert not ok and "Couldn't reach" in message


class FakeWindow:
    def __init__(self):
        self.loaded, self.title = [], ""
        self.events = type("Events", (), {"shown": threading.Event(), "loaded": threading.Event()})()
        self.events.shown.set()
        self.events.loaded.set()

    def load_url(self, url):
        self.loaded.append(("url", url))

    def load_html(self, html):
        self.loaded.append(("html", html))

    def set_title(self, title):
        self.title = title


def _app(tmp_path):
    from shikari.desktop_app import App, ChooserApi
    app = App(tmp_path, "log")
    app.window = FakeWindow()
    return app, ChooserApi(app)


def test_a_window_slow_to_appear_is_waited_for(tmp_path):
    """WebKit's first start on a slow machine passed pywebview's 20 s limit and killed the start-up."""
    app, _ = _app(tmp_path)
    app.choice = None
    app.window.events.shown = threading.Event()
    threading.Timer(0.3, app.window.events.shown.set).start()
    app.boot()
    assert app.window.loaded and app.window.loaded[-1][0] == "html"


def test_nothing_is_sent_before_the_web_view_has_loaded(tmp_path):
    """Windows: WebView2 comes up after the window is shown, and a page sent before it has loaded the
    splash was dropped silently, leaving "Starting Shikari..." up for good."""
    app, _ = _app(tmp_path)
    app.choice = None
    app.window.events.loaded = threading.Event()
    seen = []
    threading.Timer(0.3, lambda: (seen.append(list(app.window.loaded)), app.window.events.loaded.set())).start()
    app.boot()
    assert seen == [[]]
    assert app.window.loaded[-1][0] == "html"


def test_chooser_connects_and_remembers(tmp_path):
    server, url = _serve(json.dumps({"status": "ok", "app": "shikari"}))
    try:
        app, api = _app(tmp_path)
        app.show_chooser()
        assert api.connect(url) == ""
        assert app.window.loaded[-1] == ("url", url) and not app.choosing
        assert client.resolve(tmp_path).url == url
    finally:
        server.shutdown()


def test_chooser_reports_a_bad_address(tmp_path):
    app, api = _app(tmp_path)
    app.show_chooser()
    assert "https" in api.connect("http://shikari.corp.example")
    assert app.choosing and client.resolve(tmp_path) is None


def test_server_pages_cannot_repoint_the_app(tmp_path):
    """pywebview gives the API to every page, the organisation's server's too."""
    server, url = _serve(json.dumps({"status": "ok", "app": "shikari"}))
    try:
        app, api = _app(tmp_path)
        app.open_server("https://shikari.corp.example")
        assert api.connect(url) == "Not available"
        api.use_local()
        assert app.window.loaded == [("url", "https://shikari.corp.example")]
        assert client.resolve(tmp_path) is None
    finally:
        server.shutdown()


def test_bundled_git_comes_after_an_installed_one(tmp_path, monkeypatch):
    import os
    from shikari import desktop_app
    (tmp_path / "mingit" / "cmd").mkdir(parents=True)
    monkeypatch.setattr(desktop_app, "ROOT", tmp_path)
    monkeypatch.setenv("PATH", "installed")
    desktop_app.bundled_git()
    assert os.environ["PATH"] == os.pathsep.join(["installed", str(tmp_path / "mingit" / "cmd")])

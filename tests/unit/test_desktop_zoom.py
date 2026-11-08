"""The desktop app's zoom: View > Zoom In / Zoom Out / Reset Zoom and Cmd/Ctrl + - 0 (shikari.desktop_app)."""

import json

from shikari import desktop_app


class FakeWindow:
    def __init__(self):
        self.js = []

    def evaluate_js(self, script):
        self.js.append(script)


def _app(home):
    app = desktop_app.App.__new__(desktop_app.App)
    app.home, app.window = home, FakeWindow()
    app.zoom = desktop_app.load_zoom(home)
    return app


def test_opens_at_90_percent(tmp_path):
    assert desktop_app.load_zoom(tmp_path) == 0.9


def test_zoom_steps_by_ten_percent_and_is_remembered(tmp_path):
    app = _app(tmp_path)
    app.zoom_by(1)
    app.zoom_by(1)
    assert app.zoom == 1.1
    assert json.loads((tmp_path / "zoom.json").read_text()) == {"zoom": 1.1}
    assert "document.documentElement.style.zoom=1.1;" in app.window.js[-1]
    assert desktop_app.load_zoom(tmp_path) == 1.1


def test_zoom_stays_within_limits_and_resets(tmp_path):
    app = _app(tmp_path)
    for _ in range(20):
        app.zoom_by(-1)
    assert app.zoom == desktop_app.ZOOM_MIN
    for _ in range(30):
        app.zoom_by(1)
    assert app.zoom == desktop_app.ZOOM_MAX
    app.zoom_by(0)
    assert app.zoom == desktop_app.ZOOM_DEFAULT


def test_a_bad_saved_zoom_falls_back(tmp_path):
    (tmp_path / "zoom.json").write_text("not json")
    assert desktop_app.load_zoom(tmp_path) == 0.9
    (tmp_path / "zoom.json").write_text(json.dumps({"zoom": 9}))
    assert desktop_app.load_zoom(tmp_path) == desktop_app.ZOOM_MAX

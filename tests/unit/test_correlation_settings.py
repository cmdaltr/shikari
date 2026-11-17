"""Correlation settings (Profile -> Config) are saved in data/, merged, and never rewrite the source.

Saving used to rewrite config.py and engine.py, filling in any setting the request left out with a
default: a test posting two unrelated fields set engine.py's per-vendor default to 25.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import shikari.app as app_module
from shikari import paths
from shikari.correlation import settings

SOURCES = [Path(app_module.__file__).parent / "config.py", Path(app_module.__file__).parent / "ai/genai/engine.py"]


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "DATA", tmp_path)
    return tmp_path


@pytest.fixture
def client(monkeypatch):
    class Db:
        def close(self):
            pass

    monkeypatch.setattr(app_module, "_require_admin", lambda request, session, json=True: (object(), Db()))
    return TestClient(app_module.app)


def test_defaults_without_a_file():
    assert settings.load() == settings.DEFAULTS


def test_a_save_changes_only_what_it_names(data_dir):
    settings.save({"per_vendor": 80})
    assert settings.save({"threshold": 0.5}) == {"threshold": 0.5, "per_vendor": 80, "tech_freq": 20}
    assert json.loads((data_dir / "correlation_settings.json").read_text())["per_vendor"] == 80


@pytest.mark.parametrize("changes,error", [
    ({"threshold": 1.5}, "threshold must be between"),
    ({"per_vendor": 0}, "per_vendor must be between"),
    ({"tech_freq": "lots"}, "tech_freq must be a number"),
    ({"max_per_vendor": 25}, "Unknown setting"),
])
def test_bad_values_are_refused_and_nothing_is_written(data_dir, changes, error):
    with pytest.raises(ValueError, match=error):
        settings.save(changes)
    assert not (data_dir / "correlation_settings.json").exists()


def test_a_damaged_file_falls_back_per_setting(data_dir):
    (data_dir / "correlation_settings.json").write_text('{"threshold": 7, "per_vendor": 90}')
    assert settings.load() == {"threshold": 0.4, "per_vendor": 90, "tech_freq": 20}
    (data_dir / "correlation_settings.json").write_text("not json")
    assert settings.load() == settings.DEFAULTS


def test_the_api_saves_to_data_and_leaves_the_source_alone(client, data_dir):
    before = [p.read_bytes() for p in SOURCES]
    r = client.post("/api/correlation/params", json={"tech_freq": 30, "time_window": "15m"})
    assert r.status_code == 200 and r.json()["tech_freq"] == 30 and r.json()["per_vendor"] == 60
    assert [p.read_bytes() for p in SOURCES] == before
    got = client.get("/api/correlation/params").json()
    assert (got["threshold"], got["per_vendor"], got["tech_freq"]) == (0.4, 60, 30)


@pytest.mark.parametrize("body", [{"time_window": "15m"}, {"threshold": 2}])
def test_the_api_refuses_nothing_to_save_and_bad_values(client, data_dir, body):
    r = client.post("/api/correlation/params", json=body)
    assert r.status_code == 400 and not (data_dir / "correlation_settings.json").exists()


def test_the_api_needs_an_admin():
    r = TestClient(app_module.app).post("/api/correlation/params", json={"threshold": 0.5})
    assert r.status_code in (401, 403)

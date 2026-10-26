"""Detections-as-code repo config (#20 admin settings)."""

import os

import archer.export.repo_config as rc


def test_load_default_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "_PATH", str(tmp_path / "none.json"))
    cfg = rc.load()
    assert cfg["repo_path"] and cfg["remote_url"] == "" and cfg["push_enabled"] is False


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setattr(rc, "DATA_DIR", str(tmp_path))
    rc.save("/some/repo", "git@host:org/repo.git", True)
    cfg = rc.load()
    assert cfg["repo_path"] == "/some/repo"
    assert cfg["remote_url"] == "git@host:org/repo.git"
    assert cfg["push_enabled"] is True


def test_blank_path_falls_back_to_default(tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setattr(rc, "DATA_DIR", str(tmp_path))
    saved = rc.save("   ", "", False)
    assert saved["repo_path"] == rc.DETECTIONS_REPO_DIR


def test_connectivity_existing_dir(tmp_path):
    out = rc.test_connectivity(str(tmp_path), "")
    assert out["repo_ok"] is True
    assert "writable" in out["repo_message"]
    assert out["remote_ok"] is None  # no remote given


def test_connectivity_creatable_path(tmp_path):
    out = rc.test_connectivity(str(tmp_path / "newdir"), "")
    assert out["repo_ok"] is True
    assert "will be created" in out["repo_message"]
    assert out["remote_ok"] is None


def test_connectivity_uncreatable_path():
    out = rc.test_connectivity("/nonexistent-root-xyz/sub/repo", "")
    assert out["repo_ok"] is False

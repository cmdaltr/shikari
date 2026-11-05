"""Custom-execution recordings round-trip through lab.datasets() (#27), and the lab-host gate.

The telemetry parser is exercised elsewhere; here we isolate lab.py's manifest handling by stubbing
parse/summarise, so the tests are about the schema (custom vs ART vs novel) and backward compatibility.
"""
import json
import os

import pytest

from shikari.telemetry import lab


def _write_run(root, run, manifest, folders):
    run_dir = os.path.join(root, run)
    os.makedirs(run_dir)
    with open(os.path.join(run_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    for folder in folders:
        d = os.path.join(run_dir, folder)
        os.makedirs(d)
        with open(os.path.join(d, "events.xml"), "w", encoding="utf-8") as fh:
            fh.write("<events/>")


@pytest.fixture
def lab_dir(tmp_path, monkeypatch):
    root = str(tmp_path / "lab")
    os.makedirs(root)
    monkeypatch.setattr(lab, "LAB_DIR", root)
    # Isolate from the real parser: one synthetic event, deterministic summary.
    monkeypatch.setattr(lab, "parse", lambda blob, *a, **k: [("proc", {"image": "x"})])
    monkeypatch.setattr(lab, "summarise", lambda events: ({"proc": 1}, {"proc": {"image": ["x"]}}))
    return root


def _collect(lab_dir):
    return {d["id"]: (d, vals) for d, vals, key in lab.datasets({})}


def test_art_entry_still_works(lab_dir):
    _write_run(lab_dir, "host-1", {"platform": "windows", "tests": [
        {"technique": "T1059.001", "test": 1, "name": "enc ps", "folder": "T1059.001-1"}]}, ["T1059.001-1"])
    out = _collect(lab_dir)
    d, vals = out["lab:host-1/T1059.001-1"]
    assert d["techniques"] == ["T1059.001"]
    assert d["tools"] == ["Atomic Red Team"]
    assert not d.get("custom")
    assert vals == {"proc": {"image": ["x"]}}


def test_custom_mapped_entry(lab_dir):
    _write_run(lab_dir, "lab-2", {"platform": "linux", "tool": "Custom execution", "tests": [
        {"custom": True, "folder": "custom-1", "name": "sneaky cron", "mapping": "T1053.003",
         "mapping_kind": "sub", "command": "echo '* * * * * evil' | crontab -", "notes": "variant",
         "provenance": "ben@vm", "start": "2026-11-05T10:00:00Z"}]}, ["custom-1"])
    d, vals = _collect(lab_dir)["lab:lab-2/custom-1"]
    assert d["custom"] is True and d["novel"] is False
    assert d["techniques"] == ["T1053.003"]
    assert "T1053.003" in d["title"]
    assert d["command"].startswith("echo") and d["notes"] == "variant" and d["provenance"] == "ben@vm"
    assert d["date"] == "2026-11-05"
    assert vals == {"proc": {"image": ["x"]}}          # grounds detection fields like any dataset


def test_custom_novel_entry_has_no_technique(lab_dir):
    _write_run(lab_dir, "lab-3", {"platform": "windows", "tests": [
        {"custom": True, "folder": "custom-1", "name": "undocumented persistence",
         "mapping_kind": "novel", "command": "rundll32 evil.dll,Go"}]}, ["custom-1"])
    d, _ = _collect(lab_dir)["lab:lab-3/custom-1"]
    assert d["novel"] is True
    assert d["techniques"] == []                       # nothing to key on — that's the point
    assert "(novel)" in d["title"]


def test_novel_when_mapping_absent_even_without_kind(lab_dir):
    _write_run(lab_dir, "lab-4", {"platform": "macos", "tests": [
        {"custom": True, "folder": "custom-1", "name": "x", "command": "id"}]}, ["custom-1"])
    d, _ = _collect(lab_dir)["lab:lab-4/custom-1"]
    assert d["novel"] is True and d["techniques"] == []


def test_entry_without_technique_or_custom_is_skipped(lab_dir):
    _write_run(lab_dir, "lab-5", {"platform": "linux", "tests": [
        {"folder": "junk-1", "name": "no technique, not custom"}]}, ["junk-1"])
    assert _collect(lab_dir) == {}


# ── Lab-host designation gate ────────────────────────────────────────────────────────────────────
from shikari.lab import designation
from shikari.lab.runner import LabError


@pytest.fixture
def no_markers(tmp_path, monkeypatch):
    monkeypatch.delenv("SHIKARI_LAB_HOST", raising=False)
    monkeypatch.setattr(designation, "MARKER", str(tmp_path / "none" / "LAB_HOST"))
    monkeypatch.setattr(designation, "HOME_MARKER", str(tmp_path / ".shikari-lab-host"))


def test_not_a_lab_host_by_default(no_markers):
    assert not designation.is_designated_lab_host()
    with pytest.raises(LabError):
        designation.require_lab_host()


def test_env_var_designates(no_markers, monkeypatch):
    monkeypatch.setenv("SHIKARI_LAB_HOST", "yes")
    assert designation.is_designated_lab_host()
    designation.require_lab_host()                     # does not raise


def test_marker_file_designates(no_markers):
    path = designation.designate(home_marker=True)
    assert os.path.exists(path)
    assert designation.is_designated_lab_host()

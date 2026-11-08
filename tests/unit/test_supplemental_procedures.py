"""
Unit tests for supplemental (non-MITRE) procedure merging in
``shikari.build.detections.load_supplemental_indicators``.

The generator derives indicators only from MITRE ATT&CK procedure examples, so a
procedure MITRE does not document (e.g. a CALDERA ability) would never be detected.
The supplemental-procedure files let such procedures be curated and committed; these
tests cover the loader that reads them and the shipped discovery file.

No network or STIX access is involved — the loader reads local YAML only.
"""

from pathlib import Path

import pytest

from shikari.build.detections import load_supplemental_indicators
from shikari import paths


def _write(base: Path, name: str, text: str) -> None:
    base.mkdir(parents=True, exist_ok=True)
    (base / name).write_text(text, encoding="utf-8")


def test_returns_indicators_for_known_technique(tmp_path):
    _write(tmp_path, "a.yaml", "T1016:\n  cmd:\n    - nbtstat -n\n")
    assert load_supplemental_indicators("T1016", base_dir=tmp_path) == {"cmd": ["nbtstat -n"]}


def test_technique_lookup_is_case_insensitive(tmp_path):
    _write(tmp_path, "a.yaml", "t1016:\n  cmd:\n    - nbtstat -n\n")
    assert load_supplemental_indicators("T1016", base_dir=tmp_path) == {"cmd": ["nbtstat -n"]}
    assert load_supplemental_indicators("t1016", base_dir=tmp_path) == {"cmd": ["nbtstat -n"]}


def test_unknown_technique_returns_empty(tmp_path):
    _write(tmp_path, "a.yaml", "T1016:\n  cmd:\n    - nbtstat -n\n")
    assert load_supplemental_indicators("T9999", base_dir=tmp_path) == {}


def test_missing_directory_returns_empty(tmp_path):
    assert load_supplemental_indicators("T1016", base_dir=tmp_path / "nope") == {}


def test_merges_and_dedupes_across_files(tmp_path):
    _write(tmp_path, "a.yaml", "T1057:\n  cmd:\n    - get-process\n    - gwmi win32_process\n")
    _write(tmp_path, "b.yaml", "T1057:\n  cmd:\n    - get-process\n    - tasklist\n")
    result = load_supplemental_indicators("T1057", base_dir=tmp_path)
    # de-duplicated, first-seen order preserved
    assert result == {"cmd": ["get-process", "gwmi win32_process", "tasklist"]}


def test_scalar_value_is_coerced_to_list(tmp_path):
    _write(tmp_path, "a.yaml", "T1082:\n  cmd: systeminfo\n")
    assert load_supplemental_indicators("T1082", base_dir=tmp_path) == {"cmd": ["systeminfo"]}


def test_malformed_file_is_skipped_not_fatal(tmp_path):
    _write(tmp_path, "bad.yaml", "T1016:\n  cmd:\n  -  : : [unterminated\n")
    _write(tmp_path, "good.yaml", "T1016:\n  cmd:\n    - nbtstat -n\n")
    # the bad file is skipped with a warning; the good one still loads
    assert load_supplemental_indicators("T1016", base_dir=tmp_path) == {"cmd": ["nbtstat -n"]}


def test_defaults_to_data_supplemental_procedures(tmp_path, monkeypatch):
    # with base_dir omitted the loader reads <data>/supplemental_procedures
    monkeypatch.setenv("SHIKARI_HOME", str(tmp_path))
    import importlib
    import shikari.paths as p
    importlib.reload(p)
    import shikari.build.detections as d
    importlib.reload(d)
    _write(tmp_path / "data" / "supplemental_procedures", "x.yaml",
           "T1016:\n  cmd:\n    - nbtstat -n\n")
    assert d.load_supplemental_indicators("T1016") == {"cmd": ["nbtstat -n"]}
    importlib.reload(p)
    importlib.reload(d)


def test_shipped_discovery_file_covers_caldera_procedures():
    """The committed discovery file must keep the CALDERA discovery procedures."""
    shipped = Path(__file__).resolve().parents[2] / "data" / "supplemental_procedures" / "discovery_caldera.yaml"
    assert shipped.is_file(), "discovery_caldera.yaml should be committed"
    assert load_supplemental_indicators("T1016", base_dir=shipped.parent)["cmd"] == ["nbtstat -n"]
    assert set(load_supplemental_indicators("T1057", base_dir=shipped.parent)["cmd"]) == {
        "gwmi win32_process", "get-process"}
    assert load_supplemental_indicators("T1082", base_dir=shipped.parent)["cmd"] == [
        "[environment]::OSVersion.Version"]

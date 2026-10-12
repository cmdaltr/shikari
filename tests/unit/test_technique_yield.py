"""Techniques known to produce nothing: the ATT&CK list, the learnt AI list, run outcomes."""

import json

import pytest

from archer.build import run_files, technique_yield as ty


@pytest.fixture
def yield_files(tmp_path, monkeypatch):
    static = tmp_path / "technique_yield.json"
    static.write_text(json.dumps({"attack_version": "test", "techniques": {
        "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["Initial Access"], "reason": "no_indicators"}}}))
    monkeypatch.setattr(ty, "STATIC_PATH", str(static))
    monkeypatch.setattr(ty, "LEDGER_PATH", str(tmp_path / "ledger.json"))
    monkeypatch.setattr(ty, "_static", None)
    return tmp_path


def test_preflight_depends_on_mode(yield_files):
    assert set(ty.preflight(["T1190", "T1003.001"])) == {"T1190"}
    assert ty.preflight(["t1190"], osint=True) == {}
    assert ty.preflight(["T1190"], ai=True) == {}


def test_ai_empty_runs_are_learnt_and_cleared(yield_files):
    for _ in range(ty.LLM_EMPTY_LIMIT - 1):
        ty.record_llm("T1001", False)
    assert not ty.llm_exhausted("T1001")
    ty.record_llm("T1001", False)
    assert ty.llm_exhausted("T1001") == ty.LLM_EMPTY_LIMIT
    assert ty.preflight(["T1001"], ai=True)["T1001"]["reason"] == "llm_empty"
    ty.record_llm("T1001", True)
    assert not ty.llm_exhausted("T1001")


def test_run_manifest_lists_techniques_with_no_detection(tmp_path, monkeypatch):
    monkeypatch.setattr(run_files, "RUNS_DIR", str(tmp_path))
    run_files.begin("G")
    run_files.outcome("G", "T1190", "Exploit", False, "no_indicators")
    run_files.outcome("G", "T1059", "Cmd", False, "no_source")
    run_files.outcome("G", "T1059", "Cmd", True, None)
    run_files.outcome("G", "T1059", "Cmd", False, "no_source")
    run_files.finish("G")
    missed = run_files.latest_run("G")["no_detection"]
    assert [m["technique"] for m in missed] == ["T1190"]
    assert missed[0]["reason"] == "no_indicators"

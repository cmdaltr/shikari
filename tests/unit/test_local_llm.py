"""Local-model harness (#9): compact prompt, cost cap, smoke test — no model needed."""

import pytest

from archer.build import local_llm
from archer.build.llm_queries import build_compact_local_prompt

TECH = dict(technique_id="T1059.001", technique_name="PowerShell", tactic="Execution",
            procedure_example="Adversary runs an encoded PowerShell download cradle." * 50,
            evidence_json='{"cmd": ["powershell -enc", "IEX", "DownloadString"], "sw": ["powershell.exe"]}',
            platforms=["Windows"])


def test_compact_prompt_within_token_budget():
    p = build_compact_local_prompt(siem="secops", detectable_via="Process creation", group_name="FIN7", **TECH)
    assert len(p) < 32000           # ~8k tokens at ~4 chars/token
    assert "Google SecOps YARA-L" in p
    assert "T1059.001" in p and "PowerShell" in p
    assert "## " in p and "Example query object" in p


def test_compact_prompt_names_siem_sources():
    p = build_compact_local_prompt(siem="mde", **TECH)
    assert "Microsoft Defender XDR KQL" in p
    # the MDE schema's table names should be offered as the data sources
    assert "DeviceProcessEvents" in p


def test_compact_prompt_truncates_long_procedure():
    p = build_compact_local_prompt(siem="splunk", **TECH)
    # the 50x-repeated procedure is cut to 800 chars, so the prompt stays lean
    assert len(p) < 32000


def test_run_cap_env(monkeypatch):
    monkeypatch.delenv("ARCHER_LOCAL_LLM_CAP", raising=False)
    assert local_llm.local_run_cap() == local_llm.DEFAULT_CAP
    monkeypatch.setenv("ARCHER_LOCAL_LLM_CAP", "3")
    assert local_llm.local_run_cap() == 3
    monkeypatch.setenv("ARCHER_LOCAL_LLM_CAP", "nonsense")
    assert local_llm.local_run_cap() == local_llm.DEFAULT_CAP


def test_run_plan_caps_and_estimates():
    plan = local_llm.local_run_plan(25, cap=10, seconds_per_call=30)
    assert plan["will_run"] == 10 and plan["over_cap"] and plan["excess"] == 15
    assert plan["needs_confirmation"] and plan["est_seconds"] == 300
    under = local_llm.local_run_plan(4, cap=10)
    assert under["will_run"] == 4 and not under["over_cap"]
    unlimited = local_llm.local_run_plan(100, cap=-1)
    assert unlimited["will_run"] == 100 and not unlimited["over_cap"]


_GOOD = '{"technique_id": "T1003.001", "queries": [{"source_index": "PROCESS_LAUNCH", "reason": "lsass", "query": "metadata.event_type = \\"PROCESS_LAUNCH\\""}]}'


def test_smoke_test_suitable():
    out = local_llm.smoke_test_local_model({}, call_fn=lambda prompt, cfg: _GOOD, siem="secops")
    assert out["suitable"] and out["query_count"] == 1
    assert out["seconds_per_call"] == out["elapsed_s"]
    assert out["prompt_chars"] > 0


def test_smoke_test_rejects_loop():
    looped = '{"query": "x ' + "AAAA " * 200
    out = local_llm.smoke_test_local_model({}, call_fn=lambda p, c: looped)
    assert not out["suitable"] and ("repetition" in out["reason"] or "truncated" in out["reason"])


def test_smoke_test_rejects_empty():
    out = local_llm.smoke_test_local_model({}, call_fn=lambda p, c: "I cannot help with that.")
    assert not out["suitable"] and out["query_count"] == 0


def test_smoke_test_flags_slow():
    out = local_llm.smoke_test_local_model({}, call_fn=lambda p, c: _GOOD, time_budget_s=0)
    assert not out["suitable"] and "budget" in out["reason"]


def test_smoke_test_handles_call_failure():
    def boom(p, c):
        raise RuntimeError("connection refused")
    out = local_llm.smoke_test_local_model({}, call_fn=boom)
    assert not out["suitable"] and "call failed" in out["reason"]

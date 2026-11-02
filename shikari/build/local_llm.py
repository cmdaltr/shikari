"""
Local-model guardrails for detection generation (#9).

A local model on CPU is slow and loops easily, so running a whole group through one is a 40-hour
mistake. These helpers keep it sane without a model present to test against:

- a per-run cap on how many techniques go to a local model, with a pre-run estimate;
- a one-technique smoke test that says whether a configured local model returns something usable,
  so the UI can mark it suitable (or not) for detection generation.

The trimmed prompt itself is ``llm_queries.build_compact_local_prompt``. The loop/truncation guard
is ``llm_queries.detect_degenerate_response``. Nothing here needs a model to be unit-tested — the
call is injectable.
"""

import os
import time
from typing import Callable, Dict, Optional

# A fixed, minimal technique for the smoke test: OS Credential Dumping: LSASS Memory.
_SMOKE = {
    "technique_id": "T1003.001",
    "technique_name": "LSASS Memory",
    "tactic": "Credential Access",
    "procedure_example": "An adversary dumps credential material from the LSASS process memory, "
                         "for example with procdump or comsvcs.dll MiniDump.",
    "evidence_json": '{"cmd": ["procdump", "comsvcs.dll", "lsass"], "sw": ["lsass.exe"]}',
    "platforms": ["Windows"],
    "detectable_via": "Process creation, process access",
}

DEFAULT_CAP = 10


def local_run_cap() -> int:
    """How many techniques may go to a local model in one run (SHIKARI_LOCAL_LLM_CAP, default 10).

    0 or negative means no local generation; a non-integer value falls back to the default."""
    raw = os.getenv("SHIKARI_LOCAL_LLM_CAP")
    if raw is None:
        return DEFAULT_CAP
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_CAP


def local_run_plan(n_techniques: int, cap: Optional[int] = None,
                   seconds_per_call: Optional[float] = None) -> Dict:
    """Plan a local run: how many of n_techniques will run, and whether the cap trims it.

    seconds_per_call, if known from a smoke test, gives a rough time estimate so the UI can warn
    before the run starts. Whole groups are expected to go to a cloud model instead."""
    cap = local_run_cap() if cap is None else cap
    n = max(0, int(n_techniques))
    will_run = n if cap < 0 else min(n, cap)
    plan = {
        "requested": n,
        "cap": cap,
        "will_run": will_run,
        "over_cap": n > will_run,
        "excess": n - will_run,
        "needs_confirmation": n > will_run,
    }
    if seconds_per_call:
        plan["est_seconds"] = round(will_run * seconds_per_call)
    return plan


def smoke_test_local_model(config: Dict, call_fn: Optional[Callable[[str, Dict], str]] = None,
                           siem: str = "secops", time_budget_s: float = 180.0) -> Dict:
    """Run one technique through a local model and judge whether it's usable for generation.

    call_fn(prompt, config) -> raw text; defaults to llm_queries.call_llm. Returns suitability, a
    reason, how long it took, and how many queries parsed. Used by the UI to mark a model (not) fit
    for detection generation, and to feed seconds_per_call into local_run_plan."""
    from shikari.build.llm_queries import (build_compact_local_prompt, detect_degenerate_response,
                                           parse_llm_response)

    if call_fn is None:
        from shikari.build.llm_queries import call_llm as _call
        call_fn = _call

    prompt = build_compact_local_prompt(
        technique_id=_SMOKE["technique_id"], technique_name=_SMOKE["technique_name"],
        tactic=_SMOKE["tactic"], procedure_example=_SMOKE["procedure_example"],
        evidence_json=_SMOKE["evidence_json"], platforms=_SMOKE["platforms"],
        siem=siem, detectable_via=_SMOKE["detectable_via"])

    start = time.monotonic()
    try:
        response = call_fn(prompt, config)
    except Exception as e:
        return {"suitable": False, "reason": f"call failed: {e}", "elapsed_s": round(time.monotonic() - start, 1),
                "query_count": 0, "prompt_chars": len(prompt)}
    elapsed = time.monotonic() - start

    degenerate = detect_degenerate_response(response)
    if degenerate:
        return {"suitable": False, "reason": degenerate, "elapsed_s": round(elapsed, 1),
                "query_count": 0, "prompt_chars": len(prompt)}

    # A contract document or the legacy JSON shape both count as usable.
    queries = []
    try:
        from shikari.contract import is_contract_document, handle_contract_response
        if is_contract_document(response):
            queries = handle_contract_response(response, technique_id=_SMOKE["technique_id"]) or []
    except Exception:
        pass
    if not queries:
        queries = parse_llm_response(response)

    if not queries:
        return {"suitable": False, "reason": "no parseable query in the answer", "elapsed_s": round(elapsed, 1),
                "query_count": 0, "prompt_chars": len(prompt)}
    over = elapsed > time_budget_s
    return {
        "suitable": not over,
        "reason": (f"returned {len(queries)} query(s) but took {elapsed:.0f}s (> {time_budget_s:.0f}s budget)"
                   if over else f"returned {len(queries)} contract-valid query(s) in {elapsed:.0f}s"),
        "elapsed_s": round(elapsed, 1),
        "seconds_per_call": round(elapsed, 1),
        "query_count": len(queries),
        "prompt_chars": len(prompt),
    }

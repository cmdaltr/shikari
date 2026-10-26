# Local LLM detection generation — implementation plan

**Issue:** #9 · **Blocked on:** Ollama + a model on the Mac Mini · **Depends on:** #10 (provider plumbing)

Generate detections with a local model through the same LLM path cloud models use, without 40-hour runs or unparseable output.

## Already done

- `detect_degenerate_response()` rejects a looping or truncated answer before parsing — writes nothing, logs why (`archer/build/llm_queries.py`, 8 tests).
- Ollama calls pass `repeat_penalty` (default 1.15).

Those are the "stop loops / fail cleanly" half of the acceptance criteria and needed no model to validate. The rest below needs a model running, because it's judged on real output and real timings.

## Part A — Setup you provide

On the **Mac Mini** (the model host — the ARM MacBook this repo sits on can't stand in for the acceptance timing):

1. Ollama running and reachable (localhost:11434, or the Tailscale IP if Archer runs elsewhere), with a detection-capable model pulled — start with `qwen3:8b` (the issue's benchmark).
2. In Archer, **Profile → API Keys**: add the local provider (endpoint + model). Confirm Ask Archer already answers through it — that proves the provider path works end to end.
3. Confirm the state of **#10** (passing the chosen provider into generation). If it's not done, it's the first dependency; say so and I'll fold it in.

**Expected outcome:** a reachable local model Archer is configured to use, Ask Archer answering through it, and agreement to benchmark on `T1003.001` with `qwen3:8b` (the acceptance case).

## Part B — Implementation plan (Archer)

1. **Trimmed local prompt** — a compact builder (`build_llm_prompt(use_local=True)` → ~6–8k tokens): the technique, its MITRESaw evidence, the target SIEM's schema snippet, and one or two exemplars — not the full 115k-char master. New `_load_local_prompt_compact()`; the reference material is left out. Unit-test asserts the assembled prompt stays under the token budget.
2. **Per-run cost cap** — a setting (`ARCHER_LOCAL_LLM_CAP`, default ~10 techniques) with a pre-run estimate shown; a run over the cap asks before spending the time; whole groups route to a cloud model. Unit-test the cap/estimate logic.
3. **Model smoke test** — `smoke_test_local_model(config)` runs one technique and checks the answer is contract-valid JSON within a time bound, so the UI can mark a model suitable/unsuitable for generation. Harness unit-tested with a mocked model.
4. **Wiring** — pass the chosen provider through `modified_process_group_wrapper` → `process_group(use_llm="llm", llm_config=…)`, reusing the degenerate-response guard and `repeat_penalty` already in place. (Gated on #10.)
5. **Tests (offline)** — prompt-size, cap/estimate, smoke-test harness, all with a mocked model. **Live validation** on the Mac Mini confirms the acceptance: `T1003.001` with `qwen3:8b` returns at least one contract-valid query in under 3 minutes, a looping/truncated answer writes nothing and logs why, and a run over the cap asks first.

**Stays deferred until Part A:** anything judged on real model output or timing. The prompt builder, cap and smoke-test *harness* ship and are tested with a mock; the acceptance numbers need the host.

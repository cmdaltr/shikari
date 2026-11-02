# Local LLM detection generation — implementation plan

**Issue:** #9 · **Blocked on:** Ollama + a model on the Mac Mini · **Depends on:** #10 (provider plumbing)

Generate detections with a local model through the same LLM path cloud models use, without 40-hour runs or unparseable output.

## Already done

- `detect_degenerate_response()` rejects a looping or truncated answer before parsing — writes nothing, logs why (`shikari/build/llm_queries.py`, 8 tests).
- Ollama calls pass `repeat_penalty` (default 1.15).

Those are the "stop loops / fail cleanly" half of the acceptance criteria and needed no model to validate. The rest below needs a model running, because it's judged on real output and real timings.

## Part A — Setup you provide

On the **Mac Mini** (the model host — the ARM MacBook this repo sits on can't stand in for the acceptance timing):

1. Ollama running and reachable (localhost:11434, or the Tailscale IP if Shikari runs elsewhere), with a detection-capable model pulled — start with `qwen3:8b` (the issue's benchmark).
2. In Shikari, **Profile → API Keys**: add the local provider (endpoint + model). Confirm Ask Shikari already answers through it — that proves the provider path works end to end.
3. Confirm the state of **#10** (passing the chosen provider into generation). If it's not done, it's the first dependency; say so and I'll fold it in.

**Expected outcome:** a reachable local model Shikari is configured to use, Ask Shikari answering through it, and agreement to benchmark on `T1003.001` with `qwen3:8b` (the acceptance case).

## Part B — Implementation plan (Shikari)

The harness is now built and unit-tested with a mocked model — only the wiring and the live acceptance numbers remain.

1. ✅ **Trimmed local prompt** — `llm_queries.build_compact_local_prompt(...)`: the technique, its MITRESaw evidence, the target SIEM's data-source names and one exemplar — not the 115k-char master. Comes out ~500 tokens (budget was 6–8k), so a small CPU model reads it whole. Asks for the legacy JSON shape `parse_llm_response` already understands. Unit-tested for budget, SIEM language and source names.
2. ✅ **Per-run cost cap** — `local_llm.local_run_cap()` (`SHIKARI_LOCAL_LLM_CAP`, default 10) + `local_run_plan(n, cap, seconds_per_call)` returning `will_run`, `over_cap`, `needs_confirmation` and an `est_seconds`. Unit-tested. (UI hook — show the estimate and confirm before a capped run — lands with the wiring in step 4.)
3. ✅ **Model smoke test** — `local_llm.smoke_test_local_model(config, call_fn=…)` runs the one canned technique through the compact prompt, rejects a degenerate/empty answer or one over the time budget, and reports `seconds_per_call` to feed the estimate. Call is injectable; unit-tested for suitable / loop / empty / slow / call-failure.
4. **Wiring (remaining)** — pass the chosen provider through `modified_process_group_wrapper` → `process_group(use_llm="llm", llm_config=…)`, using `build_compact_local_prompt` for local providers, enforcing `local_run_cap`, and surfacing the smoke-test verdict + run estimate in the UI. Reuses the degenerate-response guard and `repeat_penalty` already in place. (Gated on #10.)
5. **Live validation (remaining)** — on the Mac Mini: `T1003.001` with `qwen3:8b` returns at least one contract-valid query in under 3 minutes; a looping/truncated answer writes nothing and logs why (already true); a run over the cap asks first.

**Stays deferred until Part A:** the wiring into generation (needs #10) and the acceptance numbers (need the host). The prompt builder, cap and smoke-test harness are shipped and tested with a mock.

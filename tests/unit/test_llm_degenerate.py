"""Degenerate local-LLM response guard (#9): loop/truncation rejection."""

from archer.build.llm_queries import detect_degenerate_response


def test_valid_json_passes():
    good = '{"technique_id": "T1059.001", "queries": [{"source_index": "DeviceProcessEvents", "query": "x"}]}'
    assert detect_degenerate_response(good) is None


def test_contract_document_passes():
    doc = '{"archer_output": {"technique_id": "T1003.001", "detections": [{"siem": "mde", "query": "a"}]}}'
    assert detect_degenerate_response(doc) is None


def test_think_block_stripped_then_valid():
    r = "<think>let me reason about LSASS at length...</think>\n" + '{"technique_id":"T1003.001","queries":[]}'
    assert detect_degenerate_response(r) is None


def test_empty_is_degenerate():
    assert detect_degenerate_response("") == "empty answer"
    assert detect_degenerate_response("<think>only thinking</think>") == "empty answer"


def test_repetition_loop_caught():
    looped = '{"query": "index=waf ' + "httpMethod=GET " * 200 + '"'
    reason = detect_degenerate_response(looped)
    assert reason and "repetition loop" in reason


def test_single_char_loop_caught():
    reason = detect_degenerate_response('{"q":"' + ("a" * 600))
    assert reason and "repetition loop" in reason


def test_truncated_json_caught():
    truncated = '{"technique_id": "T1059.001", "queries": [{"query": "index=main | where field=1'
    reason = detect_degenerate_response(truncated)
    assert reason == "truncated before the JSON object closed"


def test_prose_without_json_is_not_degenerate():
    # No loop, no opened JSON object -> not our concern (the parser returns [] for it).
    assert detect_degenerate_response("I could not find a suitable detection for this technique.") is None

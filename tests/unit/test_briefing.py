"""Threat briefing without AI: coverage, weakest stage and gaps from a run's attack flow."""

from archer.build import briefing


def _node(tid, detected, attributed=True, degree=0, name=None):
    return {"id": tid, "name": name or tid, "detected": detected, "attributed": attributed, "degree": degree,
            "url": f"https://attack.mitre.org/techniques/{tid}/"}


FLOW = {"lanes": [
    {"tactic": "Initial Access", "nodes": [_node("T1566", True), _node("T1190", False, degree=1)]},
    {"tactic": "Execution", "nodes": [_node("T1059", True), _node("T1204", True)]},
    {"tactic": "Defense Evasion", "nodes": [_node("T1027", False, degree=3), _node("T1070", False), _node("T1112", True)]},
]}


def test_coverage_weakest_stage_and_gaps_in_kill_chain_order():
    b = briefing.build(FLOW)
    assert (b["techniques"], b["detected"], b["coverage"]) == (7, 4, 57)
    assert b["weakest"]["tactic"] == "Defense Evasion"
    # Earliest tactic first; within a tactic, the most-linked technique first
    assert [g["id"] for g in b["gaps"]] == ["T1190", "T1027", "T1070"]
    assert b["summary"].startswith("Archer has detections for 4 of 7 techniques (57%) across 3 tactics.")
    assert "Defense Evasion: 1 of 3 detected" in b["summary"]


def test_run_techniques_with_no_detection_count_as_gaps_without_attribution():
    flow = {"lanes": [{"tactic": "Execution", "nodes": [_node("T1059", True, attributed=False),
                                                         _node("T1204", False, attributed=False)]}]}
    no_detection = [{"technique": "T1204", "text": "No indicators in ATT&CK"},
                    {"technique": "T1588", "text": "Pre-compromise"}]
    b = briefing.build(flow, no_detection)
    assert [(g["id"], g["why"]) for g in b["gaps"]] == [("T1204", "No indicators in ATT&CK"), ("T1588", "Pre-compromise")]


def test_no_flow_no_briefing_and_full_coverage_says_so():
    assert briefing.build(None) is None and briefing.build({"lanes": []}) is None
    full = briefing.build({"lanes": [{"tactic": "Execution", "nodes": [_node("T1059", True)]}]})
    assert full["gaps"] == [] and full["weakest"] is None
    assert full["summary"].endswith("Every technique in this run has a detection.")


def test_ai_summary_is_kept_only_for_the_same_coverage(tmp_path, monkeypatch):
    monkeypatch.setattr(briefing, "BRIEFINGS_DIR", str(tmp_path))
    b = briefing.build(FLOW)
    briefing.save_summary("G1", b, " Prose. ", "Anthropic")
    assert briefing.load_summary("G1", b)["text"] == "Prose."
    changed = briefing.build({"lanes": FLOW["lanes"][:2]})
    assert briefing.load_summary("G1", changed) is None
    assert "Earliest gaps: T1190" in briefing.prompt("G1", b)

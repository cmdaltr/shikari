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


def test_coverage_weakest_tactic_and_gaps_by_action_then_severity():
    b = briefing.build(FLOW, [{"technique": "T1190", "reason": "osint_empty"}])
    assert (b["techniques"], b["detected"], b["coverage"]) == (7, 4, 57)
    assert b["weakest"]["tactic"] == "Defense Evasion"
    # Buildable before research, whatever the tactic's column; then severity, then links
    assert [g["id"] for g in b["gaps"]] == ["T1027", "T1070", "T1190"]
    assert [g["action"] for g in b["gaps"]] == ["build", "build", "research"]
    assert b["by_action"] == {"build": 2, "source": 0, "research": 1}
    assert b["summary"].startswith("Archer has detections for 4 of 7 attributed techniques (57%) across 3 tactics.")
    assert "Defense Evasion: 1 of 3 detected" in b["summary"]


def test_higher_severity_gaps_come_first():
    flow = {"lanes": [{"tactic": "Discovery", "nodes": [_node("T1087", False, degree=5)]},
                      {"tactic": "Lateral Movement", "nodes": [_node("T1021", False)]}]}
    assert [g["id"] for g in briefing.build(flow)["gaps"]] == ["T1021", "T1087"]


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
    assert "Gaps to close first" in briefing.prompt("G1", b) and "T1190" in briefing.prompt("G1", b)


def test_sub_techniques_expanded_from_attributed_parents_are_extra_not_gaps():
    sub = dict(_node("T1055.001", True, attributed=False), via_parent=True)
    flow = {"lanes": [{"tactic": "Defense Evasion", "nodes": [_node("T1055", False), sub]}]}
    # T1055.002 built nothing and never reached the flow: its parent is attributed, so no gap
    b = briefing.build(flow, [{"technique": "T1055.002", "reason": "no_indicators"}])
    assert (b["techniques"], b["detected"], b["extra_detected"], b["extra_total"]) == (1, 0, 1, 1)
    assert [g["id"] for g in b["gaps"]] == ["T1055"]
    assert "also covers 1 sub-technique of attributed techniques" in b["summary"]

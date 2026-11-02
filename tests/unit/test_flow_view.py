"""Results-page attack flow: lanes, coverage, gaps, correlation edges and the Attack Flow export."""
import textwrap

from shikari.visualization.flow_view import AF_EXTENSION, build_flow_view, to_attack_flow_bundle


def _det(tmp_path, name, tid, tactics, connector):
    path = tmp_path / f"{name.replace(' ', '')}_{connector}.yaml"
    path.write_text(textwrap.dedent(f"""\
        name: {name}
        technique_id: {tid}
        requiredDataConnectors:
          - connectorId: {connector}
        tactics: {tactics}
        query: x
        """))
    return str(path)


def test_lanes_coverage_gaps_and_edges(tmp_path):
    phish = _det(tmp_path, "Phishing", "T1566", ["Initial Access"], "GoogleSecOps")
    pwsh_s = _det(tmp_path, "PowerShell", "T1059.001", ["Execution"], "GoogleSecOps")
    pwsh_m = _det(tmp_path, "PowerShell", "T1059.001", ["Execution"], "MicrosoftThreatProtection")
    c2 = _det(tmp_path, "Web Protocols", "T1071.001", ["Command And Control"], "MicrosoftThreatProtection")
    view = build_flow_view(
        {"googlesecops": [phish, pwsh_s], "mde": [pwsh_m, c2]},
        [{"vendor": "googlesecops", "a": phish, "b": pwsh_s, "relevance_score": 0.9},
         {"vendor": "mde", "a": pwsh_m, "b": c2, "relevance_score": 0.7}],
        attributed=[{"id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["Impact"]},
                    {"id": "T1562.001", "name": "Disable or Modify Tools", "tactics": ["Defense Evasion"]}],
        tactic_lookup={"T1486": ["Impact"], "T1566": ["Initial Access"]},  # T1562.001 retired
    )

    assert [l["tactic"] for l in view["lanes"]] == ["Initial Access", "Execution", "Command and Control", "Impact"]
    nodes = {n["id"]: n for l in view["lanes"] for n in l["nodes"]}
    assert nodes["T1059.001"]["vendors"] == {"googlesecops": 1, "mde": 1}
    assert not nodes["T1486"]["detected"] and nodes["T1486"]["attributed"]
    assert "T1562.001" not in nodes  # not in current ATT&CK: no gap node for it
    assert {(e["from"], e["to"], tuple(e["vendors"])) for e in view["edges"]} == {
        ("T1566", "T1059.001", ("googlesecops",)), ("T1059.001", "T1071.001", ("mde",))}
    assert [v["key"] for v in view["vendors"]] == ["googlesecops", "mde"]
    assert view["stats"] == {"techniques": 4, "detected": 3, "gaps": 1, "edges": 2, "tactics": 4, "intel_only": 0,
                             "attributed": 1, "via_parent": 0}


def test_attack_flow_bundle_follows_correlations(tmp_path):
    a = _det(tmp_path, "Phishing", "T1566", ["Initial Access"], "GoogleSecOps")
    b = _det(tmp_path, "PowerShell", "T1059.001", ["Execution"], "GoogleSecOps")
    view = build_flow_view({"googlesecops": [a, b]}, [{"vendor": "googlesecops", "a": a, "b": b}])

    bundle = to_attack_flow_bundle(view, "Scattered Spider")

    by_type = {}
    for o in bundle["objects"]:
        by_type.setdefault(o["type"], []).append(o)
    flow = by_type["attack-flow"][0]
    actions = {o["technique_id"]: o for o in by_type["attack-action"]}
    assert by_type["extension-definition"][0]["id"] == AF_EXTENSION
    assert all(AF_EXTENSION in o["extensions"] for o in [flow, *actions.values()])
    assert flow["start_refs"] == [actions["T1566"]["id"]]
    assert actions["T1566"]["effect_refs"] == [actions["T1059.001"]["id"]]
    # Deterministic IDs: re-exporting the same group gives the same action IDs
    again = {o["technique_id"]: o["id"] for o in to_attack_flow_bundle(view, "Scattered Spider")["objects"]
             if o["type"] == "attack-action"}
    assert again == {t: o["id"] for t, o in actions.items()}


def _three_step_view(tmp_path):
    phish = _det(tmp_path, "Phishing", "T1566", ["Initial Access"], "GoogleSecOps")
    pwsh_s = _det(tmp_path, "PowerShell", "T1059.001", ["Execution"], "GoogleSecOps")
    pwsh_m = _det(tmp_path, "PowerShell", "T1059.001", ["Execution"], "MicrosoftThreatProtection")
    c2 = _det(tmp_path, "Web Protocols", "T1071.001", ["Command And Control"], "MicrosoftThreatProtection")
    return build_flow_view(
        {"googlesecops": [phish, pwsh_s], "mde": [pwsh_m, c2]},
        [{"vendor": "googlesecops", "a": phish, "b": pwsh_s, "relevance_score": 0.9},
         {"vendor": "mde", "a": pwsh_m, "b": c2, "relevance_score": 0.7}],
        attributed=[{"id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["Impact"]}])


def _ids(view):
    return sorted(n["id"] for lane in view["lanes"] for n in lane["nodes"])


def _links(view):
    return sorted((e["from"], e["to"]) for e in view["edges"])


def test_apply_edits_matches_what_the_page_shows(tmp_path):
    from shikari.visualization.flow_view import apply_edits

    view = _three_step_view(tmp_path)
    assert apply_edits(view, {}) == dict(view, edited=True)

    unlinked = apply_edits(view, {"unlinked": ["T1566>T1059.001"]})
    assert _links(unlinked) == [("T1059.001", "T1071.001")]

    hidden = apply_edits(view, {"removed": ["T1071.001"], "gaps": False})
    assert _ids(hidden) == ["T1059.001", "T1566"]  # T1486 is a gap, T1071.001 hidden
    assert _links(hidden) == [("T1566", "T1059.001")]

    secops = apply_edits(view, {"vendors": ["googlesecops"], "gaps": False})
    assert _ids(secops) == ["T1059.001", "T1566"]  # T1071.001 is MDE-only
    assert [n["vendors"] for lane in secops["lanes"] for n in lane["nodes"] if n["id"] == "T1059.001"] == [{"googlesecops": 1}]
    assert _links(secops) == [("T1566", "T1059.001")]


def test_edited_bundle_drops_unlinked_techniques(tmp_path):
    from shikari.visualization.flow_view import apply_edits

    bundle = to_attack_flow_bundle(apply_edits(_three_step_view(tmp_path), {"unlinked": ["T1059.001>T1071.001"]}), "G")
    actions = {o["technique_id"] for o in bundle["objects"] if o["type"] == "attack-action"}
    assert actions == {"T1566", "T1059.001"}
    flow = next(o for o in bundle["objects"] if o["type"] == "attack-flow")
    assert flow["name"] == "G: correlated techniques (edited)"


def test_pre_compromise_techniques_are_shown_intel_only_ones_are_not_gaps():
    from shikari.visualization.flow_view import build_flow_view

    attributed = [{"id": "T1595", "name": "Active Scanning", "tactics": ["Reconnaissance"]},
                  {"id": "T1583", "name": "Acquire Infrastructure", "tactics": ["Resource Development"]},
                  {"id": "T1566", "name": "Phishing", "tactics": ["Reconnaissance", "Initial Access"]},
                  {"id": "T1059", "name": "Interpreter", "tactics": ["Execution"]}]
    view = build_flow_view({}, [], attributed)
    assert [lane["tactic"] for lane in view["lanes"]] == ["Reconnaissance", "Resource Development", "Execution"]
    nodes = {n["id"]: n for lane in view["lanes"] for n in lane["nodes"]}
    # Acquire Infrastructure happens on the adversary's side; scanning reaches the estate
    assert nodes["T1583"]["intel_only"] and not nodes["T1595"]["intel_only"]
    assert view["stats"]["techniques"] == 4
    assert view["stats"]["intel_only"] == 1 and view["stats"]["gaps"] == 3


def test_drag_and_drop_edits_reach_the_view_and_bundle(tmp_path):
    from shikari.visualization.flow_layouts import clean_state
    from shikari.visualization.flow_view import apply_edits

    view = _three_step_view(tmp_path)
    state = clean_state({
        # T1071.001 dragged into Execution, ahead of PowerShell; Impact moved first
        "arrangement": {"Execution": ["T1071.001", "T1059.001"], "Bad<lane>": ["T1566"]},
        "lane_order": ["Impact", "Nowhere"],
        "linked": ["T1486>T1566", "T1566>T1566", "x>y"],
    })
    assert "Bad<lane>" not in state["arrangement"] and state["linked"] == ["T1486>T1566"]
    edited = apply_edits(view, state)
    lanes = [(l["tactic"], [n["id"] for n in l["nodes"]]) for l in edited["lanes"]]
    assert lanes == [("Impact", ["T1486"]), ("Initial Access", ["T1566"]), ("Execution", ["T1071.001", "T1059.001"])]
    moved = next(n for l in edited["lanes"] for n in l["nodes"] if n["id"] == "T1071.001")
    assert moved["tactic"] == "Execution" and moved["tactics"] == ["Command and Control"]
    drawn = [e for e in edited["edges"] if e.get("manual")]
    assert [(e["from"], e["to"]) for e in drawn] == [("T1486", "T1566")]

    bundle = to_attack_flow_bundle(edited, "G")
    actions = {o["technique_id"]: o for o in bundle["objects"] if o["type"] == "attack-action"}
    assert actions["T1071.001"]["description"].startswith("Execution (moved; ATT&CK: Command and Control)")
    assert actions["T1486"]["effect_refs"] == [actions["T1566"]["id"]]
    flow = next(o for o in bundle["objects"] if o["type"] == "attack-flow")
    assert "arrows the analyst drew" in flow["description"]


def test_every_tactic_has_a_phase_in_each_lifecycle_model():
    from shikari.visualization.flow_view import TACTIC_ORDER
    from shikari.visualization.frameworks import FRAMEWORKS

    for fw in FRAMEWORKS:
        phases = {p["name"] for p in fw["phases"]}
        assert set(fw["tactics"]) == set(TACTIC_ORDER), fw["key"]
        assert set(fw["tactics"].values()) | set(fw["techniques"].values()) <= phases, fw["key"]


def test_phase_goes_by_technique_then_parent_then_tactic():
    from shikari.visualization.frameworks import UNMAPPED, phase_of

    assert phase_of("ckc", "T1566.001", "Initial Access") == "Delivery"
    assert phase_of("ckc", "T1190", "Initial Access") == "Exploitation"
    assert phase_of("ckc", "T1204.002", "Execution") == "Exploitation"  # via its parent
    assert phase_of("ckc", "T1059.001", "Command and Control") == "Command & Control"  # a card moved to C2
    assert phase_of("tal", "T1078.002", "Defense Evasion") == "Maintain Presence"
    assert phase_of("tal", "T1003.001", "Credential Access") == "Escalate Privileges"
    assert phase_of("tal", "T1000", "Not A Tactic") == UNMAPPED


def test_built_sub_technique_of_an_attributed_parent_is_via_parent(tmp_path):
    sub = _det(tmp_path, "DLL Injection", "T1055.001", ["Defense Evasion"], "GoogleSecOps")
    other = _det(tmp_path, "PowerShell", "T1059.001", ["Execution"], "GoogleSecOps")
    view = build_flow_view({"googlesecops": [sub, other]}, [],
                           attributed=[{"id": "T1055", "name": "Process Injection", "tactics": ["Defense Evasion"]}])
    nodes = {n["id"]: n for l in view["lanes"] for n in l["nodes"]}
    assert nodes["T1055.001"]["via_parent"] and not nodes["T1055"]["via_parent"]
    assert not nodes["T1059.001"]["via_parent"]  # its parent isn't attributed
    assert (view["stats"]["attributed"], view["stats"]["via_parent"]) == (1, 1)

"""Results-page attack flow: lanes, coverage, gaps, correlation edges and the Attack Flow export."""
import textwrap

from archer.visualization.flow_view import AF_EXTENSION, build_flow_view, to_attack_flow_bundle


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
    assert view["stats"] == {"techniques": 4, "detected": 3, "gaps": 1, "edges": 2, "tactics": 4}


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

"""Threat library and assessments (#24): test-case building and outcome export."""

import json

from archer.assessments.export import results_to_csv, results_to_navigator
from archer.assessments.library import build_test_cases, _signature


def _csv(tmp_path):
    p = tmp_path / "mitre_procedures.csv"
    p.write_text(
        "group_sw_id,group_sw_name,technique_id,technique_name,tactic,platforms,framework,procedure_example,evidence,detectable_via\n"
        'G1,APT-X,T1059.001,PowerShell,Execution,Windows,Enterprise,[Software: Foo] ran ps,'
        '"{""cmd"": [""powershell -enc""]}",Defender\n'
        'G2,APT-Y,T1059.001,PowerShell,Execution,Windows,Enterprise,[Software: Foo] ran ps,'
        '"{""cmd"": [""powershell -enc""]}",Defender\n'
        'G2,APT-Y,T1003.001,LSASS Memory,Credential Access,Windows,Enterprise,dumped lsass,'
        '"{""cmd"": [""procdump lsass""]}",Sysmon\n',
        encoding="utf-8")
    return str(p)


def test_build_prevalence_and_dedup(tmp_path):
    cases = build_test_cases(["APT-X", "APT-Y"], csv_path=_csv(tmp_path))
    by_tech = {c["technique_id"]: c for c in cases}
    # Same procedure from two groups dedups to one case, prevalence 2 (both groups use it)
    assert by_tech["T1059.001"]["prevalence"] == 2
    assert by_tech["T1003.001"]["prevalence"] == 1
    # Sorted by prevalence desc, so the two-group technique is first
    assert cases[0]["technique_id"] == "T1059.001"
    assert by_tech["T1059.001"]["indicators"] == {"cmd": ["powershell -enc"]}


def test_build_unknown_group_is_empty(tmp_path):
    assert build_test_cases(["NoSuchGroup"], csv_path=_csv(tmp_path)) == []


def test_build_missing_csv():
    assert build_test_cases(["APT-X"], csv_path="/nonexistent/x.csv") == []


def test_signature_stable():
    assert _signature("T1059.001", "ran ps") == _signature("T1059.001", "ran ps")
    assert _signature("T1059.001", "a") != _signature("T1059.001", "b")


def test_csv_export_columns(tmp_path):
    rows = [{"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution",
             "red_outcome": "executed", "blue_outcome": "logged", "detection_file": "x.yaml", "notes": "n"}]
    out = results_to_csv(rows)
    assert out.splitlines()[0] == "technique_id,technique_name,tactic,red_outcome,blue_outcome,detection_file,notes"
    assert "T1059.001" in out and "executed" in out


def test_navigator_scores_by_blue():
    rows = [{"technique_id": "T1059.001", "blue_outcome": "alerted", "red_outcome": "executed"},
            {"technique_id": "T1003.001", "blue_outcome": "not_logged", "red_outcome": "executed"}]
    layer = json.loads(results_to_navigator("Camp", rows))
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores["T1059.001"] == 3 and scores["T1003.001"] == 1
    assert layer["domain"] == "enterprise-attack"
    assert "Red: executed" in layer["techniques"][0]["comment"]

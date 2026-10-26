"""Emulation planner (#25): the pure plan-shaping helpers."""

import tomllib

from archer.telemetry.planner import (_best_dataset, _collect, plan_to_runsheet, plan_to_test_cases)


def test_best_dataset_prefers_visible_then_most_events():
    recs = [
        {"source": "a", "title": "x", "visible": False, "events": 999, "platforms": ["windows"]},
        {"source": "b", "title": "y", "visible": True, "events": 10, "platforms": ["linux"]},
        {"source": "c", "title": "z", "visible": True, "events": 50, "platforms": ["windows"]},
    ]
    best = _best_dataset(recs)
    assert best["source"] == "c"  # visible and most events among visible


def test_best_dataset_none_when_empty():
    assert _best_dataset([]) is None


def test_collect_native_first_and_deduped():
    ev = [
        {"label": "Sysmon 1", "collection": "sysmon", "recordings": 9, "event": "s1"},
        {"label": "Security 4688", "collection": "native", "recordings": 3, "event": "4688"},
        {"label": "EDR row", "collection": "edr", "recordings": 20, "event": "edr"},
        {"label": "Security 4688", "collection": "native", "recordings": 1, "event": "4688b"},  # dup label
    ]
    got = _collect(ev)
    labels = [c["log"] for c in got]
    assert labels[0] == "Security 4688"  # native ranked above sysmon/edr
    assert labels.count("Security 4688") == 1  # deduped


def _plan():
    return {
        "target": {"kind": "group", "value": "APT-X"}, "siems": ["secops", "mde"],
        "summary": {"techniques": 2, "recordable": 1, "with_atomic": 1, "gaps": 1},
        "techniques": [
            {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution",
             "platforms": ["windows"], "atomic_guid": "guid-1",
             "dataset": {"source": "splunk", "title": "macro"},
             "collect": [{"log": "PowerShell 4104", "collection": "native", "event": "4104"}], "recordings": 3},
            {"technique_id": "T1003.001", "technique_name": "LSASS", "tactic": "Credential Access",
             "platforms": ["windows"], "atomic_guid": None, "dataset": None, "collect": [], "recordings": 0},
        ],
    }


def test_runsheet_is_markdown_table():
    md = plan_to_runsheet(_plan())
    assert md.startswith("# Emulation run sheet — group: APT-X")
    assert "| Technique | Tactic |" in md
    assert "T1059.001 PowerShell" in md
    assert "splunk macro" in md
    assert "gap" in md.lower()  # the dataset-less technique shows as a gap


def test_plan_to_test_cases_shape():
    cases = plan_to_test_cases(_plan())
    assert len(cases) == 2
    c = cases[0]
    assert c["technique_id"] == "T1059.001" and c["atomic_guid"] == "guid-1"
    assert c["group_name"] == "APT-X"  # group target carries the group
    assert c["signature"]  # stable key for the MACAT export


def test_plan_test_cases_export_as_valid_macatable():
    from archer.assessments.macat import test_cases_to_macatable

    data = tomllib.loads(test_cases_to_macatable(plan_to_test_cases(_plan())))
    assert len(data["lib_procedures"]) == 2
    assert data["lib_procedures"][0]["primary_technique"] == "T1059.001"

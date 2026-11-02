"""MACATable library TOML export (#24 / MACAT interop)."""

import tomllib

from shikari.assessments.macat import test_cases_to_macatable as to_macatable, _tactic_slug


CASES = [
    {"signature": "sig1", "technique_id": "T1053.005", "technique_name": "Scheduled Task",
     "tactic": "Persistence, Privilege Escalation", "procedure": "schtasks created a task",
     "atomic_guid": "abc-123", "group_name": "APT-X", "indicators": {"cmd": ["schtasks"]}},
    {"signature": "sig2", "technique_id": "T1059.001", "technique_name": "PowerShell",
     "tactic": "Execution", "procedure": "ran powershell", "atomic_guid": None,
     "group_name": "APT-X", "indicators": {}},
]


def test_output_is_valid_toml_and_parses():
    data = tomllib.loads(to_macatable(CASES))
    assert data["version"] == 1
    assert len(data["lib_procedures"]) == 2


def test_required_fields_present():
    procs = tomllib.loads(to_macatable(CASES))["lib_procedures"]
    for p in procs:
        assert p["id"] and p["name"]  # schema-required
        # id is a uuid
        import uuid
        uuid.UUID(p["id"])


def test_technique_and_tactic_mapping():
    procs = {p["primary_technique"]: p for p in tomllib.loads(to_macatable(CASES))["lib_procedures"]}
    sched = procs["T1053.005"]
    assert sched["primary_tactic"] == "persistence"
    assert sched["mitre_tactics_ref"] == ["persistence", "privilege-escalation"]
    assert sched["src_type"] == "art"  # has an atomic
    assert "atomic:abc-123" in sched["tags"]
    assert "Attributed to APT-X" in sched["description"]


def test_no_atomic_is_macat_src():
    procs = {p["primary_technique"]: p for p in tomllib.loads(to_macatable(CASES))["lib_procedures"]}
    assert procs["T1059.001"]["src_type"] == "macat"


def test_ref_pattern_and_uniqueness():
    import re
    procs = tomllib.loads(to_macatable(CASES))["lib_procedures"]
    refs = [p["ref"] for p in procs]
    assert len(refs) == len(set(refs))
    for r in refs:
        assert re.fullmatch(r"[a-z][a-z0-9_]*", r)


def test_tactic_slug():
    assert _tactic_slug("Privilege Escalation") == "privilege-escalation"
    assert _tactic_slug("Command and Control") == "command-and-control"


def test_stable_ids_across_runs():
    a = tomllib.loads(to_macatable(CASES))["lib_procedures"]
    b = tomllib.loads(to_macatable(CASES))["lib_procedures"]
    assert [p["id"] for p in a] == [p["id"] for p in b]


def test_special_characters_escaped():
    case = [{"signature": "s", "technique_id": "T1027", "technique_name": 'Obfuscation "quoted"',
             "tactic": "Defense Evasion", "procedure": "line1\nline2 with \\ and \"quote\"",
             "atomic_guid": None, "group_name": "G", "indicators": {}}]
    data = tomllib.loads(to_macatable(case))  # must not raise
    assert 'quoted' in data["lib_procedures"][0]["name"]

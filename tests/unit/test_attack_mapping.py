"""
An analyst can change a detection's ATT&CK technique and tactics, with a comment, and
restore the ATT&CK default (shikari.build.attack_mapping).
"""
import os

import pytest
import yaml

from shikari.build import attack_mapping as mapping
from shikari.build import run_files
from shikari.build import yaml as writer

KQL = "DeviceProcessEvents\n| where ProcessCommandLine has \"procdump\""
YARAL = """rule shikari_t1003_001 {
meta:
author = "Shikari Detection Engineering"
description = "Detects LSASS Memory (T1003.001)"
mitre_attack_technique = "T1003.001"
severity = "HIGH"

events:
$e.metadata.event_type = "PROCESS_LAUNCH"
re.regex($e.target.process.command_line, `procdump`) nocase

outcome:
$risk_score = 75
$hostname = $e.principal.hostname

condition:
$e
}"""
INDEX = {
    "T1003.001": {"name": "LSASS Memory", "tactics": ["Credential Access"]},
    "T1055": {"name": "Process Injection", "tactics": ["Privilege Escalation", "Stealth"]},
}
TACTICS = ["Execution", "Persistence", "Privilege Escalation", "Stealth", "Credential Access",
           "Discovery", "Impact"]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(os.path.dirname(writer.__file__) + "/../..")
    monkeypatch.setattr(run_files, "RUNS_DIR", str(tmp_path / "runs"))
    yield tmp_path
    run_files.finish("APT1")


def _write(path, query=KQL, connector="MicrosoftThreatProtection", **kw):
    writer.write_yaml(str(path), "LSASS Memory", "T1003.001", "d", connector,
                      ["Credential Access"], "APT1", query, datatype="DeviceProcessEvents", **kw)


def _doc(path):
    return yaml.safe_load(path.read_text().split("\n", 1)[1])


def _change(path, tid="T1055", tactics=("Stealth",), comment="Seen as injection here"):
    return mapping.change(str(path), tid, list(tactics), comment, "analyst@example.test",
                          index=INDEX, tactic_order=TACTICS)


def test_change_sets_the_mapping_and_records_the_default(env):
    path = env / "d.yaml"
    _write(path)
    _change(path)
    doc = _doc(path)
    assert (doc["technique_id"], doc["name"], doc["tactics"]) == ("T1055", "Process Injection", ["Stealth"])
    assert doc["severity"] == "Medium"
    o = doc["attack_override"]
    assert o["comment"] == "Seen as injection here" and o["by"] == "analyst@example.test"
    assert o["default"] == {"technique_id": "T1003.001", "name": "LSASS Memory", "tactics": ["Credential Access"]}
    assert doc["attack_mapping_history"][0]["action"] == "changed"
    # Only the mapping moved: the query is untouched and not counted as a hand edit
    assert doc["query"].strip() == KQL and not writer.file_state(str(path))["edited"]


def test_a_comment_is_required(env):
    path = env / "d.yaml"
    _write(path)
    with pytest.raises(mapping.MappingError, match="comment"):
        _change(path, comment="  ")
    _change(path)
    with pytest.raises(mapping.MappingError, match="comment"):
        mapping.restore(str(path), "", "analyst@example.test")


def test_unknown_technique_and_tactic_are_refused(env):
    path = env / "d.yaml"
    _write(path)
    with pytest.raises(mapping.MappingError, match="current ATT&CK"):
        _change(path, tid="T9999")
    with pytest.raises(mapping.MappingError, match="Not an ATT&CK tactic"):
        _change(path, tactics=["Hacking"])
    with pytest.raises(mapping.MappingError, match="already"):
        _change(path, tid="T1003.001", tactics=["Credential Access"])


def test_tactic_only_change_keeps_the_technique(env):
    path = env / "d.yaml"
    _write(path)
    _change(path, tid="T1003.001", tactics=["Credential Access", "Impact"])
    doc = _doc(path)
    assert doc["technique_id"] == "T1003.001" and doc["name"] == "LSASS Memory"
    assert doc["tactics"] == ["Credential Access", "Impact"] and doc["severity"] == "Critical"


def test_restore_puts_the_default_back_and_keeps_history(env):
    path = env / "d.yaml"
    _write(path)
    _change(path)
    mapping.restore(str(path), "Back to ATT&CK", "lead@example.test")
    doc = _doc(path)
    assert (doc["technique_id"], doc["tactics"], doc["severity"]) == ("T1003.001", ["Credential Access"], "High")
    assert "attack_override" not in doc
    assert [h["action"] for h in doc["attack_mapping_history"]] == ["changed", "restored"]
    assert doc["attack_mapping_history"][1]["comment"] == "Back to ATT&CK"


def test_choosing_the_default_again_is_a_restore(env):
    path = env / "d.yaml"
    _write(path)
    _change(path)
    _change(path, tid="T1003.001", tactics=["Credential Access"], comment="Changed my mind")
    doc = _doc(path)
    assert "attack_override" not in doc and doc["attack_mapping_history"][-1]["action"] == "restored"


def test_secops_rule_meta_follows_the_mapping(env):
    path = env / "d.yaml"
    _write(path, query=YARAL, connector="GoogleSecOps")
    _change(path, tactics=["Stealth", "Impact"])
    query = _doc(path)["query"]
    assert 'mitre_attack_technique = "T1055"' in query
    assert '"Detects Process Injection (T1055)"' in query
    assert 'severity = "CRITICAL"' in query and "$risk_score = 90" in query
    assert "rule shikari_t1003_001 {" in query  # the rule's identity in SecOps stays
    assert not writer.file_state(str(path))["edited"]


def test_mapping_change_leaves_a_hand_edit_marked(env):
    path = env / "d.yaml"
    _write(path)
    path.write_text(path.read_text().replace("procdump", "procdump64"))
    _change(path)
    assert writer.file_state(str(path))["edited"]


def test_regenerate_keeps_the_hand_made_mapping(env):
    path = env / "d.yaml"
    _write(path)
    _change(path)
    run_files.begin("APT1", regenerate=True)
    rewrite = writer.detection_action(str(path), "APT1")
    assert rewrite["attack_override"]["technique_id"] == "T1055"
    _write(path, query=KQL + " and 2", **rewrite)
    doc = _doc(path)
    assert "and 2" in doc["query"]
    assert doc["technique_id"] == "T1055" and doc["tactics"] == ["Stealth"]
    assert doc["attack_override"]["default"]["technique_id"] == "T1003.001"
    assert len(doc["attack_mapping_history"]) == 1


def test_repair_history_after_the_mapping_is_kept(env):
    path = env / "d.yaml"
    _write(path)
    _change(path)
    path.write_text(path.read_text() + "repair_history:\n- at: x\n  reason: y\n")
    mapping.restore(str(path), "Back", "a@example.test")
    doc = _doc(path)
    assert doc["repair_history"] == [{"at": "x", "reason": "y"}] and "attack_override" not in doc


def test_rule_rename_is_opt_in_and_restore_puts_it_back(env):
    path = env / "d.yaml"
    _write(path, query=YARAL, connector="GoogleSecOps")
    _change(path)
    assert "rule shikari_t1003_001 {" in _doc(path)["query"]
    mapping.change(str(path), "T1055", ["Stealth", "Impact"], "Rename it", "a@example.test",
                   index=INDEX, tactic_order=TACTICS, rename_rule=True)
    doc = _doc(path)
    assert "rule shikari_t1055 {" in doc["query"]
    assert doc["attack_override"]["rule_name"] == "shikari_t1055"
    assert doc["attack_mapping_history"][-1]["rule_renamed"] == {"from": "shikari_t1003_001", "to": "shikari_t1055"}
    assert not writer.file_state(str(path))["edited"]
    mapping.restore(str(path), "Back", "a@example.test")
    doc = _doc(path)
    assert "rule shikari_t1003_001 {" in doc["query"] and 'mitre_attack_technique = "T1003.001"' in doc["query"]


def test_regenerate_keeps_a_renamed_rule(env):
    path = env / "d.yaml"
    _write(path, query=YARAL, connector="GoogleSecOps")
    mapping.change(str(path), "T1055", ["Stealth"], "Rename", "a@example.test",
                   index=INDEX, tactic_order=TACTICS, rename_rule=True)
    run_files.begin("APT1", regenerate=True)
    rewrite = writer.detection_action(str(path), "APT1")
    _write(path, query=YARAL, connector="GoogleSecOps", **rewrite)
    doc = _doc(path)
    assert "rule shikari_t1055 {" in doc["query"] and 'mitre_attack_technique = "T1055"' in doc["query"]
    assert doc["attack_override"]["default"]["rule_name"] == "shikari_t1003_001"


def test_library_content_change_and_restore():
    content = {"technique": "LSASSMemory", "technique_display": "LSASS Memory", "title": "Process",
               "query": YARAL, "tactic": "Credential Access", "tactics": ["Credential Access"]}
    state = mapping.content_state(content, INDEX)
    assert state["mapping"]["technique_id"] == "T1003.001"  # from the rule's meta
    out = mapping.apply_content(content, *mapping.plan_change(
        state, "T1055", ["Stealth"], "Library change", "a@example.test", INDEX, TACTICS), index=INDEX)
    assert (out["attack_id"], out["technique_display"], out["tactic"]) == ("T1055", "Process Injection", "Stealth")
    assert 'mitre_attack_technique = "T1055"' in out["query"] and out["attack_override"]["comment"] == "Library change"
    back = mapping.apply_content(out, *mapping.plan_restore(mapping.content_state(out, INDEX), "Back", "a"), index=INDEX)
    assert back["tactics"] == ["Credential Access"] and "attack_override" not in back
    assert len(back["attack_mapping_history"]) == 2


def test_upgrade_moves_to_the_replacement_and_renames_the_file(env):
    path = env / "LSASSMemory_DeviceProcessEvents.yaml"
    _write(path)
    index = {**INDEX, "T1685.006": {"name": "Clear Logs", "tactics": ["Stealth"]}}
    result = mapping.upgrade(str(path), "T1685.006", ["Stealth"], "ATT&CK revoked it", "a@example.test",
                             index, TACTICS)
    assert result == {"file": "ClearLogs_DeviceProcessEvents.yaml", "renamed_from": path.name, "duplicate": None}
    doc = _doc(env / result["file"])
    assert (doc["technique_id"], doc["name"], doc["tactics"]) == ("T1685.006", "Clear Logs", ["Stealth"])
    assert "attack_override" not in doc  # the replacement is the new ATT&CK default
    assert doc["attack_mapping_history"][0]["action"] == "upgraded"
    assert not path.exists() and not writer.file_state(str(env / result["file"]))["edited"]


def test_upgrade_with_other_tactics_keeps_them_as_an_override(env):
    path = env / "LSASSMemory_DeviceProcessEvents.yaml"
    _write(path)
    (env / "ClearLogs_DeviceProcessEvents.yaml").write_text("existing")
    index = {**INDEX, "T1685.006": {"name": "Clear Logs", "tactics": ["Stealth"]}}
    result = mapping.upgrade(str(path), "T1685.006", ["Stealth", "Impact"], "Upgrade", "a", index, TACTICS)
    assert result["duplicate"] == "ClearLogs_DeviceProcessEvents.yaml" and result["renamed_from"] is None
    o = _doc(path)["attack_override"]
    assert o["default"] == {"technique_id": "T1685.006", "name": "Clear Logs", "tactics": ["Stealth"]}
    assert o["tactics"] == ["Stealth", "Impact"]

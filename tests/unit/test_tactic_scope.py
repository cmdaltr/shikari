"""
Reconnaissance and Resource Development are shown everywhere (archer.tactic_scope); only
the adversary-side techniques ("intel only") are never written as a detection or counted
as a gap. Those the estate's logs see (T1595, T1598, T1594, T1589) are written.
"""
import os

import pytest
import yaml

from archer import tactic_scope
from archer.build import run_files
from archer.build import yaml as writer
from archer.visualization import navigator


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(os.path.dirname(writer.__file__) + "/../..")
    monkeypatch.setattr(run_files, "RUNS_DIR", str(tmp_path / "runs"))
    yield tmp_path


def test_pre_compromise_names_and_ids():
    for t in ("Reconnaissance", "resource-development", "Resource Development", "TA0043", "TA0042"):
        assert tactic_scope.pre_compromise(t)
    assert not tactic_scope.pre_compromise("Initial Access")


def test_intel_only():
    assert tactic_scope.intel_only("T1583.001", ["Resource Development"])
    assert tactic_scope.intel_only("T1593", ["reconnaissance"])
    # The estate's logs see these: scanning, phishing for information
    assert not tactic_scope.intel_only("T1595.002", ["Reconnaissance"])
    assert not tactic_scope.intel_only("T1598", ["Reconnaissance"])
    # A later tactic as well: detectable like any other technique
    assert not tactic_scope.intel_only("T1583", ["Resource Development", "Initial Access"])
    assert not tactic_scope.intel_only("T1566", [])


def _write(path, tactics, tid="T1566.002"):
    writer.write_yaml(str(path), "Spearphishing Link", tid, "d", "MicrosoftThreatProtection",
                      tactics, "APT1", "DeviceEvents\n| where 1", datatype="DeviceEvents")


def test_intel_only_detection_is_not_written(env):
    path = env / "d.yaml"
    _write(path, ["Resource Development"], tid="T1583.001")
    assert not path.exists()


def test_detectable_pre_compromise_detection_is_written(env):
    path = env / "d.yaml"
    _write(path, ["Reconnaissance"], tid="T1595.002")
    doc = yaml.safe_load(path.read_text().split("\n", 1)[1])
    assert doc["tactics"] == ["Reconnaissance"]


def test_mixed_tactics_keep_every_tactic(env):
    path = env / "d.yaml"
    _write(path, ["Resource Development", "Initial Access"])
    doc = yaml.safe_load(path.read_text().split("\n", 1)[1])
    assert doc["tactics"] == ["Resource Development", "Initial Access"]


def _bundle():
    ref = lambda i: [{"source_name": "mitre-attack", "external_id": i}]
    phase = lambda p: {"kill_chain_name": "mitre-attack", "phase_name": p}
    tactics = [{"type": "x-mitre-tactic", "id": f"x--{s}", "name": n, "x_mitre_shortname": s}
               for s, n in (("reconnaissance", "Reconnaissance"), ("initial-access", "Initial Access"))]
    return {"objects": tactics + [
        {"type": "x-mitre-matrix", "external_references": ref("enterprise-attack"),
         "tactic_refs": ["x--reconnaissance", "x--initial-access"]},
        {"type": "attack-pattern", "name": "Phishing for Information", "external_references": ref("T1598"),
         "kill_chain_phases": [phase("reconnaissance")]},
        {"type": "attack-pattern", "name": "Phishing", "external_references": ref("T1566"),
         "kill_chain_phases": [phase("initial-access")]},
    ]}


def test_matrix_and_index_include_them():
    b = _bundle()
    assert [c["tactic"] for c in navigator.matrix(b)] == ["Reconnaissance", "Initial Access"]
    assert set(navigator.technique_index(b)) == {"T1566", "T1598"}


def test_detection_layer_uses_the_mapping_in_force(env, tmp_path):
    from archer.build import attack_mapping
    d = tmp_path / "groups"
    d.mkdir()
    _write(d / "a.yaml", ["Initial Access"])
    _write(d / "b.yaml", ["Reconnaissance", "Initial Access"])
    attack_mapping.change(str(d / "b.yaml"), "T1566.002", ["Execution"], "Moved", "a@example.test")
    layer = navigator.detections_by_tactic(str(d))
    assert layer["Initial Access"]["T1566.002"] == {"count": 1, "vendors": ["MDE"], "changed": False}
    assert layer["Execution"]["T1566.002"]["changed"] is True


def test_legacy_techniques_name_their_replacement():
    b = _bundle()
    ref = lambda i: [{"source_name": "mitre-attack", "external_id": i}]
    b["objects"] += [
        {"type": "attack-pattern", "id": "attack-pattern--old", "name": "Old Way", "revoked": True,
         "external_references": ref("T1070.002")},
        {"type": "attack-pattern", "id": "attack-pattern--new", "name": "New Way", "external_references": ref("T1685.006"),
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]},
        {"type": "relationship", "relationship_type": "revoked-by",
         "source_ref": "attack-pattern--old", "target_ref": "attack-pattern--new"},
    ]
    assert navigator.legacy(b) == {"T1070.002": {
        "name": "Old Way", "status": "revoked", "by": "T1685.006", "by_name": "New Way", "by_tactics": ["Initial Access"]}}

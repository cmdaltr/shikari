"""
Reconnaissance and Resource Development are out of Archer's scope everywhere
(archer.tactic_scope): never written into a detection, never offered in the matrix or a
mapping.
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


def test_excluded_names_and_ids():
    for t in ("Reconnaissance", "resource-development", "Resource Development", "TA0043", "TA0042"):
        assert tactic_scope.excluded(t)
    assert tactic_scope.keep(["Reconnaissance", "Initial Access"]) == ["Initial Access"]


def _write(path, tactics):
    writer.write_yaml(str(path), "Spearphishing Link", "T1566.002", "d", "MicrosoftThreatProtection",
                      tactics, "APT1", "DeviceEvents\n| where 1", datatype="DeviceEvents")


def test_pre_compromise_only_detection_is_not_written(env):
    path = env / "d.yaml"
    _write(path, ["Reconnaissance"])
    assert not path.exists()


def test_mixed_tactics_drop_the_excluded(env):
    path = env / "d.yaml"
    _write(path, ["Resource Development", "Initial Access"])
    doc = yaml.safe_load(path.read_text().split("\n", 1)[1])
    assert doc["tactics"] == ["Initial Access"] and doc["severity"] == "Medium"


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


def test_matrix_and_index_leave_them_out():
    b = _bundle()
    assert [c["tactic"] for c in navigator.matrix(b)] == ["Initial Access"]
    assert set(navigator.technique_index(b)) == {"T1566"}

"""The group download: correlation files go in, and a selection keeps only what's ticked."""

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

import archer.app as app_module
from archer.build import correlation_files


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    gen, corr, flows = tmp_path / "groups", tmp_path / "correlate", tmp_path / "flows"
    for d in (gen, corr / "G1", flows):
        d.mkdir(parents=True)
    for name in ("A_GoogleSecOps.yaml", "B_GoogleSecOps.yaml"):
        (gen / name).write_text("tags:\n  - G1 (Group)\nquery: x\n")
    (gen / "Other_GoogleSecOps.yaml").write_text("tags:\n  - G2 (Group)\n")
    for name in ("A_and_B_GoogleSecOps.yaml", "B_and_C_GoogleSecOps.yaml"):
        (corr / "G1" / name).write_text("query: |\n  x\n")
    (corr / "G1.json").write_text(json.dumps({"vendor_correlations": [
        {"file": "G1/A_and_B_GoogleSecOps.yaml"}, {"file": "G1/B_and_C_GoogleSecOps.yaml"}]}))
    monkeypatch.setattr(app_module, "GENERATE_DIR", str(gen))
    monkeypatch.setattr(app_module, "CORRELATE_DIR", str(corr))
    monkeypatch.setattr(app_module, "ATTACK_FLOWS_DIR", str(flows))
    monkeypatch.setattr(correlation_files, "CORRELATE_DIR", str(corr))



def _contents(group, detections=None, correlations=None):
    client = TestClient(app_module.app)
    if detections is None:
        response = client.get(f"/api/download/all/{group}")
    else:
        response = client.post(f"/api/download/all/{group}",
                               data={"detections": sorted(detections), "correlations": sorted(correlations)})
    assert response.status_code == 200
    return zipfile.ZipFile(io.BytesIO(response.content))


def test_everything_includes_each_correlation_file(dirs):
    names = set(_contents("G1").namelist())
    assert names == {"detections/A_GoogleSecOps.yaml", "detections/B_GoogleSecOps.yaml", "correlations/G1.json",
                     "correlations/G1/A_and_B_GoogleSecOps.yaml", "correlations/G1/B_and_C_GoogleSecOps.yaml"}


def test_selection_keeps_only_ticked_files_and_index_entries(dirs):
    z = _contents("G1", {"A_GoogleSecOps.yaml"}, {"B_and_C_GoogleSecOps.yaml"})
    assert set(z.namelist()) == {"detections/A_GoogleSecOps.yaml", "correlations/G1.json",
                                 "correlations/G1/B_and_C_GoogleSecOps.yaml"}
    index = json.loads(z.read("correlations/G1.json"))
    assert [c["file"] for c in index["vendor_correlations"]] == ["G1/B_and_C_GoogleSecOps.yaml"]


def test_selection_names_cannot_reach_outside_the_group(dirs):
    z = _contents("G1", {"../groups/Other_GoogleSecOps.yaml"}, {"x"})
    assert [n for n in z.namelist() if n.startswith("detections/")] == []

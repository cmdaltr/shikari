"""Detections as code (#20): git export, diff and the dry-run SIEM push."""

import os

import pytest

from shikari.export import detections_git, siem_push


def _write(gdir, name, tid, siem_connector, query="x"):
    doc = f"""name: {name}
technique_id: {tid}
query: '{query}'
severity: medium
requiredDataConnectors:
  - connectorId: {siem_connector}
    dataTypes: [X]
"""
    with open(os.path.join(gdir, f"{name}.yaml"), "w") as fh:
        fh.write(doc)


def _lister(gdir):
    def list_files(_group, _dir):
        return sorted(n for n in os.listdir(gdir) if n.endswith(".yaml"))
    return list_files


@pytest.fixture
def dirs(tmp_path):
    gdir = tmp_path / "groups"
    repo = tmp_path / "repo"
    gdir.mkdir()
    return str(gdir), str(repo)


def test_export_commits_and_paths(dirs):
    gdir, repo = dirs
    _write(gdir, "ProcDump", "T1003.001", "MicrosoftThreatProtection")
    _write(gdir, "Rundll", "T1218.011", "GoogleSecOps")
    res = detections_git.export_run("APT99", gdir, repo, _lister(gdir))
    assert res["committed"] and res["commit"]
    assert any(p.startswith("APT99/mde/T1003.001_") for p in res["files"])
    assert any(p.startswith("APT99/secops/T1218.011_") for p in res["files"])


def test_reexport_no_change_is_not_committed(dirs):
    gdir, repo = dirs
    _write(gdir, "ProcDump", "T1003.001", "MicrosoftThreatProtection")
    first = detections_git.export_run("APT99", gdir, repo, _lister(gdir))
    second = detections_git.export_run("APT99", gdir, repo, _lister(gdir))
    assert second["committed"] is False
    assert second["commit"] == first["commit"]


def test_diff_added_removed_changed(dirs):
    gdir, repo = dirs
    _write(gdir, "ProcDump", "T1003.001", "MicrosoftThreatProtection", query="orig")
    _write(gdir, "Rundll", "T1218.011", "GoogleSecOps")
    a = detections_git.export_run("APT99", gdir, repo, _lister(gdir))["commit"]
    # Change one query, remove one detection, add another
    _write(gdir, "ProcDump", "T1003.001", "MicrosoftThreatProtection", query="changed")
    os.remove(os.path.join(gdir, "Rundll.yaml"))
    _write(gdir, "Wmic", "T1047", "MicrosoftThreatProtection")
    b = detections_git.export_run("APT99", gdir, repo, _lister(gdir))["commit"]
    diff = detections_git.diff_runs(repo, a, b)
    assert any("T1047" in p for p in diff["added"])
    assert any("T1218.011" in p for p in diff["removed"])
    assert any("T1003.001" in p for p in diff["changed"])


def test_list_commits_newest_first(dirs):
    gdir, repo = dirs
    _write(gdir, "ProcDump", "T1003.001", "MicrosoftThreatProtection", query="one")
    detections_git.export_run("APT99", gdir, repo, _lister(gdir))
    _write(gdir, "ProcDump", "T1003.001", "MicrosoftThreatProtection", query="two")
    detections_git.export_run("APT99", gdir, repo, _lister(gdir))
    commits = detections_git.list_commits(repo)
    assert len(commits) >= 2
    assert all(c["sha"] and c["short"] for c in commits)


def test_push_plan_is_dry_run():
    dets = [{"name": "ProcDump", "technique_id": "T1003.001", "query": "DeviceProcessEvents",
             "severity": "high", "siem": "mde"}]
    plan = siem_push.plan_push("mde", dets)
    assert plan["success"] and plan["dry_run"] is True
    assert plan["rule_count"] == 1 and plan["created_disabled"] is True
    assert plan["calls"][0]["body"]["isEnabled"] is False
    assert plan["calls"][0]["body"]["detectionAction"]["alertTemplate"]["mitreTechniques"] == ["T1003.001"]


def test_push_execute_without_credentials_refused():
    dets = [{"name": "x", "technique_id": "T1047", "query": "q", "severity": "low", "siem": "secops"}]
    res = siem_push.plan_push("secops", dets, execute=True)
    assert res["success"] is False


def test_push_unknown_siem_refused():
    assert siem_push.plan_push("splunk", [])["success"] is False

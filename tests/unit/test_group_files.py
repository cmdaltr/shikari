"""
A group's detections are only the files tagged or named for it, so its correlations
pair only that group's detections.

The engine paired every YAML in data/groups, so other groups' rules crowded a
group's own pairs out of the per-vendor cap: Scattered Spider's flow fell from
95 links to 33 as other runs added files, with 87 of 112 correlations touching
another group's detection.
"""
import pytest

from archer.ai.genai.engine import _list_yaml_files
from archer.build.group_files import group_yaml_files


def _write(d, name, groups):
    tags = "\n".join(f"  - {g} (Group)" for g in groups)
    (d / name).write_text(f"name: x\ntags:\n{tags}\n")


def test_only_the_groups_tagged_detections(tmp_path):
    _write(tmp_path, "CloudAccounts_GoogleSecOps.yaml", ["Scattered Spider", "APT29"])
    _write(tmp_path, "At_GoogleSecOps.yaml", ["FIN7"])
    want = [str(tmp_path / "CloudAccounts_GoogleSecOps.yaml")]
    assert group_yaml_files("Scattered Spider", str(tmp_path)) == want
    assert _list_yaml_files("Scattered Spider", str(tmp_path)) == want


def test_cve_runs_use_technique_named_files(tmp_path):
    _write(tmp_path, "T1190_DeviceNetworkEvents.yaml", ["CVE-2024-3400"])
    _write(tmp_path, "At_GoogleSecOps.yaml", ["FIN7"])
    assert group_yaml_files("CVE-2024-3400", str(tmp_path)) == [str(tmp_path / "T1190_DeviceNetworkEvents.yaml")]


@pytest.fixture
def groups_dir(tmp_path):
    (tmp_path / "TemplateInjection_DeviceEvents.yaml").write_text("tags:\n  - APT41 (Group)\nquery: |\n  x\n")
    (tmp_path / "ExploitPublic-FacingApplication_GoogleSecOps.yaml").write_text("tags:\n  - CVE-2024-3400 (Group)\n")
    (tmp_path / "IOCSweepUNC3944_GoogleSecOps.yaml").write_text("tags:\n  - IOC Sweep\n")
    (tmp_path / "Phishing_x_bespoke.yaml").write_text("threat_groups:\n- FIN7\ndetection_platforms:\n- Splunk\n")
    return str(tmp_path)


@pytest.mark.unit
def test_untagged_group_gets_nothing_not_everything(groups_dir):
    # A CVE that generated nothing used to show every T*.yaml (TemplateInjection_...)
    assert group_yaml_files("CVE-2021-0000", groups_dir) == []


@pytest.mark.unit
def test_tagged_named_and_bespoke_files(groups_dir):
    names = lambda g: [p.rsplit("/", 1)[-1] for p in group_yaml_files(g, groups_dir)]
    assert names("CVE-2024-3400") == ["ExploitPublic-FacingApplication_GoogleSecOps.yaml"]
    assert names("UNC3944") == ["IOCSweepUNC3944_GoogleSecOps.yaml"]
    assert names("FIN7") == ["Phishing_x_bespoke.yaml"]
    assert names("APT41") == ["TemplateInjection_DeviceEvents.yaml"]


def _stamped(d, name, groups, query="x"):
    from archer.build.yaml import _stamp

    tags = "\n".join(f"  - {g} (Group)" for g in groups)
    body = f"name: x\ntags:\n{tags}\nquery: |\n  {query}\nversion: 1.0\n"
    (d / name).write_text(_stamp(body) + body)


def test_prune_drops_the_group_from_files_its_run_did_not_make(tmp_path):
    from archer.build.group_files import prune

    _stamped(tmp_path, "Made_UDM.yaml", ["Scattered Spider"])
    _stamped(tmp_path, "Shared_DeviceEvents.yaml", ["APT41", "Scattered Spider"])
    _stamped(tmp_path, "Only_DeviceEvents.yaml", ["Scattered Spider"])
    _stamped(tmp_path, "Edited_UDM.yaml", ["Scattered Spider"])
    edited = tmp_path / "Edited_UDM.yaml"
    edited.write_text(edited.read_text().replace("  x\n", "  y\n"))
    _stamped(tmp_path, "Other_UDM.yaml", ["APT41"])

    report = prune("Scattered Spider", {"Made_UDM.yaml"}, str(tmp_path))
    assert report == {"untagged": ["Shared_DeviceEvents.yaml"], "removed": ["Only_DeviceEvents.yaml"],
                      "kept_edited": ["Edited_UDM.yaml"]}
    assert "Scattered Spider" not in (tmp_path / "Shared_DeviceEvents.yaml").read_text()
    assert "APT41 (Group)" in (tmp_path / "Shared_DeviceEvents.yaml").read_text()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["Edited_UDM.yaml", "Made_UDM.yaml", "Other_UDM.yaml",
                                                           "Shared_DeviceEvents.yaml"]


def test_a_query_refused_on_writing_is_not_the_runs(tmp_path, monkeypatch):
    from archer.build import run_files
    from archer.build.yaml import write_yaml

    monkeypatch.setattr(run_files, "RUNS_DIR", str(tmp_path / "runs"))
    run_files.begin("G-refused")
    try:
        bad, good = str(tmp_path / "Bad_DeviceEvents.yaml"), str(tmp_path / "Good_DeviceEvents.yaml")
        write_yaml(bad, "Bad", "T1059", "d", "MicrosoftThreatProtection", ["Execution"], "G-refused",
                   "DeviceEvents\n  | where ( OR )")
        write_yaml(good, "Good", "T1059", "d", "MicrosoftThreatProtection", ["Execution"], "G-refused",
                   "DeviceEvents\n  | where FileName =~ \"x.exe\"")
        assert run_files.produced("G-refused") == {"Good_DeviceEvents.yaml"}
    finally:
        run_files.finish("G-refused")

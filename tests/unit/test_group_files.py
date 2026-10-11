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

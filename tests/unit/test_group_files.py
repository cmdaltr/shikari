"""
A group's correlations pair only that group's detections.

The engine paired every YAML in data/groups, so other groups' rules crowded a
group's own pairs out of the per-vendor cap: Scattered Spider's flow fell from
95 links to 33 as other runs added files, with 87 of 112 correlations touching
another group's detection.
"""
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

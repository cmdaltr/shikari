"""Files named for a product are renamed for the query language, and the names indexes hold follow."""
import json

from shikari.build import migrate_names


def test_files_and_the_names_that_point_at_them(tmp_path, monkeypatch):
    groups, correlate, runs = tmp_path / "groups", tmp_path / "correlate", tmp_path / "runs"
    for d in (groups, correlate / "G1", runs):
        d.mkdir(parents=True)
    for name in ("At_GoogleSecOps.yaml", "IOCSweepG1_MicrosoftThreatProtection.yaml", "At_DeviceEvents.yaml",
                 "Taken_GoogleSecOps.yaml", "Taken_UDM.yaml"):
        (groups / name).write_text("query: |\n  x\n")
    (correlate / "G1" / "At_and_Bits_DefenderXDR_2.yaml").write_text("parts:\n  - \"At_GoogleSecOps.yaml\"\n")
    (correlate / "G1.json").write_text(json.dumps({"vendor_correlations": [
        {"a": "data/groups/At_GoogleSecOps.yaml", "file": "G1/At_and_Bits_DefenderXDR_2.yaml"}]}))
    (runs / "G1.json").write_text(json.dumps({"files": ["At_GoogleSecOps.yaml", "At_DeviceEvents.yaml"]}))
    monkeypatch.setattr(migrate_names, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(migrate_names, "GENERATE_DIR", str(groups))
    monkeypatch.setattr(migrate_names, "CORRELATE_DIR", str(correlate))
    monkeypatch.setattr(migrate_names, "RUNS_DIR", str(runs))

    report = migrate_names.migrate()
    assert sorted(p.name for p in groups.iterdir()) == ["At_DeviceEvents.yaml", "At_UDM.yaml",
                                                        "IOCSweepG1_KQL.yaml", "Taken_GoogleSecOps.yaml",
                                                        "Taken_UDM.yaml"]
    assert report["conflicts"] == ["groups/Taken_GoogleSecOps.yaml"]
    assert [p.name for p in (correlate / "G1").iterdir()] == ["At_and_Bits_KQL_2.yaml"]
    assert "At_UDM.yaml" in (correlate / "G1" / "At_and_Bits_KQL_2.yaml").read_text()
    index = json.loads((correlate / "G1.json").read_text())["vendor_correlations"][0]
    assert index == {"a": "data/groups/At_UDM.yaml", "file": "G1/At_and_Bits_KQL_2.yaml"}
    assert json.loads((runs / "G1.json").read_text())["files"] == ["At_UDM.yaml", "At_DeviceEvents.yaml"]
    assert migrate_names.migrate() == {"renamed": [], "rewritten": [], "conflicts": ["groups/Taken_GoogleSecOps.yaml"]}

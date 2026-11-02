"""Per-tenant data-source availability gating + deploy exclusion (#12)."""

import os

import pytest

import shikari.build.availability as av


def _mde(table):
    return {"technique_id": "T1059.001", "name": f"d-{table}",
            "requiredDataConnectors": [{"connectorId": "MicrosoftThreatProtection", "dataTypes": [table]}]}


def _secops(et):
    return {"technique_id": "T1059.001", "name": f"s-{et}",
            "requiredDataConnectors": [{"connectorId": "GoogleSecOps", "dataTypes": [et]}]}


def test_save_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(av, "_PATH", tmp_path / "availability.json")
    monkeypatch.setattr(av, "_MAPPINGS_DIR", tmp_path)
    saved = av.save({"mde": ["DeviceFileEvents", "DeviceFileEvents"], "secops": ["PROCESS_LAUNCH"],
                     "elastic": ["ignored"]})  # non-gated SIEM dropped
    assert saved == {"mde": ["DeviceFileEvents"], "secops": ["PROCESS_LAUNCH"]}
    assert av.load() == saved


def test_missing_sources_flags_uningested():
    cfg = {"secops": ["FILE_CREATION", "REGISTRY_MODIFICATION"]}
    miss = av.missing_sources(_secops("PROCESS_LAUNCH"), cfg)
    assert miss == [{"siem": "secops", "connector": "GoogleSecOps", "dataType": "PROCESS_LAUNCH"}]
    assert av.is_available(_secops("PROCESS_LAUNCH"), cfg) is False


def test_ingested_source_passes():
    cfg = {"secops": ["PROCESS_LAUNCH"], "mde": ["DeviceFileEvents"]}
    assert av.missing_sources(_secops("PROCESS_LAUNCH"), cfg) == []
    assert av.is_available(_mde("DeviceFileEvents"), cfg) is True


def test_ungated_siem_not_flagged():
    # No 'mde' key in config -> MDE detections aren't gated at all.
    cfg = {"secops": ["PROCESS_LAUNCH"]}
    assert av.missing_sources(_mde("DeviceProcessEvents"), cfg) == []
    assert av.is_available(_mde("DeviceProcessEvents"), cfg) is True


def test_empty_config_gates_nothing():
    assert av.missing_sources(_mde("DeviceProcessEvents"), {}) == []


def test_export_excludes_unavailable(tmp_path, monkeypatch):
    import yaml
    from shikari.export import detections_git as dg

    gen = tmp_path / "gen"
    gen.mkdir()
    (gen / "a_DeviceFileEvents.yaml").write_text(yaml.safe_dump(_mde("DeviceFileEvents")))
    (gen / "b_PROCESS_LAUNCH.yaml").write_text(yaml.safe_dump(_secops("PROCESS_LAUNCH")))

    # Estate ingests file events but not process launches.
    monkeypatch.setattr(av, "load", lambda: {"secops": ["FILE_CREATION"], "mde": ["DeviceFileEvents"]})

    repo = tmp_path / "repo"
    files = lambda group, gd: sorted(os.path.join(gd, f) for f in os.listdir(gd))
    res = dg.export_run("TestGroup", str(gen), str(repo), files)

    assert any("DeviceFileEvents" in f for f in res["files"])          # ingested -> committed
    assert not any("PROCESS_LAUNCH" in f for f in res["files"])        # un-ingested -> excluded
    assert res["excluded"] and res["excluded"][0]["missing"] == ["PROCESS_LAUNCH"]


def test_udm_catalogue_default_and_override(tmp_path, monkeypatch):
    monkeypatch.setattr(av, "_UDM_REF_FILE", tmp_path / "none.json")
    default = av.udm_event_type_catalogue()
    assert "PROCESS_LAUNCH" in default and "NETWORK_DNS" in default and len(default) > 50
    ref = tmp_path / "udm.json"
    ref.write_text('["PROCESS_LAUNCH", "CUSTOM_EVENT"]')
    monkeypatch.setattr(av, "_UDM_REF_FILE", ref)
    assert av.udm_event_type_catalogue() == ["PROCESS_LAUNCH", "CUSTOM_EVENT"]


def test_source_catalogue_unions_runs_and_docs(tmp_path, monkeypatch):
    import yaml
    monkeypatch.setattr(av, "_UDM_REF_FILE", tmp_path / "udm.json")
    (tmp_path / "udm.json").write_text('["PROCESS_LAUNCH"]')
    gen = tmp_path / "gen"
    gen.mkdir()
    # A run emits an event type not in the override list -> it must still appear.
    (gen / "x_UDM.yaml").write_text(yaml.safe_dump(_secops("SERVICE_CREATION")))
    cat = av.source_catalogue(str(gen))
    assert set(cat["secops"]) == {"PROCESS_LAUNCH", "SERVICE_CREATION"}


def test_export_keeps_all_when_exclude_off(tmp_path, monkeypatch):
    import yaml
    from shikari.export import detections_git as dg

    gen = tmp_path / "gen"
    gen.mkdir()
    (gen / "b_PROCESS_LAUNCH.yaml").write_text(yaml.safe_dump(_secops("PROCESS_LAUNCH")))
    monkeypatch.setattr(av, "load", lambda: {"secops": ["FILE_CREATION"]})

    repo = tmp_path / "repo"
    files = lambda group, gd: [os.path.join(gd, f) for f in os.listdir(gd)]
    res = dg.export_run("G", str(gen), str(repo), files, exclude_unavailable=False)
    assert len(res["files"]) == 1 and not res["excluded"]

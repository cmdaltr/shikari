"""Per-environment schema override resolution (#12)."""

import json

import pytest

from archer.build import schema_overrides as so


def test_aliases_resolve():
    assert so.base_filename("secops") == "schemaGoogleSecOps.json"
    assert so.base_filename("googlesecops") == "schemaGoogleSecOps.json"
    assert so.base_filename("MicrosoftThreatProtection") == "schemaMDE.json"
    assert so.base_filename("Defender") == "schemaMDE.json"
    assert so.base_filename("elastic") == "schemaElastic.json"
    assert so.base_filename("splunk") == "schemaSplunk.json"


def test_custom_filename():
    assert so.custom_filename("secops") == "schemaGoogleSecOps_custom.json"
    assert so.custom_filename("mde") == "schemaMDE_custom.json"


def test_base_when_no_override(tmp_path):
    (tmp_path / "schemaMDE.json").write_text('{"DeviceProcessEvents": "x"}')
    assert so.active_schema_path("mde", tmp_path).name == "schemaMDE.json"
    assert so.has_override("mde", tmp_path) is False
    assert so.load_active_schema("mde", tmp_path) == {"DeviceProcessEvents": "x"}


def test_override_preferred(tmp_path):
    (tmp_path / "schemaMDE.json").write_text('{"DeviceProcessEvents": "x", "DeviceNetworkEvents": "y"}')
    (tmp_path / "schemaMDE_custom.json").write_text('{"DeviceProcessEvents": "x"}')
    assert so.active_schema_path("mde", tmp_path).name == "schemaMDE_custom.json"
    assert so.has_override("mde", tmp_path) is True
    assert so.load_active_schema("mde", tmp_path) == {"DeviceProcessEvents": "x"}


def test_invalid_override_returns_empty(tmp_path):
    (tmp_path / "schemaElastic_custom.json").write_text("{not json")
    assert so.load_active_schema("elastic", tmp_path) == {}


def test_unknown_siem():
    with pytest.raises(KeyError):
        so.base_filename("qradar")
    assert so.load_active_schema("qradar") == {}


def test_save_reset_override_roundtrip(tmp_path):
    (tmp_path / "schemaSplunk.json").write_text('{"cmd": {"index=main": "x"}}')
    assert so.override_info("splunk", tmp_path)["has_override"] is False

    saved = so.save_override("splunk", {"cmd": {"index=edr": "y"}}, tmp_path)
    assert saved["keys"] == 1
    info = so.override_info("splunk", tmp_path)
    assert info["has_override"] is True
    assert info["schema"] == {"cmd": {"index=edr": "y"}}
    assert so.load_active_schema("splunk", tmp_path) == {"cmd": {"index=edr": "y"}}

    assert so.reset_override("splunk", tmp_path) is True
    assert so.override_info("splunk", tmp_path)["has_override"] is False
    assert so.reset_override("splunk", tmp_path) is False  # already gone


def test_save_override_rejects_non_object(tmp_path):
    for bad in ({}, [], "x", 3, None):
        with pytest.raises(ValueError):
            so.save_override("elastic", bad, tmp_path)


def test_secops_elastic_builders_still_load_base():
    # With no override committed, the builders read the shipped base schema unchanged.
    from archer.build.secops import SecOpsGenerator
    from archer.build.elastic import ElasticQueryGenerator

    assert SecOpsGenerator().schema          # non-empty UDM map
    assert ElasticQueryGenerator().schema    # non-empty ECS map

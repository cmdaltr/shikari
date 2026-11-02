"""Defender XDR cloud-native tables (CloudAppEvents, Identity*) only for cloud techniques or cloud indicators."""
from shikari.build import queries

FLAT = {"DeviceEvents": ["ActionType"], "CloudAppEvents": ["ActionType", "ActivityType"],
        "IdentityLogonEvents": ["ActionType", "Application"]}


def _cloud(monkeypatch):
    monkeypatch.setattr(queries, "LOG_SOURCE_CATEGORIES", {
        "endpoint": {"MDE": ["DeviceEvents"]},
        "cloud_native_azure": {"MDE": ["CloudAppEvents", "IdentityLogonEvents"], "Splunk": ["azure_ad"]}})


def test_windows_technique_gets_no_cloud_tables(monkeypatch):
    _cloud(monkeypatch)
    assert set(queries.get_valid_indices_for_platform(FLAT, "MDE", set(), "Windows", "cmd")) == {"DeviceEvents"}


def test_any_cloud_platform_or_cloud_indicator_keeps_them(monkeypatch):
    _cloud(monkeypatch)
    assert set(queries.get_valid_indices_for_platform(FLAT, "MDE", set(), ["Windows", "Identity Provider"], "cmd")) == set(FLAT)
    assert set(queries.get_valid_indices_for_platform(FLAT, "MDE", {"azure"}, "Windows", "cmd")) == set(FLAT)


def test_splunk_flat_mappings_are_unchanged(monkeypatch):
    _cloud(monkeypatch)
    flat = {"index=azure_ad": ["operation"], "index=windows": ["CommandLine"]}
    assert queries.get_valid_indices_for_platform(flat, "Splunk", set(), "Windows", "cmd") == flat

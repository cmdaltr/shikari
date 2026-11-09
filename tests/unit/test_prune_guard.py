"""A run that produces far less than the group already has doesn't prune the group's detections."""

import pytest

from shikari.build.orchestrator import PRUNE_GUARD_MIN, prune_held_back


def _files(d, n, group="FIN7"):
    for i in range(n):
        (d / f"T{i}_UDM.yaml").write_text(f"title: t{i}\ntags:\n  - {group} (Group)\n")
    return {f"T{i}_UDM.yaml" for i in range(n)}


@pytest.mark.unit
def test_a_near_empty_run_is_held_back(tmp_path):
    names = _files(tmp_path, 100)
    assert "made 38 detection file(s) but FIN7 has 100" in prune_held_back("FIN7", set(list(names)[:38]), str(tmp_path))


@pytest.mark.unit
def test_a_normal_run_prunes(tmp_path):
    names = _files(tmp_path, 100)
    assert prune_held_back("FIN7", set(list(names)[:95]), str(tmp_path)) is None


@pytest.mark.unit
def test_a_small_group_is_never_held_back(tmp_path):
    names = _files(tmp_path, PRUNE_GUARD_MIN - 1)
    assert prune_held_back("FIN7", set(list(names)[:1]), str(tmp_path)) is None


@pytest.mark.unit
def test_platform_table_is_reread_and_missing_stops_the_run(tmp_path, monkeypatch):
    import json
    import os

    from shikari import paths
    from shikari.build import queries
    from shikari.build.detections import MappingsError

    monkeypatch.setattr(paths, "BESPOKE", tmp_path)
    monkeypatch.setattr(queries, "_platform_cache", {"mtime": None, "mappings": {}})
    with pytest.raises(MappingsError):
        queries.get_platforms_for_index("DeviceProcessEvents")

    src = tmp_path / "mappings" / "sources"
    src.mkdir(parents=True)
    (src / "platforms.json").write_text(json.dumps({"Windows": {"MDE": ["DeviceProcessEvents"]}}))
    assert queries.get_platforms_for_index("DeviceProcessEvents") == ["Windows"]

    (src / "platforms.json").write_text(json.dumps({"Linux": {"MDE": ["DeviceProcessEvents"]}}))
    os.utime(src / "platforms.json", (1, 2))      # a changed file is read again
    assert queries.get_platforms_for_index("DeviceProcessEvents") == ["Linux"]

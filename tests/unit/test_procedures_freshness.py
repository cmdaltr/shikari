import json

from shikari.mitre import procedures as p


def _bundle(path, version):
    path.write_text(json.dumps({"objects": [{"type": "x-mitre-collection", "x_mitre_version": version}]}))
    return path


def _csv(tmp_path, meta):
    csv = tmp_path / "mitre_procedures.csv"
    csv.write_text("group_sw_id\n")
    if meta is not None:
        (tmp_path / "mitre_procedures.meta.json").write_text(json.dumps(meta))
    return csv


def test_missing_csv_is_stale(tmp_path):
    assert p.is_cache_stale(tmp_path / "none.csv", _bundle(tmp_path / "b.json", "20.0"))


def test_no_meta_is_stale(tmp_path):
    assert p.is_cache_stale(_csv(tmp_path, None), _bundle(tmp_path / "b.json", "20.0"))


def test_same_version_is_fresh_whatever_its_age(tmp_path):
    csv = _csv(tmp_path, {"attack_version": "20.0", "flags": p._MITRESAW_FLAGS})
    old = 0  # 1970: age no longer counts
    import os
    os.utime(csv, (old, old))
    assert not p.is_cache_stale(csv, _bundle(tmp_path / "b.json", "20.0"))
    assert p.built_version(csv) == "20.0"


def test_new_attack_release_is_stale(tmp_path):
    csv = _csv(tmp_path, {"attack_version": "19.1", "flags": p._MITRESAW_FLAGS})
    assert p.is_cache_stale(csv, _bundle(tmp_path / "b.json", "20.0"))


def test_other_flags_are_stale(tmp_path):
    csv = _csv(tmp_path, {"attack_version": "20.0", "flags": ["-f", "Enterprise"]})
    assert p.is_cache_stale(csv, _bundle(tmp_path / "b.json", "20.0"))


def test_no_bundle_keeps_a_built_csv(tmp_path):
    csv = _csv(tmp_path, {"attack_version": "20.0", "flags": p._MITRESAW_FLAGS})
    assert not p.is_cache_stale(csv, tmp_path / "missing.json")

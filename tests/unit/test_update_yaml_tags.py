"""update_yaml adds a group's tag to a detection whichever way its tag list is laid out: a later hunt
crashed on detections yaml.safe_dump had written ("tags:\n- ", no indent)."""
import pytest

from shikari.build import yaml as build_yaml


@pytest.mark.parametrize("body,expected", [
    ("tags:\n  - A (Group)\nversion: 1.0.0\n", "tags:\n  - B (Group)\n  - A (Group)\nversion: 1.1.0\n"),
    ("tags:\n- A (Group)\nversion: 1.0.0\n", "tags:\n- B (Group)\n- A (Group)\nversion: 1.1.0\n"),
    ("tags: []\nversion: 1.0.0\n", "tags: []\nversion: 1.0.0\n"),   # nothing to add to: left alone
])
def test_group_tag_added(tmp_path, monkeypatch, body, expected):
    monkeypatch.setattr(build_yaml.run_files, "note", lambda *a: None)
    f = tmp_path / "d.yaml"
    f.write_text(body)
    build_yaml.update_yaml(str(f), "B")
    assert f.read_text() == expected

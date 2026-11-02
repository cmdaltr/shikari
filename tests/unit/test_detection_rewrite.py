"""
Detections on disk are rewritten when the generator changes, kept when edited by hand,
and replaced on Regenerate (shikari.build.yaml.detection_action).
"""
import json
import os

import pytest
import yaml

from shikari.build import run_files
from shikari.build import yaml as writer

QUERY = "DeviceProcessEvents\n| where ProcessCommandLine has \"procdump\""


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(os.path.dirname(writer.__file__) + "/../..")
    monkeypatch.setattr(run_files, "RUNS_DIR", str(tmp_path / "runs"))
    yield tmp_path
    for group in ("APT1", "APT2"):
        run_files.finish(group)


def _write(path, tag, query=QUERY, **kw):
    writer.write_yaml(str(path), "LSASS Memory", "T1003.001", "d", "MicrosoftThreatProtection",
                      ["Credential Access"], tag, query, datatype="DeviceProcessEvents", **kw)


def _act(path, tag, query=QUERY):
    """What a run does for one procedure: decide, then write if told to."""
    rewrite = writer.detection_action(str(path), tag)
    if rewrite is not None:
        _write(path, tag, query, **rewrite)
    return rewrite


def test_new_file_is_stamped(env):
    path = env / "d.yaml"
    _write(path, "APT1")
    state = writer.file_state(str(path))
    assert state["generator"] == writer.GENERATOR_VERSION and not state["edited"]
    assert yaml.safe_load(path.read_text())["severity"] == "High"


def test_current_file_is_only_tagged(env):
    path = env / "d.yaml"
    _write(path, "APT1")
    run_files.begin("APT2")
    assert _act(path, "APT2", query=QUERY + " and 1") is None
    data = yaml.safe_load(path.read_text())
    assert "APT2 (Group)" in data["tags"] and "and 1" not in data["query"]


def test_older_generator_is_rewritten_keeping_tags(env):
    path = env / "d.yaml"
    _write(path, "APT1")
    # As written before stamps existed
    path.write_text(path.read_text().split("\n", 1)[1])
    run_files.begin("APT2")
    assert _act(path, "APT2", query=QUERY + " and 2") == {"tags": ["APT1 (Group)"], "version": "1.1"}
    data = yaml.safe_load(path.read_text())
    assert "and 2" in data["query"] and set(data["tags"]) == {"APT1 (Group)", "APT2 (Group)"}
    assert data["version"] == 1.1 and writer.file_state(str(path))["generator"] == writer.GENERATOR_VERSION


def test_hand_edited_file_is_kept_and_reported(env):
    path = env / "d.yaml"
    _write(path, "APT1")
    path.write_text(path.read_text().replace("procdump", "procdump64"))
    assert writer.file_state(str(path))["edited"]
    # Even a generator change leaves it alone
    path.write_text(path.read_text().replace(f"generator: {writer.GENERATOR_VERSION} ", "generator: 1 ", 1))
    run_files.begin("APT1")
    assert _act(path, "APT1", query=QUERY + " and 3") is None
    assert "procdump64" in path.read_text() and "and 3" not in path.read_text()
    run_files.finish("APT1")
    assert run_files.latest_run("APT1")["kept_edited"] == ["d.yaml"]


def test_regenerate_replaces_even_an_edited_file(env):
    path = env / "d.yaml"
    _write(path, "APT1")
    path.write_text(path.read_text().replace("procdump", "procdump64"))
    run_files.begin("APT1", regenerate=True)
    assert run_files.regenerating("APT1")
    assert _act(path, "APT1", query=QUERY + " and 4") is not None
    text = path.read_text()
    assert "procdump64" not in text and "and 4" in text and not writer.file_state(str(path))["edited"]
    run_files.finish("APT1")
    assert not run_files.regenerating("APT1")


def test_a_run_rewrites_a_file_once(env):
    # Several procedures can produce the same technique/table: the first query stands
    path = env / "d.yaml"
    run_files.begin("APT1", regenerate=True)
    assert _act(path, "APT1", query=QUERY + " and first") == {}
    assert _act(path, "APT1", query=QUERY + " and second") is None
    assert "and first" in path.read_text() and "and second" not in path.read_text()


def test_a_description_that_opens_with_a_citation_stays_valid_yaml(tmp_path):
    import yaml as pyyaml

    from shikari.build.yaml import write_yaml

    path = tmp_path / "FileDeletion_UDM.yaml"
    desc = ("(Citation: Earlier Report) [Vidar](https://attack.mitre.org/software/S9050) deleted it with "
            "`del /f /q x.exe &\n del C:\\ProgramData\\*.dll`. (Citation: Vidar 2023)")
    write_yaml(str(path), "File Deletion", "T1070.004", desc, "GoogleSecOps", ["Defense Evasion"],
               "Scattered Spider", 'metadata.event_type = "PROCESS_LAUNCH"', datatype="PROCESS_LAUNCH")
    doc = pyyaml.safe_load(path.read_text())
    assert doc["description"].startswith("[Vidar]")
    assert "Citation" not in doc["description"]

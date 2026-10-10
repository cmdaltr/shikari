"""
Missing indicator mappings must fail generation visibly.

load_indicator_mappings() used to call sys.exit(1). Inside the generation
worker thread SystemExit bypassed every `except Exception`, killed the thread
silently and left progress stuck at creating_yamls 0/N.
"""
from unittest.mock import MagicMock, patch

import pytest

from archer.build import detections, orchestrator
from archer.build.detections import MappingsError, load_indicator_mappings


def _point_mappings_at(tmp_path):
    """load_indicator_mappings resolves bespoke/mappings two levels above archer/build/."""
    build_dir = tmp_path / "archer" / "build"
    build_dir.mkdir(parents=True)
    mappings_dir = tmp_path / "bespoke" / "mappings"
    return patch.object(detections.os.path, "dirname", return_value=str(build_dir)), mappings_dir


def test_missing_directory_raises_mappings_error(tmp_path):
    patcher, _ = _point_mappings_at(tmp_path)
    with patcher, pytest.raises(MappingsError, match="does not exist"):
        load_indicator_mappings()


def test_empty_directory_raises_mappings_error(tmp_path):
    patcher, mappings_dir = _point_mappings_at(tmp_path)
    mappings_dir.mkdir(parents=True)
    with patcher, pytest.raises(MappingsError, match="setup_mappings.py"):
        load_indicator_mappings()


def test_incomplete_mappings_raise_mappings_error(tmp_path):
    patcher, mappings_dir = _point_mappings_at(tmp_path)
    mappings_dir.mkdir(parents=True)
    (mappings_dir / "indicatorMapping.json").write_text('{"cmd": {}}')
    with patcher, pytest.raises(MappingsError, match="missing required types"):
        load_indicator_mappings()


def test_mappings_error_is_catchable_as_exception():
    # The whole point: generation handlers catch Exception, not BaseException
    assert issubclass(MappingsError, Exception)


def test_process_group_fails_fast_and_records_error():
    progress = []
    with patch.object(orchestrator, "get_stix_data", return_value=MagicMock()), \
         patch.object(orchestrator, "obtain_technique_descriptions", return_value=[]), \
         patch.object(orchestrator, "check_group_in_mitre", return_value="Y"), \
         patch.object(orchestrator, "load_indicator_mappings",
                      side_effect=MappingsError("No indicator mapping files found")), \
         patch.object(orchestrator, "compile_query") as compile_query, \
         patch.object(orchestrator, "safe_progress_update",
                      side_effect=lambda g, d: progress.append(d)):
        with pytest.raises(MappingsError):
            orchestrator.process_group("Scattered Spider")

    compile_query.assert_not_called()
    assert progress[-1]["status"] == "failed"
    assert "No indicator mapping files found" in progress[-1]["error"]

#!/usr/bin/env python3
"""
Unit Tests: MITRE ATT&CK Integration

Tests the internal MITRE ATT&CK data handling:
1. Group lookup by name and alias
2. Technique retrieval for groups
3. Progress file creation and reading
4. Correlation file structure
5. YAML detection structure

Can be run directly: python test_mitre_integration.py
Or via pytest: pytest test_mitre_integration.py
"""

import os
import sys
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add shikari to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def create_mock_mitre_bundle():
    """Create a mock MITRE ATT&CK bundle for testing."""
    mock_bundle = MagicMock()
    mock_bundle.objects = [
        {
            "type": "intrusion-set",
            "id": "intrusion-set--apt29",
            "name": "APT29",
            "aliases": ["Cozy Bear", "The Dukes"],
            "description": "APT29 is a Russian threat group.",
        },
        {
            "type": "intrusion-set",
            "id": "intrusion-set--apt28",
            "name": "APT28",
            "aliases": ["Fancy Bear"],
            "description": "APT28 is a Russian threat group.",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1566",
            "name": "Phishing",
            "description": "Adversaries may send phishing messages.",
            "x_mitre_detection": "Monitor for suspicious emails.",
            "x_mitre_data_sources": ["Email: Content"],
            "kill_chain_phases": [{"phase_name": "initial-access"}],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1059",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command interpreters.",
            "x_mitre_detection": "Monitor for process creation.",
            "x_mitre_data_sources": ["Process: Process Creation"],
            "kill_chain_phases": [{"phase_name": "execution"}],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059"}
            ],
        },
        {
            "type": "relationship",
            "id": "relationship--apt29-uses-t1566",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--apt29",
            "target_ref": "attack-pattern--t1566",
            "description": "APT29 has used spearphishing.",
        },
    ]
    return mock_bundle


def test_check_group_in_mitre():
    """Test that check_group_in_mitre finds groups by name."""
    from shikari.mitre import check_group_in_mitre

    mock_bundle = create_mock_mitre_bundle()

    result = check_group_in_mitre(mock_bundle, "APT29")

    assert result == "Y"
    return True


def test_check_group_in_mitre_by_alias():
    """Test that check_group_in_mitre finds groups by alias."""
    from shikari.mitre import check_group_in_mitre

    mock_bundle = create_mock_mitre_bundle()

    result = check_group_in_mitre(mock_bundle, "Cozy Bear")

    assert result == "Y"
    return True


def test_check_group_in_mitre_not_found():
    """Test that unknown groups return 'N'."""
    from shikari.mitre import check_group_in_mitre

    mock_bundle = create_mock_mitre_bundle()

    result = check_group_in_mitre(mock_bundle, "NonExistentGroup12345")

    assert result == "N"
    return True


def test_retrieve_group():
    """Test retrieving a group ID by name."""
    from shikari.mitre import retrieve_group

    mock_bundle = create_mock_mitre_bundle()

    group_id = retrieve_group(mock_bundle, "APT29")

    assert group_id == "intrusion-set--apt29"
    return True


def test_retrieve_techniques():
    """Test getting techniques used by a threat group."""
    from shikari.mitre import retrieve_group, retrieve_techniques

    mock_bundle = create_mock_mitre_bundle()

    group_id = retrieve_group(mock_bundle, "APT29")
    techniques = retrieve_techniques(mock_bundle, group_id)

    # Should return techniques associated with APT29
    assert isinstance(techniques, list)
    assert len(techniques) > 0
    # Techniques are tuples of (description, target_ref)
    assert any("attack-pattern--t1566" in t[1] for t in techniques)
    return True


def test_progress_file_creation():
    """Test that progress files are created correctly."""
    from shikari.build.progress import write_progress, read_progress

    with tempfile.TemporaryDirectory() as tmpdir:
        progress_dir = Path(tmpdir)

        progress_data = {
            "status": "processing",
            "stage": "yaml",
            "created_yaml": 5,
            "total_yaml": 10,
            "current_technique": "T1059.001",
        }

        with patch("shikari.build.progress.PROGRESS_DIR", str(progress_dir)):
            write_progress("TestGroup", progress_data)

            result = read_progress("TestGroup")

            assert result["status"] == "processing"
            assert result["created_yaml"] == 5
            assert result["total_yaml"] == 10
    return True


def test_progress_status_complete():
    """Test that progress shows completion status."""
    from shikari.build.progress import write_progress, read_progress

    with tempfile.TemporaryDirectory() as tmpdir:
        progress_dir = Path(tmpdir)

        progress_data = {
            "status": "complete",
            "created_yaml": 10,
            "total_yaml": 10,
        }

        with patch("shikari.build.progress.PROGRESS_DIR", str(progress_dir)):
            write_progress("CompleteGroup", progress_data)

            result = read_progress("CompleteGroup")

            assert result["status"] == "complete"
            assert result["created_yaml"] == result["total_yaml"]
    return True


def test_progress_status_failed():
    """Test that progress shows failure status."""
    from shikari.build.progress import write_progress, read_progress

    with tempfile.TemporaryDirectory() as tmpdir:
        progress_dir = Path(tmpdir)

        progress_data = {
            "status": "failed",
            "error": "API connection timeout",
        }

        with patch("shikari.build.progress.PROGRESS_DIR", str(progress_dir)):
            write_progress("FailedGroup", progress_data)

            result = read_progress("FailedGroup")

            assert result["status"] == "failed"
            assert "error" in result
    return True


def test_correlation_file_structure():
    """Test that correlation files have correct structure."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corr_dir = Path(tmpdir)

        corr_data = {
            "group_name": "TestGroup",
            "correlations": [
                {"technique": "T1059.001", "queries": ["query1", "query2"]},
                {"technique": "T1566.001", "queries": ["query3"]},
            ],
        }

        corr_file = corr_dir / "TestGroup.json"
        with open(corr_file, "w") as f:
            json.dump(corr_data, f)

        # Read back and verify
        with open(corr_file) as f:
            result = json.load(f)

        assert result["group_name"] == "TestGroup"
        assert len(result["correlations"]) == 2
        assert result["correlations"][0]["technique"] == "T1059.001"
    return True


def test_yaml_detection_structure():
    """Test that YAML detection files have correct structure."""
    import yaml

    detection = {
        "title": "Test Detection Rule",
        "id": "test-rule-001",
        "status": "test",
        "description": "Detects test activity",
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection": {
                "CommandLine|contains": "test",
            },
            "condition": "selection",
        },
        "level": "medium",
        "tags": ["attack.execution", "attack.t1059"],
    }

    yaml_str = yaml.dump(detection, default_flow_style=False)

    # Verify it can be parsed back
    parsed = yaml.safe_load(yaml_str)

    assert parsed["title"] == "Test Detection Rule"
    assert "detection" in parsed
    assert "logsource" in parsed
    return True


def test_technique_id_extraction():
    """Test extracting technique IDs from MITRE data."""
    mock_bundle = create_mock_mitre_bundle()

    technique_ids = []
    for obj in mock_bundle.objects:
        if obj["type"] == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_ids.append(ref["external_id"])

    assert "T1566" in technique_ids
    assert "T1059" in technique_ids
    return True


def test_threat_group_workflow():
    """Standalone test function for CLI execution."""
    print("Testing Threat Group Detection Generation Workflow...")
    print("=" * 60)

    tests = [
        ("Check group in MITRE", test_check_group_in_mitre),
        ("Check group by alias", test_check_group_in_mitre_by_alias),
        ("Group not found", test_check_group_in_mitre_not_found),
        ("Retrieve group", test_retrieve_group),
        ("Retrieve techniques", test_retrieve_techniques),
        ("Progress file creation", test_progress_file_creation),
        ("Progress status complete", test_progress_status_complete),
        ("Progress status failed", test_progress_status_failed),
        ("Correlation file structure", test_correlation_file_structure),
        ("YAML detection structure", test_yaml_detection_structure),
        ("Technique ID extraction", test_technique_id_extraction),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            print(f"PASS: {name}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {name}")
            print(f"      {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {name}")
            print(f"       {e}")
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")

    return failed == 0


if __name__ == "__main__":
    success = test_threat_group_workflow()
    sys.exit(0 if success else 1)

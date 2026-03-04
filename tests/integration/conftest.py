"""
Shared fixtures for integration tests.

Provides TestClient, mock data directories, and helper fixtures
for API testing.
"""
import pytest
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient


@pytest.fixture
def temp_dir(tmp_path):
    """Create a temporary directory for tests."""
    return tmp_path


@pytest.fixture
def mock_dirs(temp_dir):
    """Create mock data directories."""
    dirs = {
        "generate": temp_dir / "generate",
        "correlate": temp_dir / "correlate",
        "drafts": temp_dir / "drafts",
        "uploads": temp_dir / "uploads",
        "blog": temp_dir / "blog",
        "progress": temp_dir / "progress",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


@pytest.fixture
def client(mock_dirs):
    """Create test client with mocked directories."""
    with patch.dict("archer.config.__dict__", {
        "GENERATE_DIR": str(mock_dirs["generate"]),
        "CORRELATE_DIR": str(mock_dirs["correlate"]),
        "DRAFTS_DIR": str(mock_dirs["drafts"]),
        "UPLOADS_DIR": str(mock_dirs["uploads"]),
        "BLOG_DIR": str(mock_dirs["blog"]),
        "PROGRESS_DIR": str(mock_dirs["progress"]),
    }):
        from archer.app import app
        yield TestClient(app)


@pytest.fixture
def authenticated_client(client):
    """Create an authenticated test client."""
    # For endpoints requiring authentication
    # This can be expanded based on auth implementation
    return client


@pytest.fixture
def mock_mitre_bundle():
    """Create a mock MITRE ATT&CK bundle."""
    mock_group = {
        "type": "intrusion-set",
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes"],
        "description": "Russian threat group",
    }
    mock_group2 = {
        "type": "intrusion-set",
        "name": "APT28",
        "aliases": ["Fancy Bear"],
        "description": "Another Russian threat group",
    }
    mock_technique = {
        "type": "attack-pattern",
        "name": "PowerShell",
        "external_references": [{"external_id": "T1059.001"}],
    }

    bundle = MagicMock()
    bundle.objects = [mock_group, mock_group2, mock_technique]
    return bundle


@pytest.fixture
def sample_progress_data():
    """Sample progress tracking data."""
    return {
        "status": "processing",
        "stage": "yaml",
        "created_yaml": 5,
        "total_yaml": 10,
        "current_technique": "T1059.001",
    }


@pytest.fixture
def sample_correlation_data():
    """Sample correlation results data."""
    return {
        "group_name": "APT29",
        "correlations": [
            {
                "technique_id": "T1059.001",
                "technique": "PowerShell",
                "detections": ["detection1.yaml", "detection2.yaml"],
            }
        ],
        "summary": {
            "total_techniques": 10,
            "techniques_with_detections": 8,
        }
    }


@pytest.fixture
def sample_draft_data():
    """Sample draft data for testing."""
    return {
        "draft_id": "test-draft-001",
        "group_name": "APT29",
        "techniques": ["T1059.001", "T1566.001"],
        "created_at": "2025-01-20T10:00:00Z",
    }


@pytest.fixture
def sample_blog_analysis():
    """Sample blog analysis result."""
    return {
        "success": True,
        "techniques": ["T1566.001", "T1059.001", "T1003.001"],
        "group_name": "APT29",
        "procedures": ["Used spearphishing to gain access"],
        "iocs": {
            "domain": ["evil.com"],
            "ip": ["192.168.1.100"],
        }
    }

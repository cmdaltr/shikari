"""
Shared fixtures for feature tests.

Provides test clients, mock data, and helper functions
for end-to-end workflow testing.
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
def mock_all_dirs(temp_dir):
    """Create all mock directories needed for feature tests."""
    dirs = {
        "generate": temp_dir / "generate",
        "correlate": temp_dir / "correlate",
        "drafts": temp_dir / "drafts",
        "uploads": temp_dir / "uploads",
        "blog": temp_dir / "blog",
        "progress": temp_dir / "progress",
        "attack_flows": temp_dir / "attack_flows",
        "profile_pics": temp_dir / "profile_pics",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


@pytest.fixture
def feature_client(mock_all_dirs):
    """Create test client with all directories mocked."""
    with patch.dict("shikari.config.__dict__", {
        "GENERATE_DIR": str(mock_all_dirs["generate"]),
        "CORRELATE_DIR": str(mock_all_dirs["correlate"]),
        "DRAFTS_DIR": str(mock_all_dirs["drafts"]),
        "UPLOADS_DIR": str(mock_all_dirs["uploads"]),
        "BLOG_DIR": str(mock_all_dirs["blog"]),
        "PROGRESS_DIR": str(mock_all_dirs["progress"]),
        "ATTACK_FLOWS_DIR": str(mock_all_dirs["attack_flows"]),
        "PROFILE_PICS_DIR": str(mock_all_dirs["profile_pics"]),
    }):
        from shikari.app import app
        yield TestClient(app)


@pytest.fixture
def mock_mitre_bundle():
    """Create a comprehensive mock MITRE ATT&CK bundle."""
    # Groups
    apt29 = {
        "type": "intrusion-set",
        "id": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM"],
        "description": "APT29 is a threat group attributed to Russia.",
    }

    # Techniques
    t1059_001 = {
        "type": "attack-pattern",
        "id": "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
        "name": "PowerShell",
        "description": "Adversaries may abuse PowerShell for execution.",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
    }
    t1566_001 = {
        "type": "attack-pattern",
        "id": "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597",
        "name": "Spearphishing Attachment",
        "description": "Adversaries may send spearphishing emails.",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1566.001"}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
    }
    t1003_001 = {
        "type": "attack-pattern",
        "id": "attack-pattern--65f2d882-3f41-4d48-8a06-29af77ec9f90",
        "name": "LSASS Memory",
        "description": "Adversaries may dump credentials from LSASS.",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1003.001"}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
    }

    # Relationships
    rel1 = {
        "type": "relationship",
        "relationship_type": "uses",
        "source_ref": apt29["id"],
        "target_ref": t1059_001["id"],
    }

    bundle = MagicMock()
    bundle.objects = [apt29, t1059_001, t1566_001, t1003_001, rel1]
    return bundle


@pytest.fixture
def sample_blog_html():
    """Sample threat intelligence blog HTML."""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>APT29 Campaign Analysis</title></head>
    <body>
        <article>
            <h1>APT29 Campaign Analysis</h1>
            <p>This report details the tactics used by APT29 threat actor.</p>
            <h2>Initial Access</h2>
            <p>The threat actor used T1566.001 (Spearphishing Attachment).</p>
            <h2>Execution</h2>
            <p>They executed T1059.001 (PowerShell) commands.</p>
            <h2>Credential Access</h2>
            <p>T1003.001 (LSASS Memory) was used to dump credentials.</p>
        </article>
    </body>
    </html>
    """

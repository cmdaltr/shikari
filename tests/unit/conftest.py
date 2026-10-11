"""
Shared fixtures for unit tests.

Provides mock objects, test data, and temporary directories
for isolated unit testing.
"""
import pytest
import json
from pathlib import Path
from unittest.mock import MagicMock, patch


# ============================================================================
# Temporary Directory Fixtures
# ============================================================================

@pytest.fixture
def temp_dir(tmp_path):
    """Create a temporary directory for tests."""
    return tmp_path


@pytest.fixture
def mock_data_dir(temp_dir):
    """Create a mock data directory structure."""
    data_dir = temp_dir / "data"
    data_dir.mkdir()

    # Create subdirectories
    (data_dir / "groups").mkdir()
    (data_dir / "blog_analysis").mkdir()
    (data_dir / "progress").mkdir()
    (data_dir / "correlate").mkdir()

    return data_dir


@pytest.fixture
def mock_output_dir(temp_dir):
    """Create a mock output directory for generated YAML files."""
    output_dir = temp_dir / "output"
    output_dir.mkdir()
    return output_dir


# ============================================================================
# Sample Data Fixtures
# ============================================================================

@pytest.fixture
def sample_blog_html():
    """Sample blog HTML content with threat intelligence."""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>APT29 Analysis Report</title></head>
    <body>
        <article>
            <h1>APT29 Campaign Analysis</h1>
            <p>This report details the tactics used by APT29 threat actor.</p>

            <h2>Initial Access</h2>
            <p>The threat actor used T1566.001 (Spearphishing Attachment) to gain
            initial access to the victim organization.</p>

            <h2>Execution</h2>
            <p>After gaining access, they executed T1059.001 (PowerShell) commands
            to download additional payloads.</p>

            <h2>Credential Access</h2>
            <p>T1003.001 (LSASS Memory) was used to dump credentials from memory.</p>

            <h2>IOCs</h2>
            <ul>
                <li>Domain: malicious-c2.example.com</li>
                <li>IP: 192.168.100.50</li>
                <li>Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</li>
            </ul>
        </article>
    </body>
    </html>
    """


@pytest.fixture
def sample_blog_text():
    """Sample extracted text from a blog post."""
    return """
    APT29 Campaign Analysis

    This report details the tactics used by APT29 threat actor.

    Initial Access
    The threat actor used T1566.001 (Spearphishing Attachment) to gain
    initial access to the victim organization.

    Execution
    After gaining access, they executed T1059.001 (PowerShell) commands
    to download additional payloads.

    Credential Access
    T1003.001 (LSASS Memory) was used to dump credentials from memory.

    IOCs
    Domain: malicious-c2.example.com
    IP: 192.168.100.50
    Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """


@pytest.fixture
def sample_techniques():
    """Sample MITRE ATT&CK technique IDs."""
    return ["T1566.001", "T1059.001", "T1003.001"]


@pytest.fixture
def sample_iocs():
    """Sample IOCs extracted from threat intelligence."""
    return {
        "domain": ["malicious-c2.example.com", "evil-domain.net"],
        "ip": ["192.168.100.50", "10.0.0.100"],
        "hash": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "file": ["/tmp/malware.exe", "C:\\Windows\\Temp\\payload.dll"],
        "reg": ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware"],
    }


@pytest.fixture
def sample_mitre_technique():
    """Sample MITRE ATT&CK technique data."""
    return {
        "technique_id": "T1059.001",
        "technique": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "platforms": ["Windows"],
        "data_sources": ["Process: Process Creation", "Command: Command Execution"],
        "detection": "Monitor for processes named powershell.exe.",
    }


@pytest.fixture
def sample_threat_group():
    """Sample threat group data from MITRE ATT&CK."""
    return {
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes"],
        "description": "APT29 is a threat group attributed to Russia's Foreign Intelligence Service (SVR).",
        "techniques": [
            {"technique_id": "T1566.001", "technique": "Spearphishing Attachment"},
            {"technique_id": "T1059.001", "technique": "PowerShell"},
            {"technique_id": "T1003.001", "technique": "LSASS Memory"},
        ],
    }


@pytest.fixture
def sample_progress_data():
    """Sample progress tracking data."""
    return {
        "status": "processing",
        "stage": "yaml",
        "created_yaml": 5,
        "total_yaml": 10,
        "current_technique": "T1059.001",
        "techniques_processed": ["T1566.001", "T1059.001"],
    }


@pytest.fixture
def sample_yaml_detection():
    """Sample generated YAML detection content."""
    return {
        "title": "PowerShell Execution Detection",
        "id": "abc123",
        "status": "experimental",
        "description": "Detects PowerShell execution potentially used by threat actors",
        "references": ["https://attack.mitre.org/techniques/T1059/001/"],
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection": {
                "CommandLine|contains": ["powershell", "pwsh"],
            },
            "condition": "selection",
        },
        "tags": ["attack.execution", "attack.t1059.001"],
        "level": "medium",
    }


# ============================================================================
# Mock Object Fixtures
# ============================================================================

@pytest.fixture
def mock_requests_response():
    """Mock requests.Response object."""
    response = MagicMock()
    response.status_code = 200
    response.content = b"<html><body>Test content</body></html>"
    response.text = "<html><body>Test content</body></html>"
    response.headers = {"Content-Type": "text/html"}
    response.raise_for_status = MagicMock()
    return response


@pytest.fixture
def mock_mitre_bundle():
    """Mock MITRE ATT&CK STIX bundle."""
    bundle = MagicMock()
    bundle.get_groups.return_value = [
        {"name": "APT29", "external_id": "G0016"},
        {"name": "APT28", "external_id": "G0007"},
    ]
    bundle.get_techniques.return_value = [
        {"technique_id": "T1059.001", "technique": "PowerShell"},
        {"technique_id": "T1566.001", "technique": "Spearphishing Attachment"},
    ]
    return bundle


@pytest.fixture
def mock_file_intelligence_extractor():
    """Mock FileIntelligenceParser."""
    extractor = MagicMock()
    extractor.extract_iocs.return_value = {
        "domain": ["example.com"],
        "ip": ["192.168.1.1"],
        "hash": [],
    }
    return extractor


# ============================================================================
# Helper Fixtures
# ============================================================================

@pytest.fixture
def write_json_file(temp_dir):
    """Factory fixture to write JSON files for testing."""
    def _write(filename: str, data: dict) -> Path:
        filepath = temp_dir / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f)
        return filepath
    return _write


@pytest.fixture
def read_json_file():
    """Factory fixture to read JSON files."""
    def _read(filepath: Path) -> dict:
        with open(filepath) as f:
            return json.load(f)
    return _read


@pytest.fixture(autouse=True)
def _ioc_flows_in_tmp(tmp_path, monkeypatch):
    """write_ioc_sweeps saves an IOC flow; keep it out of the real data/ioc_flows."""
    from archer.build import ioc_flow

    monkeypatch.setattr(ioc_flow, "IOC_FLOWS_DIR", str(tmp_path / "ioc_flows"))

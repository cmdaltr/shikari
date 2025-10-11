"""
Shared pytest fixtures for all tests
"""

import pytest
import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


# Import Playwright fixtures from config
from playwright.sync_api import sync_playwright


@pytest.fixture(scope="session")
def playwright():
    """Provide Playwright instance"""
    with sync_playwright() as p:
        yield p


@pytest.fixture(scope="session")
def browser_type(playwright):
    """Provide browser type (Chromium by default)"""
    return playwright.chromium


@pytest.fixture(scope="session")
def browser(browser_type):
    """Launch browser for testing"""
    # Check if HEADLESS environment variable is set
    headless = os.getenv("HEADLESS", "true").lower() == "true"

    browser = browser_type.launch(
        headless=headless,
        slow_mo=int(os.getenv("SLOW_MO", "0")),
    )
    yield browser
    browser.close()


@pytest.fixture(scope="function")
def context(browser):
    """Create a new browser context for each test"""
    context = browser.new_context(
        viewport={"width": 1280, "height": 720},
        ignore_https_errors=True,
    )
    yield context
    context.close()


@pytest.fixture(scope="function")
def page(context):
    """Create a new page for each test"""
    page = context.new_page()

    # Set default timeout
    page.set_default_timeout(30000)  # 30 seconds

    yield page
    page.close()


@pytest.fixture(scope="session")
def base_url():
    """Base URL for the application"""
    return os.getenv("BASE_URL", "http://localhost:8000")


@pytest.fixture(scope="session")
def api_base_url():
    """API base URL"""
    return os.getenv("API_BASE_URL", "http://localhost:8000")


# Fixtures for API testing
@pytest.fixture
def test_client():
    """FastAPI test client"""
    from fastapi.testclient import TestClient
    from archer.app import app

    return TestClient(app)


# Sample data fixtures
@pytest.fixture
def sample_threat_group():
    """Sample threat group name for testing"""
    return "APT29"


@pytest.fixture
def sample_technique_id():
    """Sample MITRE ATT&CK technique ID"""
    return "T1059.001"


@pytest.fixture
def sample_techniques():
    """List of sample technique IDs"""
    return ["T1059.001", "T1003", "T1018"]


# Temporary file fixtures
@pytest.fixture
def temp_pdf_file(tmp_path):
    """Create a temporary PDF file for testing"""
    pdf_path = tmp_path / "test_report.pdf"
    # Minimal PDF structure
    content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT
/F1 12 Tf
100 700 Td
(Test PDF) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000214 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
308
%%EOF"""
    pdf_path.write_bytes(content)
    return str(pdf_path)


@pytest.fixture
def temp_text_file(tmp_path):
    """Create a temporary text file with threat intelligence"""
    txt_path = tmp_path / "threat_intel.txt"
    content = """Threat Intelligence Report

Threat Actor: APT29
Date: 2024-10-01

Techniques Observed:
- T1059.001: PowerShell execution
- T1003: Credential Dumping
- T1018: Remote System Discovery

Indicators of Compromise:
- IP Address: 192.168.1.100
- Domain: malicious-domain.com
- File Hash: d41d8cd98f00b204e9800998ecf8427e
- Command: powershell.exe -encodedcommand

Registry Keys Modified:
- HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- HKEY_CURRENT_USER\\Software\\Classes

Event IDs: 4688, 4624, 4625
"""
    txt_path.write_text(content)
    return str(txt_path)


@pytest.fixture
def temp_json_file(tmp_path):
    """Create a temporary JSON file with structured IOCs"""
    json_path = tmp_path / "iocs.json"
    content = """{
  "threat_actor": "APT29",
  "campaign": "Test Campaign",
  "ttps": ["T1059.001", "T1003", "T1018"],
  "iocs": {
    "ips": ["192.168.1.1", "10.0.0.1"],
    "domains": ["evil.com", "malicious.net"],
    "hashes": {
      "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
      "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    },
    "commands": [
      "powershell.exe -enc",
      "cmd.exe /c whoami"
    ]
  }
}"""
    json_path.write_text(content)
    return str(json_path)


# Markers for test categorization
def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line("markers", "ui: mark test as UI test using Playwright")
    config.addinivalue_line("markers", "api: mark test as API test")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "requires_atomic: mark test as requiring Atomic Red Team")
    config.addinivalue_line("markers", "requires_vectr: mark test as requiring VECTR")
    config.addinivalue_line("markers", "requires_openai: mark test as requiring OpenAI API")


# Pytest collection hooks for better test organization
def pytest_collection_modifyitems(config, items):
    """Automatically mark tests based on file location or name"""
    for item in items:
        # Mark UI tests
        if "test_ui_" in item.nodeid:
            item.add_marker(pytest.mark.ui)
            item.add_marker(pytest.mark.slow)

        # Mark API tests
        if "test_api_" in item.nodeid:
            item.add_marker(pytest.mark.api)

        # Mark tests requiring external services
        if "atomic" in item.nodeid.lower():
            item.add_marker(pytest.mark.requires_atomic)

        if "vectr" in item.nodeid.lower():
            item.add_marker(pytest.mark.requires_vectr)

        if "openai" in item.nodeid.lower():
            item.add_marker(pytest.mark.requires_openai)

"""
Pytest configuration for Shikari test suite

Test Categories:
- Functionality tests: Quick tests that verify endpoints respond correctly
- Feature tests: End-to-end tests that validate full generation pipelines
"""
import pytest
import os


def pytest_configure(config):
    """Configure pytest markers"""
    config.addinivalue_line(
        "markers", "feature: marks tests as feature tests (deselect with '-m \"not feature\"')"
    )


def pytest_collection_modifyitems(config, items):
    """Auto-skip feature tests unless --run-feature-tests is provided"""
    if config.getoption("--run-feature-tests", default=False):
        return

    skip_feature = pytest.mark.skip(reason="need --run-feature-tests option to run")
    for item in items:
        if "feature" in item.keywords:
            item.add_marker(skip_feature)


def pytest_addoption(parser):
    """Add custom command line options"""
    parser.addoption(
        "--run-feature-tests",
        action="store_true",
        default=False,
        help="run feature tests (generation tests)"
    )
    parser.addoption(
        "--shikari-url",
        action="store",
        default=os.getenv("SHIKARI_BASE_URL", "http://127.0.0.1:8000"),
        help="Shikari base URL for testing"
    )


@pytest.fixture(scope="session")
def shikari_url(request):
    """Get Shikari base URL from command line or environment"""
    return request.config.getoption("--shikari-url")

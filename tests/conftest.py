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
        default=os.getenv("SHIKARI_BASE_URL", "http://127.0.0.1:32453"),
        help="Shikari base URL for testing"
    )


@pytest.fixture(scope="session")
def shikari_url(request):
    """Get Shikari base URL from command line or environment"""
    return request.config.getoption("--shikari-url")


@pytest.fixture(autouse=True)
def _login_gate_passed(request, monkeypatch):
    """Route tests mock require_auth and test the route; the sign-in gate in front of every route
    (shikari.app.api_token_auth) is passed for them. Tests marked login_gate get the real one."""
    import sys

    if request.node.get_closest_marker("login_gate"):
        return
    app_module = sys.modules.get("shikari.app")
    if app_module is None and _uses_app(getattr(request.module, "__file__", "")):
        import shikari.app as app_module  # a test that imports it inside the test still gets the patch
    if app_module is not None:
        monkeypatch.setattr(app_module, "_signed_in", lambda session_id: True)


_APP_USERS = {}


def _uses_app(path):
    if path not in _APP_USERS:
        try:
            text = open(path, encoding="utf-8").read()
        except OSError:
            text = ""
        _APP_USERS[path] = "shikari.app" in text or "from shikari import app" in text
    return _APP_USERS[path]

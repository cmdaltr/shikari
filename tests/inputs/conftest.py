"""
Shared fixtures for input method tests.
"""
import pytest
import requests
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any


# Configuration
DEFAULT_BASE_URL = os.getenv("SHIKARI_BASE_URL", "http://127.0.0.1:32453")
DEFAULT_TIMEOUT = 30
GENERATION_TIMEOUT = 300  # 5 minutes for generation tests


@pytest.fixture(scope="session")
def base_url(request):
    """Get Shikari base URL from command line or environment."""
    return request.config.getoption("--shikari-url", default=DEFAULT_BASE_URL)


@pytest.fixture(scope="session")
def session():
    """Create a requests session for all tests."""
    sess = requests.Session()
    yield sess
    sess.close()


@pytest.fixture(scope="session")
def authenticated_session(session, base_url):
    """
    Create an authenticated session.
    Attempts to login with test credentials.
    """
    # Try to authenticate
    try:
        response = session.post(
            f"{base_url}/login",
            data={
                "email": "admin@shikari.app",
                "password": "BigGameHunter"
            },
            allow_redirects=False
        )
        # Session cookies are automatically stored in the session
    except Exception:
        pass  # Continue without auth for tests that don't require it

    return session


class ShikariClient:
    """Helper client for making Shikari API calls."""

    def __init__(self, base_url: str, session: requests.Session):
        self.base_url = base_url
        self.session = session
        self.timeout = DEFAULT_TIMEOUT

    def get(self, endpoint: str, **kwargs) -> requests.Response:
        """Make a GET request."""
        kwargs.setdefault("timeout", self.timeout)
        return self.session.get(f"{self.base_url}{endpoint}", **kwargs)

    def post(self, endpoint: str, **kwargs) -> requests.Response:
        """Make a POST request."""
        kwargs.setdefault("timeout", self.timeout)
        return self.session.post(f"{self.base_url}{endpoint}", **kwargs)

    def wait_for_progress(
        self,
        group_name: str,
        timeout: int = GENERATION_TIMEOUT,
        poll_interval: int = 5
    ) -> Dict[str, Any]:
        """
        Poll progress endpoint until completion or timeout.

        Returns:
            Progress data dict with status, or error information
        """
        waited = 0
        last_progress = None

        while waited < timeout:
            time.sleep(poll_interval)
            waited += poll_interval

            try:
                response = self.get(
                    "/progress_status",
                    params={"group_name": group_name}
                )

                if response.status_code == 200:
                    data = response.json()
                    progress = data.get("progress", data)
                    last_progress = progress
                    status = progress.get("status", "")

                    if status == "complete":
                        return {"success": True, "progress": progress}
                    elif status == "error":
                        return {
                            "success": False,
                            "error": progress.get("error", "Unknown error"),
                            "progress": progress
                        }
            except Exception as e:
                pass  # Continue polling

        # Timeout
        return {
            "success": False,
            "error": f"Timeout after {timeout}s",
            "progress": last_progress
        }

    def check_health(self) -> bool:
        """Check if Shikari is healthy."""
        try:
            response = self.get("/health", timeout=10)
            return response.status_code == 200
        except Exception:
            return False


@pytest.fixture(scope="session")
def client(base_url, authenticated_session):
    """Create an Shikari client instance."""
    return ShikariClient(base_url, authenticated_session)


@pytest.fixture(scope="session")
def test_data_dir():
    """Get the test data directory path."""
    return Path(__file__).parent / "test_data"


@pytest.fixture(scope="session")
def ensure_shikari_running(client):
    """Ensure Shikari is running before tests."""
    if not client.check_health():
        pytest.skip("Shikari is not running. Start it with: shikari start")
    return True

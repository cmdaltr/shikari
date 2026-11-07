"""
Shared fixtures for API tests.

These tests hit a running Shikari instance and validate every API endpoint.
"""
import pytest
import requests
import os

BASE_URL = os.getenv("SHIKARI_BASE_URL", "http://127.0.0.1:32453")


@pytest.fixture(scope="session")
def base_url(request):
    return request.config.getoption("--shikari-url", default=BASE_URL)


@pytest.fixture(scope="session")
def session():
    sess = requests.Session()
    yield sess
    sess.close()


@pytest.fixture(scope="session")
def auth_session(session, base_url):
    """Authenticate and return session with cookies."""
    try:
        session.post(
            f"{base_url}/login",
            data={
                "email": os.getenv("SHIKARI_TEST_EMAIL", "admin@shikari.app"),
                "password": os.getenv("SHIKARI_TEST_PASSWORD", "BigGameHunter"),
            },
            allow_redirects=False,
        )
    except Exception:
        pass
    return session


@pytest.fixture(scope="session")
def api(base_url, auth_session):
    """Simple API helper."""
    class API:
        def __init__(self):
            self.url = base_url
            self.s = auth_session

        def get(self, path, **kw):
            kw.setdefault("timeout", 30)
            return self.s.get(f"{self.url}{path}", **kw)

        def post(self, path, **kw):
            kw.setdefault("timeout", 30)
            return self.s.post(f"{self.url}{path}", **kw)

        def put(self, path, **kw):
            kw.setdefault("timeout", 30)
            return self.s.put(f"{self.url}{path}", **kw)

        def delete(self, path, **kw):
            kw.setdefault("timeout", 30)
            return self.s.delete(f"{self.url}{path}", **kw)

    return API()


@pytest.fixture(scope="session")
def ensure_running(api):
    """Skip all tests if Shikari is not reachable."""
    try:
        r = api.get("/health", timeout=10)
        if r.status_code != 200:
            pytest.skip("Shikari not healthy")
    except Exception:
        pytest.skip("Shikari not running")

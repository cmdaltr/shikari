"""
Shared fixtures for API tests.

These tests hit a running Shikari instance and validate every API endpoint.
"""
import pytest
import requests
import os
from urllib.parse import parse_qs, quote, urlparse

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
    from tests.live_auth import sign_in

    try:
        sign_in(session, base_url)
    except requests.RequestException:
        pass
    return session


@pytest.fixture(scope="session")
def api(base_url, auth_session):
    """Simple API helper."""
    class API:
        def __init__(self):
            self.url = base_url
            self.s = auth_session
            self.started = []

        def get(self, path, **kw):
            kw.setdefault("timeout", 30)
            return self.s.get(f"{self.url}{path}", **kw)

        def post(self, path, **kw):
            kw.setdefault("timeout", 30)
            r = self.s.post(f"{self.url}{path}", **kw)
            self._note_run(r)
            return r

        def _note_run(self, r):
            """A request that started a run answers with its progress page (JSON or a redirect)."""
            target = r.headers.get("location", "")
            if "json" in r.headers.get("content-type", ""):
                try:
                    target = (r.json() or {}).get("redirect_url") or target
                except (ValueError, AttributeError):
                    pass
            if target.startswith("/progress?"):
                group = parse_qs(urlparse(target).query).get("group_name", [""])[0]
                if group:
                    self.started.append(group)

        def cancel_started(self):
            """Stop the runs this test started, so the next test doesn't queue behind them."""
            while self.started:
                group = self.started.pop()
                try:
                    self.s.post(f"{self.url}/api/progress/{quote(group, safe='')}/cancel", timeout=30)
                except requests.RequestException:
                    pass

        def put(self, path, **kw):
            kw.setdefault("timeout", 30)
            return self.s.put(f"{self.url}{path}", **kw)

        def delete(self, path, **kw):
            kw.setdefault("timeout", 30)
            return self.s.delete(f"{self.url}{path}", **kw)

    return API()


@pytest.fixture(autouse=True)
def stop_started_runs(request):
    """Each accepted generation request starts a real run; stop them when the test ends. Left going,
    they piled up and slowed every later request past its timeout."""
    yield
    if "api" in request.fixturenames:
        request.getfixturevalue("api").cancel_started()


@pytest.fixture(scope="session")
def ensure_running(api):
    """Skip all tests if Shikari is not reachable."""
    try:
        r = api.get("/health", timeout=10)
        if r.status_code != 200:
            pytest.skip("Shikari not healthy")
    except Exception:
        pytest.skip("Shikari not running")

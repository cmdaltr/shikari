"""
Sign a requests.Session in to a running Shikari, for the suites that test a live server.

SHIKARI_TOKEN (an API token from Profile → Security → API Tokens) is used when set; otherwise
the login form, with SHIKARI_TEST_EMAIL / SHIKARI_TEST_PASSWORD (default: the documented
default administrator). Every page and API but /health and the sign-in pages needs one or the
other. The login form needs its CSRF token, read from the page first.
"""
import os
import re

import requests


def sign_in(session: requests.Session, base_url: str) -> bool:
    """Return True when the session is signed in."""
    token = os.getenv("SHIKARI_TOKEN")
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    else:
        page = session.get(f"{base_url}/login", timeout=30)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        session.post(
            f"{base_url}/login",
            data={
                "email": os.getenv("SHIKARI_TEST_EMAIL", "admin"),
                "password": os.getenv("SHIKARI_TEST_PASSWORD", "BigGameHunter"),
                "csrf_token": csrf.group(1) if csrf else "",
            },
            allow_redirects=False,
            timeout=30,
        )
    return session.get(f"{base_url}/library", allow_redirects=False, timeout=30).status_code == 200

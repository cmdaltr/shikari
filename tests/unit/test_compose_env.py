"""Docker passes the container only the variables docker-compose.yml lists, so every email setting
shikari/auth/email.py reads must be listed there, or Forgot password can't be switched on in Docker."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_compose_passes_every_email_setting():
    read = set(re.findall(r'os\.getenv\("([A-Z_]+)"', (ROOT / "shikari/auth/email.py").read_text()))
    compose = (ROOT / "docker-compose.yml").read_text()
    passed = set(re.findall(r"^\s+- ([A-Z_]+)=", compose, flags=re.M))
    assert {"EMAIL_ENABLED", "SMTP_HOST", "BASE_URL"} <= read
    assert read <= passed, f"not passed to the container: {sorted(read - passed)}"

"""
Is there a newer Shikari, and installing it: the shared half of `shikari update` (shikari/service.py,
a source checkout), the installed app's `shikari update` and its update notice (shikari/desktop_app.py).

Standard library (and truststore, when it's there), so it works when the rest of the app is broken,
which is when an update matters.

A release is GitHub's latest release of SHIKARI_REPO (cmdaltr/shikari). The repository is private, so
reading it needs a token: GH_TOKEN, GITHUB_TOKEN or a logged-in gh, as the install scripts do. The
app checks at most once a day, sends nothing but the request, and never when SHIKARI_UPDATE_CHECK=0
or update.json in its home says {"check": false}. An installed app updates by running the install
script for its platform (desktop/install.sh, install.ps1), which downloads the release's installer,
checks it against SHA256SUMS and installs it.
"""

import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
DAY = 24 * 60 * 60
# gh, for its token, where a GUI app's short PATH (launched from the Dock) won't find it
GH_PLACES = ["/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"]


class UpdateError(Exception):
    """Why there's no answer: offline, no access to the repository, no release."""


def repo():
    return os.environ.get("SHIKARI_REPO") or "cmdaltr/shikari"


def token():
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(name):
            return os.environ[name]
    gh = shutil.which("gh") or next((p for p in GH_PLACES if os.path.exists(p)), None)
    if gh:
        try:
            out = subprocess.run([gh, "auth", "token"], capture_output=True, text=True, timeout=10)
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def parse_version(text):
    """'v2.1.0' or '2.1.0' as (2, 1, 0); anything after the numbers (a -rc1) is ignored."""
    m = re.match(r"v?(\d+(?:\.\d+)*)", (text or "").strip())
    return tuple(int(p) for p in m.group(1).split(".")) if m else ()


def is_newer(latest, current):
    a, b = parse_version(latest), parse_version(current)
    # Pad so 2.1 == 2.1.0
    width = max(len(a), len(b))
    return bool(a) and a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))


def _context():
    # The OS certificate store, as shikari.desktop_client does: the installed app's own Python has
    # no CA bundle of its own (its check of GitHub timed out on macOS without this)
    try:
        import truststore
        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except ImportError:
        return ssl.create_default_context()


def latest_release(timeout=10):
    """{'tag', 'version', 'url', 'notes'} for the latest release, or UpdateError."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "shikari-update"}
    tok = token()
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    try:
        with urlopen(Request(f"https://api.github.com/repos/{repo()}/releases/latest", headers=headers),
                     timeout=timeout, context=_context()) as r:
            data = json.load(r)
    except HTTPError as e:
        if e.code == 404:
            # A private repository answers 404, not 401, to a request it won't serve
            raise UpdateError(f"no release of {repo()} is visible" + (
                "" if tok else ": the repository is private, so set GH_TOKEN or log in with gh auth login"))
        raise UpdateError(f"GitHub answered {e.code}")
    except (URLError, OSError, ValueError) as e:
        raise UpdateError(f"couldn't reach GitHub ({getattr(e, 'reason', e)})")
    tag = data.get("tag_name") or ""
    return {"tag": tag, "version": tag.lstrip("v"), "url": data.get("html_url", ""),
            "notes": (data.get("body") or "").strip()}


# --- the installed app's daily check -------------------------------------------------------------

def _state_path(home):
    return Path(home) / "update.json"


def _read_state(home):
    try:
        return json.loads(_state_path(home).read_text())
    except (OSError, ValueError):
        return {}


def _write_state(home, state):
    try:
        _state_path(home).write_text(json.dumps(state, indent=2))
    except OSError:
        pass


def checks_enabled(home):
    if os.environ.get("SHIKARI_UPDATE_CHECK", "").strip().lower() in ("0", "false", "no", "off"):
        return False
    return _read_state(home).get("check", True) is not False


def set_checks(home, enabled):
    state = _read_state(home)
    state["check"] = bool(enabled)
    _write_state(home, state)


def daily_check(home, current, now=None):
    """The newer release if there is one, else None. Asks GitHub at most once a day; a failed or
    switched-off check is just None (the notice is a courtesy, not something to report)."""
    if not checks_enabled(home):
        return None
    now = time.time() if now is None else now
    state = _read_state(home)
    if "checked_at" not in state or now - state["checked_at"] >= DAY:
        try:
            state["latest"] = latest_release()
        except UpdateError:
            state.pop("latest", None)
        state["checked_at"] = now
        _write_state(home, state)
    latest = state.get("latest")
    if latest and is_newer(latest.get("version"), current) and latest.get("version") != state.get("skipped"):
        return latest
    return None


def skip(home, version):
    """Don't show the notice again for this version (a later one still shows)."""
    state = _read_state(home)
    state["skipped"] = version
    _write_state(home, state)


# --- installing it -------------------------------------------------------------------------------

def install_script(seed=None):
    """The install script for this platform: the copy the app carries in seed/, else the checkout's."""
    name = "install.ps1" if sys.platform == "win32" else "install.sh"
    for base in filter(None, [seed, ROOT / "seed", ROOT / "desktop"]):
        path = Path(base) / name
        if path.exists():
            return path
    return None


def installer_command(script, tag, wait_pid=None, log=None, launch=True):
    """The command that waits for the app (wait_pid) to quit, then installs `tag` (and reopens it)."""
    if sys.platform == "win32":
        wait = f"Wait-Process -Id {int(wait_pid)} -ErrorAction SilentlyContinue; " if wait_pid else ""
        tail = f" *> '{log}'" if log else ""
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                f"{wait}& '{script}' -Version '{tag}'{' -Launch' if launch else ''}{tail}"]
    wait = f"while kill -0 {int(wait_pid)} 2>/dev/null; do sleep 1; done; " if wait_pid else ""
    tail = f" > '{log}' 2>&1" if log else ""
    return ["/bin/sh", "-c", f"{wait}sh '{script}' --version '{tag}'{' --launch' if launch else ''}{tail}"]


def start_installer(script, tag, wait_pid, log):
    """Start the install in the background, detached, so it outlives the app that started it."""
    cmd = installer_command(script, tag, wait_pid, log)
    env = dict(os.environ)
    tok = token()
    if tok:
        env["GH_TOKEN"] = tok
    if sys.platform == "win32":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        subprocess.Popen(cmd, env=env, creationflags=flags, close_fds=True)
    else:
        subprocess.Popen(cmd, env=env, start_new_session=True, close_fds=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_installer(script, tag):
    """Install `tag` in the foreground, for `shikari update` in a terminal (sudo can ask there)."""
    env = dict(os.environ)
    tok = token()
    if tok:
        env["GH_TOKEN"] = tok
    return subprocess.call(installer_command(script, tag, launch=False), env=env)

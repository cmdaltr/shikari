"""
Admin configuration for the detections-as-code git repository (#20).

Where exports commit (a local path), an optional git remote to push to, and whether to push after a
commit — set by an admin under Profile → Config, stored as JSON in DATA_DIR (gitignored). The default
is the built-in ``DETECTIONS_REPO_DIR``. Credentials are never stored here: a remote push uses the
host's own git auth (SSH key, credential helper, or a token in the URL the admin provides).
"""

import json
import os
import subprocess
from typing import Dict

from archer.config import DATA_DIR, DETECTIONS_REPO_DIR

_PATH = os.path.join(DATA_DIR, "detections_code.json")
_DEFAULT = {"repo_path": DETECTIONS_REPO_DIR, "remote_url": "", "push_enabled": False}


def load() -> Dict:
    data = dict(_DEFAULT)
    try:
        with open(_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            data.update({k: saved[k] for k in _DEFAULT if k in saved})
    except (OSError, ValueError):
        pass
    if not (data.get("repo_path") or "").strip():
        data["repo_path"] = DETECTIONS_REPO_DIR
    return data


def save(repo_path: str, remote_url: str = "", push_enabled: bool = False) -> Dict:
    data = {"repo_path": (repo_path or "").strip() or DETECTIONS_REPO_DIR,
            "remote_url": (remote_url or "").strip(), "push_enabled": bool(push_enabled)}
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return data


def repo_path() -> str:
    return load()["repo_path"]


def is_configured() -> bool:
    """True once an admin has saved config; false while it's still the built-in default."""
    return os.path.isfile(_PATH)


def test_connectivity(repo_path: str, remote_url: str = "") -> Dict:
    """Check the local path is usable and, if a remote is given, that git can reach it (read-only)."""
    out = {"repo_ok": False, "repo_message": "", "remote_ok": None, "remote_message": ""}

    path = (repo_path or "").strip() or DETECTIONS_REPO_DIR
    try:
        if os.path.isdir(path):
            out["repo_ok"] = os.access(path, os.W_OK)
            out["repo_message"] = f"{path} exists and is writable" if out["repo_ok"] else f"{path} is not writable"
        else:
            parent = os.path.dirname(os.path.abspath(path)) or "."
            out["repo_ok"] = os.path.isdir(parent) and os.access(parent, os.W_OK)
            out["repo_message"] = (f"{path} will be created on first export" if out["repo_ok"]
                                   else f"cannot create {path}: parent not writable")
    except OSError as e:
        out["repo_message"] = f"path error: {e}"

    url = (remote_url or "").strip()
    if url:
        try:
            r = subprocess.run(["git", "ls-remote", url, "HEAD"], capture_output=True, text=True,
                               timeout=20, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
            out["remote_ok"] = r.returncode == 0
            out["remote_message"] = ("reachable" if r.returncode == 0
                                     else (r.stderr.strip().splitlines() or ["unreachable"])[-1][:200])
        except subprocess.TimeoutExpired:
            out["remote_ok"] = False
            out["remote_message"] = "timed out (no response in 20s)"
        except OSError as e:
            out["remote_ok"] = False
            out["remote_message"] = f"git error: {e}"
    return out


def push(repo: str, remote_url: str, branch: str = "main") -> Dict:
    """Push the repo to the configured remote using the host's own git auth. Read nothing, store nothing."""
    import subprocess as sp

    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        # Point 'origin' at the configured URL (idempotent), then push.
        sp.run(["git", "-C", repo, "remote", "remove", "origin"], capture_output=True, text=True)
        sp.run(["git", "-C", repo, "remote", "add", "origin", remote_url], capture_output=True, text=True, check=True)
        r = sp.run(["git", "-C", repo, "push", "origin", f"HEAD:{branch}"], capture_output=True, text=True,
                   timeout=60, env=env)
        if r.returncode == 0:
            return {"success": True, "message": f"pushed to {branch}"}
        return {"success": False, "message": (r.stderr.strip().splitlines() or ["push failed"])[-1][:200]}
    except (OSError, sp.SubprocessError) as e:
        return {"success": False, "message": f"push error: {e}"}

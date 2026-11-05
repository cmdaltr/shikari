"""
What Shikari knows about the machines it made: the template each came from, so the page can
show its OS and what it records, and provisioning knows which script to run. Docker and Tart
don't record that, so Shikari keeps it. One small JSON file; machines made outside Shikari are
still listed, just without a template.
"""

import json
import os
import threading
from typing import Dict, Optional

from shikari.config import DATA_DIR

LAB_DIR = os.path.join(DATA_DIR, "lab")
_PATH = os.path.join(LAB_DIR, "machines.json")
_lock = threading.Lock()


def _key(engine: str, name: str) -> str:
    return f"{engine}/{name}"


def _load() -> Dict:
    try:
        with open(_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: Dict):
    os.makedirs(LAB_DIR, exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, _PATH)


def record(engine: str, name: str, template_id: str, os_name: str, image: str, owner=None):
    """Remember a machine Shikari made or adopted. `owner` is the user id that may manage it
    (an admin may manage any); it's kept across re-records unless a new one is given."""
    with _lock:
        data = _load()
        existing = data.get(_key(engine, name), {})
        data[_key(engine, name)] = {"template": template_id, "os": os_name, "image": image,
                                    "provisioned": existing.get("provisioned", []), "shikari": True,
                                    "owner": owner if owner is not None else existing.get("owner")}
        _save(data)


def get(engine: str, name: str) -> Optional[Dict]:
    return _load().get(_key(engine, name))


def mark_provisioned(engine: str, name: str, step: str):
    with _lock:
        data = _load()
        entry = data.get(_key(engine, name))
        if entry is not None:
            steps = entry.setdefault("provisioned", [])
            if step not in steps:
                steps.append(step)
            _save(data)


def forget(engine: str, name: str):
    with _lock:
        data = _load()
        if data.pop(_key(engine, name), None) is not None:
            _save(data)


def set_desktop(engine: str, name: str, host: str, port: int, kind: str = "vnc"):
    """Record the trusted graphical-console endpoint for a machine (#28): host, port and kind
    ('vnc' or 'spice'). Upserts onto the machine's entry, creating a minimal one if Shikari didn't
    make the machine. The WebSocket bridge reads this and never a client-supplied address — see
    shikari.lab.desktop."""
    with _lock:
        data = _load()
        entry = data.get(_key(engine, name))
        if entry is None:
            entry = {"template": None, "os": "", "image": "", "provisioned": [], "shikari": False,
                     "owner": None}
        entry["desktop"] = {"host": host, "port": int(port), "kind": kind}
        data[_key(engine, name)] = entry
        _save(data)


def get_desktop(engine: str, name: str):
    """The stored (host, port, kind) for a machine's graphical console, or None if not configured."""
    entry = _load().get(_key(engine, name)) or {}
    desktop = entry.get("desktop") or {}
    if desktop.get("host") and desktop.get("port"):
        return desktop["host"], int(desktop["port"]), desktop.get("kind") or "vnc"
    return None


def clear_desktop(engine: str, name: str):
    with _lock:
        data = _load()
        entry = data.get(_key(engine, name))
        if entry is not None and entry.pop("desktop", None) is not None:
            _save(data)

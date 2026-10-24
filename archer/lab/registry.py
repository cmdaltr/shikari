"""
What Archer knows about the machines it made: the template each came from, so the page can
show its OS and what it records, and provisioning knows which script to run. Docker and Tart
don't record that, so Archer keeps it. One small JSON file; machines made outside Archer are
still listed, just without a template.
"""

import json
import os
import threading
from typing import Dict, Optional

from archer.config import DATA_DIR

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


def record(engine: str, name: str, template_id: str, os_name: str, image: str):
    with _lock:
        data = _load()
        data[_key(engine, name)] = {"template": template_id, "os": os_name, "image": image,
                                    "provisioned": [], "archer": True}
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

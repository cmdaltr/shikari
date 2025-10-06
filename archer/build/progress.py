import os
import json
from typing import Dict, Any


PROGRESS_DIR = os.path.join("data", "progress")


def ensure_progress_dir():
    os.makedirs(PROGRESS_DIR, exist_ok=True)


def progress_path(group_name: str) -> str:
    ensure_progress_dir()
    safe = group_name.replace("/", "_")
    return os.path.join(PROGRESS_DIR, f"{safe}.json")


def write_progress(group_name: str, data: Dict[str, Any]):
    path = progress_path(group_name)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        pass


def read_progress(group_name: str) -> Dict[str, Any]:
    path = progress_path(group_name)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}

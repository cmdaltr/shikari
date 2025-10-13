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
    """
    Write progress data, merging with existing data to preserve all fields.
    This prevents race conditions where different parts of the code
    update different fields and overwrite each other.
    """
    path = progress_path(group_name)
    try:
        # Read existing data first
        existing = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    existing = json.load(fh)
            except Exception:
                existing = {}

        # Merge new data into existing (new data takes precedence)
        merged = {**existing, **data}

        # Write merged data
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(merged, fh, indent=2)
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

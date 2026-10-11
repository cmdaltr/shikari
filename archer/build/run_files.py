"""
Which detection YAMLs each group's latest run produced.

Technique YAMLs are shared between groups and accumulate across runs, so the results
page can't tell this run's detections from earlier ones by looking at the files: a
re-run often leaves a file untouched because it already carries the group's tag. The
YAML writer reports every file it writes or re-tags here, and the list is saved when
the run completes (data/runs/<group>.json).
"""

import json
import os
import threading
import time
from typing import Dict, List, Optional, Set

from archer.config import DATA_DIR

RUNS_DIR = os.path.join(DATA_DIR, "runs")

_lock = threading.Lock()
_active: Dict[str, Set[str]] = {}


def _manifest_path(group: str) -> str:
    return os.path.join(RUNS_DIR, group.replace("/", "_") + ".json")


def begin(group: str) -> None:
    with _lock:
        _active[group] = set()


def note(path: str, group: Optional[str]) -> None:
    """Called by the YAML writer for each file it writes or tags for a group."""
    if not group:
        return
    with _lock:
        files = _active.get(group)
        if files is not None:
            files.add(os.path.basename(path))


def finish(group: str, started_at: Optional[float] = None) -> None:
    """Save the run's files; a group with no run in progress keeps its last manifest."""
    with _lock:
        files = _active.pop(group, None)
    if files is None:
        return
    os.makedirs(RUNS_DIR, exist_ok=True)
    tmp = _manifest_path(group) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"group": group, "started_at": started_at, "completed_at": time.time(),
                   "files": sorted(files)}, fh, indent=2)
    os.replace(tmp, _manifest_path(group))


def latest_run(group: str) -> Optional[dict]:
    try:
        with open(_manifest_path(group), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None

"""
Which detection YAMLs each group's latest run produced.

Technique YAMLs are shared between groups and accumulate across runs, so the results
page can't tell this run's detections from earlier ones by looking at the files: a
re-run often leaves a file untouched because it already carries the group's tag. The
YAML writer reports every file it writes or re-tags here, and the list is saved when
the run completes (data/runs/<group>.json).

A run can also ask for every detection to be rewritten (Regenerate on the results page),
and the writer reports here any file it kept because someone edited its query by hand.
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
_touches: Dict[str, int] = {}
_missed: Dict[str, Dict[str, dict]] = {}
_hit: Dict[str, Set[str]] = {}
_regenerate: Set[str] = set()
_kept: Dict[str, Set[str]] = {}
_warnings: Dict[str, List[str]] = {}


def _manifest_path(group: str) -> str:
    return os.path.join(RUNS_DIR, group.replace("/", "_") + ".json")


def begin(group: str, regenerate: bool = False) -> None:
    with _lock:
        _active[group] = set()
        _touches[group] = 0
        _missed[group] = {}
        _hit[group] = set()
        _kept[group] = set()
        _warnings[group] = []
        if regenerate:
            _regenerate.add(group)
        else:
            _regenerate.discard(group)


def regenerating(group: Optional[str]) -> bool:
    """True while the group's run rewrites every detection, hand-edited ones included."""
    with _lock:
        return bool(group) and group in _regenerate and group in _active


def kept(path: str, group: Optional[str]) -> None:
    """A detection left as it was because its query was edited by hand."""
    if not group:
        return
    with _lock:
        if group in _kept:
            _kept[group].add(os.path.basename(path))


def warn(group: Optional[str], text: str) -> None:
    """Something the results page should say about the run (an explicit input outside the technology stack)."""
    with _lock:
        if group in _warnings and text not in _warnings[group]:
            _warnings[group].append(text)


def note(path: str, group: Optional[str]) -> None:
    """Called by the YAML writer for each file it writes or tags for a group."""
    if not group:
        return
    with _lock:
        files = _active.get(group)
        if files is not None:
            files.add(os.path.basename(path))
            _touches[group] += 1


def seen(path: str, group: Optional[str]) -> bool:
    """Whether this run has already written or tagged the file for the group."""
    if not group:
        return False
    with _lock:
        return os.path.basename(path) in _active.get(group, ())


def produced(group: str) -> Optional[Set[str]]:
    """The file names written or tagged so far in the group's run; None when no run is tracked."""
    with _lock:
        files = _active.get(group)
        return set(files) if files is not None else None


def touches(group: str) -> Optional[int]:
    """Files written or tagged so far in the group's run; None when no run is tracked."""
    with _lock:
        return _touches.get(group) if group in _active else None


def outcome(group: str, technique: str, name: str, produced: bool, reason: Optional[str]) -> None:
    """A technique's result in the run; one produced by any of its procedures counts as produced."""
    with _lock:
        if group not in _active or not technique:
            return
        if produced:
            _hit[group].add(technique)
            _missed[group].pop(technique, None)
        elif technique not in _hit[group]:
            _missed[group][technique] = {"technique": technique, "name": name or technique,
                                         "reason": reason or "no_source"}


def finish(group: str, started_at: Optional[float] = None) -> None:
    """Save the run's files; a group with no run in progress keeps its last manifest."""
    with _lock:
        files = _active.pop(group, None)
        _touches.pop(group, None)
        missed = list(_missed.pop(group, {}).values())
        _hit.pop(group, None)
        kept_files = sorted(_kept.pop(group, set()))
        warnings = _warnings.pop(group, [])
        _regenerate.discard(group)
    if files is None:
        return
    os.makedirs(RUNS_DIR, exist_ok=True)
    tmp = _manifest_path(group) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"group": group, "started_at": started_at, "completed_at": time.time(),
                   "files": sorted(files),
                   "no_detection": sorted(missed, key=lambda m: m["technique"]),
                   "kept_edited": kept_files, "stack_warnings": warnings}, fh, indent=2)
    os.replace(tmp, _manifest_path(group))


def latest_run(group: str) -> Optional[dict]:
    try:
        with open(_manifest_path(group), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None

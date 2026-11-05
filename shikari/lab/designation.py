"""Is this machine sanctioned for detonating novel/untrusted code? (#27)

Custom-execution recording runs operator-supplied commands — a novel procedure, a custom variant, a
behaviour that exists in no public corpus. That is, by definition, code we haven't vetted, and it must
never run on a host that matters. So a machine has to *opt in* before any custom-execution path will
touch it: set ``SHIKARI_LAB_HOST`` truthy in the environment, or drop a marker file. Absence means "not a
lab host" — the recording wrapper and any in-app execution path check this first and refuse otherwise.

This is opt-in, not a safety guarantee: it stops an accidental run on a workstation, not a determined one.
The real isolation is a disposable VM / microVM (sbx); this marks which machine that is.
"""
from __future__ import annotations

import os

from shikari import paths
from shikari.lab.runner import LabError

_TRUE = {"1", "true", "yes", "on"}

# A file whose mere presence designates this machine. Two locations: Shikari's own data dir (for the
# in-app path) and the operator's home (handy on a bare detonation VM that has no checkout).
MARKER = str(paths.DATA / "lab" / "LAB_HOST")
HOME_MARKER = os.path.expanduser("~/.shikari-lab-host")


def is_designated_lab_host() -> bool:
    """True iff this machine has opted in to detonating custom/novel code."""
    if os.environ.get("SHIKARI_LAB_HOST", "").strip().lower() in _TRUE:
        return True
    return os.path.exists(MARKER) or os.path.exists(HOME_MARKER)


def require_lab_host(action: str = "run custom or novel code") -> None:
    """Raise LabError unless this machine is a designated lab host. Call before any path that executes
    operator-supplied behaviour (#27)."""
    if not is_designated_lab_host():
        raise LabError(
            "This machine isn't a designated lab host",
            f"Refusing to {action} here. Designate a disposable machine by setting SHIKARI_LAB_HOST=1 "
            f"or creating {HOME_MARKER}. Never designate a host that matters — use a snapshot-and-revert "
            "VM or sbx microVM.")


def designate(home_marker: bool = True) -> str:
    """Mark this machine as a lab host by writing a marker file; returns the path written. For scripted
    set-up of a disposable VM. The env var is the lighter-touch alternative."""
    target = HOME_MARKER if home_marker else MARKER
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        fh.write("This machine is a Shikari lab host: it may detonate custom/novel code (#27).\n")
    return target

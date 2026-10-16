"""
Build → Emulate (templates/emulate.html): recorded attack telemetry per technique, per data
source, and a group's detections checked against it (archer.telemetry). Browsing needs no
account; checking a group's detections and rebuilding do.
"""

import json
import os
import threading
import time
from collections import deque
from typing import Dict, Optional

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import JSONResponse

from archer.auth import get_user_from_session_id
from archer.config import DATA_DIR, GENERATE_DIR
from archer.database.db import get_db
from archer.telemetry import check, datasets as ds

router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])
_job: Dict = {"state": "idle", "started": None, "finished": None, "error": None}
_log: deque = deque(maxlen=300)
_lock = threading.Lock()


def _user(archer_session: Optional[str]):
    if not archer_session:
        return None
    db = next(get_db())
    try:
        return get_user_from_session_id(archer_session, db)
    finally:
        db.close()


@router.get("/status")
def status():
    from archer.telemetry import guide

    s = ds.load()
    g = guide.load()
    return {"sources": s.get("sources", {}), "datasets": len(s["datasets"]), "techniques": len(ds.covered()),
            "guide": {**g["source"], "techniques": len(g["techniques"])} if g else None,
            "values": ds.values() is not None, "job": dict(_job), "log": list(_log)[-40:]}


@router.post("/build")
def start_build(archer_session: Optional[str] = Cookie(None)):
    """Fetch what changed in both sources and rebuild (admin; runs in the background)."""
    from archer.database.models import UserRole

    user = _user(archer_session)
    if not user or user.role != UserRole.ADMIN:
        return JSONResponse({"error": "Only an admin can rebuild the recorded telemetry"}, status_code=403)
    with _lock:
        if _job["state"] == "running":
            return {"started": False, "job": dict(_job)}
        _job.update(state="running", started=time.time(), finished=None, error=None)
        _log.clear()

    def run():
        from archer.telemetry.__main__ import build

        try:
            build(log=lambda m: _log.append({"t": time.time(), "msg": str(m)}))
            _job.update(state="done")
        except Exception as e:
            _job.update(state="failed", error=str(e))
            _log.append({"t": time.time(), "msg": f"Failed: {e}"})
        finally:
            _job["finished"] = time.time()
            check._haystack.clear()

    threading.Thread(target=run, daemon=True, name="telemetry-build").start()
    return {"started": True, "job": dict(_job)}


def _collections(collections: str) -> Optional[list]:
    """?collections=native,edr: the kinds of log that count (archer.telemetry.datasets.COLLECTIONS); all when absent."""
    picked = [c for c in (collections or "").split(",") if c in ds.COLLECTIONS]
    return picked or None


def _platforms(platforms: str) -> Optional[list]:
    """?platforms=linux,macos: only recordings from these platforms; all when absent."""
    picked = [p for p in (platforms or "").split(",") if p in ds.PLATFORMS]
    return picked or None


@router.get("/technique/{tid}")
def technique(tid: str, collections: str = "", platforms: str = ""):
    from archer.telemetry import guide

    return {**check.technique(tid, _collections(collections), _platforms(platforms)), "defender": guide.for_technique(tid)}


@router.get("/techniques")
def techniques(collections: str = "", platforms: str = ""):
    """Every recorded technique with its recordings per source, logs and data sources."""
    from archer.telemetry import guide

    rows = check.overview(_collections(collections), _platforms(platforms))
    for r in rows:
        g = guide.for_technique(r["technique"])
        r["defender"] = {k: g.get(k) for k in ("alerts", "orgs", "tp_rate", "family")} if g else None
    return {"techniques": rows, "guide": guide.load() is not None,
            "collections": ds.COLLECTIONS, "platforms": ds.PLATFORMS}


@router.get("/search")
def search(q: str):
    """Recorded techniques whose events hold a field value containing q."""
    found = check.search(q[:200])
    if found is None:
        return JSONResponse({"error": "The recordings' field values aren't on this machine"}, status_code=503)
    return {"techniques": found}


@router.get("/data-sources")
def data_sources(collections: str = "", platforms: str = ""):
    return check.by_data_source(_collections(collections), _platforms(platforms))


@router.get("/groups")
def groups(archer_session: Optional[str] = Cookie(None)):
    """Groups with a finished run, newest first (data/runs)."""
    if not _user(archer_session):
        return JSONResponse({"error": "Log in to check a group's detections"}, status_code=401)
    runs = os.path.join(DATA_DIR, "runs")
    out = []
    for name in os.listdir(runs) if os.path.isdir(runs) else []:
        if name.endswith(".json"):
            try:
                with open(os.path.join(runs, name), encoding="utf-8") as fh:
                    rec = json.load(fh)
                out.append({"group": rec.get("group") or name[:-5], "completed": rec.get("completed_at")})
            except (OSError, ValueError):
                continue
    return {"groups": sorted(out, key=lambda g: -(g["completed"] or 0))}


@router.get("/group-techniques")
def group_techniques(group: str, archer_session: Optional[str] = Cookie(None)):
    """The techniques a group's latest detections are for."""
    import re

    from archer.build.group_files import group_yaml_files

    if not _user(archer_session):
        return JSONResponse({"error": "Log in to filter by a group"}, status_code=401)
    found = set()
    for name in group_yaml_files(group, GENERATE_DIR):
        try:
            with open(os.path.join(GENERATE_DIR, os.path.basename(name)), encoding="utf-8") as fh:
                m = re.search(r"(?m)^technique_id:\s*['\"]?(T\d{4}(?:\.\d{3})?)", fh.read())
        except OSError:
            continue
        if m:
            found.add(m.group(1))
    return {"group": group, "techniques": sorted(found)}


@router.get("/check")
def check_group(group: str, archer_session: Optional[str] = Cookie(None)):
    if not _user(archer_session):
        return JSONResponse({"error": "Log in to check a group's detections"}, status_code=401)
    return check.group(group, GENERATE_DIR)

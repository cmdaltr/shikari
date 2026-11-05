"""
Build → Emulate (templates/emulate.html): recorded attack telemetry per technique, per data
source, and a group's detections checked against it (shikari.telemetry). Browsing needs no
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

from shikari.auth import get_user_from_session_id
from shikari.config import DATA_DIR, GENERATE_DIR
from shikari.database.db import get_db
from shikari.telemetry import check, datasets as ds

router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])
_job: Dict = {"state": "idle", "started": None, "finished": None, "error": None}
_log: deque = deque(maxlen=300)
_lock = threading.Lock()


def _user(shikari_session: Optional[str]):
    if not shikari_session:
        return None
    db = next(get_db())
    try:
        return get_user_from_session_id(shikari_session, db)
    finally:
        db.close()


@router.get("/status")
def status():
    from shikari.telemetry import guide

    s = ds.load()
    g = guide.load()
    return {"sources": s.get("sources", {}), "datasets": len(s["datasets"]), "techniques": len(ds.covered()),
            "guide": {**g["source"], "techniques": len(g["techniques"])} if g else None,
            "values": ds.values() is not None, "job": dict(_job), "log": list(_log)[-40:]}


@router.post("/build")
def start_build(shikari_session: Optional[str] = Cookie(None)):
    """Fetch what changed in both sources and rebuild (operational analyst or admin; backgrounded)."""
    from shikari.database.models import UserRole, at_least

    user = _user(shikari_session)
    if not at_least(user, UserRole.OPERATOR):
        return JSONResponse({"error": "Rebuilding the recorded telemetry needs the Operational analyst role"},
                            status_code=403)
    with _lock:
        if _job["state"] == "running":
            return {"started": False, "job": dict(_job)}
        _job.update(state="running", started=time.time(), finished=None, error=None)
        _log.clear()

    def run():
        from shikari.telemetry.__main__ import build

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
    """?collections=native,edr: the kinds of log that count (shikari.telemetry.datasets.COLLECTIONS); all when absent."""
    picked = [c for c in (collections or "").split(",") if c in ds.COLLECTIONS]
    return picked or None


def _platforms(platforms: str) -> Optional[list]:
    """?platforms=linux,macos: only recordings from these platforms; all when absent."""
    picked = [p for p in (platforms or "").split(",") if p in ds.PLATFORMS]
    return picked or None


@router.get("/technique/{tid}")
def technique(tid: str, collections: str = "", platforms: str = ""):
    from shikari.telemetry import guide

    return {**check.technique(tid, _collections(collections), _platforms(platforms)), "defender": guide.for_technique(tid)}


@router.get("/techniques")
def techniques(collections: str = "", platforms: str = ""):
    """Every recorded technique with its recordings per source, logs and data sources."""
    from shikari.telemetry import guide

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


@router.get("/custom")
def custom_recordings():
    """Your custom-execution recordings (#27), including novel/unmapped ones that the technique views
    can't show. Each carries its mapping (or novel), command, notes and event counts."""
    return {"recordings": ds.custom_recordings()}


@router.get("/custom/generate")
def custom_generate(id: str):
    """Generate detection queries grounded in a custom recording's own telemetry (#27) — no AI, no
    MITRESaw evidence. For a novel behaviour with no public procedure example."""
    from shikari.build import bespoke_queries

    rec = next((d for d in ds.custom_recordings() if d["id"] == id), None)
    if rec is None:
        return JSONResponse({"error": "No such custom recording"}, status_code=404)
    vals = ds.values()
    if vals is None:
        return JSONResponse({"error": "The recordings' field values aren't on this machine",
                             "detail": "Run a build here first (Update)."}, status_code=503)
    rec_values = vals.get(id)
    if not rec_values:
        return JSONResponse({"error": "This recording captured no searchable field values"}, status_code=422)
    technique = (rec.get("techniques") or [""])[0]
    queries = bespoke_queries.generate_from_telemetry(rec_values, technique, rec.get("title", ""), "")
    return {"id": id, "title": rec.get("title", ""), "technique": technique, "novel": rec.get("novel", False),
            "queries": queries}


@router.get("/groups")
def groups(shikari_session: Optional[str] = Cookie(None)):
    """Groups with a finished run, newest first (data/runs)."""
    if not _user(shikari_session):
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
def group_techniques(group: str, shikari_session: Optional[str] = Cookie(None)):
    """The techniques a group's latest detections are for."""
    import re

    from shikari.build.group_files import group_yaml_files

    if not _user(shikari_session):
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
def check_group(group: str, shikari_session: Optional[str] = Cookie(None)):
    if not _user(shikari_session):
        return JSONResponse({"error": "Log in to check a group's detections"}, status_code=401)
    return check.group(group, GENERATE_DIR)

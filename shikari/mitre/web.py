"""
The MITRESaw tab (templates/mitresaw.html): what the procedures CSV holds, a rebuild run
through Shikari's runner (shikari.mitre.procedures: one at a time, checked against ATT&CK)
with its log, a search of the procedures, and MITRESaw's indicator exclusions.
Browsing needs no account; anything that changes a file does.
"""

import csv
import json
import logging
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import FileResponse, JSONResponse

from shikari.auth import get_user_from_session_id
from shikari.database.db import get_db
from shikari.mitre import procedures

router = APIRouter(prefix="/api/mitresaw", tags=["mitresaw"])

_PAGE_SIZE = 25

# The job this Shikari started from the tab; a rebuild started elsewhere (startup, Splunk)
# shows as busy without a log
_job: Dict = {"state": "idle", "mode": None, "started": None, "finished": None, "error": None, "by": None}
_log: deque = deque(maxlen=400)
_job_lock = threading.Lock()


class _LogCapture(logging.Handler):
    def emit(self, record):
        _log.append({"t": record.created, "level": record.levelname, "msg": record.getMessage()})


def _user(shikari_session: Optional[str]):
    if not shikari_session:
        return None
    db = next(get_db())
    try:
        return get_user_from_session_id(shikari_session, db)
    finally:
        db.close()


def _denied():
    return JSONResponse({"error": "Log in to change MITRESaw's data"}, status_code=401)


# ---------------------------------------------------------------------------
# Procedures CSV, read once per change
# ---------------------------------------------------------------------------

_cache: Dict = {"mtime": None, "rows": []}


def _rows() -> List[dict]:
    path = procedures._DEFAULT_CSV
    if not path.exists():
        return []
    mtime = path.stat().st_mtime
    if _cache["mtime"] != mtime:
        csv.field_size_limit(sys.maxsize)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        for r in rows:
            r["attribution"] = procedures._attribution(r.get("procedure_example", ""))
        _cache.update(mtime=mtime, rows=rows)
    return _cache["rows"]


def _indicators(evidence: str) -> Dict[str, List[str]]:
    try:
        data = json.loads(evidence or "{}")
    except ValueError:
        return {}
    return {k: v for k, v in data.items() if isinstance(v, list) and v} if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# Status and run
# ---------------------------------------------------------------------------

@router.get("/status")
def status():
    path = procedures._DEFAULT_CSV
    meta = procedures._read_meta(path) or {}
    meta.pop("objects", None)
    rows = _rows()
    building = None
    progress = path.with_name(path.stem + ".building.json")
    if progress.exists():
        try:
            building = len(json.loads(progress.read_text(encoding="utf-8")).get("done", []))
        except (OSError, ValueError):
            pass
    tactics = sorted({t.strip() for r in rows for t in (r.get("tactic") or "").split(",") if t.strip()})
    return {
        "csv": {
            "exists": path.exists(),
            "modified": path.stat().st_mtime if path.exists() else None,
            "size": path.stat().st_size if path.exists() else 0,
            "rows": len(rows),
            "groups": len({r["group_sw_id"] for r in rows}),
            "techniques": len({r["technique_id"] for r in rows}),
            "xlsx": procedures._DEFAULT_XLSX.exists(),
        },
        "meta": meta,
        "check": procedures.LAST_CHECK and {k: procedures.LAST_CHECK[k] for k in ("ok", "groups", "techniques")}
                 | {"summary": procedures.describe_check(procedures.LAST_CHECK)},
        "plan": procedures.LAST_PLAN,
        "busy": procedures.is_busy(),
        "groups_resumable": building,
        "job": dict(_job),
        "log": list(_log),
        "tactics": tactics,
        "mitresaw_dir": str(procedures._MITRESAW_DIR),
    }


@router.post("/run")
async def run(request: Request, shikari_session: Optional[str] = Cookie(None)):
    user = _user(shikari_session)
    if not user:
        return _denied()
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    full = bool(body.get("full"))
    with _job_lock:
        if _job["state"] == "running" or procedures.is_busy():
            return JSONResponse({"error": "MITRESaw is already rebuilding the procedures CSV"}, status_code=409)
        _log.clear()
        _job.update(state="running", mode="full" if full else "incremental", started=time.time(),
                    finished=None, error=None, by=getattr(user, "username", None))

    def work():
        handler = _LogCapture(logging.INFO)
        procedures.logger.addHandler(handler)
        previous = procedures.logger.level
        if procedures.logger.getEffectiveLevel() > logging.INFO:
            procedures.logger.setLevel(logging.INFO)
        try:
            procedures.run_mitresaw(full=full)
            _job["state"] = "done"
        except procedures.MitresawBusy as e:
            _job.update(state="failed", error=str(e))
        except Exception as e:
            stopped = _job.get("stopping")
            _job.update(state="stopped" if stopped else "failed", error=None if stopped else str(e)[-600:])
        finally:
            _job.pop("stopping", None)
            _job["finished"] = time.time()
            procedures.logger.removeHandler(handler)
            procedures.logger.setLevel(previous)

    threading.Thread(target=work, name="mitresaw-tab", daemon=True).start()
    return {"status": "started", "mode": _job["mode"]}


@router.post("/stop")
def stop(shikari_session: Optional[str] = Cookie(None)):
    if not _user(shikari_session):
        return _denied()
    if _job["state"] != "running":
        return JSONResponse({"error": "No run from this tab is in progress"}, status_code=409)
    _job["stopping"] = True
    return {"stopped": procedures.stop_running()}


# ---------------------------------------------------------------------------
# Procedures
# ---------------------------------------------------------------------------

@router.get("/groups")
def groups():
    seen: Dict[str, dict] = {}
    for r in _rows():
        g = seen.setdefault(r["group_sw_id"], {"id": r["group_sw_id"], "name": r["group_sw_name"], "techniques": set()})
        g["techniques"].add(r["technique_id"])
    out = [{"id": g["id"], "name": g["name"], "techniques": len(g["techniques"])} for g in seen.values()]
    return {"groups": sorted(out, key=lambda g: g["name"].casefold())}


@router.get("/procedures")
def search(group: str = "", technique: str = "", tactic: str = "", attribution: str = "",
           q: str = "", page: int = 1):
    group, technique, words = group.strip().casefold(), technique.strip().upper(), q.casefold().split()
    tactic = tactic.strip().casefold()
    hits = []
    for r in _rows():
        if group and group not in (r["group_sw_id"].casefold(), r["group_sw_name"].casefold()):
            continue
        if technique and not (r["technique_id"] == technique or r["technique_id"].startswith(technique + ".")):
            continue
        if tactic and tactic not in [t.strip().casefold() for t in (r.get("tactic") or "").split(",")]:
            continue
        if attribution and not r["attribution"].startswith(attribution):
            continue
        if words:
            hay = " ".join((r["group_sw_name"], r["technique_id"], r["technique_name"],
                            r.get("procedure_example", ""), r.get("evidence", ""))).casefold()
            if not all(w in hay for w in words):
                continue
        hits.append(r)
    page = max(1, page)
    shown = hits[(page - 1) * _PAGE_SIZE: page * _PAGE_SIZE]
    return {
        "total": len(hits),
        "page": page,
        "pages": max(1, -(-len(hits) // _PAGE_SIZE)),
        "rows": [{
            "group_id": r["group_sw_id"], "group": r["group_sw_name"],
            "technique_id": r["technique_id"], "technique": r["technique_name"],
            "tactic": r.get("tactic", ""), "platforms": r.get("platforms", ""),
            "procedure": r.get("procedure_example", ""), "attribution": r["attribution"],
            "indicators": _indicators(r.get("evidence", "")),
            "detectable_via": r.get("detectable_via", ""),
        } for r in shown],
    }


@router.get("/download/{kind}")
def download(kind: str):
    path = {"csv": procedures._DEFAULT_CSV, "xlsx": procedures._DEFAULT_XLSX}.get(kind)
    if not path or not path.exists():
        return JSONResponse({"error": "Not built yet"}, status_code=404)
    return FileResponse(path, filename=path.name)


# ---------------------------------------------------------------------------
# MITRESaw's indicator exclusions (its data/exclusions.csv)
# ---------------------------------------------------------------------------

def _exclusions_path() -> Path:
    return procedures._MITRESAW_DIR / "data" / "exclusions.csv"


@router.get("/exclusions")
def get_exclusions():
    path = _exclusions_path()
    if not path.exists():
        return {"exclusions": []}
    with open(path, newline="", encoding="utf-8") as fh:
        return {"exclusions": [{"indicator": r.get("indicator", ""), "reason": r.get("reason", "")}
                               for r in csv.DictReader(fh) if r.get("indicator", "").strip()]}


@router.post("/exclusions")
async def save_exclusions(request: Request, shikari_session: Optional[str] = Cookie(None)):
    if not _user(shikari_session):
        return _denied()
    rows = (await request.json()).get("exclusions", [])
    clean, seen = [], set()
    for r in rows:
        ind = str(r.get("indicator", "")).strip()
        if ind and ind.casefold() not in seen:
            seen.add(ind.casefold())
            clean.append({"indicator": ind, "reason": str(r.get("reason", "")).strip()})
    path = _exclusions_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["indicator", "reason"])
        writer.writeheader()
        writer.writerows(clean)
    tmp.replace(path)
    return {"saved": len(clean)}

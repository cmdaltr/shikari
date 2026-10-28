"""
Batch hunts and streamed progress (#35).

    POST /api/batch                 {"groups": [...], "cves": [...], "correlate": true}: hunts them one
                                    after another, as the caller; returns the batch's id
    GET  /api/batch                 the caller's batches, newest first
    GET  /api/batch/{id}            one batch: each item's run name and outcome
    GET  /api/progress/{run}/stream a run's progress as Server-Sent Events, until it finishes

A batch runs its hunts in turn rather than together: each one already fans out across techniques
and SIEMs, and several at once would only compete for the same CPU and API quotas. Each item
goes through the same routes the web app and archer.client use, as the user who started the
batch, so their SIEM platforms, technology stack and AI settings apply.
"""

import asyncio
import json
import os
import secrets
import threading
import time
from typing import Dict, List, Optional

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import JSONResponse, StreamingResponse

from archer import paths

MAX_ITEMS = 50
TERMINAL = {"complete", "error", "failed", "cancelled"}
_lock = threading.Lock()

router = APIRouter()


def _dir() -> str:
    d = str(paths.DATA / "batches")
    os.makedirs(d, exist_ok=True)
    return d


def _save(batch: Dict) -> None:
    with _lock:
        tmp = os.path.join(_dir(), batch["id"] + ".json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(batch, fh, indent=2)
        os.replace(tmp, os.path.join(_dir(), batch["id"] + ".json"))


def load(batch_id: str) -> Optional[Dict]:
    if not batch_id.isalnum():
        return None
    try:
        with open(os.path.join(_dir(), batch_id + ".json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def items_from(body: Dict) -> List[Dict]:
    """The batch's hunts, in order, without duplicates."""
    seen, items = set(), []
    for kind, values in (("group", body.get("groups") or []), ("cve", body.get("cves") or [])):
        for value in values:
            value = str(value).strip()
            if kind == "cve":
                value = value.upper()
            if value and (kind, value.lower()) not in seen:
                seen.add((kind, value.lower()))
                items.append({"kind": kind, "target": value, "status": "queued", "run": None, "error": None})
    return items


def run_batch(batch: Dict, client) -> Dict:
    """Hunt each item in turn through the client; one failing doesn't stop the rest."""
    batch["status"] = "running"
    _save(batch)
    for item in batch["items"]:
        item["status"], item["started"] = "running", time.time()
        _save(batch)
        try:
            if item["kind"] == "group":
                # OSINT enhancement on, as the Hunt tab ticks it
                item["run"] = client.hunt_group(item["target"], correlate=batch["correlate"], osint=True)
            else:
                item["run"] = client.hunt_cve(item["target"], correlate=batch["correlate"])
            _save(batch)
            final = client.wait(item["run"], timeout=batch.get("timeout", 7200))
            item["status"] = final.get("status") or final.get("phase") or "complete"
            item["created_yaml"] = final.get("created_yaml")
        except Exception as e:
            item["status"], item["error"] = "failed", str(e)[:300]
        item["finished"] = time.time()
        _save(batch)
    failed = sum(1 for i in batch["items"] if i["status"] in ("error", "failed", "cancelled"))
    batch["status"] = "complete" if not failed else ("failed" if failed == len(batch["items"]) else "partial")
    batch["finished"] = time.time()
    _save(batch)
    return batch


def _user(archer_session: Optional[str]):
    from archer.auth import get_user_from_session_id
    from archer.database.db import get_db

    if not archer_session:
        return None
    db = next(get_db())
    try:
        return get_user_from_session_id(archer_session, db)
    finally:
        db.close()


@router.post("/api/batch")
async def start_batch(request: Request, archer_session: Optional[str] = Cookie(None)):
    user = _user(archer_session)
    if not user:
        return JSONResponse({"error": "Please log in"}, status_code=401)
    body = await request.json()
    items = items_from(body)
    if not items:
        return JSONResponse({"error": "Give groups and/or cves to hunt"}, status_code=400)
    if len(items) > MAX_ITEMS:
        return JSONResponse({"error": f"At most {MAX_ITEMS} hunts in one batch"}, status_code=400)
    batch = {"id": secrets.token_hex(6), "user_id": user.id, "created": time.time(), "status": "queued",
             "correlate": body.get("correlate", True) is not False, "items": items}
    _save(batch)

    from archer.client import ArcherClient

    # The server's own routes, as this user: a batch does exactly what the web app would
    internal = os.getenv("ARCHER_INTERNAL_URL") or str(request.base_url)
    client = ArcherClient(url=internal, session_cookie=archer_session, timeout=300)
    threading.Thread(target=run_batch, args=(batch, client), daemon=True, name=f"batch-{batch['id']}").start()
    return {"id": batch["id"], "items": len(items), "status_url": f"/api/batch/{batch['id']}"}


@router.get("/api/batch")
def list_batches(archer_session: Optional[str] = Cookie(None)):
    user = _user(archer_session)
    if not user:
        return JSONResponse({"error": "Please log in"}, status_code=401)
    mine = []
    for name in os.listdir(_dir()):
        if name.endswith(".json"):
            batch = load(name[:-5])
            if batch and batch.get("user_id") == user.id:
                mine.append(batch)
    return {"batches": sorted(mine, key=lambda b: b["created"], reverse=True)}


@router.get("/api/batch/{batch_id}")
def get_batch(batch_id: str, archer_session: Optional[str] = Cookie(None)):
    user = _user(archer_session)
    if not user:
        return JSONResponse({"error": "Please log in"}, status_code=401)
    batch = load(batch_id)
    if not batch or batch.get("user_id") != user.id:
        return JSONResponse({"error": "No such batch"}, status_code=404)
    return batch


async def progress_events(run: str, read, poll: float = 1.0, heartbeat: float = 15.0, limit: float = 7200):
    """SSE frames for a run: one "progress" event per change, a comment line to keep proxies from
    closing a quiet stream, and a final "done" event once the run reaches a terminal state."""
    last, quiet, start = None, 0.0, time.time()
    while time.time() - start < limit:
        progress = read(run) or {}
        if progress != last:
            last, quiet = progress, 0.0
            yield f"event: progress\ndata: {json.dumps(progress, default=str)}\n\n"
            if (progress.get("status") in TERMINAL) or progress.get("phase") == "complete":
                yield f"event: done\ndata: {json.dumps({'run': run, 'status': progress.get('status')})}\n\n"
                return
        elif quiet >= heartbeat:
            quiet = 0.0
            yield ": still running\n\n"
        await asyncio.sleep(poll)
        quiet += poll


@router.get("/api/progress/{run}/stream")
def stream_progress(run: str, archer_session: Optional[str] = Cookie(None)):
    if not _user(archer_session):
        return JSONResponse({"error": "Please log in"}, status_code=401)
    from archer.build.progress import read_progress

    return StreamingResponse(progress_events(run, read_progress), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

"""
Hunt runs: one request to hunt a target, with an id that a later hunt of the same group doesn't
overwrite (docs/suite/INTEGRATION.md, "Hunt runs"). Ostraka starts them for a record, carrying its
reference; anyone signed in may start one.

    POST /api/runs        {"kind": "group" | "cve" | "techniques", "target", "external_ref"?, "execute"?,
                           "window_days"?} -> 202 {"id", "status": "queued", "group_name", "status_url"}
    GET  /api/runs        the caller's runs (an admin's: everyone's), newest first; ?external_ref= filters
    GET  /api/runs/{id}   one run: its detections, and when executed, each query's count

Generation goes through the same routes the web app, the batch API and shikari.client use, as the
user who started the run, so their SIEM platforms, technology stack and AI settings apply (as
shikari/runs_api.py's batches do). When it finishes, the run copies its detections and their queries,
since the group's files are rewritten by its next hunt. With execute, each query is then run once
against Shikari's SIEM connections (shikari/query/counts.py) over the last window_days days, and only
how many results it found is kept: no result row is stored, logged or returned.

Statuses: queued -> generating -> generated, then executing -> executed when asked to execute; failed
at any step, with the error. A run's run.completed and run.failed webhooks carry its id and reference,
and run.executed follows its execution (shikari/webhooks.py).
"""

import json
import logging
import os
import re
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime
from typing import Callable, Dict, List, Optional

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

KINDS = ("group", "cve", "techniques")
STATUSES = ("queued", "generating", "generated", "executing", "executed", "failed")
UNFINISHED = ("queued", "generating", "executing")
REFERENCE = re.compile(r"^(OST|HNT)-\d{2}(\d{2})?-\d{3,}$")
CVE = re.compile(r"^CVE-20\d{2}-\d{4,}$")
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
WINDOW_DAYS = (1, 90)
DEFAULT_WINDOW_DAYS = 7
MAX_TARGETS = 50
MAX_GROUP_NAME = 200

# How many runs generate at once (the rest wait, queued), how many queries one run has in flight, and
# how long each query may take
RUN_SLOTS = max(1, int(os.getenv("SHIKARI_HUNT_RUNS_AT_ONCE", "2") or 2))
QUERY_WORKERS = max(1, int(os.getenv("SHIKARI_HUNT_RUN_QUERIES_AT_ONCE", "4") or 4))
QUERY_TIMEOUT = float(os.getenv("SHIKARI_HUNT_RUN_QUERY_TIMEOUT", "120") or 120)
GENERATION_TIMEOUT = 7200

_slots = threading.BoundedSemaphore(RUN_SLOTS)
_generating: Dict[str, int] = {}  # group name -> how many hunt runs are generating it in this process
_generating_lock = threading.Lock()

router = APIRouter()


class RunProblem(ValueError):
    """Why a hunt run can't be started, worded for the caller."""


# ---------------------------------------------------------------------------------------------------
# The request


def _targets(kind: str, target) -> List[str]:
    values = [str(t).strip() for t in (target if isinstance(target, list) else str(target or "").split(","))]
    values = [v for v in values if v]
    if not values:
        raise RunProblem("Give a target to hunt")
    if len(values) > MAX_TARGETS:
        raise RunProblem(f"At most {MAX_TARGETS} targets in one run")
    if kind == "cve":
        values = [v.upper() for v in values]
        bad = [v for v in values if not CVE.fullmatch(v)]
        if bad:
            raise RunProblem(f"Not a CVE id: {', '.join(bad)} (CVE-2024-3400)")
    elif kind == "techniques":
        values = [v.upper() for v in values]
        bad = [v for v in values if not TECHNIQUE.fullmatch(v)]
        if bad:
            raise RunProblem(f"Not an ATT&CK technique id: {', '.join(bad)} (T1059 or T1059.001)")
    return values


def expected_group_name(kind: str, targets: List[str]) -> str:
    """The name the generation route gives the run's group, as /generate, /generate/cve and
    /hunt/technique name it. The worker keeps the name the route actually answers with."""
    from shikari.security import sanitize_group_name

    if kind == "group":
        return targets[0]
    first = targets[0] if kind == "cve" else f"Hunt_{targets[0]}"
    name = first if len(targets) == 1 else f"{first}_plus_{len(targets) - 1}"
    return name if kind == "cve" else sanitize_group_name(name)


def parse_request(body) -> Dict:
    """The run a POST /api/runs body asks for. Raises RunProblem with what's wrong."""
    if not isinstance(body, dict):
        raise RunProblem("Send a JSON object")
    kind = body.get("kind")
    if kind not in KINDS:
        raise RunProblem(f"kind is one of: {', '.join(KINDS)}")
    targets = _targets(kind, body.get("target"))
    if kind == "group":
        if len(targets) != 1 or len(targets[0]) > MAX_GROUP_NAME:
            raise RunProblem("A group run hunts one ATT&CK group, by name")
        targets = [str(body.get("target")).strip()]
    ref = body.get("external_ref")
    if ref in (None, ""):
        ref = None
    elif not isinstance(ref, str) or not REFERENCE.fullmatch(ref):
        raise RunProblem("external_ref is an Ostraka reference, OST-26-014 or HNT-26-003")
    execute = body.get("execute", False)
    if not isinstance(execute, bool):
        raise RunProblem("execute is true or false")
    days = body.get("window_days", DEFAULT_WINDOW_DAYS)
    if isinstance(days, bool) or not isinstance(days, int) or not WINDOW_DAYS[0] <= days <= WINDOW_DAYS[1]:
        raise RunProblem(f"window_days is a whole number of days, {WINDOW_DAYS[0]} to {WINDOW_DAYS[1]}")
    return {"kind": kind, "targets": targets, "target": ",".join(targets), "external_ref": ref,
            "execute": execute, "window_days": days, "group_name": expected_group_name(kind, targets)}


# ---------------------------------------------------------------------------------------------------
# The store


def _db():
    from shikari.database import db as database

    return database.SessionLocal()


def _iso(when: Optional[datetime]) -> Optional[str]:
    return when.isoformat() + "Z" if when else None


def _loads(text: Optional[str], default):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def totals_of(detections: List[Dict], counts: List[Dict]) -> Dict:
    """How many queries the run has, and of the counted ones how many ran, how many results they found,
    how many failed and how many were skipped."""
    queries = sum(len(d.get("queries") or []) for d in detections)
    ran = [c for c in counts if not c.get("skipped") and not c.get("error")]
    return {"queries": queries, "run": len(ran), "hits": sum(c.get("hits") or 0 for c in ran),
            "errors": sum(1 for c in counts if c.get("error") and not c.get("skipped")),
            "skipped": sum(1 for c in counts if c.get("skipped"))}


def describe(row, full: bool = True) -> Dict:
    """A run as the API shows it; `full` adds its detections and counts."""
    detections = _loads(row.detections, [])
    counts = _loads(row.counts, [])
    out = {"id": row.id, "kind": row.kind, "target": row.target, "external_ref": row.external_ref,
           "execute": bool(row.execute), "window_days": row.window_days, "status": row.status,
           "group_name": row.group_name, "created_at": _iso(row.created_at),
           "completed_at": _iso(row.completed_at), "executed_at": _iso(row.executed_at),
           "error": row.error or None,
           "totals": _loads(row.totals, None) or totals_of(detections, counts)}
    if full:
        out["detections"] = detections
        out["counts"] = counts
    return out


def create(db, user_id: int, request: Dict):
    from shikari.database.models import HuntRun

    row = HuntRun(id=secrets.token_hex(8), user_id=user_id, kind=request["kind"], target=request["target"],
                  external_ref=request["external_ref"], execute=request["execute"],
                  window_days=request["window_days"], status="queued", group_name=request["group_name"],
                  detections="[]", counts="[]")
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _update(run_id: str, **fields) -> None:
    from shikari.database.models import HuntRun

    db = _db()
    try:
        db.query(HuntRun).filter(HuntRun.id == run_id).update(fields, synchronize_session=False)
        db.commit()
    finally:
        db.close()


def load(run_id: str):
    from shikari.database.models import HuntRun

    db = _db()
    try:
        row = db.get(HuntRun, run_id)
        if row is not None:
            db.expunge(row)
        return row
    finally:
        db.close()


def interrupted() -> int:
    """Mark runs a restart cut short as failed (start-up): no thread is left to finish them."""
    from shikari.database.models import HuntRun

    db = _db()
    try:
        n = db.query(HuntRun).filter(HuntRun.status.in_(UNFINISHED)).update(
            {"status": "failed", "error": "Shikari restarted before the run finished"}, synchronize_session=False)
        db.commit()
        return n
    finally:
        db.close()


def executing() -> int:
    """How many hunt runs are running their queries now: /api/busy counts them, since a restart would
    cut them short (generating ones are already counted as the hunts they are)."""
    from shikari.database.models import HuntRun

    db = _db()
    try:
        return db.query(HuntRun).filter(HuntRun.status == "executing").count()
    finally:
        db.close()


def generating(group_name: str) -> bool:
    """Whether a hunt run in this process is generating the group (its webhooks are the run's own)."""
    with _generating_lock:
        return _generating.get(group_name, 0) > 0


def _claim_group(group_name: str) -> None:
    with _generating_lock:
        _generating[group_name] = _generating.get(group_name, 0) + 1


def _release_group(group_name: str) -> None:
    with _generating_lock:
        left = _generating.get(group_name, 0) - 1
        if left > 0:
            _generating[group_name] = left
        else:
            _generating.pop(group_name, None)


# ---------------------------------------------------------------------------------------------------
# Generating


def snapshot(results: Dict) -> List[Dict]:
    """What a run keeps of its detections from GET /api/results/{group}?run=latest: each one's file,
    name, techniques, platforms and queries."""
    out = []
    for d in (results or {}).get("detections") or []:
        if not isinstance(d, dict) or d.get("error"):
            continue
        out.append({"file": d.get("file", ""), "name": d.get("name", ""),
                    "techniques": list(d.get("techniques") or []), "platforms": list(d.get("platforms") or []),
                    "queries": [{"platform": q.get("platform", ""), "query": q.get("query", "")}
                                for q in d.get("queries") or [] if isinstance(q, dict)]})
    return out


def _start(client, kind: str, targets: List[str]) -> str:
    if kind == "group":
        # OSINT enhancement on, as the Hunt tab ticks it (and as a batch hunts)
        return client.hunt_group(targets[0], correlate=True, osint=True)
    if kind == "cve":
        return client.hunt_cve(",".join(targets), correlate=True)
    return client.hunt_techniques(targets)


def _failed(run_id: str, error: str, group_name: str, external_ref: Optional[str]) -> None:
    from shikari import webhooks

    error = (error or "The run failed")[:500]
    _update(run_id, status="failed", error=error)
    webhooks.emit_run(group_name, {"status": "failed", "error": error}, run_id=run_id, external_ref=external_ref)


def work(run_id: str, client, counters: Optional[Callable[[], Dict]] = None) -> None:
    """Generate the run's detections through the client, keep them, then (with execute) count each
    query's results. Runs on its own thread; at most RUN_SLOTS at once."""
    from shikari import webhooks

    with _slots:
        row = load(run_id)
        if row is None:
            return
        group_name, ref = row.group_name, row.external_ref
        claimed = None
        try:
            _update(run_id, status="generating")
            claimed = group_name
            _claim_group(claimed)
            name = _start(client, row.kind, [t for t in row.target.split(",") if t])
            if name != group_name:
                _release_group(claimed)
                claimed = group_name = name
                _claim_group(claimed)
                _update(run_id, group_name=name)
            final = client.wait(name, timeout=GENERATION_TIMEOUT)
            status = final.get("status") or final.get("phase")
            if status in ("error", "failed", "cancelled"):
                _update(run_id, status="failed", error=str(final.get("error") or final.get("message") or status)[:500])
                webhooks.emit_run(name, final, run_id=run_id, external_ref=ref)
                return
            detections = snapshot(client.results(name, latest=True))
            totals = totals_of(detections, [])
            _update(run_id, status="generated", detections=json.dumps(detections), totals=json.dumps(totals),
                    completed_at=datetime.utcnow())
            _release_group(claimed)
            claimed = None
            webhooks.emit_run(name, {"phase": final.get("phase") or "complete",
                                     "created_yaml": final.get("created_yaml")}, run_id=run_id, external_ref=ref)
            if not row.execute:
                return
            _update(run_id, status="executing")
            from shikari.query.counts import counters as configured

            counts = execute(detections, row.window_days, (counters or configured)())
            totals = totals_of(detections, counts)
            _update(run_id, status="executed", counts=json.dumps(counts), totals=json.dumps(totals),
                    executed_at=datetime.utcnow())
            webhooks.emit_executed(run_id, ref, name, totals)
        except Exception as e:
            # The error's text, never anything a SIEM answered with
            logger.warning("Hunt run %s failed: %s", run_id, type(e).__name__)
            _failed(run_id, str(e), group_name, ref)
        finally:
            if claimed:
                _release_group(claimed)


# ---------------------------------------------------------------------------------------------------
# Executing: counts, never rows


def plan(detections: List[Dict]) -> List[Dict]:
    """One count entry per query, in order, before anything is run."""
    entries = []
    for d in detections:
        techniques = d.get("techniques") or []
        for i, q in enumerate(d.get("queries") or []):
            entries.append({"file": d.get("file", ""), "technique": techniques[0] if techniques else "",
                            "platform": q.get("platform", ""), "query_index": i, "hits": None, "error": "",
                            "skipped": False, "_query": q.get("query") or ""})
    return entries


def _short(error: Exception) -> str:
    text = str(error).strip() or type(error).__name__
    return text.splitlines()[0][:300]


def execute(detections: List[Dict], window_days: int, counters: Dict[str, Callable],
            timeout: float = QUERY_TIMEOUT, workers: int = QUERY_WORKERS) -> List[Dict]:
    """Run each query once, at most `workers` at a time and each for at most `timeout` seconds, through
    the counter for its platform. Returns the count entries: hits, or an error, or skipped when the
    platform has no connection here."""
    from shikari.query.counts import platform_key

    entries = plan(detections)
    pending = []
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="hunt-run-query")
    try:
        for entry in entries:
            key = platform_key(entry["platform"])
            counter = counters.get(key) if key else None
            if counter is None:
                entry["skipped"] = True
                entry["error"] = f"No {entry['platform'] or 'SIEM'} connection here"
                continue
            if not entry["_query"].strip():
                entry["error"] = "The detection has no query"
                continue
            pending.append((entry, pool.submit(counter, entry["_query"], window_days, timeout)))
        for entry, future in pending:
            try:
                entry["hits"] = int(future.result(timeout=timeout * 1.25 + 1))  # the client's own timeout first
            except FutureTimeout:
                future.cancel()
                entry["error"] = f"No answer within {int(timeout)} seconds"
            except Exception as e:
                entry["error"] = _short(e)
    finally:
        # A query still hanging past its timeout doesn't hold the run up
        pool.shutdown(wait=False, cancel_futures=True)
    for entry in entries:
        entry.pop("_query", None)
    return entries


# ---------------------------------------------------------------------------------------------------
# Routes


def _user(shikari_session: Optional[str]):
    from shikari.auth import get_user_from_session_id

    if not shikari_session:
        return None
    db = _db()
    try:
        user = get_user_from_session_id(shikari_session, db)
        if user is not None:
            db.expunge(user)
        return user
    finally:
        db.close()


def _sees_all(user) -> bool:
    from shikari.database.models import UserRole, at_least

    return at_least(user, UserRole.ADMIN)


def _client(request: Request, shikari_session: str):
    from shikari.client import ShikariClient

    # The server's own routes, as this user: a hunt run does exactly what the web app would
    internal = os.getenv("SHIKARI_INTERNAL_URL") or str(request.base_url)
    return ShikariClient(url=internal, session_cookie=shikari_session, timeout=300)


def _spawn(run_id: str, client) -> None:
    threading.Thread(target=work, args=(run_id, client), daemon=True, name=f"hunt-run-{run_id}").start()


@router.post("/api/runs")
async def start_run(request: Request, shikari_session: Optional[str] = Cookie(None)):
    user = _user(shikari_session)
    if not user:
        return JSONResponse({"error": "Please log in"}, status_code=401)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "Send a JSON object"}, status_code=422)
    try:
        wanted = parse_request(body)
    except RunProblem as e:
        return JSONResponse({"error": str(e)}, status_code=422)
    db = _db()
    try:
        row = create(db, user.id, wanted)
        run_id, group_name = row.id, row.group_name
    finally:
        db.close()
    _spawn(run_id, _client(request, shikari_session))
    return JSONResponse({"id": run_id, "status": "queued", "group_name": group_name,
                         "status_url": f"/api/runs/{run_id}"}, status_code=202)


@router.get("/api/runs")
def list_runs(external_ref: str = "", shikari_session: Optional[str] = Cookie(None)):
    from shikari.database.models import HuntRun

    user = _user(shikari_session)
    if not user:
        return JSONResponse({"error": "Please log in"}, status_code=401)
    db = _db()
    try:
        query = db.query(HuntRun)
        if not _sees_all(user):
            query = query.filter(HuntRun.user_id == user.id)
        if external_ref:
            query = query.filter(HuntRun.external_ref == external_ref)
        rows = query.order_by(HuntRun.created_at.desc()).limit(200).all()
        return {"runs": [describe(r, full=False) for r in rows]}
    finally:
        db.close()


@router.get("/api/runs/{run_id}")
def get_run(run_id: str, shikari_session: Optional[str] = Cookie(None)):
    user = _user(shikari_session)
    if not user:
        return JSONResponse({"error": "Please log in"}, status_code=401)
    row = load(run_id) if re.fullmatch(r"[0-9a-f]{1,32}", run_id or "") else None
    if row is None or (row.user_id != user.id and not _sees_all(user)):
        return JSONResponse({"error": "No such run"}, status_code=404)
    return describe(row)

"""
Build → Emulate → Lab: install, create and manage the containers and VMs a run records on
(archer.lab). Browsing the host and templates needs an account; changing anything needs admin.

The quick verbs (start, stop, status, logs, delete, snapshot) answer straight away. The slow
ones that pull an image or run a script inside the machine (create, revert, provision) run as
one background job at a time, with a log the page polls — the same shape as the telemetry build.
"""

import threading
import time
from collections import deque
from typing import Dict, Optional

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import JSONResponse

from archer.auth import get_user_from_session_id
from archer.database.db import get_db
from archer.lab import hosts, machines, provision
from archer.lab.runner import LabError
from archer.lab.templates import offered

router = APIRouter(prefix="/api/lab", tags=["lab"])
_job: Dict = {"state": "idle", "what": "", "started": None, "finished": None, "error": None}
_log: deque = deque(maxlen=200)
_lock = threading.Lock()


def _user(archer_session: Optional[str]):
    if not archer_session:
        return None
    db = next(get_db())
    try:
        return get_user_from_session_id(archer_session, db)
    finally:
        db.close()


def _admin(archer_session: Optional[str]):
    from archer.database.models import UserRole

    user = _user(archer_session)
    if not user:
        return JSONResponse({"error": "Please log in"}, status_code=401)
    if user.role != UserRole.ADMIN:
        return JSONResponse({"error": "Only an admin can manage lab machines"}, status_code=403)
    return None


def _say(line: str):
    _log.append(f"{time.strftime('%H:%M:%S')}  {line}")


def _background(what: str, fn):
    """Run one slow job at a time; its progress is in _job and _log for the page to poll."""
    with _lock:
        if _job["state"] == "running":
            return {"started": False, "job": dict(_job)}
        _job.update(state="running", what=what, started=time.time(), finished=None, error=None)
        _log.clear()
    _say(what)

    def worker():
        try:
            fn(_say)
            _job.update(state="done", finished=time.time())
            _say("Done")
        except LabError as e:
            _job.update(state="error", finished=time.time(), error=e.message)
            _say(f"Failed: {e.message}")
            if e.detail:
                _say(e.detail[:500])
        except Exception as e:  # noqa: BLE001 — a job must never take the server down
            _job.update(state="error", finished=time.time(), error=str(e))
            _say(f"Failed: {e}")

    threading.Thread(target=worker, daemon=True).start()
    return {"started": True, "job": dict(_job)}


@router.get("/overview")
def overview(archer_session: Optional[str] = Cookie(None)):
    """The host, the templates it can run, and the machines on it. Browsing needs no admin."""
    caps = hosts.capabilities()
    try:
        current = machines.listing(caps["ready"])
    except LabError:
        current = []
    # Every name already on the host — Archer's machines and, so a new name can't collide with
    # one Archer doesn't manage, the host's other VMs too — for the create dialog's suggested name
    taken = sorted({m["name"] for m in current} | set(machines.all_host_names(caps["ready"])))
    return {"host": caps, "templates": offered(caps), "machines": current, "taken": taken, "job": dict(_job)}


@router.get("/machines")
def list_machines(archer_session: Optional[str] = Cookie(None)):
    return {"machines": machines.listing(), "job": dict(_job)}


@router.get("/job")
def job():
    return {"job": dict(_job), "log": list(_log)}


@router.get("/logs")
def machine_logs(engine: str, name: str):
    try:
        return {"logs": machines.logs(engine, name)}
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)


@router.post("/create")
async def create(request: Request, archer_session: Optional[str] = Cookie(None)):
    denied = _admin(archer_session)
    if denied:
        return denied
    data = await request.json()
    template_id, name = data.get("template", ""), data.get("name", "")
    try:
        from archer.lab.runner import safe_name
        from archer.lab.templates import BY_ID

        safe_name(name)
        if template_id not in BY_ID:
            raise LabError("Unknown template", template_id)
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)

    def work(say):
        say(f"Creating {name} from {BY_ID[template_id]['name']} (pulling the image can take a while)…")
        machines.create(template_id, name)

    return _background(f"Create {name}", work)


@router.post("/action")
async def action(request: Request, archer_session: Optional[str] = Cookie(None)):
    """start, stop, delete, snapshot, revert. The quick ones answer now; revert runs as a job."""
    denied = _admin(archer_session)
    if denied:
        return denied
    data = await request.json()
    engine, name, act = data.get("engine", ""), data.get("name", ""), data.get("action", "")
    snap = data.get("snapshot", "")
    try:
        if act == "start":
            machines.start(engine, name)
        elif act == "stop":
            machines.stop(engine, name)
        elif act == "delete":
            machines.delete(engine, name)
        elif act == "snapshot":
            return {"ok": True, **machines.snapshot(engine, name, snap)}
        elif act == "revert":
            return _background(f"Revert {name} to {snap}",
                               lambda say: (say(f"Reverting {name} to {snap}…"), machines.revert(engine, name, snap)))
        else:
            return JSONResponse({"error": f"Unknown action {act}"}, status_code=400)
        return {"ok": True}
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)


@router.post("/adopt")
async def adopt(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Set the OS of a VM Archer manages but didn't create (a UTM VM), so it can be provisioned
    and recorded."""
    denied = _admin(archer_session)
    if denied:
        return denied
    data = await request.json()
    engine, name, os_name = data.get("engine", ""), data.get("name", ""), data.get("os", "")
    try:
        return {"ok": True, **machines.adopt(engine, name, os_name)}
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)


@router.get("/provision-steps")
def provision_steps(os: str):
    return {"steps": provision.steps_for(os)}


@router.post("/provision")
async def run_provision(request: Request, archer_session: Optional[str] = Cookie(None)):
    denied = _admin(archer_session)
    if denied:
        return denied
    data = await request.json()
    engine, name, os_name, step = data.get("engine", ""), data.get("name", ""), data.get("os", ""), data.get("step", "")
    label = provision.LABELS.get(step, step)

    def work(say):
        say(f"{label} on {name}. This changes the machine — snapshot it first if you haven't.")
        out = provision.run_step(engine, name, os_name, step)
        for line in (out or "").strip().splitlines()[-12:]:
            say(line)

    return _background(f"{label} on {name}", work)


@router.post("/record")
async def record(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Run Atomic Red Team in a machine and import the recording into Your lab. execute=false
    (the default) only previews the plan; execute=true detonates, and the dialog makes the
    caller confirm the machine is snapshotted first.
    """
    denied = _admin(archer_session)
    if denied:
        return denied
    from archer.lab import record as lab_run

    data = await request.json()
    engine, name, os_name = data.get("engine", ""), data.get("name", ""), data.get("os", "")
    techniques, execute = data.get("techniques", ""), bool(data.get("execute"))
    revert_to, run_name = data.get("revert_to", ""), data.get("run_name", "")
    settle, timeout = int(data.get("settle", 20)), int(data.get("timeout", 120))
    try:
        techs = lab_run.clean_techniques(techniques)
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)
    if not execute:
        # The preview is cheap and synchronous: just the plan and any warnings
        return {"preview": True, "plan": lab_run.plan(engine, name, os_name, techs, run_name or f"{name}-run"),
                "warnings": lab_run.preflight(engine, name, os_name), "techniques": techs}

    def work(say):
        lab_run.record(engine, name, os_name, techs, run_name=run_name, settle=settle, timeout=timeout,
                       revert_to=revert_to, execute=True, say=say)

    return _background(f"Record {','.join(techs)} on {name}", work)

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
from archer.lab import hosts, iso, machines, provision
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


def _lab(archer_session: Optional[str]):
    """(user, None) if they may use the lab — an operational analyst or admin — else (None, denial).
    The lab runs host commands and detonates atomics, so it sits above the plain analyst role."""
    from archer.database.models import UserRole, at_least

    user = _user(archer_session)
    if not user:
        return None, JSONResponse({"error": "Please log in"}, status_code=401)
    if not at_least(user, UserRole.OPERATOR):
        return None, JSONResponse({"error": "The lab needs the Operational analyst role",
                                   "detail": "Ask an admin to grant it."}, status_code=403)
    return user, None


def _is_admin(user) -> bool:
    from archer.database.models import UserRole, at_least

    return at_least(user, UserRole.ADMIN)


def _can_lab(user) -> bool:
    from archer.database.models import UserRole, at_least

    return at_least(user, UserRole.OPERATOR)


def _owns(user, engine: str, name: str) -> bool:
    """Whether this user may act on the named machine (admin on any, owner on their own, any
    operational analyst on an unclaimed UTM VM)."""
    return machines.can_manage(engine, name, user.id, _is_admin(user))


def _not_yours():
    return JSONResponse({"error": "That machine isn't yours to manage",
                         "detail": "Only its owner or an admin can."}, status_code=403)


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
    """The host, the templates it can run, and the machines this user may manage. Anyone signed
    in sees the host and templates; the machine list is empty below the Operational analyst role."""
    user = _user(archer_session)
    can_lab = _can_lab(user)
    is_admin = _is_admin(user)
    caps = hosts.capabilities()
    current, taken = [], []
    if can_lab:
        try:
            current = machines.listing(caps["ready"], user_id=user.id, is_admin=is_admin)
        except LabError:
            current = []
        # Every name already on the host — Archer's and the host's other VMs too — so a new name
        # can't collide, for the create dialog's suggestion
        taken = sorted({m["name"] for m in current} | set(machines.all_host_names(caps["ready"])))
    return {"host": caps, "templates": offered(caps), "machines": current, "taken": taken,
            "job": dict(_job), "can_lab": can_lab, "is_admin": is_admin}


@router.get("/machines")
def list_machines(archer_session: Optional[str] = Cookie(None)):
    user, denied = _lab(archer_session)
    if denied:
        return denied
    return {"machines": machines.listing(user_id=user.id, is_admin=_is_admin(user)), "job": dict(_job)}


@router.get("/job")
def job():
    return {"job": dict(_job), "log": list(_log)}


@router.get("/logs")
def machine_logs(engine: str, name: str, archer_session: Optional[str] = Cookie(None)):
    user, denied = _lab(archer_session)
    if denied:
        return denied
    if not _owns(user, engine, name):
        return _not_yours()
    try:
        return {"logs": machines.logs(engine, name)}
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)


@router.post("/create")
async def create(request: Request, archer_session: Optional[str] = Cookie(None)):
    user, denied = _lab(archer_session)
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
        machines.create(template_id, name, owner=user.id)

    return _background(f"Create {name}", work)


@router.post("/action")
async def action(request: Request, archer_session: Optional[str] = Cookie(None)):
    """start, stop, delete, snapshot, revert. The quick ones answer now; revert runs as a job."""
    user, denied = _lab(archer_session)
    if denied:
        return denied
    data = await request.json()
    engine, name, act = data.get("engine", ""), data.get("name", ""), data.get("action", "")
    snap = data.get("snapshot", "")
    if not _owns(user, engine, name):
        return _not_yours()
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
    user, denied = _lab(archer_session)
    if denied:
        return denied
    data = await request.json()
    engine, name, os_name = data.get("engine", ""), data.get("name", ""), data.get("os", "")
    if not _owns(user, engine, name):
        return _not_yours()
    try:
        return {"ok": True, **machines.adopt(engine, name, os_name, owner=user.id)}
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)


@router.post("/clone")
async def clone(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Clone an existing VM into a new one — UTM's fast Windows path (copy a prepared VM)."""
    user, denied = _lab(archer_session)
    if denied:
        return denied
    data = await request.json()
    engine, name, new_name = data.get("engine", ""), data.get("name", ""), data.get("new_name", "")
    if not _owns(user, engine, name):
        return _not_yours()
    try:
        from archer.lab.runner import safe_name

        safe_name(new_name)
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)

    def work(say):
        say(f"Cloning {name} to {new_name} — copying the disk can take a few minutes…")
        machines.clone(engine, name, new_name, owner=user.id)

    return _background(f"Clone {name}", work)


@router.post("/verify-iso")
async def verify_iso(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Check a downloaded file is a Windows 11 ARM64 installer, before you build the VM from it
    in UTM. Read-only: it only reads the ISO's volume descriptor and directory tree."""
    _user_, denied = _lab(archer_session)
    if denied:
        return denied
    import os as _os

    path = (await request.json()).get("path", "").strip()
    if not path:
        return JSONResponse({"error": "Give the path to the .iso file."}, status_code=400)
    return iso.inspect(_os.path.expanduser(path)).as_dict()


@router.get("/provision-steps")
def provision_steps(os: str):
    return {"steps": provision.steps_for(os)}


@router.post("/provision")
async def run_provision(request: Request, archer_session: Optional[str] = Cookie(None)):
    user, denied = _lab(archer_session)
    if denied:
        return denied
    data = await request.json()
    engine, name, os_name, step = data.get("engine", ""), data.get("name", ""), data.get("os", ""), data.get("step", "")
    if not _owns(user, engine, name):
        return _not_yours()
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
    user, denied = _lab(archer_session)
    if denied:
        return denied
    from archer.lab import record as lab_run

    data = await request.json()
    engine, name, os_name = data.get("engine", ""), data.get("name", ""), data.get("os", "")
    if not _owns(user, engine, name):
        return _not_yours()
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


# ---------------------------------------------------------------- CALDERA (#30)

def _caldera():
    from archer.lab import caldera

    return caldera, caldera.Client.from_settings()


@router.get("/caldera/status")
def caldera_status(archer_session: Optional[str] = Cookie(None)):
    """Whether CALDERA is configured and answering, and its agent groups. Never returns the key."""
    user, denied = _lab(archer_session)
    if denied:
        return denied
    from archer.lab import caldera

    if not caldera.configured():
        return {"configured": False, "groups": [],
                "detail": "Set caldera.url and caldera.api_key in bespoke/config.yaml"}
    try:
        _, client = _caldera()
        return {"configured": True, "url": client.url, "groups": caldera.groups(client.agents())}
    except LabError as e:
        return {"configured": True, "error": e.message, "detail": e.detail, "groups": []}


@router.post("/caldera/operate")
async def caldera_operate(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Plan a CALDERA operation for a group, CVE or technique list against an agent group.
    execute=false (the default) returns the plan and creates nothing; execute=true creates the
    adversary and starts the operation, then collects its results when it finishes.
    """
    user, denied = _lab(archer_session)
    if denied:
        return denied
    from archer.config import GENERATE_DIR

    data = await request.json()
    kind, value = data.get("kind", "technique"), str(data.get("value", "")).strip()
    group, name, execute = str(data.get("group", "")).strip(), data.get("name", ""), bool(data.get("execute"))
    capture = data.get("capture") or None  # {engine, name, os} of the lab machine the agent runs on
    if not group:
        return JSONResponse({"error": "Choose an agent group"}, status_code=400)
    try:
        caldera, client = _caldera()
        techs = caldera.resolve_techniques(kind, value, GENERATE_DIR)
        if not execute:
            p = caldera.plan(client.abilities(), client.agents(), techs, group)
            label = caldera.safe_name(name) if name else "archer-operation"
            return {"preview": True, "plan": caldera.plan_lines(p, label), "warnings": p["warnings"],
                    "steps": p["steps"], "gaps": p["gaps"], "agents": p["agents"]}
        if capture and not _owns(user, capture.get("engine", ""), capture.get("name", "")):
            return _not_yours()
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)

    def work(say):
        run = caldera.operate(client, techs, group, name=name, target=f"{kind}: {value}", execute=True, say=say)
        state = caldera.wait(client, run["operation_id"], say=say)
        say(f"Operation finished: {state}")
        manifest = caldera.collect(client, run["operation_id"], say=say, rebuild=not capture)
        if capture:
            caldera.capture(capture["engine"], capture["name"], capture.get("os", ""), manifest,
                            host=capture.get("host", ""), say=say)

    return _background(f"CALDERA operation on {group}", work)


@router.post("/caldera/collect")
async def caldera_collect(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Pull an existing operation's results (one started in CALDERA itself, say)."""
    user, denied = _lab(archer_session)
    if denied:
        return denied
    data = await request.json()
    op_id = str(data.get("operation_id", "")).strip()
    if not op_id:
        return JSONResponse({"error": "Give the operation's id"}, status_code=400)
    try:
        caldera, client = _caldera()
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)
    return _background(f"Collect CALDERA operation {op_id}", lambda say: caldera.collect(client, op_id, say=say))


@router.get("/caldera/operations")
def caldera_operations(archer_session: Optional[str] = Cookie(None)):
    """The operations collected here, newest first, without their steps' output."""
    user, denied = _lab(archer_session)
    if denied:
        return denied
    from archer.lab import caldera

    return {"operations": [{"name": m.get("name"), "operation_id": m.get("operation_id"), "state": m.get("state"),
                            "group": m.get("group"), "collected": m.get("collected"),
                            "steps": len(m.get("steps") or []),
                            "hosts": sorted({s.get("host") or s.get("paw") or "" for s in m.get("steps") or []}),
                            "captured": bool(m.get("captured"))}
                           for m in caldera.collected()]}


@router.get("/caldera/check")
def caldera_check(name: str, archer_session: Optional[str] = Cookie(None)):
    """An operation's steps against the saved detections and correlations. Static; no AI."""
    user, denied = _lab(archer_session)
    if denied:
        return denied
    from archer.config import GENERATE_DIR
    from archer.lab import caldera

    manifest = caldera.load(name)
    if not manifest:
        return JSONResponse({"error": "No such operation collected here"}, status_code=404)
    return {**caldera.check_operation(manifest, GENERATE_DIR),
            "correlations": caldera.check_correlations(manifest, GENERATE_DIR)}

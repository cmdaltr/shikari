"""
Build → Emulate → Lab: install, create and manage the containers and VMs a run records on
(shikari.lab). Browsing the host and templates needs an account; changing anything needs admin.

The quick verbs (start, stop, status, logs, delete, snapshot) answer straight away. The slow
ones that pull an image or run a script inside the machine (create, revert, provision) run as
one background job at a time, with a log the page polls — the same shape as the telemetry build.
"""

import threading
import time
from collections import deque
from typing import Dict, Optional

from fastapi import APIRouter, Cookie, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from shikari.auth import get_user_from_session_id
from shikari.database.db import get_db
from shikari.lab import hosts, iso, machines, provision
from shikari.lab.runner import LabError
from shikari.lab.templates import offered

router = APIRouter(prefix="/api/lab", tags=["lab"])
_job: Dict = {"state": "idle", "what": "", "started": None, "finished": None, "error": None, "tasks": []}
_log: deque = deque(maxlen=200)
_lock = threading.Lock()


def _task(tid: str, **changes):
    """Update one entry in the running job's task list (what the Provision modal renders)."""
    for t in _job.get("tasks", []):
        if t["id"] == tid:
            t.update(changes)
            return


def _user(shikari_session: Optional[str]):
    if not shikari_session:
        return None
    db = next(get_db())
    try:
        return get_user_from_session_id(shikari_session, db)
    finally:
        db.close()


def _lab(shikari_session: Optional[str]):
    """(user, None) if they may use the lab — an operational analyst or admin — else (None, denial).
    The lab runs host commands and detonates atomics, so it sits above the plain analyst role."""
    from shikari.database.models import UserRole, at_least

    user = _user(shikari_session)
    if not user:
        return None, JSONResponse({"error": "Please log in"}, status_code=401)
    if not at_least(user, UserRole.OPERATOR):
        return None, JSONResponse({"error": "The lab needs the Operational analyst role",
                                   "detail": "Ask an admin to grant it."}, status_code=403)
    return user, None


def _is_admin(user) -> bool:
    from shikari.database.models import UserRole, at_least

    return at_least(user, UserRole.ADMIN)


def _can_lab(user) -> bool:
    from shikari.database.models import UserRole, at_least

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


def _background(what: str, fn, tasks=None):
    """Run one slow job at a time; its progress is in _job and _log for the page to poll. `tasks`
    seeds the structured task list (Provision); other jobs leave it empty."""
    with _lock:
        if _job["state"] == "running":
            return {"started": False, "job": dict(_job)}
        _job.update(state="running", what=what, started=time.time(), finished=None, error=None)
        _job["tasks"] = list(tasks or [])
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
def overview(shikari_session: Optional[str] = Cookie(None)):
    """The host, the templates it can run, and the machines this user may manage. Anyone signed
    in sees the host and templates; the machine list is empty below the Operational analyst role."""
    user = _user(shikari_session)
    can_lab = _can_lab(user)
    is_admin = _is_admin(user)
    caps = hosts.capabilities()
    current, taken = [], []
    if can_lab:
        try:
            current = machines.listing(caps["ready"], user_id=user.id, is_admin=is_admin)
        except LabError:
            current = []
        from shikari.lab import caldera

        hosts_enrolled = caldera.agent_hosts(_caldera_overrides(user))
        for m in current:
            m["enrolled"] = (m.get("name") or "").lower() in hosts_enrolled
        # Every name already on the host — Shikari's and the host's other VMs too — so a new name
        # can't collide, for the create dialog's suggestion
        taken = sorted({m["name"] for m in current} | set(machines.all_host_names(caps["ready"])))
    return {"host": caps, "templates": offered(caps), "machines": current, "taken": taken,
            "job": dict(_job), "can_lab": can_lab, "is_admin": is_admin, "naming": _caldera_naming()}


@router.get("/machines")
def list_machines(shikari_session: Optional[str] = Cookie(None)):
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    from shikari.lab import caldera

    rows = machines.listing(user_id=user.id, is_admin=_is_admin(user))
    # Mark which machines are currently CALDERA agents, so the UI can show enrolled vs not.
    hosts = caldera.agent_hosts(_caldera_overrides(user))
    for m in rows:
        m["enrolled"] = (m.get("name") or "").lower() in hosts
    return {"machines": rows, "job": dict(_job), "naming": _caldera_naming()}


def _caldera_naming() -> dict:
    """The lab naming/group convention, from the backend, so web and CLI can't drift apart."""
    from shikari.lab import caldera, templates

    # The Linux machines the "Add agent" modal offers, each with its template, engine, label and
    # name tag — Ubuntu (VM or container) and Rocky (container only). macOS/Windows resolve by OS.
    flavours = [{"template": t["id"], "engine": t["engine"], "label": t["name"], "tag": t["tag"]}
                for t in templates.TEMPLATES if t.get("os") == "linux"]
    return {"os_tag": caldera.OS_TAG, "group_for": caldera.GROUP_FOR,
            "template_tag": templates.TEMPLATE_TAG, "linux_flavours": flavours}


@router.get("/job")
def job():
    return {"job": dict(_job), "log": list(_log)}


@router.get("/logs")
def machine_logs(engine: str, name: str, shikari_session: Optional[str] = Cookie(None)):
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    if not _owns(user, engine, name):
        return _not_yours()
    try:
        return {"logs": machines.logs(engine, name)}
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)


@router.post("/create")
async def create(request: Request, shikari_session: Optional[str] = Cookie(None)):
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    data = await request.json()
    template_id, name = data.get("template", ""), data.get("name", "")
    try:
        from shikari.lab.runner import safe_name
        from shikari.lab.templates import BY_ID

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
async def action(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """start, stop, delete, snapshot, revert. The quick ones answer now; revert runs as a job."""
    user, denied = _lab(shikari_session)
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
async def adopt(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """Set the OS of a VM Shikari manages but didn't create (a UTM VM), so it can be provisioned
    and recorded."""
    user, denied = _lab(shikari_session)
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
async def clone(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """Clone an existing VM into a new one — UTM's fast Windows path (copy a prepared VM)."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    data = await request.json()
    engine, name, new_name = data.get("engine", ""), data.get("name", ""), data.get("new_name", "")
    if not _owns(user, engine, name):
        return _not_yours()
    try:
        from shikari.lab.runner import safe_name

        safe_name(new_name)
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)

    def work(say):
        say(f"Cloning {name} to {new_name} — copying the disk can take a few minutes…")
        machines.clone(engine, name, new_name, owner=user.id)

    return _background(f"Clone {name}", work)


@router.post("/verify-iso")
async def verify_iso(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """Check a downloaded file is a Windows 11 ARM64 installer, before you build the VM from it
    in UTM. Read-only: it only reads the ISO's volume descriptor and directory tree."""
    _user_, denied = _lab(shikari_session)
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
async def run_provision(request: Request, shikari_session: Optional[str] = Cookie(None)):
    user, denied = _lab(shikari_session)
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
async def record(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """
    Run Atomic Red Team in a machine and import the recording into Your lab. execute=false
    (the default) only previews the plan; execute=true detonates, and the dialog makes the
    caller confirm the machine is snapshotted first.
    """
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    from shikari.lab import record as lab_run

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

def _caldera_overrides(user) -> dict:
    """The user's own CALDERA settings (Profile → Emulation Tools), decrypted. caldera.settings()
    layers the environment over this and falls back to bespoke/config.yaml, so this is just the
    per-user layer. Returns {} when nothing is stored for them."""
    if not user:
        return {}
    from shikari.auth.encryption import decrypt_api_key
    from shikari.database.models import APIKey

    ov: dict = {}
    if getattr(user, "caldera_url", None):
        ov["url"] = user.caldera_url
    if getattr(user, "caldera_verify_tls", None) is not None:
        ov["verify_tls"] = bool(user.caldera_verify_tls)
    db = next(get_db())
    try:
        row = db.query(APIKey).filter(APIKey.user_id == user.id, APIKey.platform == "caldera").first()
        if row:
            try:
                ov["api_key"] = decrypt_api_key(row.encrypted_key)
            except Exception:  # a key that won't decrypt is treated as unset, not a 500
                pass
    finally:
        db.close()
    return ov


def _caldera(user=None):
    from shikari.lab import caldera

    return caldera, caldera.Client.from_settings(_caldera_overrides(user))


@router.get("/caldera/status")
def caldera_status(shikari_session: Optional[str] = Cookie(None)):
    """Whether CALDERA is configured and answering, and its agent groups. Never returns the key."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    from shikari.lab import caldera, caldera_provision

    overrides = _caldera_overrides(user)
    # Whether this host can stand CALDERA up in-app (macOS, admin, opt-in), and whether a lab it
    # provisioned is up right now — so the panel shows Provision, or green Re-provision/De-provision.
    can_provision = caldera_provision.can_provision(_is_admin(user))[0]
    provisioned = can_provision and caldera_provision.lab_up()
    # host_os/host_name describe this machine — the host the diagram shows the CALDERA server
    # running on (for a lab Provisioned here that's literally this box; the server node wears its
    # OS icon and hostname). A Provisioned server runs in local Docker, so name that environment;
    # for a server you point Shikari at yourself we don't know, so leave it blank.
    import platform as _plat
    host_os = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}.get(_plat.system(), "")
    host_name = _plat.node() or ""
    base = {"can_provision": can_provision, "provisioned": provisioned, "host_os": host_os,
            "host_name": host_name, "host_env": "Docker" if provisioned else ""}
    if not caldera.configured(overrides):
        return {"configured": False, "groups": [],
                "detail": "Set your CALDERA server and key in Profile → API Keys → Emulation Tools", **base}
    try:
        _, client = _caldera(user)
        ags = client.agents()
        # Match agents to Shikari-managed machines so each node shows the environment it runs in.
        mach = machines.listing(user_id=user.id, is_admin=_is_admin(user))
        return {"configured": True, "url": client.url, "groups": caldera.groups(ags),
                "agents": caldera.agent_nodes(ags, mach, host_name), **base}
    except LabError as e:
        return {"configured": True, "error": e.message, "detail": e.detail, "groups": [], **base}


@router.post("/caldera/agent/forget")
async def caldera_agent_forget(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """Forget an agent from CALDERA — clears a dead or stale record from the topology. A sandcat
    still running on the host re-registers on its next beacon, so this never kills a live agent."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    data = await request.json()
    paw = str(data.get("paw", "")).strip()
    if not paw:
        return JSONResponse({"error": "No agent given"}, status_code=400)
    try:
        _, client = _caldera(user)
        client.delete_agent(paw)
        return {"ok": True}
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)


@router.post("/caldera/enrol")
async def caldera_enrol(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """Run a sandcat agent on an Shikari-managed machine, enrolling it as a CALDERA agent. Slow for a
    VM (it may still be settling), so it runs as a background job the page polls."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    data = await request.json()
    engine, name, os_name = data.get("engine", ""), data.get("name", ""), str(data.get("os", ""))
    if not _owns(user, engine, name):
        return _not_yours()
    try:
        cald, client = _caldera(user)
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)
    group, url = cald.GROUP_FOR.get(os_name, "disposable"), client.url
    return _background(f"Enrol {name} in CALDERA",
                       lambda say: cald.enrol_agent(engine, name, os_name, group, url, say=say))


@router.post("/caldera/provision-agent")
async def caldera_provision_agent(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """Create an Shikari-managed machine for an OS and enrol it as a CALDERA agent, in one job — the
    web half of `shikari-cli caldera provision`. Linux offers tart (VM) or docker (container)."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    from shikari.lab import templates
    data = await request.json()
    os_name = str(data.get("os", ""))
    engine = str(data.get("engine", "tart"))
    name = str(data.get("name", "")).strip()
    try:
        cald, client = _caldera(user)
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)
    # The modal sends the chosen template (its distro and engine are the template's own); older
    # callers may still send os+engine, so fall back to the Ubuntu map for those.
    template = str(data.get("template", "")).strip() or \
        {"linux": "ubuntu-container" if engine == "docker" else "ubuntu-vm", "macos": "macos-vm"}.get(os_name)
    if template not in templates.BY_ID or not name:
        return JSONResponse({"error": "Pick a machine and a name (Windows: build the UTM VM, then Enrol it)"},
                            status_code=400)
    os_name = templates.BY_ID[template]["os"]  # trust the template's own OS for the group
    group, url = cald.GROUP_FOR.get(os_name, "disposable"), client.url
    return _background(f"Provision {name} for CALDERA",
                       lambda say: cald.provision_for_caldera(template, name, group, url, owner=user.id, say=say))


@router.post("/caldera/operate")
async def caldera_operate(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """
    Plan a CALDERA operation for a group, CVE or technique list against an agent group.
    execute=false (the default) returns the plan and creates nothing; execute=true creates the
    adversary and starts the operation, then collects its results when it finishes.
    """
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    from shikari.config import GENERATE_DIR

    data = await request.json()
    kind, value = data.get("kind", "technique"), str(data.get("value", "")).strip()
    group, name, execute = str(data.get("group", "")).strip(), data.get("name", ""), bool(data.get("execute"))
    # capture: {engine:"caldera"} to capture over the agent's own C2 (no machine needed), or
    # {engine, name, os} of the lab machine the agent runs on for the hypervisor-exec path.
    capture = data.get("capture") or None
    if not group:
        return JSONResponse({"error": "Choose an agent group"}, status_code=400)
    try:
        caldera, client = _caldera(user)
        techs = caldera.resolve_techniques(kind, value, GENERATE_DIR)
        if not execute:
            p = caldera.plan(client.abilities(), client.agents(), techs, group)
            label = caldera.safe_name(name) if name else "shikari-operation"
            return {"preview": True, "plan": caldera.plan_lines(p, label), "warnings": p["warnings"],
                    "steps": p["steps"], "gaps": p["gaps"], "agents": p["agents"]}
        if capture and capture.get("engine") != "caldera" \
                and not _owns(user, capture.get("engine", ""), capture.get("name", "")):
            return _not_yours()
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)

    def work(say):
        run = caldera.operate(client, techs, group, name=name, target=f"{kind}: {value}", execute=True, say=say)
        state = caldera.wait(client, run["operation_id"], say=say)
        say(f"Operation finished: {state}")
        manifest = caldera.collect(client, run["operation_id"], say=say, rebuild=not capture)
        if capture:
            if capture.get("engine") == "caldera":
                caldera.capture_via_agent(client, manifest, say=say)
            else:
                caldera.capture(capture["engine"], capture["name"], capture.get("os", ""), manifest,
                                host=capture.get("host", ""), say=say)

    return _background(f"CALDERA operation on {group}", work)


@router.post("/caldera/plan-matrix")
async def caldera_plan_matrix(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """For the Detonate dialog: resolve a group/CVE/technique target to techniques, and show per
    agent group which VMs it has and which of those techniques each can run. Reads only."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    from shikari.config import GENERATE_DIR

    data = await request.json()
    kind, value = data.get("kind", "technique"), str(data.get("value", "")).strip()
    if not value:
        return JSONResponse({"error": "Choose a target"}, status_code=400)
    try:
        caldera, client = _caldera(user)
        techs = caldera.resolve_techniques(kind, value, GENERATE_DIR)
        if not techs:
            return JSONResponse({"error": f"Nothing resolved from {kind} {value!r}"}, status_code=400)
        return {"ok": True, **caldera.coverage(client.abilities(), client.agents(), techs)}
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)


@router.post("/caldera/detonate")
async def caldera_detonate(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """Run the target against one or more agent groups, capturing each step's logs over the agent's
    own C2 and checking detections against them. One background job runs the groups in turn."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    from shikari.config import GENERATE_DIR

    data = await request.json()
    kind, value = data.get("kind", "technique"), str(data.get("value", "")).strip()
    name = data.get("name", "")
    groups_sel = [str(g).strip() for g in (data.get("groups") or []) if str(g).strip()]
    if not value:
        return JSONResponse({"error": "Choose a target"}, status_code=400)
    if not groups_sel:
        return JSONResponse({"error": "Choose at least one agent group"}, status_code=400)
    try:
        caldera, client = _caldera(user)
        techs = caldera.resolve_techniques(kind, value, GENERATE_DIR)
        if not techs:
            return JSONResponse({"error": f"Nothing resolved from {kind} {value!r}"}, status_code=400)
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)

    def work(say):
        for group in groups_sel:
            say(f"— Group {group} —")
            try:
                run = caldera.operate(client, techs, group, name=name, target=f"{kind}: {value}",
                                      execute=True, say=say)
            except LabError as e:
                say(f"Skipped {group}: {e.message}")  # e.g. no ability this group can run — carry on
                continue
            state = caldera.wait(client, run["operation_id"], say=say)
            say(f"Operation on {group} finished: {state}")
            manifest = caldera.collect(client, run["operation_id"], say=say, rebuild=False)
            caldera.capture_via_agent(client, manifest, say=say)

    return _background(f"Detonate {kind} {value} on {', '.join(groups_sel)}", work)


@router.post("/caldera/provision")
def caldera_provision_run(shikari_session: Optional[str] = Cookie(None)):
    """Stand up a disposable CALDERA lab on this macOS host and save its URL/key to the user's
    profile (#30, Stage 1). Nothing detonates — this only installs and starts the server/agents.
    Progress is a structured task list on the job, which the Provision modal polls."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    from shikari.lab import caldera_provision as prov

    ok, why = prov.can_provision(_is_admin(user))
    if not ok:
        return JSONResponse({"error": "In-app provisioning isn't available here", "detail": why}, status_code=400)

    uid = user.id

    def save_key(url: str, key: str, verify_tls: bool):
        """Store the provisioned server's URL/key on the user, encrypted, like Profile does."""
        from shikari.auth.encryption import encrypt_api_key
        from shikari.database.models import APIKey, User

        db = next(get_db())
        try:
            u = db.query(User).filter(User.id == uid).first()
            if u:
                u.caldera_url = url.rstrip("/")
                u.caldera_verify_tls = verify_tls
            row = db.query(APIKey).filter(APIKey.user_id == uid, APIKey.platform == "caldera").first()
            if row:
                row.encrypted_key = encrypt_api_key(key)
            else:
                db.add(APIKey(user_id=uid, platform="caldera", encrypted_key=encrypt_api_key(key)))
            db.commit()
        finally:
            db.close()

    return _background("Provision CALDERA", lambda say: prov.provision(say, _task, save_key),
                       tasks=prov.initial_tasks())


@router.post("/caldera/deprovision")
def caldera_deprovision(shikari_session: Optional[str] = Cookie(None)):
    """Tear down the provisioned lab (stop the server, delete the agents) and remove CALDERA from
    the user's profile. Only where in-app provisioning is allowed."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    from shikari.lab import caldera_provision as prov

    ok, why = prov.can_provision(_is_admin(user))
    if not ok:
        return JSONResponse({"error": "In-app provisioning isn't available here", "detail": why}, status_code=400)

    uid = user.id

    def clear_key():
        from shikari.database.models import APIKey, User

        db = next(get_db())
        try:
            u = db.query(User).filter(User.id == uid).first()
            if u:
                u.caldera_url = None
            row = db.query(APIKey).filter(APIKey.user_id == uid, APIKey.platform == "caldera").first()
            if row:
                db.delete(row)
            db.commit()
        finally:
            db.close()

    def work(say):
        prov.deprovision(say)
        clear_key()
        say("CALDERA removed from your profile.")

    return _background("De-provision CALDERA", work)


@router.post("/caldera/collect")
async def caldera_collect(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """Pull an existing operation's results (one started in CALDERA itself, say)."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    data = await request.json()
    op_id = str(data.get("operation_id", "")).strip()
    if not op_id:
        return JSONResponse({"error": "Give the operation's id"}, status_code=400)
    try:
        caldera, client = _caldera(user)
    except LabError as e:
        return JSONResponse({"error": e.message, "detail": e.detail}, status_code=400)
    return _background(f"Collect CALDERA operation {op_id}", lambda say: caldera.collect(client, op_id, say=say))


@router.get("/caldera/operations")
def caldera_operations(shikari_session: Optional[str] = Cookie(None)):
    """The operations collected here, newest first, without their steps' output."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    from shikari.lab import caldera

    return {"operations": [{"name": m.get("name"), "operation_id": m.get("operation_id"), "state": m.get("state"),
                            "group": m.get("group"), "collected": m.get("collected"),
                            "steps": len(m.get("steps") or []),
                            "hosts": sorted({s.get("host") or s.get("paw") or "" for s in m.get("steps") or []}),
                            "captured": bool(m.get("captured"))}
                           for m in caldera.collected()]}


@router.get("/caldera/check")
def caldera_check(name: str, shikari_session: Optional[str] = Cookie(None)):
    """An operation's steps against the saved detections and correlations. Static; no AI."""
    user, denied = _lab(shikari_session)
    if denied:
        return denied
    from shikari.config import GENERATE_DIR
    from shikari.lab import caldera

    manifest = caldera.load(name)
    if not manifest:
        return JSONResponse({"error": "No such operation collected here"}, status_code=404)
    return {**caldera.check_operation(manifest, GENERATE_DIR),
            "correlations": caldera.check_correlations(manifest, GENERATE_DIR)}


@router.websocket("/console")
async def console_ws(websocket: WebSocket):
    """An interactive shell on a lab machine, bridged over the WebSocket (#28).

    Gated exactly like every other lab action: an operational analyst (or admin) who owns the machine.
    engine and name come as query params; pass `sid` to reconnect to a shell whose browser dropped (the
    scrollback is replayed). A `{"type":"resize",...}` text frame resizes the PTY, any other frame is
    keystrokes; output is binary. On connect the server sends `{"type":"session","sid":...}`, and
    `{"type":"exit"}` when the shell itself ends (so the client knows not to reconnect). The PTY survives
    a dropped socket for a grace window and is reaped if idle or abandoned (shikari.lab.console.REGISTRY).
    """
    import asyncio
    import json

    from shikari.lab.console import REGISTRY, ConsoleSession, console_argv, valid_name
    from shikari.lab.engines import engine_for

    engine = websocket.query_params.get("engine", "")
    name = websocket.query_params.get("name", "")
    sid = websocket.query_params.get("sid", "") or ""
    user = _user(websocket.cookies.get("shikari_session"))
    if not user or not _can_lab(user):
        await websocket.close(code=4401)
        return
    if engine not in ("docker", "tart", "utm") or not valid_name(name) or not _owns(user, engine, name):
        await websocket.close(code=4403)
        return

    managed = REGISTRY.get(sid, user.id, engine, name) if sid else None
    await websocket.accept()
    if managed is None:
        windows = "win" in name.lower()
        try:
            windows = windows or engine_for(engine).status(name).get("os") == "windows"
        except Exception:  # noqa: BLE001 — status is best-effort; the name heuristic still stands
            pass
        try:
            session = ConsoleSession(console_argv(engine, name, windows))
        except Exception as e:  # noqa: BLE001 — surface the reason, then close
            await websocket.send_text(f"\r\n[console failed: {e}]\r\n")
            await websocket.close()
            return
        sid = REGISTRY.create(user.id, engine, name, session)
        managed = REGISTRY.get(sid, user.id, engine, name)
    else:
        managed.attach()

    sess = managed.session
    await websocket.send_text(json.dumps({"type": "session", "sid": sid}))
    if managed.buf:  # replay scrollback to a reconnecting (or any) client
        await websocket.send_bytes(bytes(managed.buf))

    loop = asyncio.get_event_loop()
    outq: "asyncio.Queue" = asyncio.Queue()
    state = {"exited": False}

    def on_readable():
        data = sess.read()
        if data:
            managed.record(data)
            outq.put_nowait(data)
        elif not sess.alive():
            state["exited"] = True
            outq.put_nowait(None)  # the shell itself ended

    async def sender():
        while True:
            data = await outq.get()
            if data is None:
                break
            await websocket.send_bytes(data)
        if state["exited"]:
            try:
                await websocket.send_text(json.dumps({"type": "exit"}))
            except Exception:  # noqa: BLE001
                pass
        try:
            await websocket.close()
        except Exception:  # noqa: BLE001
            pass

    loop.add_reader(sess.fd, on_readable)
    send_task = asyncio.ensure_future(sender())
    try:
        while True:
            msg = await websocket.receive()
            if msg.get("type") == "websocket.disconnect":
                break
            if msg.get("bytes") is not None:
                sess.write(msg["bytes"])
                managed.touch()
            elif msg.get("text"):
                text = msg["text"]
                if text.startswith("{"):
                    try:
                        obj = json.loads(text)
                        if obj.get("type") == "resize":
                            sess.resize(obj.get("rows", 24), obj.get("cols", 80))
                            managed.touch()
                            continue
                    except ValueError:
                        pass
                sess.write(text.encode())
                managed.touch()
    except WebSocketDisconnect:
        pass
    finally:
        try:
            loop.remove_reader(sess.fd)
        except Exception:  # noqa: BLE001
            pass
        outq.put_nowait(None)
        try:
            await send_task
        except Exception:  # noqa: BLE001
            pass
        # Keep the shell for a reconnect if it's still alive; the reaper closes it after the grace
        # window (or sooner if idle). If it already exited, drop it now.
        if state["exited"] or not sess.alive():
            REGISTRY.drop(sid)
        else:
            managed.detach()


@router.get("/desktop-endpoint")
def desktop_endpoint_get(engine: str, name: str, shikari_session: Optional[str] = Cookie(None)):
    """Report a machine's graphical-console endpoint (VNC or SPICE) for the UI (#28)."""
    from shikari.lab import registry
    from shikari.lab.console import valid_name

    user = _user(shikari_session)
    if not user or not _can_lab(user):
        return JSONResponse({"error": "Please log in"}, status_code=401)
    if engine not in ("docker", "tart", "utm") or not valid_name(name) or not _owns(user, engine, name):
        return _not_yours()
    ep = registry.get_desktop(engine, name)
    return {"configured": bool(ep), "host": ep[0] if ep else "", "port": ep[1] if ep else None,
            "kind": ep[2] if ep else "vnc"}


@router.post("/desktop-endpoint")
async def desktop_endpoint_set(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """Set (or clear) a machine's trusted graphical-console endpoint and kind (vnc|spice). Owner/admin
    only; the host must be loopback/private — a lab console never bridges to the public internet (#28)."""
    from shikari.lab import desktop, registry
    from shikari.lab.console import valid_name

    user = _user(shikari_session)
    if not user or not _can_lab(user):
        return JSONResponse({"error": "Please log in"}, status_code=401)
    body = await request.json()
    engine = body.get("engine", "")
    name = body.get("name", "")
    if engine not in ("docker", "tart", "utm") or not valid_name(name) or not _owns(user, engine, name):
        return _not_yours()
    if body.get("clear"):
        registry.clear_desktop(engine, name)
        return {"configured": False}
    host = (body.get("host") or "").strip()
    port = body.get("port")
    kind = body.get("kind") or "vnc"
    if kind not in desktop.KINDS:
        return JSONResponse({"error": "kind must be vnc or spice"}, status_code=400)
    if not desktop.valid_endpoint(host, port):
        return JSONResponse({"error": "Endpoint must be a loopback/private host and a port 1-65535",
                             "detail": "e.g. 127.0.0.1:5900 (VNC) or 127.0.0.1:5930 (SPICE)"}, status_code=400)
    registry.set_desktop(engine, name, host, int(port), kind)
    return {"configured": True, "host": host, "port": int(port), "kind": kind}


@router.websocket("/desktop")
async def desktop_ws(websocket: WebSocket):
    """Bridge the browser to a machine's graphical console — VNC (noVNC) or SPICE (spice-html5) (#28).

    Gated like the text console: an operational analyst (or admin) who owns the machine. The target
    host:port is resolved from trusted per-machine config (registry.get_desktop) by engine+name — never
    from the request — so a caller can't aim the bridge anywhere (SSRF). The byte pump is protocol-
    agnostic; noVNC asks for the 'binary' subprotocol, so we echo any requested subprotocol back.
    """
    from shikari.lab import desktop, registry
    from shikari.lab.console import valid_name

    engine = websocket.query_params.get("engine", "")
    name = websocket.query_params.get("name", "")
    user = _user(websocket.cookies.get("shikari_session"))
    if not user or not _can_lab(user):
        await websocket.close(code=4401)
        return
    if engine not in ("docker", "tart", "utm") or not valid_name(name) or not _owns(user, engine, name):
        await websocket.close(code=4403)
        return
    ep = registry.get_desktop(engine, name)
    if not ep:
        await websocket.close(code=4404)  # no graphical endpoint configured for this machine
        return

    requested = websocket.scope.get("subprotocols") or []
    sub = requested[0] if requested else None
    await websocket.accept(subprotocol=sub)
    await desktop.bridge(websocket, ep[0], ep[1])

"""
The lifecycle of a lab machine, the same verbs for a container or a VM: create (from a
template), start, stop, snapshot, revert (to a snapshot), delete, status and logs. Each verb
dispatches to the engine that runs the machine (shikari.lab.engines).

A machine Shikari made is tagged in shikari.lab.registry with its template, so the page shows
its OS and what it records, and provisioning knows which script to run. Machines made outside
Shikari are listed too, just without that.
"""

from typing import Dict, List, Optional

from shikari.lab import registry
from shikari.lab.engines import ENGINES, engine_for
from shikari.lab.runner import LabError, safe_name
from shikari.lab.templates import BY_ID

# Engines whose VMs Shikari drives whether or not it made them: each lists every VM on the host,
# and one built by hand (in UTM, Hyper-V Manager or virt-manager) is adopted with Set OS.
HAND_BUILT = ("utm", "hyperv", "libvirt")


def _manageable(engine: str, owner, user_id, is_admin: bool) -> bool:
    """Who may act on a machine: an admin on any; its owner on their own; any operational analyst
    on an unclaimed UTM VM (built by hand outside Shikari, not yet adopted). An unclaimed Hyper-V
    or libvirt VM is an admin's to adopt: those hosts are often servers with VMs that aren't lab
    machines, where a Mac's UTM holds only what you built for it."""
    if is_admin:
        return True
    if owner is not None and owner == user_id:
        return True
    return engine == "utm" and owner is None


def _decorate(m: Dict, user_id=None, is_admin: bool = False) -> Dict:
    """Add what Shikari remembers about the machine to the engine's own view.

    A UTM VM counts as Shikari's the moment it exists — Shikari didn't make it, but it drives any
    UTM VM — so it shows even before it's adopted; its OS is unknown until you set it."""
    known = registry.get(m["engine"], m["name"])
    template = BY_ID.get((known or {}).get("template", ""))
    owner = (known or {}).get("owner")
    return {**m,
            "shikari": bool(known) or m["engine"] in HAND_BUILT,
            "adopted": bool(known),
            "os": (known or {}).get("os") or m.get("os") or "",
            "template": (known or {}).get("template", ""),
            "records": template["records"] if template else "",
            "provisioned": (known or {}).get("provisioned", []),
            "desktop": bool((known or {}).get("desktop")),
            "desktop_kind": ((known or {}).get("desktop") or {}).get("kind", ""),
            "owner": owner,
            "manageable": _manageable(m["engine"], owner, user_id, is_admin)}


def can_manage(engine_key: str, name: str, user_id, is_admin: bool) -> bool:
    """Whether this user may act on the machine (start, snapshot, delete, provision, record…)."""
    owner = (registry.get(engine_key, name) or {}).get("owner")
    return _manageable(engine_key, owner, user_id, is_admin)


def listing(engines: Optional[List[str]] = None, user_id=None, is_admin: bool = False) -> List[Dict]:
    """The machines Shikari made, across the engines given (default: all that are ready), that this
    user may see: an admin sees all; an operational analyst sees their own plus unclaimed UTM VMs.

    Anything built outside Shikari (a VM you cloned yourself, say) is left out — except UTM VMs,
    which Shikari drives whether or not it made them."""
    out = []
    for key, engine in ENGINES.items():
        if engines is not None and key not in engines:
            continue
        try:
            out += [d for d in (_decorate(m, user_id, is_admin) for m in engine.list())
                    if d["shikari"] and d["manageable"]]
        except LabError:
            continue  # an engine that isn't running doesn't stop the others
    out.sort(key=lambda m: (m["engine"], m["name"]))
    return out


def adopt(engine_key: str, name: str, os_name: str, owner=None, access: Optional[Dict] = None) -> Dict:
    """Tell Shikari what OS a VM it didn't create runs, so it can provision and record it, and
    claim it for `owner`. For UTM, Hyper-V and libvirt VMs built by hand. `access` is how to get in
    where the engine has no agent of its own (Hyper-V): user and password for PowerShell Direct, or
    user, key and host for SSH; registry.set_access keeps it."""
    name = safe_name(name)
    if os_name not in ("windows", "linux", "macos"):
        raise LabError("Unknown OS", "Pick windows, linux or macos")
    known = registry.get(engine_key, name) or {}
    registry.record(engine_key, name, known.get("template") or f"{engine_key}-vm", os_name,
                    known.get("image", ""), owner=owner)
    access = {k: str(v).strip() for k, v in (access or {}).items() if k in ("user", "password", "key", "host") and v}
    if access:
        registry.set_access(engine_key, name, **access)
    return {"engine": engine_key, "name": name, "os": os_name}


def clone(engine_key: str, name: str, new_name: str, owner=None) -> Dict:
    """Clone an existing VM into a new Shikari-managed machine — the fast Windows path: copy a
    prepared VM rather than install one from an ISO. UTM only (its engine has clone). The clone
    inherits the source's OS when Shikari knows it, so Set up and Record work on it straight away;
    otherwise set the OS on it afterwards. The clone is owned by `owner`."""
    engine, name = _op(engine_key, name)
    engine_clone = getattr(engine, "clone", None)
    if engine_clone is None:
        raise LabError("This engine can't clone a machine", engine_key)
    new_name = safe_name(new_name)
    os_name = (registry.get(engine_key, name) or {}).get("os") or ""
    engine_clone(name, new_name)
    registry.record(engine_key, new_name, f"{engine_key}-vm", os_name, "", owner=owner)
    return {"engine": engine_key, "name": new_name, "os": os_name}


def all_host_names(engines: Optional[List[str]] = None) -> List[str]:
    """Every machine name the engines report, Shikari's and not (Tart lists all its VMs; Docker
    lists Shikari's containers) — so the create dialog can suggest a name that won't collide."""
    names = []
    for key, engine in ENGINES.items():
        if engines is not None and key not in engines:
            continue
        try:
            names += [m["name"] for m in engine.list()]
        except LabError:
            continue
    if engines is None or "tart" in engines:
        from shikari.lab.engines import parse_tart_list_raw

        try:
            names += parse_tart_list_raw()  # includes VMs and snapshots outside Shikari
        except LabError:
            pass
    return names


def create(template_id: str, name: str, owner=None) -> Dict:
    template = BY_ID.get(template_id)
    if not template:
        raise LabError("Unknown template", template_id)
    name = safe_name(name)
    import shikari.lab.hosts as hosts

    arch = hosts.arch()
    image = (template.get("image") or {}).get(arch)
    if not image:
        raise LabError(f"{template['name']} can't run on this machine",
                       f"no image built for {arch}")
    engine = engine_for(template["engine"])
    engine.create(name, image, **(template.get("create") or {}))
    registry.record(template["engine"], name, template_id, template["os"], image, owner=owner)
    return {"name": name, "engine": template["engine"], "template": template_id}


def create_from_image(engine_key: str, name: str, image: str, os_name: str, owner=None,
                      access: Optional[Dict] = None) -> Dict:
    """Create a VM from your own disk image or ISO, on an engine that takes one (Hyper-V: VHDX,
    VHD, qcow2 or ISO; libvirt: qcow2 or ISO) — the way to a Windows machine there, since no
    template can carry Windows. From an ISO the OS is installed by you, over the VM's console."""
    engine = engine_for(engine_key)
    if not getattr(engine, "from_image", False):
        raise LabError("This engine creates only from templates", engine_key)
    if os_name not in ("windows", "linux"):
        raise LabError("Unknown OS", "Pick windows or linux")
    name = safe_name(name)
    engine.create(name, image, os_name=os_name)
    registry.record(engine_key, name, f"{engine_key}-vm", os_name, image, owner=owner)
    access = {k: str(v).strip() for k, v in (access or {}).items() if k in ("user", "password", "key", "host") and v}
    if access:
        registry.set_access(engine_key, name, **access)
    return {"name": name, "engine": engine_key, "os": os_name}


def _op(engine_key: str, name: str):
    return engine_for(engine_key), safe_name(name)


def start(engine_key: str, name: str):
    e, name = _op(engine_key, name)
    e.start(name)


def stop(engine_key: str, name: str):
    e, name = _op(engine_key, name)
    e.stop(name)


def snapshot(engine_key: str, name: str, snapshot_name: str) -> Dict:
    e, name = _op(engine_key, name)
    snap = safe_name(snapshot_name)
    e.snapshot(name, snap)
    return {"snapshot": snap}


def revert(engine_key: str, name: str, snapshot_name: str):
    e, name = _op(engine_key, name)
    e.revert(name, safe_name(snapshot_name))


def delete(engine_key: str, name: str):
    e, name = _op(engine_key, name)
    e.delete(name)
    registry.forget(engine_key, name)


def status(engine_key: str, name: str) -> Dict:
    e, name = _op(engine_key, name)
    return _decorate(e.status(name))


def logs(engine_key: str, name: str, tail: int = 200) -> str:
    e, name = _op(engine_key, name)
    return e.logs(name, tail)

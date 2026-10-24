"""
The lifecycle of a lab machine, the same verbs for a container or a VM: create (from a
template), start, stop, snapshot, revert (to a snapshot), delete, status and logs. Each verb
dispatches to the engine that runs the machine (archer.lab.engines).

A machine Archer made is tagged in archer.lab.registry with its template, so the page shows
its OS and what it records, and provisioning knows which script to run. Machines made outside
Archer are listed too, just without that.
"""

from typing import Dict, List, Optional

from archer.lab import registry
from archer.lab.engines import ENGINES, engine_for
from archer.lab.runner import LabError, safe_name
from archer.lab.templates import BY_ID


def _decorate(m: Dict) -> Dict:
    """Add what Archer remembers about the machine to the engine's own view."""
    known = registry.get(m["engine"], m["name"])
    template = BY_ID.get((known or {}).get("template", ""))
    return {**m,
            "archer": bool(known),
            "os": (known or {}).get("os") or m.get("os") or "",
            "template": (known or {}).get("template", ""),
            "records": template["records"] if template else "",
            "provisioned": (known or {}).get("provisioned", [])}


def listing(engines: Optional[List[str]] = None) -> List[Dict]:
    """The machines Archer made, across the engines given (default: all that are ready).

    Only machines in the registry are returned — anything built outside Archer (a VM you
    cloned yourself, say) is left out, since Archer can't vouch for how it's set up."""
    out = []
    for key, engine in ENGINES.items():
        if engines is not None and key not in engines:
            continue
        try:
            out += [d for d in (_decorate(m) for m in engine.list()) if d["archer"]]
        except LabError:
            continue  # an engine that isn't running doesn't stop the others
    out.sort(key=lambda m: (m["engine"], m["name"]))
    return out


def all_host_names(engines: Optional[List[str]] = None) -> List[str]:
    """Every machine name the engines report, Archer's and not (Tart lists all its VMs; Docker
    lists Archer's containers) — so the create dialog can suggest a name that won't collide."""
    names = []
    for key, engine in ENGINES.items():
        if engines is not None and key not in engines:
            continue
        try:
            names += [m["name"] for m in engine.list()]
        except LabError:
            continue
    if engines is None or "tart" in engines:
        from archer.lab.engines import parse_tart_list_raw

        try:
            names += parse_tart_list_raw()  # includes VMs and snapshots outside Archer
        except LabError:
            pass
    return names


def create(template_id: str, name: str) -> Dict:
    template = BY_ID.get(template_id)
    if not template:
        raise LabError("Unknown template", template_id)
    name = safe_name(name)
    import archer.lab.hosts as hosts

    arch = hosts.arch()
    image = (template.get("image") or {}).get(arch)
    if not image:
        raise LabError(f"{template['name']} can't run on this machine",
                       f"no image built for {arch}")
    engine = engine_for(template["engine"])
    engine.create(name, image)
    registry.record(template["engine"], name, template_id, template["os"], image)
    return {"name": name, "engine": template["engine"], "template": template_id}


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

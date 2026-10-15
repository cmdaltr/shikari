"""
Saved ATT&CK Flow edits.

A logged-in user's edits to a group's flow persist once that group's results are
in their library. Saving to the library tags each item "Group:<name>" or
"CVE:<id>", and that tag is what marks a group's results as saved.
"""

import json
import math
import re
from typing import Dict, Iterable, Optional

import os

from fastapi import APIRouter, Cookie, HTTPException, Request
from fastapi.responses import JSONResponse

from archer.database.db import get_db
from archer.database.models import FlowLayout, LibraryCorrelation, LibraryDetection

router = APIRouter(prefix="/api", tags=["attack-flow"])

MAX_BODY = 256 * 1024
MAX_ITEMS = 5000
MAX_OFFSET = 50000
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_VENDORS = {"googlesecops", "mde", "splunk", "elastic"}


def library_tag(group_name: str) -> str:
    """The tag the results page's Save to Library gives this group's items."""
    if group_name.upper().startswith("CVE-"):
        return f"CVE:{group_name}"
    return f"Group:{group_name.replace('_', ' ')}"


def results_in_library(db, user_id: int, group_name: str) -> bool:
    # Tags are stored as a JSON array, so match the quoted, JSON-escaped tag
    needle = json.dumps(library_tag(group_name))
    for model in (LibraryDetection, LibraryCorrelation):
        hit = (db.query(model.id)
               .filter(model.user_id == user_id, model.tags.contains(needle, autoescape=True))
               .first())
        if hit:
            return True
    return False


def group_from_tag(tag: str) -> Optional[str]:
    """The results-page group name a library tag belongs to, or None for other tags."""
    from archer.security import sanitize_group_name

    if not isinstance(tag, str):
        return None
    if tag.startswith("CVE:"):
        return tag[4:] or None
    if tag.startswith("Group:"):
        return sanitize_group_name(tag[6:]) or None
    return None


def library_groups(db, user_id: int) -> set:
    """The results-page group names of everything the user has saved to their library."""
    groups = set()
    for model in (LibraryDetection, LibraryCorrelation):
        for (raw,) in db.query(model.tags).filter(model.user_id == user_id).all():
            try:
                tags = json.loads(raw) if raw else []
            except (ValueError, TypeError):
                continue
            groups.update(g for g in map(group_from_tag, tags if isinstance(tags, list) else []) if g)
    return groups


def library_flows(db, user_id: int, bundle=None) -> list:
    """
    The attack flows of the user's library: one per saved group, CVE or report, from the
    flow view the results page last saved (data/attack_flows/<group>_flow_view.json).
    kind: "Threat group" (an ATT&CK group), "CVE", "Technique hunt", "Company profile" or
    "Report". view is None when the results page hasn't built the flow yet.
    """
    from datetime import datetime

    from archer.build.progress import read_progress
    from archer.config import ATTACK_FLOWS_DIR

    attack_groups = set()
    for obj in getattr(bundle, "objects", None) or []:
        if obj.get("type") == "intrusion-set":
            attack_groups.update(n.lower() for n in [obj.get("name", "")] + list(obj.get("aliases") or []))
    flows = []
    for group in library_groups(db, user_id):
        path = os.path.join(ATTACK_FLOWS_DIR, f"{group}_flow_view.json")
        view, saved = None, None
        if os.path.dirname(os.path.abspath(path)) == os.path.abspath(ATTACK_FLOWS_DIR) and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    view = json.load(fh).get("view")
                saved = datetime.fromtimestamp(os.path.getmtime(path))
            except (OSError, ValueError):
                view = None
        source = (read_progress(group) or {}).get("source_type")
        if group.upper().startswith("CVE-") or source == "cve":
            kind = "CVE"
        elif source == "technique_hunt" or group.startswith("Hunt_"):
            kind = "Technique hunt"
        elif source == "profile":
            kind = "Company profile"
        elif group.replace("_", " ").lower() in attack_groups or group.lower() in attack_groups:
            kind = "Threat group"
        else:
            kind = "Report"
        flows.append({"group": group, "label": group.replace("_", " "), "kind": kind, "view": view,
                      "saved": saved, "stats": (view or {}).get("stats") or {}})
    order = {"Threat group": 0, "Report": 1, "CVE": 2, "Technique hunt": 3, "Company profile": 4}
    return sorted(flows, key=lambda f: (order.get(f["kind"], 9), f["label"].lower()))


def prune_layouts(db, user_id: int, tag_lists: Iterable[Optional[str]]) -> int:
    """
    Delete the saved layouts of groups no longer in the user's library.

    tag_lists: the JSON tag arrays of library items just deleted or retagged.
    Call after those changes are flushed and before the commit.
    """
    groups = set()
    for raw in tag_lists:
        try:
            tags = json.loads(raw) if raw else []
        except (ValueError, TypeError):
            continue
        groups.update(g for g in map(group_from_tag, tags if isinstance(tags, list) else []) if g)
    removed = 0
    for group in groups:
        if not results_in_library(db, user_id, group):
            removed += (db.query(FlowLayout)
                        .filter(FlowLayout.user_id == user_id, FlowLayout.group_name == group)
                        .delete(synchronize_session=False))
    return removed


def clean_state(raw) -> Dict:
    """Keep only well-formed fields; anything else is dropped rather than stored."""
    if not isinstance(raw, dict):
        raise ValueError("state must be an object")
    out: Dict = {}
    for key in ("gaps", "edges", "vertical", "reversed"):
        if isinstance(raw.get(key), bool):
            out[key] = raw[key]
    if isinstance(raw.get("vendors"), list):
        out["vendors"] = [v for v in raw["vendors"] if v in _VENDORS]
    if isinstance(raw.get("removed"), list):
        out["removed"] = [t for t in raw["removed"][:MAX_ITEMS] if isinstance(t, str) and _TECHNIQUE.match(t)]
    if isinstance(raw.get("unlinked"), list):
        out["unlinked"] = [
            k for k in raw["unlinked"][:MAX_ITEMS]
            if isinstance(k, str) and k.count(">") == 1 and all(_TECHNIQUE.match(p) for p in k.split(">"))
        ]
    if isinstance(raw.get("offsets"), dict):
        offsets = {}
        for tid, xy in list(raw["offsets"].items())[:MAX_ITEMS]:
            if (isinstance(tid, str) and _TECHNIQUE.match(tid) and isinstance(xy, list) and len(xy) == 2
                    and all(isinstance(n, (int, float)) and not isinstance(n, bool) and math.isfinite(n) for n in xy)):
                offsets[tid] = [max(-MAX_OFFSET, min(MAX_OFFSET, round(float(n), 1))) for n in xy]
        out["offsets"] = offsets
    return out


def load_layout(db, user_id: int, group_name: str) -> Optional[Dict]:
    row = db.query(FlowLayout).filter(FlowLayout.user_id == user_id, FlowLayout.group_name == group_name).first()
    if not row:
        return None
    try:
        return clean_state(json.loads(row.state))
    except (ValueError, TypeError):
        return None


def save_layout(db, user_id: int, group_name: str, state: Dict) -> None:
    row = db.query(FlowLayout).filter(FlowLayout.user_id == user_id, FlowLayout.group_name == group_name).first()
    if row:
        row.state = json.dumps(state)
    else:
        db.add(FlowLayout(user_id=user_id, group_name=group_name, state=json.dumps(state)))
    db.commit()


@router.put("/flow-layout")
async def put_flow_layout(request: Request, archer_session: Optional[str] = Cookie(None)):
    from archer.auth import get_user_from_session_id
    from archer.security import sanitize_group_name

    if not archer_session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(status_code=413, detail="Layout too large")
    try:
        payload = json.loads(body)
        group_name = sanitize_group_name(str(payload["group_name"]))
        state = clean_state(payload["state"])
    except (ValueError, KeyError, TypeError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid layout: {e}")
    if not group_name:
        raise HTTPException(status_code=400, detail="Invalid group name")

    db = next(get_db())
    try:
        user = get_user_from_session_id(archer_session, db)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if not results_in_library(db, user.id, group_name):
            raise HTTPException(status_code=409, detail="Save this group's results to your library first")
        save_layout(db, user.id, group_name, state)
        return {"saved": True}
    finally:
        db.close()


@router.post("/attack-flow/export")
async def export_edited_flow(request: Request):
    """The results page's flow, with the viewer's edits applied, as an Attack Flow 2.x bundle."""
    from archer.config import ATTACK_FLOWS_DIR
    from archer.security import sanitize_group_name
    from archer.visualization.flow_view import apply_edits, to_attack_flow_bundle

    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(status_code=413, detail="Edits too large")
    try:
        payload = json.loads(body)
        group_name = sanitize_group_name(str(payload["group_name"]))
        state = clean_state(payload.get("state") or {})
    except (ValueError, KeyError, TypeError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid request: {e}")
    path = os.path.join(ATTACK_FLOWS_DIR, f"{group_name}_flow_view.json")
    if not group_name or os.path.dirname(os.path.abspath(path)) != os.path.abspath(ATTACK_FLOWS_DIR):
        raise HTTPException(status_code=400, detail="Invalid group name")
    try:
        with open(path, encoding="utf-8") as fh:
            saved = json.load(fh)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="No flow for this group: open its results page first")
    bundle = to_attack_flow_bundle(apply_edits(saved["view"], state), saved.get("group_name") or group_name)
    return JSONResponse(bundle, headers={
        "Content-Disposition": f'attachment; filename="{group_name}_edited_flow.json"'})

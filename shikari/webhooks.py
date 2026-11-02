"""
Webhooks: Shikari POSTs JSON to URLs an admin registers when something happens (#35).

Events
    run.completed    a hunt finished: {run, phase, created_yaml, results_url}
    run.failed       a hunt stopped with an error: {run, status, error}
    watchlist.match  a Threat Feed watchlist found new posts: {user_id, matches: [{query, title, url}]}

Each delivery is {"event", "sent_at", "data"}, with X-Shikari-Event and, when the webhook has a
secret, X-Shikari-Signature: sha256=<hex HMAC-SHA256 of the raw body>, so the receiver can check
it came from this server. Deliveries run on a background thread, three tries with backoff; the
last 20 are kept per webhook for the admin page. Registered webhooks (with their secrets) live in
data/webhooks.json, which never leaves the install.
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, Cookie, Request
from fastapi.responses import JSONResponse

from shikari import paths

EVENTS = ("run.completed", "run.failed", "watchlist.match")
KEEP_DELIVERIES = 20
TRIES = 3
_lock = threading.Lock()


def _path() -> str:
    return str(paths.DATA / "webhooks.json")


def _load() -> List[Dict]:
    try:
        with open(_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return []


def _save(hooks: List[Dict]) -> None:
    os.makedirs(os.path.dirname(_path()), exist_ok=True)
    tmp = _path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(hooks, fh, indent=2)
    os.replace(tmp, _path())


def _public(hook: Dict) -> Dict:
    """A webhook as the API shows it: the secret only as whether there is one."""
    return {**{k: v for k, v in hook.items() if k != "secret"}, "has_secret": bool(hook.get("secret"))}


def validate(url: str, events: List[str]) -> Optional[str]:
    """Why a webhook can't be saved, or None."""
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return "The URL must be http:// or https://"
    unknown = set(events or []) - set(EVENTS)
    if not events or unknown:
        return f"Choose events from {', '.join(EVENTS)}"
    return None


def add(url: str, events: List[str], secret: Optional[str] = None, description: str = "") -> Dict:
    hook = {"id": secrets.token_hex(6), "url": url.strip(), "events": sorted(set(events)),
            "secret": secret if secret is not None else secrets.token_urlsafe(24),
            "description": description.strip(), "enabled": True, "created": time.time(), "deliveries": []}
    with _lock:
        hooks = _load()
        hooks.append(hook)
        _save(hooks)
    return hook


def update(hook_id: str, **fields) -> Optional[Dict]:
    with _lock:
        hooks = _load()
        for hook in hooks:
            if hook["id"] == hook_id:
                hook.update({k: v for k, v in fields.items() if k in ("url", "events", "enabled", "description")})
                _save(hooks)
                return hook
    return None


def remove(hook_id: str) -> bool:
    with _lock:
        hooks = _load()
        kept = [h for h in hooks if h["id"] != hook_id]
        _save(kept)
    return len(kept) != len(hooks)


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _record(hook_id: str, delivery: Dict) -> None:
    with _lock:
        hooks = _load()
        for hook in hooks:
            if hook["id"] == hook_id:
                hook["deliveries"] = ([delivery] + hook.get("deliveries", []))[:KEEP_DELIVERIES]
                _save(hooks)
                return


def deliver(hook: Dict, event: str, data: Dict, tries: int = TRIES, backoff: float = 2.0) -> Dict:
    """POST one event to one webhook; returns the delivery record (also kept on the webhook)."""
    body = json.dumps({"event": event, "sent_at": time.time(), "data": data}, default=str).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Shikari-Webhook/1", "X-Shikari-Event": event}
    if hook.get("secret"):
        headers["X-Shikari-Signature"] = sign(hook["secret"], body)
    result = {"event": event, "at": time.time(), "ok": False, "status": None, "error": None, "tries": 0}
    for attempt in range(tries):
        result["tries"] = attempt + 1
        try:
            r = requests.post(hook["url"], data=body, headers=headers, timeout=10)
            result["status"] = r.status_code
            if r.status_code < 300:
                result.update(ok=True, error=None)
                break
            result["error"] = f"HTTP {r.status_code}"
            if r.status_code < 500 and r.status_code != 429:
                break  # the receiver refused it; trying again won't change that
        except requests.RequestException as e:
            result["error"] = str(e)[:200]
        if attempt < tries - 1:
            time.sleep(backoff * (attempt + 1))
    _record(hook["id"], result)
    return result


def emit(event: str, data: Dict) -> int:
    """Send an event to every enabled webhook that wants it, in the background. Returns how many."""
    targets = [h for h in _load() if h.get("enabled") and event in h.get("events", [])]
    for hook in targets:
        threading.Thread(target=deliver, args=(hook, event, data), daemon=True, name=f"webhook-{hook['id']}").start()
    return len(targets)


def emit_run(group_name: str, progress: Dict) -> None:
    """A run's terminal progress record, as run.completed or run.failed."""
    status = progress.get("status")
    if status in ("error", "failed", "cancelled"):
        emit("run.failed", {"run": group_name, "status": status, "error": progress.get("error") or progress.get("message")})
    else:
        base = (os.getenv("SHIKARI_PUBLIC_URL") or "").rstrip("/")
        emit("run.completed", {"run": group_name, "phase": progress.get("phase"),
                               "created_yaml": progress.get("created_yaml"),
                               "results_url": f"{base}/results/{group_name}" if base else f"/results/{group_name}"})


router = APIRouter()


def _admin(shikari_session: Optional[str]):
    from shikari.auth import get_user_from_session_id
    from shikari.database.db import get_db
    from shikari.database.models import UserRole, at_least

    if not shikari_session:
        return JSONResponse({"error": "Please log in"}, status_code=401)
    db = next(get_db())
    try:
        user = get_user_from_session_id(shikari_session, db)
    finally:
        db.close()
    if not user:
        return JSONResponse({"error": "Please log in"}, status_code=401)
    if not at_least(user, UserRole.ADMIN):
        return JSONResponse({"error": "Webhooks are an admin setting"}, status_code=403)
    return None


@router.get("/api/webhooks")
def list_webhooks(shikari_session: Optional[str] = Cookie(None)):
    denied = _admin(shikari_session)
    if denied:
        return denied
    return {"events": list(EVENTS), "webhooks": [_public(h) for h in _load()]}


@router.post("/api/webhooks")
async def create_webhook(request: Request, shikari_session: Optional[str] = Cookie(None)):
    """{"url", "events": [...], "secret"?: str, "description"?: str}. The secret is generated when
    not given, and returned once here; afterwards the API only says whether there is one."""
    denied = _admin(shikari_session)
    if denied:
        return denied
    body = await request.json()
    problem = validate(body.get("url"), body.get("events"))
    if problem:
        return JSONResponse({"error": problem}, status_code=400)
    hook = add(body["url"], body["events"], body.get("secret"), body.get("description") or "")
    return {**_public(hook), "secret": hook["secret"]}


@router.patch("/api/webhooks/{hook_id}")
async def edit_webhook(hook_id: str, request: Request, shikari_session: Optional[str] = Cookie(None)):
    denied = _admin(shikari_session)
    if denied:
        return denied
    body = await request.json()
    current = next((h for h in _load() if h["id"] == hook_id), None)
    if not current:
        return JSONResponse({"error": "No such webhook"}, status_code=404)
    problem = validate(body.get("url", current["url"]), body.get("events", current["events"]))
    if problem:
        return JSONResponse({"error": problem}, status_code=400)
    return _public(update(hook_id, **body))


@router.delete("/api/webhooks/{hook_id}")
def delete_webhook(hook_id: str, shikari_session: Optional[str] = Cookie(None)):
    denied = _admin(shikari_session)
    if denied:
        return denied
    return {"deleted": remove(hook_id)}


@router.post("/api/webhooks/{hook_id}/test")
def test_webhook(hook_id: str, shikari_session: Optional[str] = Cookie(None)):
    """Send a run.completed for a made-up run now, and wait for the answer."""
    denied = _admin(shikari_session)
    if denied:
        return denied
    hook = next((h for h in _load() if h["id"] == hook_id), None)
    if not hook:
        return JSONResponse({"error": "No such webhook"}, status_code=404)
    return deliver(hook, "run.completed", {"run": "Shikari webhook test", "test": True}, tries=1)

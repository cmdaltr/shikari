"""
Which AI provider and model each job uses, per user (GitHub #10).

Two jobs, each assigned independently, to the same provider/model or different ones:
  ask        Ask Shikari
  detection  detection generation (the Hunt prompt preselects it, a hunt can override)

Providers are the ones the user has configured: a cloud provider counts once its API key
is saved in the profile; the local provider once an OpenAI-compatible endpoint is
(Ollama, LM Studio, llama.cpp; its key is optional). Keys stay encrypted in api_keys;
everything else lives in ai_settings as JSON:

  {"models": {"anthropic": "claude-...", ...},
   "local": {"endpoint": "http://localhost:11434", "model": "qwen3:8b"},
   "ask": {"provider": "local", "model": "qwen3:8b"} | null,
   "detection": {"provider": "anthropic", "model": ""} | null,
   "remember": {"provider": "anthropic", "model": ""} | {"provider": null} | null,
   "max_detection_calls": 25}
"""

import json
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# id -> (label, default model shown as the placeholder; "" = the provider class default)
CLOUD_PROVIDERS = {
    "anthropic": ("Anthropic Claude", "claude-sonnet-5-5"),
    "openai": ("OpenAI", "gpt-4o"),
    "google": ("Google Gemini", "gemini-2.0-flash"),
    "deepseek": ("DeepSeek", "deepseek-chat"),
    "qwen": ("Qwen (DashScope)", "qwen-plus"),
    "grok": ("Grok (xAI)", "grok-2-latest"),
}
LOCAL = "local"
JOBS = ("ask", "detection")
DEFAULT_MAX_DETECTION_CALLS = 25
# Local models can't yet produce usable detections from the full prompt (GitHub #9)
LOCAL_DETECTION_BLOCKED = "Local models are Ask only until local detection generation lands (GitHub #9)"


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def load_settings(db, user_id: int) -> Dict:
    from shikari.database.models import AISettings

    row = db.query(AISettings).filter(AISettings.user_id == user_id).first()
    try:
        data = json.loads(row.settings) if row and row.settings else {}
    except ValueError:
        data = {}
    data.setdefault("models", {})
    data.setdefault("local", {})
    data.setdefault("max_detection_calls", DEFAULT_MAX_DETECTION_CALLS)
    for job in JOBS:
        data.setdefault(job, None)
    data.setdefault("remember", None)
    return data


def save_settings(db, user_id: int, data: Dict) -> None:
    from shikari.database.models import AISettings

    row = db.query(AISettings).filter(AISettings.user_id == user_id).first()
    if row is None:
        row = AISettings(user_id=user_id, settings="{}")
        db.add(row)
    row.settings = json.dumps(data)
    db.commit()


def stored_keys(db, user_id: int) -> Dict[str, str]:
    """{platform: decrypted key} for the user's saved keys."""
    from shikari.auth.encryption import decrypt_api_key
    from shikari.database.models import APIKey

    keys = {}
    for row in db.query(APIKey).filter(APIKey.user_id == user_id).all():
        try:
            keys[row.platform] = decrypt_api_key(row.encrypted_key)
        except Exception as e:
            logger.warning("Could not decrypt the %s key: %s", row.platform, e)
    return keys


# ---------------------------------------------------------------------------
# Providers and resolution
# ---------------------------------------------------------------------------

def configured_providers(db, user_id: int, settings: Optional[Dict] = None,
                         keys: Optional[Dict[str, str]] = None) -> List[Dict]:
    """The providers this user can pick from, in the order the UI lists them."""
    settings = settings if settings is not None else load_settings(db, user_id)
    keys = keys if keys is not None else stored_keys(db, user_id)
    out = []
    for pid, (label, default_model) in CLOUD_PROVIDERS.items():
        if keys.get(pid):
            out.append({"id": pid, "label": label, "kind": "cloud",
                        "model": settings["models"].get(pid) or default_model,
                        "detection": True})
    local = settings.get("local") or {}
    if local.get("endpoint"):
        host = urlparse(local["endpoint"]).netloc or local["endpoint"]
        out.append({"id": LOCAL, "label": f"Local ({host})", "kind": "local",
                    "model": local.get("model") or "", "detection": False,
                    "detection_note": LOCAL_DETECTION_BLOCKED})
    return out


def resolve(db, user_id: int, job: str, provider: Optional[str] = None,
            model: Optional[str] = None) -> Optional[Dict]:
    """
    The provider for a job: the explicit choice (a hunt's override) when given,
    otherwise the job's assignment. None when nothing is assigned or the choice isn't
    configured. Carries the credentials the call needs; never sent to the browser.
    """
    settings = load_settings(db, user_id)
    keys = stored_keys(db, user_id)
    if not provider:
        assigned = settings.get(job) or {}
        provider, model = assigned.get("provider"), model or assigned.get("model")
    if not provider:
        return None
    available = {p["id"]: p for p in configured_providers(db, user_id, settings, keys)}
    if provider not in available:
        logger.warning("AI provider %r for %s is not configured for this user", provider, job)
        return None
    entry = available[provider]
    if job == "detection" and not entry["detection"]:
        logger.warning("%s: %s", entry["label"], LOCAL_DETECTION_BLOCKED)
        return None
    resolved = {"provider": provider, "label": entry["label"], "model": model or entry["model"]}
    if provider == LOCAL:
        resolved["endpoint"] = settings["local"]["endpoint"].rstrip("/")
        resolved["api_key"] = keys.get(LOCAL) or ""
    else:
        resolved["api_key"] = keys[provider]
    if job == "detection":
        resolved["max_calls"] = int(settings.get("max_detection_calls") or DEFAULT_MAX_DETECTION_CALLS)
    return resolved


def create_llm(resolved: Dict):
    """An shikari.ai.llm.providers.LLMProvider for a resolved choice."""
    from shikari.ai.llm.providers import LLMFactory, OllamaProvider, OpenAICompatibleProvider

    if resolved["provider"] != LOCAL:
        return LLMFactory.create(resolved["provider"], api_key=resolved["api_key"], model=resolved["model"] or None)
    endpoint = resolved["endpoint"]
    if is_ollama(endpoint):
        return OllamaProvider(base_url=endpoint, model=resolved["model"] or "llama3.1:8b")
    base = endpoint if endpoint.endswith("/v1") else endpoint + "/v1"
    return OpenAICompatibleProvider("local", base, api_key=resolved.get("api_key"),
                                    model=resolved["model"] or "default", requires_key=False)


def detection_llm_config(resolved: Dict) -> Dict:
    """llm_queries.call_llm config for detection generation (via the same factory)."""
    return {
        "provider": resolved["provider"],
        "api_key": resolved.get("api_key"),
        "model": resolved.get("model"),
        "endpoint": resolved.get("endpoint"),
        "via_factory": True,
        "max_calls": resolved.get("max_calls", DEFAULT_MAX_DETECTION_CALLS),
        "label": resolved.get("label"),
    }


# ---------------------------------------------------------------------------
# Local endpoints
# ---------------------------------------------------------------------------

def is_ollama(endpoint: str) -> bool:
    import requests

    try:
        return requests.get(f"{endpoint.rstrip('/')}/api/version", timeout=3).ok
    except Exception:
        return False


def probe_local(endpoint: str, api_key: str = "") -> Dict:
    """
    Reachability and model list for a local OpenAI-compatible endpoint. Only the two
    fixed listing paths are fetched (Ollama's /api/tags, the OpenAI /v1/models).
    """
    import requests
    from urllib.parse import urlparse

    endpoint = (endpoint or "").strip().rstrip("/")
    parsed = urlparse(endpoint)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path not in ("", "/v1"):
        return {"ok": False, "error": "Use the server's base URL, e.g. http://localhost:11434"}
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    base = endpoint[:-3] if endpoint.endswith("/v1") else endpoint
    try:
        r = requests.get(f"{base}/api/tags", timeout=4)
        if r.ok and "models" in r.json():
            return {"ok": True, "kind": "ollama", "models": [m["name"] for m in r.json()["models"] if m.get("name")]}
    except Exception:
        pass
    try:
        r = requests.get(f"{base}/v1/models", headers=headers, timeout=4)
        if r.ok:
            return {"ok": True, "kind": "openai", "models": [m["id"] for m in r.json().get("data", []) if m.get("id")]}
        return {"ok": False, "error": f"{base}/v1/models answered HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": f"Not reachable: {e.__class__.__name__}"}


# ---------------------------------------------------------------------------
# Settings updates from the profile page
# ---------------------------------------------------------------------------

def apply_update(settings: Dict, update: Dict, configured: List[Dict]) -> Dict:
    """
    Merge a profile-page update into settings, validating assignments against the
    configured providers. Raises ValueError with a message for the page.
    """
    ids = {p["id"]: p for p in configured}
    for pid, model in (update.get("models") or {}).items():
        if pid in CLOUD_PROVIDERS:
            settings["models"][pid] = str(model or "").strip()
    if "local" in update:
        local = update.get("local") or {}
        settings["local"] = {"endpoint": str(local.get("endpoint") or "").strip().rstrip("/"),
                             "model": str(local.get("model") or "").strip()}
        if settings["local"]["endpoint"]:
            ids.setdefault(LOCAL, {"id": LOCAL, "detection": False})
        else:
            ids.pop(LOCAL, None)
    for job in JOBS:
        if job not in update:
            continue
        choice = update.get(job) or {}
        pid = choice.get("provider")
        if not pid:
            settings[job] = None
            continue
        if pid not in ids:
            raise ValueError(f"{pid} isn't configured: save its API key (or local endpoint) first")
        if job == "detection" and not ids[pid].get("detection", True):
            raise ValueError(LOCAL_DETECTION_BLOCKED)
        settings[job] = {"provider": pid, "model": str(choice.get("model") or "").strip()}
    if "max_detection_calls" in update:
        n = int(update["max_detection_calls"])
        if not 1 <= n <= 500:
            raise ValueError("Max LLM calls per run must be between 1 and 500")
        settings["max_detection_calls"] = n
    if "remember" in update:
        # {"provider": null} remembers "no AI"; None forgets the choice (ask again)
        remember = update["remember"]
        if remember and remember.get("provider") and not ids.get(remember["provider"], {}).get("detection"):
            raise ValueError(f"{remember['provider']} can't be remembered for detection generation")
        settings["remember"] = ({"provider": remember.get("provider") or None, "model": str(remember.get("model") or "")}
                                if remember else None)
    # An assignment whose provider has gone (key deleted) is dropped, not left dangling
    for job in JOBS:
        if settings.get(job) and settings[job]["provider"] not in ids:
            settings[job] = None
    if (settings.get("remember") or {}).get("provider") and settings["remember"]["provider"] not in ids:
        settings["remember"] = None
    return settings

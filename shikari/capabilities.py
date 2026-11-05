"""
The optional components Shikari can use, and whether each is present on this host.

Drives the dependency table on the Help page: a green tick when the component is installed,
a red cross when it isn't, and N/A when the host OS or CPU can't run it at all (Tart needs
Apple Silicon; UTM needs macOS). Detection is host-level and deliberately cheap — the lab
engine probes are already called on each Lab page load (shikari.lab.hosts) — so this is safe
to compute on every request without caching.

Status is one of: "installed", "missing", "na".
"""

import importlib.util
import os

from shikari.lab import hosts
from shikari.lab.runner import which

# Server-level API keys that make a cloud model available without any per-user setup.
_AI_ENV_KEYS = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY",
                "DEEPSEEK_API_KEY", "QWEN_API_KEY", "DASHSCOPE_API_KEY",
                "XAI_API_KEY", "GROK_API_KEY"]


def _engine_status(engine: dict) -> str:
    """Map a lab engine's host report to the table's tri-state."""
    if not engine["supported"]:
        return "na"
    return "installed" if engine["installed"] else "missing"


def _engine_detail(engine: dict) -> str:
    if not engine["supported"]:
        return "Not available on this host"
    if not engine["installed"]:
        return "Not installed"
    # Installed but the daemon/app may not be answering yet — say so, it changes nothing in the table.
    running = "" if engine["running"] else " (installed, but not running)"
    return f"{engine['name']} {engine['version']}".strip() + running


def dependency_matrix() -> dict:
    """The optional components and their status on this host, for the Help page table."""
    host = hosts.capabilities()
    engines = {e["key"]: e for e in host["engines"]}
    docker, tart, utm = engines["docker"], engines["tart"], engines["utm"]

    # AI is available out of the box when a local runtime is installed or a server key is set.
    # A user can also add their own key under Profile → API Keys, which this host-level check
    # can't see — hence the note rather than a hard "not installed".
    ollama = which("ollama") is not None
    env_key = any(os.getenv(k) for k in _AI_ENV_KEYS)
    if ollama or env_key:
        ai_status, ai_detail = "installed", ("Ollama installed" if ollama else "") + \
            (" · server API key set" if env_key else "")
    else:
        ai_status, ai_detail = "missing", "No local runtime or server key — add a key under Profile"

    # The desktop window needs pywebview (imported as `webview`); Linux also needs GTK or Qt.
    webview = importlib.util.find_spec("webview") is not None
    desktop_status = "installed" if webview else "missing"
    desktop_detail = "pywebview installed" if webview else "pip install 'shikari[desktop]'"

    rows = [
        {"name": "Docker / OrbStack", "enables": "Emulate lab Linux containers (Ubuntu, Rocky 10); CALDERA operations",
         "status": _engine_status(docker), "detail": _engine_detail(docker)},
        {"name": "Tart", "enables": "Emulate lab macOS and Linux VMs (Apple Silicon)",
         "status": _engine_status(tart), "detail": _engine_detail(tart)},
        {"name": "UTM", "enables": "Emulate lab Windows and Linux VMs (macOS)",
         "status": _engine_status(utm), "detail": _engine_detail(utm)},
        {"name": "AI provider", "enables": "Ask Shikari, Agents, AI-written queries, threat briefings",
         "status": ai_status, "detail": ai_detail.strip(" ·")},
        {"name": "Desktop app window", "enables": "The shikari app window (otherwise use a browser)",
         "status": desktop_status, "detail": desktop_detail},
    ]
    return {"host": host["label"], "rows": rows}

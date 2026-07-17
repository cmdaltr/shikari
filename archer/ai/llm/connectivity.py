"""
Network connectivity checks for cloud AI/LLM providers.

Distinguishes three failure modes that all look the same to a user staring at
a failed hunt: no internet at all, a proxy/firewall blocking specific AI
vendor domains (common in regulated or air-gapped-adjacent environments), and
a genuinely missing API key. Only the first two are network problems this
module can detect.
"""

import socket
from typing import Dict, Tuple

# Host + port used for the general "is there internet at all" probe. Cloudflare's
# resolver is fast, stable, and reachable from almost anywhere that has internet.
_GENERAL_PROBE_HOST = ("1.1.1.1", 443)

# Cloud AI provider id -> API host, used for provider-specific reachability checks.
PROVIDER_HOSTS: Dict[str, str] = {
    "anthropic": "api.anthropic.com",
    "openai": "api.openai.com",
    "google": "generativelanguage.googleapis.com",
    "deepseek": "api.deepseek.com",
    "qwen": "dashscope.aliyuncs.com",
    "grok": "api.x.ai",
}


def _tcp_reachable(host: str, port: int = 443, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_general_internet(timeout: float = 2.0) -> bool:
    """Fast check for any internet connectivity at all (not provider-specific)."""
    host, port = _GENERAL_PROBE_HOST
    return _tcp_reachable(host, port, timeout)


def check_provider_reachable(provider_id: str, timeout: float = 2.0) -> bool:
    """Check whether a specific cloud provider's API host is reachable."""
    host = PROVIDER_HOSTS.get(provider_id)
    if not host:
        return False
    return _tcp_reachable(host, 443, timeout)


def check_all_providers(timeout: float = 2.0) -> Dict[str, bool]:
    """Check reachability for every known cloud provider host."""
    return {provider_id: _tcp_reachable(host, 443, timeout) for provider_id, host in PROVIDER_HOSTS.items()}


def get_network_status(timeout: float = 2.0) -> Dict:
    """
    Full network status snapshot: general internet + per-provider reachability.

    Returns:
        {
            "internet_available": bool,
            "provider_reachable": {"openai": bool, "anthropic": bool, ...},
            "checked_at": <handled by caller — this module doesn't timestamp>
        }
    """
    internet_available = check_general_internet(timeout)

    # If there's no general internet, don't bother probing each provider
    # individually — they'll all fail, and it just adds latency at startup.
    if not internet_available:
        provider_reachable = {provider_id: False for provider_id in PROVIDER_HOSTS}
    else:
        provider_reachable = check_all_providers(timeout)

    return {
        "internet_available": internet_available,
        "provider_reachable": provider_reachable,
    }

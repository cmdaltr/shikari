"""
Which Shikari the desktop app opens: an organisation's server, or one running on this computer.

The first of these wins:

  1. Set by IT, and then the user can't change it:
       macOS     a configuration profile (MDM) for com.cmdaltr.shikari with ServerURL
       Windows   HKLM (or HKCU)\\SOFTWARE\\Policies\\cmdaltr\\Shikari, string value ServerURL (Group Policy, Intune)
       Linux     /etc/shikari/client.json: {"server_url": "https://..."}
  2. SHIKARI_SERVER: a URL, or "local"
  3. What the user picked last time (client.json in the app's folder)
  4. Otherwise the app asks

Standard library apart from truststore, which checks a server's certificate against the
operating system's store (so an internal CA IT has deployed is trusted, as it is in the window).
"""

import json
import os
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

BUNDLE_ID = "com.cmdaltr.shikari"
POLICY_KEY = r"SOFTWARE\Policies\cmdaltr\Shikari"
LINUX_POLICY = Path("/etc/shikari/client.json")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass
class Choice:
    mode: str                 # "server" or "local"
    url: str = ""
    managed: bool = False     # set by IT: no chooser, no Change Server
    source: str = ""


def managed_url() -> Optional[str]:
    """The server URL IT has enforced, if any."""
    try:
        if sys.platform == "darwin":
            from CoreFoundation import CFPreferencesAppValueIsForced, CFPreferencesCopyAppValue
            if CFPreferencesAppValueIsForced("ServerURL", BUNDLE_ID):
                value = CFPreferencesCopyAppValue("ServerURL", BUNDLE_ID)
                return str(value).strip() if value else None
        elif sys.platform == "win32":
            import winreg
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(hive, POLICY_KEY) as key:
                        value, _ = winreg.QueryValueEx(key, "ServerURL")
                        if value:
                            return str(value).strip()
                except OSError:
                    continue
        elif LINUX_POLICY.exists():
            return (json.loads(LINUX_POLICY.read_text()).get("server_url") or "").strip() or None
    except Exception as e:  # a broken policy must not stop the app opening
        print(f"Couldn't read the managed server setting: {e}")
    return None


def saved_path(home: Path) -> Path:
    return home / "client.json"


def save(home: Path, choice: Choice) -> None:
    saved_path(home).write_text(json.dumps({"mode": choice.mode, "server_url": choice.url}, indent=2))


def resolve(home: Path) -> Optional[Choice]:
    """What to open, or None to ask."""
    url = managed_url()
    if url:
        return Choice("server", url, managed=True, source="managed")
    env = os.environ.get("SHIKARI_SERVER", "").strip()
    if env:
        return Choice("local", source="env") if env.lower() == "local" else Choice("server", env, source="env")
    try:
        saved = json.loads(saved_path(home).read_text())
        if saved.get("mode") == "local":
            return Choice("local", source="saved")
        if saved.get("mode") == "server" and saved.get("server_url"):
            return Choice("server", saved["server_url"], source="saved")
    except (OSError, ValueError):
        pass
    return None


def normalise(url: str, allow_http: bool = False) -> str:
    """A server URL as typed ("shikari.corp.example") made into a base URL. Plain http only to
    this computer, unless IT or SHIKARI_SERVER set it (allow_http): a login over http to a remote
    server would cross the network in the clear."""
    url = (url or "").strip().rstrip("/")
    if not url:
        raise ValueError("Enter your organisation's Shikari address.")
    if "://" not in url:
        url = "https://" + url
    parts = urlparse(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError(f"{url} isn't a web address.")
    if parts.scheme == "http" and parts.hostname not in LOCAL_HOSTS and not allow_http:
        raise ValueError("Use an https:// address: Shikari's login shouldn't cross the network unencrypted.")
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def _context():
    try:
        import truststore
        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except ImportError:
        return ssl.create_default_context()


def probe(url: str, timeout: float = 10) -> tuple:
    """(ok, message): whether url answers as an Shikari server."""
    try:
        with urlopen(f"{url}/health", timeout=timeout, context=_context()) as response:
            body = json.loads(response.read(4096) or b"{}")
    except ssl.SSLCertVerificationError:
        return False, (f"{urlparse(url).hostname}'s certificate isn't trusted by this computer. "
                       "If it's issued by your organisation, ask IT to install its certificate authority.")
    except (URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLCertVerificationError):
            return False, (f"{urlparse(url).hostname}'s certificate isn't trusted by this computer. "
                           "If it's issued by your organisation, ask IT to install its certificate authority.")
        return False, f"Couldn't reach {url}: {reason}"
    except ValueError:
        return False, f"{url} answered, but not as Shikari."
    # "app" is missing on servers older than the desktop app: status alone, then
    if body.get("status") != "ok" or body.get("app", "shikari") != "shikari":
        return False, f"{url} answered, but not as Shikari."
    return True, ""

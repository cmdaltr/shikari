"""
Commercial licensing.

Shikari's core is AGPL-3.0 (see ``LICENSE``). A few features are reserved for a paid commercial
licence (see ``COMMERCIAL-LICENSE.md``); report branding is the first. Those features check with
this module, and stay off until a valid licence is installed.

A licence is a short JSON payload — who it's for, which features it unlocks, when it expires —
signed with the licensor's Ed25519 private key. Only the public key ships (below), so a licence
can be verified offline but not forged or altered: change a byte of the payload and the signature
no longer checks. The private key is held by the licensor and never ships with the product.

A licence is installed as ``data/licence.json`` (or pointed to by ``SHIKARI_LICENCE``) and may be
either the ``{"payload": {...}, "sig": "..."}`` object or the compact ``<payload>.<sig>`` token the
signer prints; both carry the same bytes.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import date, datetime
from pathlib import Path
from typing import List, Optional, Tuple

from shikari import paths

# The licensor's Ed25519 public key (raw, hex). Verification only — the private key is held by the
# licensor. Rotating it means shipping a new build with a new key here.
_PUBLIC_KEY_HEX = "e499f52ec803749de5d97429a632e140d98f81b8b528f61540dac3c8b3ecb282"

# Feature ids a licence may grant. "pro" / "all" grant every reserved feature at once.
FEATURE_REPORT_BRANDING = "report-branding"
_WILDCARDS = {"pro", "all", "*"}

INSTALL_PATH = paths.DATA / "licence.json"


def _b64url_decode(data: str) -> bytes:
    s = data.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical(payload: dict) -> bytes:
    """The exact bytes that are signed: compact JSON with sorted keys."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_sig(payload: dict, sig: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(_PUBLIC_KEY_HEX))
        pub.verify(_b64url_decode(sig), _canonical(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def parse(data) -> Optional[dict]:
    """Normalise a licence (dict, JSON text, or ``<payload>.<sig>`` token) to
    ``{"payload": ..., "sig": ...}``. None if it isn't a licence at all."""
    if isinstance(data, (bytes, bytearray)):
        data = data.decode("utf-8", "replace")
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("{"):
            try:
                data = json.loads(text)
            except ValueError:
                return None
        elif text.count(".") == 1:
            body, sig = text.split(".")
            try:
                payload = json.loads(_b64url_decode(body))
            except (ValueError, json.JSONDecodeError):
                return None
            return {"payload": payload, "sig": sig}
        else:
            return None
    if isinstance(data, dict) and isinstance(data.get("payload"), dict) and data.get("sig"):
        return {"payload": data["payload"], "sig": str(data["sig"])}
    return None


def _as_date(value) -> Optional[date]:
    if not value:
        return None
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def verify(licence: dict, today: Optional[date] = None) -> Tuple[bool, str]:
    """(valid, reason). Checks the signature first, then the validity window."""
    parsed = parse(licence)
    if not parsed:
        return False, "not a licence"
    payload, sig = parsed["payload"], parsed["sig"]
    if not _verify_sig(payload, sig):
        return False, "signature does not verify"
    today = today or date.today()
    starts = _as_date(payload.get("not_before"))
    if starts and today < starts:
        return False, f"not valid until {starts.isoformat()}"
    expires = _as_date(payload.get("expires"))
    if expires and today > expires:
        return False, f"expired on {expires.isoformat()}"
    return True, "valid"


# ── Loading the installed licence (cached on the file's mtime) ──────────────────

_cache: dict = {"path": None, "mtime": None, "parsed": None}


def _licence_file() -> Optional[Path]:
    env = os.getenv("SHIKARI_LICENCE")
    candidates = [Path(env).expanduser()] if env else []
    candidates += [INSTALL_PATH, paths.HOME / "licence.json"]
    for p in candidates:
        if p and p.exists():
            return p
    return None


def _load() -> Optional[dict]:
    path = _licence_file()
    if not path:
        _cache.update(path=None, mtime=None, parsed=None)
        return None
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    if _cache["path"] == str(path) and _cache["mtime"] == mtime:
        return _cache["parsed"]
    try:
        parsed = parse(path.read_text("utf-8"))
    except OSError:
        parsed = None
    _cache.update(path=str(path), mtime=mtime, parsed=parsed)
    return parsed


def status() -> dict:
    """What the UI shows: whether a valid licence is installed, and its headline fields."""
    parsed = _load()
    if not parsed:
        return {"valid": False, "reason": "no licence installed", "present": False, "features": []}
    ok, reason = verify(parsed)
    p = parsed["payload"]
    return {
        "valid": ok, "reason": reason, "present": True,
        "licensee": p.get("licensee", ""), "email": p.get("email", ""),
        "features": list(p.get("features", [])),
        "issued": p.get("issued", ""), "expires": p.get("expires") or "perpetual",
        "licence_id": p.get("licence_id", ""),
    }


def has_feature(feature: str) -> bool:
    """True when a valid installed licence grants this feature (or a wildcard)."""
    parsed = _load()
    if not parsed:
        return False
    ok, _ = verify(parsed)
    if not ok:
        return False
    granted = {str(f).lower() for f in parsed["payload"].get("features", [])}
    return feature.lower() in granted or bool(granted & _WILDCARDS)


def install(data) -> Tuple[bool, str]:
    """Verify a licence and, if it's good, write it to ``data/licence.json``. Returns (ok, message)."""
    parsed = parse(data)
    if not parsed:
        return False, "That doesn't look like a Shikari licence."
    ok, reason = verify(parsed)
    if not ok:
        return False, f"Licence rejected: {reason}."
    INSTALL_PATH.parent.mkdir(parents=True, exist_ok=True)
    INSTALL_PATH.write_text(json.dumps(parsed, indent=2), "utf-8")
    _cache.update(path=None, mtime=None, parsed=None)   # force a reload
    return True, "Licence installed."


def remove() -> None:
    INSTALL_PATH.unlink(missing_ok=True)
    _cache.update(path=None, mtime=None, parsed=None)

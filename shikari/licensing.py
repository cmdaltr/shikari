"""Which edition this installation runs, from a licence signed with Shikari's private key.

    Free       two people who can sign in; the whole core product; reports in the stock Shikari
               look; webhooks may be registered but don't fire
    Pro        the licence's seats; one report brand for the installation (report-branding) and
               webhooks (automation)
    Services   the licence's seats; Pro, plus a brand per client (brand-library) and the right to
               run Shikari for clients as a managed service, which the Elastic License 2.0
               otherwise forbids (COMMERCIAL-LICENSE.md)

The licence line, its checking, the editions, the features and grace are the suite's shared ones,
from `samarkand.licence` (docs/LICENSING_MODEL.md): this module binds them to Shikari's id, public
keys and free seat number, and keeps Shikari's own parts: where the licence is stored, accepting the
commercial terms, and the seat rule. Only public keys ship, so a licence is checked offline and can't
be forged or edited. Each product has its own key; the private half stays with the licensor
(`scripts/admin/sign_licence.py`). Rotating it means adding the new public half to PUBLIC_KEYS.

What a licence grants is its edition's features (EDITION_FEATURES) plus any it names; "*" grants
every feature. Features are checked where they're used, never at configuration time.

When a licence runs out, its edition carries on for GRACE with a warning, then the installation is
Free again. Nothing is taken away: accounts stay active and branding stays stored, but no new
account can be added past the free limit and reports go back to the stock look. A licence with no
expiry is perpetual.

Installing a licence needs an admin to accept the current commercial terms (the packaged copy in
shikari/legal/, whose version terms() reads from the text) on the licensee's behalf. The installed
file, `data/licence.json` (or the path in SHIKARI_LICENCE), keeps the line with that acceptance:
{"licence", "terms_version", "accepted_by", "accepted_by_name", "accepted_at"}. A file holding only
the bare line, as earlier builds wrote, still reads, with no acceptance recorded. It is read back
through an mtime cache.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import date, datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Optional, Tuple

from samarkand import licence as shared

from shikari import paths

PRODUCT = "shikari"
NAME = "Shikari"
# The free tier: two accounts, so an operator and a reviewer can work together. More seats need a Pro or Services licence; the licence's own
# `seats` field sets how many. The limit applies only to creating new accounts (never retroactively).
FREE_SEATS = 2
GRACE = shared.GRACE
# Raw Ed25519 public keys, hex (a tuple, so a key can be rotated by adding the new one). The matching
# private key is held by the licensor and never ships.
PUBLIC_KEYS: Tuple[str, ...] = ("e499f52ec803749de5d97429a632e140d98f81b8b528f61540dac3c8b3ecb282",)

Edition = shared.Edition
# samarkand's licence; rules().licence() builds one naming Shikari
Licence = shared.Licence
Standing = shared.Standing
LicenceProblem = shared.LicenceProblem

# Feature ids, the same in every product (docs/LICENSING_MODEL.md says what each gates). Seats are
# the licence's own `seats`, not a feature, so there is no "teams" id.
FEATURE_REPORT_BRANDING = shared.REPORT_BRANDING   # one brand for the whole installation
FEATURE_BRAND_LIBRARY = shared.BRAND_LIBRARY       # a brand per client, chosen per assessment
FEATURE_AUTOMATION = shared.AUTOMATION             # webhooks fire; checked at delivery
FEATURE_MANAGED_SERVICE = shared.MANAGED_SERVICE   # a right in COMMERCIAL-LICENSE.md, not a switch
FEATURES = shared.FEATURES
WILDCARD = shared.WILDCARD
EDITION_FEATURES = shared.EDITION_FEATURES

INSTALL_PATH = paths.DATA / "licence.json"
# The terms an admin accepts on install. Packaged with the code (not read from the repo root) because
# an installed Shikari has no repo; a test keeps it identical to COMMERCIAL-LICENSE.md.
TERMS = Path(__file__).parent / "legal" / "COMMERCIAL-LICENSE.md"


@lru_cache(maxsize=4)
def _bound(keys: Tuple[str, ...], free_seats: int) -> shared.Rules:
    return shared.Rules(PRODUCT, keys, free_seats=free_seats, name=NAME)


def rules() -> shared.Rules:
    """Shikari's rules, bound to PUBLIC_KEYS and FREE_SEATS as they are now (tests swap the keys)."""
    return _bound(tuple(PUBLIC_KEYS), FREE_SEATS)


def sign(private_key, licence: Licence) -> str:
    """The licence as a line to send to the customer (the licensor's admin script only)."""
    head = shared.head_of(licence)
    return shared.line_of(head, private_key.sign(head.encode()))


def parse(text: str) -> Licence:
    """A licence, once its signature checks out against one of PUBLIC_KEYS. Raises LicenceProblem."""
    return rules().parse(text)


def standing(licence: Optional[Licence], now: Optional[datetime] = None) -> Standing:
    """The edition a licence (or none) gives at `now`. A licence runs from the start of its
    not_before day to the end of its expiry day, then 30 days' grace, then Free."""
    return rules().standing(licence, now)


def grace_ends(licence: Licence) -> Optional[date]:
    return shared.grace_ends(licence)


def new_id() -> str:
    return f"lic_{uuid.uuid4().hex[:12]}"


def terms() -> Tuple[str, str]:
    """The commercial terms an admin accepts: (version, text). The version is the one the text states."""
    text = TERMS.read_text("utf-8")
    found = re.search(r"\*\*Version (\S+)\*\*", text)
    if not found:
        raise RuntimeError(f"{TERMS} doesn't state its version")
    return found[1], text


def check(text: str) -> Licence:
    """A licence that may be installed now: genuine and not already lapsed. Raises LicenceProblem.
    The admin page shows what it says before anyone accepts the terms for its licensee."""
    return shared.check_installable(parse(text))


def acceptance_problem(licence: Licence, accept_terms: bool, terms_version: Optional[str]) -> Optional[Tuple[int, str]]:
    """(HTTP status, reason) when an install hasn't accepted the current terms, else None. Not
    accepting is 422; accepting a version that is no longer current is 409, so an admin who read old
    terms reads the new ones before accepting."""
    version = terms()[0]
    if not accept_terms:
        return 422, f"Accept the commercial licence terms for {licence.licensee} to install this licence."
    if terms_version != version:
        return 409, f"The commercial licence terms are now version {version}. Read them, then accept again."
    return None


# ── Storage: one licence line under data/licence.json (or SHIKARI_LICENCE), mtime-cached ──────────

import os  # noqa: E402

_cache: dict = {"path": None, "mtime": None, "licence": None, "error": None, "accepted": None}


def _forget() -> None:
    _cache.update(path=None, mtime=None, licence=None, error=None, accepted=None)


def _licence_file() -> Optional[Path]:
    env = os.getenv("SHIKARI_LICENCE")
    candidates = [Path(env).expanduser()] if env else []
    candidates += [INSTALL_PATH, paths.HOME / "licence.json"]
    for p in candidates:
        if p and p.exists():
            return p
    return None


def read_record(raw: str) -> Tuple[str, Optional[dict]]:
    """The licence line and its acceptance from the installed file's text. Earlier builds wrote the
    bare line; those read back with no acceptance."""
    raw = raw.strip()
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError:
            return raw, None
        if isinstance(data, dict) and isinstance(data.get("licence"), str):
            accepted = {k: data.get(k) for k in ("terms_version", "accepted_by", "accepted_by_name", "accepted_at")}
            return data["licence"], accepted if accepted["accepted_at"] else None
    return raw, None


def licence_line(text: str) -> str:
    """The licence line from pasted text or a file, which may be an installed record."""
    return read_record(text or "")[0]


def _installed() -> Tuple[Optional[Licence], Optional[str]]:
    """The parsed installed licence and a problem message, cached on the file's mtime.
    (None, None) = nothing installed; (None, msg) = a file that won't parse; (lic, None) = good."""
    path = _licence_file()
    if not path:
        _forget()
        return None, None
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None, None
    if _cache["path"] == str(path) and _cache["mtime"] == mtime:
        return _cache["licence"], _cache["error"]
    licence, error, accepted = None, None, None
    try:
        line, accepted = read_record(path.read_text("utf-8"))
        licence = parse(line)
    except LicenceProblem as exc:
        error = str(exc)
    except OSError:
        error = "The licence file could not be read."
    _cache.update(path=str(path), mtime=mtime, licence=licence, error=error,
                  accepted=accepted if licence else None)
    return licence, error


def accepted() -> Optional[dict]:
    """Who accepted which version of the terms for the installed licence, and when (None if no
    acceptance was recorded, as with a licence installed before acceptance existed)."""
    licence, _ = _installed()
    return _cache["accepted"] if licence else None


def current() -> Standing:
    """The installation's standing from its installed licence. A stored licence that no longer
    parses (an old format, or a withdrawn key) counts as none."""
    licence, _ = _installed()
    return standing(licence)


def verify(text) -> Tuple[bool, str]:
    """(ok, reason) for a licence line: whether it is a genuine, current Shikari licence. Parses and
    signature-checks it, then confirms it isn't lapsed. Kept for callers of the old API."""
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8", "replace")
    try:
        licence = parse(text)
    except LicenceProblem as exc:
        return False, str(exc)
    st = standing(licence)
    if st.state == "lapsed":
        return False, f"expired on {licence.expires.isoformat()}" if licence.expires else "expired"
    return True, "valid"


def status() -> dict:
    """What the UI shows: edition, state, seats, and the headline fields."""
    licence, error = _installed()
    st = standing(licence)
    reason = {
        "free": "no licence installed",
        "pending": f"starts {licence.not_before.isoformat()}" if licence and licence.not_before else "not yet valid",
        "active": "valid",
        "grace": f"in grace until {grace_ends(licence).isoformat()}" if licence and grace_ends(licence) else "in grace",
        "lapsed": f"expired {licence.expires.isoformat()}" if licence and licence.expires else "expired",
    }.get(st.state, st.state)
    if error:
        reason = error
    return {
        "present": licence is not None or error is not None,
        "valid": st.state in ("active", "grace"),
        "state": st.state,
        "edition": st.edition.value,
        "reason": reason,
        "licensee": licence.licensee if licence else "",
        "email": licence.email if licence else "",
        "features": sorted(st.features),
        "seats": st.seats,               # None = unlimited
        "issued": licence.issued.isoformat() if licence else "",
        "expires": (licence.expires.isoformat() if licence and licence.expires else "perpetual") if licence else "",
        "grace_ends": grace_ends(licence).isoformat() if licence and st.state == "grace" and grace_ends(licence) else "",
        "licence_id": licence.licence_id if licence else "",
        "terms_version": terms()[0],     # the version an install accepts now
        "accepted": accepted(),          # for the installed licence, if recorded
    }


def has_feature(feature: str) -> bool:
    """True when the installation's current standing grants this feature."""
    return current().has(feature)


def seats_allowed() -> Optional[int]:
    """How many user accounts this install may hold. None = unlimited (the licence's seats), else the
    free tier's FREE_SEATS."""
    return current().seats


def can_add_user(active_count: int) -> bool:
    """Whether another account may be created, given how many active accounts there are now."""
    limit = seats_allowed()
    return limit is None or active_count < limit


def install(data, *, accepted_by_name: str, accepted_by: Optional[int] = None) -> Tuple[bool, str]:
    """Verify a licence line and, if it's genuine, store it with who accepted the current terms
    (the account id if there is one, and "Name <email>" as written) and when. The caller has
    already checked acceptance (acceptance_problem). Returns (ok, message)."""
    if isinstance(data, (bytes, bytearray)):
        data = data.decode("utf-8", "replace")
    text, _ = read_record(data or "")
    if not accepted_by_name.strip():
        return False, "Say who accepted the commercial licence terms."
    try:
        licence = check(text)
    except LicenceProblem as exc:
        return False, str(exc)
    record = {
        "licence": text,
        "terms_version": terms()[0],
        "accepted_by": accepted_by,
        "accepted_by_name": accepted_by_name.strip(),
        "accepted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    INSTALL_PATH.parent.mkdir(parents=True, exist_ok=True)
    INSTALL_PATH.write_text(json.dumps(record, indent=2) + "\n", "utf-8")
    _forget()
    seats = "unlimited" if licence.seats is None else licence.seats
    return True, f"{licence.edition.value.title()} licence installed for {licence.licensee} ({seats} seats)."


def remove() -> None:
    INSTALL_PATH.unlink(missing_ok=True)
    _forget()

"""
Threat Feed watchlists: saved searches ("Scattered Spider", "RedSun", a CVE, a vendor) that flag
new posts matching them. No AI: the matching is Search all research's (research_search), over
the archive of every post Shikari's sources carry, plus Google News and Bing News for a watchlist
that opts in (its keyword then goes to Google and Bing at each collection).

A watchlist starts from what already matches: those are marked seen, so only posts that
arrive later count as new. Each collection (feed.refresh) checks every watchlist; a match
not seen before is new until its owner marks it seen. With email on and SMTP configured
(EMAIL_ENABLED, shikari.auth.email), the owner gets one email per collection listing the
new matches.

Each user picks how often their watchlists are checked (Profile → Environment). The feed is
shared, so the collector runs at the shortest interval chosen by anyone with a watchlist.

Stored per user in data/feed/watchlists/<user id>.json, the check interval included.
"""

import json
import os
import re
import threading
import time
import uuid
from typing import Dict, List, Optional

from shikari.config import DATA_DIR

WATCH_DIR = os.path.join(DATA_DIR, "feed", "watchlists")
MAX_WATCHLISTS = 25
MAX_MATCHES = 100  # kept per watchlist, newest first
MAX_SEEN = 2000
INTERVALS = (1, 4, 6, 12, 24)  # hours a user can choose between checks
DEFAULT_INTERVAL = 6

_lock = threading.Lock()


def _path(user_id) -> str:
    return os.path.join(WATCH_DIR, f"{int(user_id)}.json")


def _load(user_id) -> Dict:
    try:
        with open(_path(user_id), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"email": None, "watchlists": []}


def _save(user_id, data: Dict) -> None:
    os.makedirs(WATCH_DIR, exist_ok=True)
    tmp = _path(user_id) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    os.replace(tmp, _path(user_id))


def normalise(query: str) -> str:
    return " ".join((query or "").split())[:100]


def matches(query: str, web: bool, bundle=None) -> List[Dict]:
    """Posts matching the query now: the source archive, and the web when opted in."""
    from shikari.intelligence import research_search as rs

    hits = [{**p, "via": p.get("source")} for p in rs.search_archive(query, limit=MAX_MATCHES)]
    if web:
        hits += [{"title": p["title"], "url": p["url"], "source": p["outlet"], "published": p.get("published"),
                  "summary": "", "via": p["via"]} for p in rs.search_web(query)]
    return hits


def _public(w: Dict) -> Dict:
    new = [m for m in w.get("matches", []) if m["url"] not in w.get("seen", [])]
    return {"id": w["id"], "query": w["query"], "web": w["web"], "email": w["email"], "created": w["created"],
            "checked": w.get("checked"), "new": new, "new_count": len(new)}


def list_for(user_id) -> List[Dict]:
    return [_public(w) for w in _load(user_id)["watchlists"]]


def watched(user_id) -> Dict[str, List[str]]:
    """{post url: [the queries it matches]}, for tagging the wall."""
    out: Dict[str, List[str]] = {}
    for w in _load(user_id)["watchlists"]:
        for m in w.get("matches", []):
            out.setdefault(m["url"], []).append(w["query"])
    return out


def new_count(user_id) -> int:
    return sum(w["new_count"] for w in list_for(user_id))


def add(user_id, email: Optional[str], query: str, web: bool = False, want_email: bool = False, bundle=None) -> Dict:
    query = normalise(query)
    if len(query) < 3:
        raise ValueError("Watch for at least three characters")
    with _lock:
        data = _load(user_id)
        if any(w["query"].lower() == query.lower() for w in data["watchlists"]):
            raise ValueError(f"You already watch “{query}”")
        if len(data["watchlists"]) >= MAX_WATCHLISTS:
            raise ValueError(f"At most {MAX_WATCHLISTS} watchlists")
    # What matches already is the baseline: only later posts are new
    baseline = [m["url"] for m in matches(query, web, bundle)]
    w = {"id": uuid.uuid4().hex[:12], "query": query, "web": bool(web), "email": bool(want_email),
         "created": time.time(), "checked": time.time(), "seen": baseline, "emailed": baseline, "matches": []}
    with _lock:
        data = _load(user_id)
        data["email"] = email
        data["watchlists"].append(w)
        _save(user_id, data)
    return _public(w)


def update(user_id, watch_id: str, **fields) -> Optional[Dict]:
    with _lock:
        data = _load(user_id)
        for w in data["watchlists"]:
            if w["id"] == watch_id:
                for k in ("web", "email"):
                    if k in fields and fields[k] is not None:
                        w[k] = bool(fields[k])
                _save(user_id, data)
                return _public(w)
    return None


def remove(user_id, watch_id: str) -> bool:
    with _lock:
        data = _load(user_id)
        kept = [w for w in data["watchlists"] if w["id"] != watch_id]
        if len(kept) == len(data["watchlists"]):
            return False
        data["watchlists"] = kept
        _save(user_id, data)
        return True


def mark_seen(user_id, watch_id: Optional[str] = None) -> int:
    """Mark one watchlist's new matches seen (all watchlists when watch_id is None)."""
    marked = 0
    with _lock:
        data = _load(user_id)
        for w in data["watchlists"]:
            if watch_id in (None, w["id"]):
                fresh = [m["url"] for m in w.get("matches", []) if m["url"] not in w["seen"]]
                w["seen"] = (w["seen"] + fresh)[-MAX_SEEN:]
                marked += len(fresh)
        _save(user_id, data)
    return marked


def _merge(w: Dict, found: List[Dict]) -> List[Dict]:
    """Add found posts to the watchlist's matches; returns those never seen or emailed before."""
    known = {m["url"] for m in w.get("matches", [])}
    added = [m for m in found if m["url"] not in known and m["url"] not in w["seen"]]
    w["matches"] = sorted(w.get("matches", []) + added, key=lambda m: m.get("published") or "", reverse=True)[:MAX_MATCHES]
    w["checked"] = time.time()
    return [m for m in added if m["url"] not in w.get("emailed", [])]


def check_user(user_id, bundle=None, send=None) -> int:
    """Run the user's watchlists; returns how many new matches were found."""
    data = _load(user_id)
    found = {w["id"]: matches(w["query"], w["web"], bundle) for w in data["watchlists"]}
    to_email, total, hooked = [], 0, []
    with _lock:
        data = _load(user_id)  # re-read: the user may have changed it while the searches ran
        for w in data["watchlists"]:
            if w["id"] not in found:
                continue
            added = _merge(w, found[w["id"]])
            total += len(added)
            hooked += [{"query": w["query"], "title": m.get("title"), "url": m.get("url")} for m in added]
            if w["email"] and added:
                to_email.append((w["query"], added))
                w["emailed"] = (w.get("emailed", []) + [m["url"] for m in added])[-MAX_SEEN:]
        _save(user_id, data)
    if to_email and data.get("email"):
        (send or _send)(data["email"], to_email)
    if hooked:
        try:
            from shikari import webhooks

            webhooks.emit("watchlist.match", {"user_id": user_id, "matches": hooked})
        except Exception as e:
            print(f"⚠️  Watchlist webhooks not sent: {e}")
    return total


def check_all(bundle=None) -> int:
    """Every user's watchlists (after each feed collection)."""
    if not os.path.isdir(WATCH_DIR):
        return 0
    total = 0
    for name in os.listdir(WATCH_DIR):
        if re.fullmatch(r"\d+\.json", name):
            try:
                total += check_user(int(name[:-5]), bundle)
            except Exception as e:
                print(f"Watchlist check failed for user {name[:-5]}: {e}")
    return total


def _send(to: str, found: List[tuple]) -> bool:
    """One email listing each watchlist's new posts (needs EMAIL_ENABLED and SMTP settings)."""
    import html

    from shikari.auth.email import BASE_URL, EMAIL_ENABLED, send_email

    if not EMAIL_ENABLED:
        return False
    n = sum(len(items) for _, items in found)
    text, rows = [], []
    for query, items in found:
        text.append(f"{query}:")
        rows.append(f"<h3>{html.escape(query)}</h3><ul>")
        for m in items:
            text.append(f"  {m['title']} ({m.get('source') or ''})\n  {m['url']}")
            rows.append(f'<li><a href="{html.escape(m["url"])}">{html.escape(m["title"])}</a> '
                        f'<small>{html.escape(m.get("source") or "")}</small></li>')
        rows.append("</ul>")
    footer = f"Manage your watchlists on the Threat Feed: {BASE_URL}/feed#fd-watch"
    return send_email(to, f"Shikari watchlists: {n} new post{'s' if n != 1 else ''}",
                      "".join(rows) + f'<p><a href="{BASE_URL}/feed#fd-watch">Manage your watchlists</a></p>',
                      "\n".join(text) + "\n\n" + footer)


def any_watchlists() -> bool:
    return os.path.isdir(WATCH_DIR) and any(re.fullmatch(r"\d+\.json", n) for n in os.listdir(WATCH_DIR))


def _interval(data: Dict) -> int:
    hours = data.get("interval")
    return hours if hours in INTERVALS else DEFAULT_INTERVAL


def interval_for(user_id) -> int:
    """Hours between this user's watchlist checks."""
    return _interval(_load(user_id))


def set_interval(user_id, hours: int) -> int:
    if isinstance(hours, bool) or hours not in INTERVALS:  # True == 1 would otherwise pass
        raise ValueError(f"Choose one of {', '.join(map(str, INTERVALS))} hours")
    with _lock:
        data = _load(user_id)
        data["interval"] = hours
        _save(user_id, data)
    return hours


def collection_interval() -> Optional[int]:
    """
    Seconds between collections: the shortest interval of any user with a watchlist, since one
    collection serves everyone. None when nobody has one (a file can outlive its watchlists).
    """
    if not os.path.isdir(WATCH_DIR):
        return None
    hours = [_interval(d) for d in (_load(int(n[:-5])) for n in os.listdir(WATCH_DIR) if re.fullmatch(r"\d+\.json", n))
             if d.get("watchlists")]
    return min(hours) * 3600 if hours else None


def keep_collecting(state, poll: int = 900) -> None:
    """
    Collect the feed on schedule while any watchlist exists, so new matches (and emails)
    don't wait for someone to open the Feed. state() returns (bundle, group metadata).
    The poll only needs to be well under the shortest interval (an hour).
    """
    from shikari.intelligence import feed

    def run():
        while True:
            time.sleep(poll)
            try:
                every = collection_interval()
                if every:
                    feed.refresh_in_background(*state(), every=every)  # a no-op until every has passed
            except Exception as e:
                print(f"Watchlist collection failed: {e}")

    threading.Thread(target=run, daemon=True, name="watchlist-collector").start()


def email_available() -> bool:
    from shikari.auth.email import EMAIL_ENABLED

    return EMAIL_ENABLED

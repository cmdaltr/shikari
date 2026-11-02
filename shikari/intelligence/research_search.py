"""
Search research by keyword ("GhostAction", "RedSun", "Salt Typhoon"), beyond the Threat Feed's
week. No AI:

- Shikari's sources: an archive of every post their feeds have carried (data/feed/archive.json),
  filled from the whole of each feed at every collection, so it reaches back years for some
  sources and grows from then on. Matched on title and summary, and on the analysed
  description where the feed analysed the post.
- MITRE ATT&CK: groups, software and campaigns whose name, aliases or description mention it.
- The web (opt-in per search; the keyword goes to Google and Bing): Google News and Bing News
  search feeds, de-duplicated, keeping stories that read as security ("RedSun" is also a
  property developer).
"""

from __future__ import annotations

import html
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, List, Optional
from urllib.parse import parse_qs, quote, urlparse

from shikari.config import DATA_DIR

ARCHIVE_PATH = os.path.join(DATA_DIR, "feed", "archive.json")
CACHE_SECONDS = 3600
MAX_QUERY = 100
WEB_SOURCES = {
    "Google News": "https://news.google.com/rss/search?q={q}&hl=en-GB&gl=GB&ceid=GB:en",
    "Bing News": "https://www.bing.com/news/search?q={q}&format=rss&setlang=en-GB&cc=GB",
}
# A web story counts when it reads as security, or comes from a security outlet
SECURITY = re.compile(r"malware|ransomware|exploit|vulnerab|zero[- ]?day|0[- ]?day|\bCVE-|threat|attack|hack|breach"
                      r"|phish|campaign|backdoor|botnet|\bAPT\b|espionage|supply[- ]chain|stealer|trojan|\bC2\b|compromis"
                      r"|security|cyber|exfiltrat|credential|patch|spyware|wiper|loader|infostealer|intrusion", re.I)
SECURITY_OUTLETS = re.compile(r"bleepingcomputer|thehackernews|securityweek|darkreading|therecord|helpnetsecurity"
                              r"|securityaffairs|cyberscoop|infosecurity-magazine|scmagazine|theregister|gitguardian"
                              r"|socradar|krebsonsecurity|csoonline|cybersecuritydive|grahamcluley|heise|borncity", re.I)

_lock = threading.Lock()
_cache: Dict[tuple, tuple] = {}


# ---------------------------------------------------------------- archive

def load_archive() -> Dict[str, Dict]:
    try:
        with open(ARCHIVE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def archive(posts: Iterable[Dict], analysed: Optional[Dict[str, Dict]] = None) -> int:
    """Add feed items to the archive (title, url, source, published, summary), and the feed's
    analysed descriptions. Returns how many are new."""
    with _lock:
        store = load_archive()
        before = len(store)
        for p in posts:
            if p.get("url") and p.get("title"):
                kept = store.get(p["url"], {})
                store[p["url"]] = {**kept, **{k: p.get(k) for k in ("title", "url", "source", "published", "summary")}}
        for url, post in (analysed or {}).items():
            if url in store and post.get("description"):
                store[url]["description"] = post["description"]
        os.makedirs(os.path.dirname(ARCHIVE_PATH), exist_ok=True)
        tmp = ARCHIVE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(store, f, separators=(",", ":"))
        os.replace(tmp, ARCHIVE_PATH)
        return len(store) - before


def _matcher(query: str) -> re.Pattern:
    """Every word of the query, as a whole word or a word start, anywhere ("salt typhoon")."""
    words = [re.escape(w) for w in query.split() if w]
    return re.compile("".join(rf"(?=.*\b{w})" for w in words), re.I | re.S)


def search_archive(query: str, limit: int = 50) -> List[Dict]:
    match = _matcher(query)
    hits = [p for p in load_archive().values()
            if match.match(" ".join(filter(None, [p.get("title"), p.get("summary"), p.get("description")])))]
    hits.sort(key=lambda p: p.get("published") or "", reverse=True)
    return [{"title": p["title"], "url": p["url"], "source": p.get("source"), "published": p.get("published"),
             "summary": (p.get("description") or p.get("summary") or "")[:300]} for p in hits[:limit]]


# ---------------------------------------------------------------- ATT&CK

def search_attack(bundle, query: str, limit: int = 20) -> List[Dict]:
    match = _matcher(query)
    kinds = {"intrusion-set": "Group", "malware": "Software", "tool": "Software", "campaign": "Campaign"}
    out = []
    objects = bundle.get("objects", []) if isinstance(bundle, dict) else getattr(bundle, "objects", None) or []
    for obj in objects:
        kind = kinds.get(obj.get("type"))
        if not kind or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        aliases = list(obj.get("aliases") or obj.get("x_mitre_aliases") or [])
        description = obj.get("description") or ""
        if not match.match(" ".join([obj.get("name", "")] + aliases + [description])):
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), {})
        named = bool(match.match(" ".join([obj.get("name", "")] + aliases)))
        out.append({"kind": kind, "id": ref.get("external_id"), "name": obj.get("name"), "url": ref.get("url"),
                    "aliases": [a for a in aliases if a != obj.get("name")][:6], "named": named})
    out.sort(key=lambda o: (not o["named"], o["kind"], o["name"]))
    return out[:limit]


# ---------------------------------------------------------------- web

def _real_url(link: str) -> str:
    """Bing wraps each link in a click-tracker; take the article's own URL out of it."""
    if "bing.com/news/apiclick" in link:
        target = parse_qs(urlparse(link).query).get("url", [""])[0]
        return target or link
    return link


def _outlet(item: Dict) -> str:
    # Google News titles end " - Outlet"
    m = re.search(r"\s[-–]\s([^-–]{2,60})$", item["title"])
    return m.group(1).strip() if m else urlparse(item["url"]).netloc.replace("www.", "")


def search_web(query: str, limit: int = 30) -> List[Dict]:
    import requests

    from shikari.intelligence.feed import FETCH_TIMEOUT, HEADERS, parse_feed

    match = _matcher(query)

    def one(name_url):
        name, url = name_url
        try:
            r = requests.get(url.format(q=quote(query)), timeout=FETCH_TIMEOUT, headers=HEADERS)
            r.raise_for_status()
            return [{**p, "url": _real_url(p["url"]), "via": name} for p in parse_feed(r.content, name)]
        except Exception as e:
            print(f"Research search: {name} unavailable: {e}")
            return []

    with ThreadPoolExecutor(max_workers=len(WEB_SOURCES)) as pool:
        items = [p for batch in pool.map(one, WEB_SOURCES.items()) for p in batch]
    out, seen = [], set()
    for p in sorted(items, key=lambda p: p.get("published") or "", reverse=True):
        text = f"{p['title']} {p.get('summary', '')}"
        if not match.match(text):
            continue
        letters = [c for c in p["title"] if c.isalpha()]
        if letters and sum(c.isascii() for c in letters) / len(letters) < 0.7:
            continue  # English only: the region and language parameters don't stop every foreign story
        outlet = _outlet(p)
        if not (SECURITY.search(text) or SECURITY_OUTLETS.search(f"{outlet} {p['url']}")):
            continue
        title = re.sub(r"\s[-–]\s[^-–]{2,60}$", "", html.unescape(p["title"])).strip()
        key = re.sub(r"\W+", "", title.lower())[:60]
        if key in seen:
            continue
        seen.add(key)
        out.append({"title": title, "url": p["url"], "outlet": outlet, "published": p.get("published"), "via": p["via"]})
    return out[:limit]


# ---------------------------------------------------------------- all

def search(query: str, bundle=None, web: bool = True) -> Dict:
    query = " ".join((query or "").split())[:MAX_QUERY]
    if len(query) < 3:
        return {"query": query, "error": "Search for at least three characters"}
    key = (query.lower(), web)
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < CACHE_SECONDS:
        return hit[1]
    result = {"query": query, "sources": search_archive(query), "attack": search_attack(bundle, query),
              "web": search_web(query) if web else None, "archive_size": len(load_archive()), "searched": time.time()}
    _cache[key] = (time.time(), result)
    return result

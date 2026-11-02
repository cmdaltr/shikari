"""
IOC search (#IOC P1): find reputable, recent cyber reporting that mentions an indicator.

Given an IOC, Shikari searches ~100 curated reputable sources (shikari/data/intel_sources.yaml) over
their RSS/Atom feeds, keeps entries from the last 7 days, and matches the indicator and its common
defanged forms (shikari.intelligence.ioc) in each entry's title and summary. Hits are ranked by source
tier then recency. No AI.

Reuses the Threat Feed's proven feed mechanics (shikari.intelligence.feed): the RSS/Atom parser, the
public-address (SSRF) guard, the request headers and timeout. P1 searches the feed-provided text
only; fetching article bodies for IOCs that appear only in the body is P2.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from shikari import paths
from shikari.intelligence import feed, ioc

_REGISTRY = Path(__file__).resolve().parent.parent / "data" / "intel_sources.yaml"
_FEED_CACHE = paths.DATA / "cache" / "intel_feeds"
_CACHE_TTL = 3600       # reuse a cached feed for an hour — polite and fast on repeat searches
_MAX_WORKERS = 12
_DEFAULT_DAYS = 7

# Searched-IOC results cache: instant repeats and a short history. A cached result newer than
# _RESULT_TTL is returned as-is (staler than that would miss new reporting and keep aged-out posts);
# entries are purged once they pass _RETAIN_DAYS, in step with the reporting window.
_RESULTS_CACHE = paths.DATA / "cache" / "ioc_results.json"
_RESULT_TTL = 3600
_RETAIN_DAYS = 7
_cache_lock = threading.Lock()

_sources_cache = (0.0, [])  # (mtime, [{name, url, tier}])


def load_sources() -> List[Dict]:
    """The curated source registry, memoised by mtime. [] if the file is missing or malformed."""
    global _sources_cache
    try:
        mtime = os.path.getmtime(_REGISTRY)
    except OSError:
        return []
    if _sources_cache[0] == mtime:
        return _sources_cache[1]
    import yaml
    try:
        with open(_REGISTRY, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        out = [{"name": s["name"], "url": s["url"], "tier": int(s.get("tier", 3))}
               for s in (data.get("sources") or []) if s.get("name") and s.get("url")]
    except (OSError, ValueError, KeyError, TypeError):
        out = []
    _sources_cache = (mtime, out)
    return out


def _cache_path(url: str) -> Path:
    return _FEED_CACHE / (hashlib.sha1(url.encode()).hexdigest() + ".xml")


def _fetch(url: str, ttl: int = _CACHE_TTL) -> Optional[bytes]:
    """A feed's bytes from the hour-long cache, else fetched fresh (public URLs only). None on failure."""
    import requests

    path = _cache_path(url)
    try:
        if path.is_file() and time.time() - path.stat().st_mtime < ttl:
            return path.read_bytes()
    except OSError:
        pass
    if feed._public_url(url):   # SSRF guard: http/https to a public address only
        return None
    try:
        r = requests.get(url, timeout=feed.FETCH_TIMEOUT, headers=feed.HEADERS)
        r.raise_for_status()
    except requests.RequestException:
        return None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(r.content)
    except OSError:
        pass
    return r.content


def _scan_source(src: Dict, search_variants: List[str], cutoff: datetime) -> Dict:
    """Fetch one source, scan its recent entries for the IOC. {hits:[...]} or {error:str}."""
    xml = _fetch(src["url"])
    if xml is None:
        return {"error": "unreachable"}
    posts = feed.parse_feed(xml, src["name"])
    hits = []
    for p in posts:
        pub = p.get("published")
        if pub:
            try:
                when = datetime.fromisoformat(pub)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                if when < cutoff:
                    continue
            except ValueError:
                pass  # keep an entry we can't date rather than drop it silently
        text = f"{p.get('title', '')} {p.get('summary', '')}"
        m = ioc.find_in(text, search_variants)
        if m:
            hits.append({"source": src["name"], "tier": src["tier"], "title": p.get("title"),
                         "url": p.get("url"), "published": pub, "matched": m[0],
                         "snippet": ioc.snippet(text, m[1], len(m[0]))})
    return {"hits": hits}


def _load_cache() -> Dict:
    try:
        with open(_RESULTS_CACHE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _purge(cache: Dict) -> Dict:
    """Drop cached IOC results older than the retention window (keeps the cache ~7 days deep)."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=_RETAIN_DAYS)).isoformat()
    return {k: v for k, v in cache.items() if (v.get("searched") or "") >= cutoff}


def _save_cache(cache: Dict) -> None:
    try:
        _RESULTS_CACHE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _RESULTS_CACHE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
        os.replace(tmp, _RESULTS_CACHE)
    except OSError:
        pass


def recent_iocs(limit: int = 40) -> List[Dict]:
    """Recently searched IOCs still within the retention window, newest first — a short history."""
    with _cache_lock:
        cache = _purge(_load_cache())
        _save_cache(cache)
    rows = [{"value": v.get("value"), "ioc_type": v.get("ioc_type"),
             "searched": v.get("searched"), "total": v.get("total", 0)}
            for v in cache.values()]
    rows.sort(key=lambda r: r.get("searched") or "", reverse=True)
    return rows[:limit]


def search(indicator: str, days: int = _DEFAULT_DAYS, tiers: Optional[List[int]] = None,
           limit: int = 200, use_cache: bool = True) -> Dict:
    """
    Reputable recent reporting that mentions `indicator`. Returns the matched IOC, the hits ranked by
    source tier then recency, and how many sources were searched vs unreachable. Networked: fetches
    feeds (cached for an hour). A fresh result is reused from the IOC results cache (purged after 7
    days). Returns {"error": ...} for an unrecognised indicator.
    """
    ioc_type, value = ioc.classify(indicator)
    if not ioc_type:
        return {"error": "Not a recognised IOC (expected an IP, domain, URL, hash, email or CVE)",
                "indicator": indicator}
    variants = ioc.variants(value, ioc_type)
    sources = [s for s in load_sources() if not tiers or s["tier"] in tiers]
    if not sources:
        return {"error": "No sources configured", "indicator": indicator}

    tier_key = ",".join(str(t) for t in sorted(tiers)) if tiers else "all"
    key = f"{ioc_type}:{value}:{tier_key}:{days}"
    now = datetime.now(timezone.utc)
    if use_cache:
        with _cache_lock:
            cache = _purge(_load_cache())
            entry = cache.get(key)
            fresh = None
            if entry:
                try:
                    if (now - datetime.fromisoformat(entry["searched"])).total_seconds() < _RESULT_TTL:
                        fresh = entry
                except (ValueError, KeyError, TypeError):
                    pass
            _save_cache(cache)  # persist the purge even on a miss
        if fresh:
            res = dict(fresh["result"])
            res["cached"] = True
            return res

    cutoff = now - timedelta(days=days)
    hits: List[Dict] = []
    searched = failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = {pool.submit(_scan_source, s, variants, cutoff): s for s in sources}
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                res = {"error": "scan failed"}
            if res.get("error"):
                failed += 1
            else:
                searched += 1
                hits.extend(res["hits"])

    # Most authoritative first (tier 1), then most recent within each tier (stable sorts)
    hits.sort(key=lambda h: _sort_date(h["published"]), reverse=True)
    hits.sort(key=lambda h: h["tier"])
    result = {"indicator": indicator, "ioc_type": ioc_type, "value": value, "days": days,
              "hits": hits[:limit], "total": len(hits), "sources_searched": searched,
              "sources_unreachable": failed, "generated": now.isoformat(), "cached": False}
    if use_cache:
        with _cache_lock:
            cache = _purge(_load_cache())
            cache[key] = {"value": value, "ioc_type": ioc_type, "searched": now.isoformat(),
                          "days": days, "total": result["total"], "result": result}
            _save_cache(cache)
    return result


def _sort_date(iso: Optional[str]) -> str:
    return iso or ""


def status() -> Dict:
    """Source counts by tier, for the UI."""
    sources = load_sources()
    by_tier: Dict[int, int] = {}
    for s in sources:
        by_tier[s["tier"]] = by_tier.get(s["tier"], 0) + 1
    return {"total": len(sources), "by_tier": dict(sorted(by_tier.items()))}

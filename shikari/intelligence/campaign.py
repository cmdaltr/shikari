"""
Campaign research: an emerging campaign ATT&CK doesn't describe yet, profiled from the
reports about it.

Each source URL goes through the same analyser as Upload blog URL, and the results are merged: the
techniques with how many sources cite each, the groups the sources name, a timeline from their
publication dates, and the indicators with a triage of whether each is still worth hunting for.
None of that uses AI. With an AI provider chosen, a model also reads the sources and writes a
profile (summary, actor, timeline, tooling, victims); that part is marked as AI-written everywhere
it appears.

Triage is by the age of the newest source citing an indicator: network indicators (IPs, domains,
URLs) are rotated quickly, so after 90 days they are probably burned; a file hash stays useful for a
year. A CIDR range, a wildcard domain or an ASN is an infrastructure pattern, not an indicator.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from typing import Callable, Dict, List, Optional

from shikari.config import DATA_DIR

CAMPAIGN_DIR = os.path.join(DATA_DIR, "campaigns")
MAX_SOURCES = 10
NETWORK_DAYS = 90
HASH_DAYS = 365
ACTIVE, BURNED, PATTERN, UNKNOWN = "Active", "Likely burned", "Infrastructure pattern", "Age unknown"
_NETWORK = {"ip", "domain"}
_TRIAGED = _NETWORK | {"hash"}
_AI_TEXT_PER_SOURCE = 12000
_PROFILE_KEYS = ("summary", "actor", "motivation", "timeline", "tooling", "victims")


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")[:60] or "campaign"


def group_name(name: str) -> str:
    """The name the campaign's detections are generated and saved under in the library."""
    return "Campaign_" + (re.sub(r"[^\w-]+", "_", name or "").strip("_")[:60] or "unnamed")


def _clean_urls(urls: List[str]) -> List[str]:
    out = []
    for u in urls:
        u = (u or "").strip()
        if re.match(r"(?i)^https?://\S+$", u) and u not in out:
            out.append(u)
    return out


def _days(published: str, today: date) -> Optional[int]:
    try:
        return (today - date.fromisoformat(published[:10])).days
    except (TypeError, ValueError):
        return None


def triage(kind: str, value: str, newest: str, today: date) -> str:
    """What an indicator is worth hunting for, by kind and the age of its newest source."""
    if kind == "ip" and "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return PATTERN
        except ValueError:
            pass
    if kind == "domain" and "*" in value:
        return PATTERN
    if re.match(r"(?i)^AS\d+$", value):
        return PATTERN
    age = _days(newest, today)
    if age is None:
        return UNKNOWN
    return ACTIVE if age <= (HASH_DAYS if kind == "hash" else NETWORK_DAYS) else BURNED


def merge(name: str, analysed: List[Dict], techniques: Dict[str, Dict], today: date) -> Dict:
    """The campaign from each source's analysis ({url, ...analyze_blog_post's result})."""
    sources, by_technique, by_group, by_ioc, iocs_by_kind = [], {}, {}, {}, {}
    for r in analysed:
        ok = bool(r.get("success"))
        sources.append({"url": r["url"], "title": r.get("title") or r["url"], "published": r.get("published") or "",
                        "success": ok, "error": "" if ok else (r.get("error") or "Couldn't read it")[:200],
                        "techniques": len(r.get("techniques") or []),
                        "iocs": sum(len(v) for v in (r.get("iocs") or {}).values()),
                        "group": r.get("group_name") or ""})
        if not ok:
            continue
        for tid in r.get("techniques") or []:
            by_technique.setdefault(tid, []).append(r["url"])
        if r.get("group_name"):
            by_group.setdefault(r["group_name"], []).append(r["url"])
        for kind, values in (r.get("iocs") or {}).items():
            for v in values or []:
                iocs_by_kind.setdefault(kind, [])
                if v not in iocs_by_kind[kind]:
                    iocs_by_kind[kind].append(v)
                if kind in _TRIAGED:
                    by_ioc.setdefault((kind, v), []).append(r)

    read = [s for s in sources if s["success"]]
    rows = []
    for tid in sorted(by_technique, key=lambda t: (-len(by_technique[t]), t)):
        info = techniques.get(tid) or {}
        rows.append({"id": tid, "name": info.get("name") or "", "tactics": info.get("tactics") or [],
                     "sources": len(by_technique[tid])})
    indicators = []
    for (kind, value), cited in sorted(by_ioc.items()):
        dates = sorted(c.get("published") for c in cited if c.get("published"))
        newest = dates[-1] if dates else ""
        indicators.append({"kind": kind, "value": value, "triage": triage(kind, value, newest, today),
                           "first_seen": dates[0] if dates else "", "last_seen": newest, "sources": len(cited)})
    timeline = sorted(({"date": s["published"], "title": s["title"], "url": s["url"]} for s in read if s["published"]),
                      key=lambda e: e["date"])
    counts = {t: sum(1 for i in indicators if i["triage"] == t) for t in (ACTIVE, BURNED, PATTERN, UNKNOWN)}
    return {
        "name": name, "slug": slug(name), "group": group_name(name),
        "researched": today.isoformat(), "sources": sources, "sources_read": len(read),
        "techniques": rows, "groups": [{"name": g, "sources": len(u)} for g, u in
                                       sorted(by_group.items(), key=lambda kv: (-len(kv[1]), kv[0]))],
        "indicators": indicators, "triage_counts": counts, "iocs": iocs_by_kind,
        "other_iocs": {k: v for k, v in iocs_by_kind.items() if k not in _TRIAGED and v},
        "timeline": timeline, "first_reported": timeline[0]["date"] if timeline else "",
        "profile": None, "ai": False,
    }


def _profile_prompt(name: str, texts: List[Dict]) -> str:
    parts = [f"Source {i + 1}: {t['title']} ({t['url']}, published {t.get('published') or 'date unknown'})\n"
             f"{t['text'][:_AI_TEXT_PER_SOURCE]}" for i, t in enumerate(texts)]
    return (
        f"You are a cyber threat intelligence analyst. From the sources below only, profile the campaign "
        f"\"{name}\". Do not use anything the sources don't say; where they don't say, leave the field empty.\n\n"
        "Return JSON only, in this shape:\n"
        '{"summary": "three or four sentences", "actor": "who is behind it and how confident the sources are", '
        '"motivation": "", "timeline": [{"date": "YYYY-MM-DD or YYYY-MM", "event": ""}], '
        '"tooling": [{"name": "", "purpose": ""}], "victims": {"sectors": [], "regions": [], "notes": ""}}\n\n'
        + "\n\n".join(parts))


def ai_profile(name: str, texts: List[Dict], llm_config: Dict, call: Optional[Callable] = None) -> Optional[Dict]:
    """The AI-written profile, or None if there's no text or the model's answer isn't usable."""
    if not texts:
        return None
    if call is None:
        from shikari.build.llm_queries import call_llm as call
    try:
        raw = call(_profile_prompt(name, texts), {**llm_config, "max_tokens": 2000})
    except Exception as e:  # a provider error leaves the deterministic profile intact
        print(f"⚠️  Campaign profile: the AI call failed ({e})")
        return None
    m = re.search(r"\{.*\}", raw or "", re.S)
    try:
        data = json.loads(m.group(0)) if m else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return None
    profile = {k: data.get(k) for k in _PROFILE_KEYS}
    profile["timeline"] = [e for e in profile["timeline"] or [] if isinstance(e, dict) and e.get("event")]
    profile["tooling"] = [t for t in profile["tooling"] or [] if isinstance(t, dict) and t.get("name")]
    if not isinstance(profile["victims"], dict):
        profile["victims"] = {}
    return profile


def research(name: str, urls: List[str], bundle=None, search_more: bool = False, llm_config: Optional[Dict] = None,
             today: Optional[date] = None, analyse: Optional[Callable] = None, find: Optional[Callable] = None,
             max_sources: int = MAX_SOURCES) -> Dict:
    """The campaign profile from its source URLs (and, with search_more, the reports Shikari's archive
    and the news searches find for its name)."""
    from shikari.visualization.navigator import technique_index

    name = " ".join((name or "").split())[:120]
    if len(name) < 3:
        raise ValueError("Give the campaign a name of at least three characters")
    urls = _clean_urls(urls)
    if search_more:
        if find is None:
            from shikari.intelligence.research_search import search as find
        found = find(name, bundle, True)
        for item in (found.get("sources") or []) + (found.get("web") or []):
            urls = _clean_urls(urls + [item.get("url") or ""])
    urls = urls[:max_sources]
    if not urls:
        raise ValueError("Give at least one report URL" + ("" if search_more else ", or search for more"))
    if analyse is None:
        from shikari.parsers.blog_analyzer import analyze_blog_post as analyse

    def one(url):
        try:
            return {**analyse(url, include_text=bool(llm_config), bundle=bundle), "url": url}
        except Exception as e:
            return {"success": False, "error": str(e), "url": url}

    with ThreadPoolExecutor(max_workers=4) as pool:
        analysed = list(pool.map(one, urls))
    today = today or datetime.now(timezone.utc).date()
    campaign = merge(name, analysed, technique_index(bundle), today)
    if llm_config:
        texts = [{"title": r.get("title") or r["url"], "url": r["url"], "published": r.get("published") or "",
                  "text": r["text"]} for r in analysed if r.get("success") and r.get("text")]
        campaign["profile"] = ai_profile(name, texts, llm_config)
        campaign["ai"] = campaign["profile"] is not None
        campaign["ai_model"] = llm_config.get("model") or llm_config.get("provider") or ""
    return campaign


# ---------------------------------------------------------------- storage

def _path(campaign_slug: str) -> str:
    return os.path.join(CAMPAIGN_DIR, f"{slug(campaign_slug)}.json")


def save(campaign: Dict) -> str:
    os.makedirs(CAMPAIGN_DIR, exist_ok=True)
    path = _path(campaign["slug"])
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(campaign, fh, indent=2)
    return path


def load(campaign_slug: str) -> Optional[Dict]:
    try:
        with open(_path(campaign_slug), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def delete(campaign_slug: str) -> bool:
    try:
        os.remove(_path(campaign_slug))
        return True
    except OSError:
        return False


def all_campaigns() -> List[Dict]:
    """Saved campaigns, newest research first, as list rows."""
    out = []
    if not os.path.isdir(CAMPAIGN_DIR):
        return out
    for f in os.listdir(CAMPAIGN_DIR):
        if not f.endswith(".json"):
            continue
        c = load(f[:-5])
        if c:
            out.append({"slug": c["slug"], "name": c["name"], "researched": c.get("researched") or "",
                        "sources": c.get("sources_read") or 0, "techniques": len(c.get("techniques") or []),
                        "indicators": len(c.get("indicators") or []), "active": (c.get("triage_counts") or {}).get(ACTIVE, 0),
                        "first_reported": c.get("first_reported") or "", "ai": bool(c.get("ai"))})
    return sorted(out, key=lambda r: (r["researched"], r["name"]), reverse=True)


def extraction(campaign: Dict, active_only: bool = True) -> Dict:
    """The campaign in Upload blog URL's extraction shape, so /blog/generate builds its detections.
    Network indicators and hashes triaged as burned are left out unless active_only is False."""
    keep = {(i["kind"], i["value"]) for i in campaign.get("indicators") or []
            if not active_only or i["triage"] in (ACTIVE, UNKNOWN)}
    iocs = {k: [v for v in vs if k not in _TRIAGED or (k, v) in keep] for k, vs in (campaign.get("iocs") or {}).items()}
    read = [s["url"] for s in campaign.get("sources") or [] if s.get("success")]
    return {"url": read[0] if read else "", "filename": f"Campaign: {campaign['name']}", "group_name": "",
            "ttps": [t["id"] for t in campaign.get("techniques") or []], "iocs": {k: v for k, v in iocs.items() if v},
            "ioc_mentions": {}, "procedures": [], "synthetic_group_name": campaign["group"],
            "ai_provider": "", "ai_model": "", "run_correlation": True}

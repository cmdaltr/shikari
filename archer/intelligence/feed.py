"""
Threat feed: the last week's research from reputable sources, sorted by whether it
matters to the user's industries.

Each post in the sources' RSS/Atom feeds from the last FEED_DAYS days is fetched and run
through the report analyser (archer.parsers.blog_analyzer: technique IDs, procedures,
IOCs), then matched two ways:

- Targets your industry: it names an ATT&CK group whose targeting (group_metadata's
  target_sectors) includes one of the user's industries, or it names the industry itself
  repeatedly or in its title. A group counts only when it (or an alias) is named in the
  title or in a paragraph with a technique ID or next to one: a passing mention in a
  policy piece or a "related reading" list isn't the post being about that group.
- Opportunistic: activity that picks no industry and can land in any of them: supply-chain
  and package-registry compromise, mass exploitation of a vulnerability, ransomware
  affiliates, infostealers, botnets, malvertising. A group whose ATT&CK objective is
  ransomware or extortion counts too.

Posts with neither are left out, as are posts with no technical content (no technique ID,
IOCs, CVE or named group): product news and webinars.

The analysis of each post is industry-independent and cached (data/feed/posts.json), so a
refresh only fetches posts it hasn't seen, and each user's view is computed on request.
"""

import html
import json
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, Iterable, List, Optional

from archer.config import DATA_DIR

FEED_DAYS = 7
ANALYSIS_VERSION = 4        # bump when the matchers change: cached posts are analysed again
REFRESH_EVERY = 6 * 3600
FEED_DIR = os.path.join(DATA_DIR, "feed")
CACHE_PATH = os.path.join(FEED_DIR, "posts.json")
# CISA's CDN refuses requests' default Accept/Accept-Encoding with a 403
HEADERS = {"User-Agent": "Archer/1.0", "Accept": "*/*", "Accept-Encoding": "identity"}

# Vendor and government research feeds: primary reporting, not news aggregation
SOURCES = [
    ("Microsoft Threat Intelligence", "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/"),
    ("Google Threat Intelligence", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("CrowdStrike", "https://www.crowdstrike.com/en-us/blog/feed"),
    ("SentinelLABS", "https://www.sentinelone.com/labs/feed/"),
    ("Kaspersky Securelist", "https://securelist.com/feed/"),
    ("ESET WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/"),
    ("Proofpoint", "https://www.proofpoint.com/us/threat-insight-blog.xml"),
    ("The DFIR Report", "https://thedfirreport.com/feed/"),
    ("Red Canary", "https://redcanary.com/blog/feed/"),
    ("Huntress", "https://www.huntress.com/blog/rss.xml"),
    ("Check Point Research", "https://research.checkpoint.com/feed/"),
    ("Elastic Security Labs", "https://www.elastic.co/security-labs/rss/feed.xml"),
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("NCSC (UK)", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"),
    ("Recorded Future", "https://www.recordedfuture.com/feed"),
    ("Trend Micro Research", "http://feeds.trendmicro.com/TrendMicroResearch"),
    ("Rapid7", "https://www.rapid7.com/blog/rss/"),
    ("FortiGuard Labs", "https://feeds.fortinet.com/fortinet/blog/threat-research"),
]

# Industries a user can follow: the sector labels ATT&CK groups are tagged with
# (archer.mitre.group_metadata), so a group's targeting matches directly
INDUSTRIES = [
    "Finance / Banking", "Government", "Defense / Military", "Aerospace / Aviation", "Energy / Utilities",
    "Healthcare / Pharma", "Technology", "Telecommunications", "Education / Research",
    "Manufacturing / Industrial", "Retail / Hospitality", "Media / Entertainment", "Transport / Logistics",
    "Critical Infrastructure", "NGO / Civil Society", "Think Tank / Policy",
]


def industry_label(industry: str) -> str:
    return industry.replace("Defense", "Defence")


# Activity that picks no industry
OPPORTUNISTIC = [
    (re.compile(r"supply[- ]chain (?:attack|compromise)|compromised (?:software )?update|trojani[sz]ed (?:installer|update|package)", re.I), "supply-chain compromise"),
    (re.compile(r"\b(?:npm|PyPI|RubyGems|NuGet|crates\.io|Docker Hub|VS ?Code extension|browser extension)s?\b.{0,80}\b(?:malicious|compromised|typosquat)", re.I | re.S), "malicious packages or extensions"),
    (re.compile(r"\b(?:malicious|compromised|typosquat\w*)\b.{0,80}\b(?:npm|PyPI|RubyGems|NuGet|packages?)\b", re.I | re.S), "malicious packages or extensions"),
    (re.compile(r"mass[- ]exploitation|exploited in the wild|widespread exploitation|actively exploited|opportunistic|indiscriminate", re.I), "mass or opportunistic exploitation"),
    # Exploitation someone reported, not an advisory's "an attacker could exploit"
    (re.compile(r"\b(?:threat actors?|attackers|adversaries|hackers|operators|criminals)\s+(?:have\s+(?:been\s+)?|are\s+|were\s+)?"
                r"(?:actively\s+|now\s+)?exploit(?:ed|ing)?\b", re.I), "vulnerability exploitation"),
    (re.compile(r"ransomware[- ]as[- ]a[- ]service|\bRaaS\b|ransomware affiliate", re.I), "ransomware-as-a-service"),
    (re.compile(r"\binfostealers?\b|information stealer|\b(?:Lumma|RedLine|Vidar|StealC|Raccoon|AMOS|Atomic Stealer|Rhadamanthys)\b", re.I), "infostealer"),
    (re.compile(r"\bbotnets?\b", re.I), "botnet"),
    (re.compile(r"malvertising|SEO poisoning|drive-by download|fake (?:browser )?update|ClickFix", re.I), "malvertising or fake updates"),
    (re.compile(r"initial access broker", re.I), "initial access broker"),
]

# Group names that are also ordinary words: matching them in prose would be noise
_AMBIGUOUS_NAMES = {"Silence", "Inception", "Equation", "Axiom", "Patchwork", "Leviathan", "Poseidon",
                    "Machete", "Sidewinder", "Moafee", "Elderwood", "Strider", "Suckfly", "Scarlet Mimic"}

# Paragraphs either side of one with a technique ID in which a group name still counts
NEAR_TECHNIQUES = 1
_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_lock = threading.Lock()
_refreshing = False
_status: Dict = {"refreshing": False, "last_refresh": None, "error": None}


# ---------------------------------------------------------------- fetching

def _text(el, *names) -> str:
    for name in names:
        found = el.find(name)
        if found is not None:
            if found.text and found.text.strip():
                return found.text.strip()
            if found.get("href"):
                return found.get("href").strip()
    return ""


def _date(value: str) -> Optional[datetime]:
    if not value:
        return None
    for parse in (parsedate_to_datetime, lambda v: datetime.fromisoformat(v.replace("Z", "+00:00"))):
        try:
            d = parse(value)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            continue
    try:
        from dateutil import parser as dateparser

        d = dateparser.parse(value)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def parse_feed(xml: bytes, source: str) -> List[Dict]:
    """RSS 2.0 items or Atom entries as {title, url, source, published, summary}."""
    root = ET.fromstring(xml)
    atom = "{http://www.w3.org/2005/Atom}"
    items = root.findall(".//item") or root.findall(f".//{atom}entry")
    posts = []
    for it in items:
        if it.tag.startswith(atom):
            link = next((l.get("href") for l in it.findall(f"{atom}link")
                         if l.get("rel") in (None, "alternate") and l.get("href")), "")
            title = _text(it, f"{atom}title")
            published = _date(_text(it, f"{atom}published", f"{atom}updated"))
            summary = _text(it, f"{atom}summary", f"{atom}content")
        else:
            link = _text(it, "link", "guid")
            title = _text(it, "title")
            published = _date(_text(it, "pubDate", "{http://purl.org/dc/elements/1.1/}date"))
            summary = _text(it, "description")
        if link.startswith("http") and title:
            posts.append({"title": re.sub(r"\s+", " ", title), "url": link, "source": source,
                          "published": published.isoformat() if published else None,
                          "summary": re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", summary)))[:600].strip()})
    return posts


def fetch_sources(days: int = FEED_DAYS, sources=SOURCES) -> List[Dict]:
    import requests

    since = datetime.now(timezone.utc) - timedelta(days=days)

    def one(src):
        name, url = src
        try:
            r = requests.get(url, timeout=20, headers=HEADERS)
            r.raise_for_status()
            return [p for p in parse_feed(r.content, name)
                    if p["published"] and datetime.fromisoformat(p["published"]) >= since]
        except Exception as e:
            print(f"Threat feed: {name} unavailable: {e}")
            return []

    with ThreadPoolExecutor(max_workers=8) as pool:
        posts = [p for batch in pool.map(one, sources) for p in batch]
    seen, unique = set(), []
    for p in sorted(posts, key=lambda p: p["published"], reverse=True):
        if p["url"] not in seen:
            seen.add(p["url"])
            unique.append(p)
    return unique


# ---------------------------------------------------------------- analysis

def group_index(bundle, group_meta: Dict) -> List[Dict]:
    """ATT&CK groups as {id, name, pattern, sectors, opportunistic} for matching in prose."""
    groups = []
    for obj in getattr(bundle, "objects", None) or []:
        if obj.get("type") != "intrusion-set" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        gid = next((r.get("external_id") for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        names = {n for n in [obj.get("name", "")] + list(obj.get("aliases") or [])
                 if len(n) >= 4 and n not in _AMBIGUOUS_NAMES}
        if not gid or not names:
            continue
        meta = group_meta.get(gid) or {}
        sectors = [s.strip() for s in (meta.get("target_sectors") or "").split(";") if s.strip()]
        objectives = meta.get("primary_objectives") or ""
        groups.append({
            "id": gid, "name": obj.get("name"),
            # Case-sensitive: aliases are proper nouns, and lower-case matches are usually words
            "pattern": re.compile(r"(?<![\w-])(?:" + "|".join(map(re.escape, sorted(names, key=len, reverse=True)))
                                  + r")(?![\w-])"),
            "sectors": sectors,
            "opportunistic": "Ransomware" in objectives,
        })
    return groups


def _sector_mentions(text: str, title: str) -> Dict[str, int]:
    from archer.mitre.group_metadata import _SECTORS

    out = {}
    for pattern, label in _SECTORS:
        n = len(pattern.findall(text))
        if pattern.search(title):
            n += 2
        if n:
            out[label] = out.get(label, 0) + n
    return out


def technique_context(title: str, text: str, near: int = NEAR_TECHNIQUES) -> str:
    """The title plus each paragraph with a technique ID and the `near` paragraphs either side."""
    paragraphs = [p for p in text.split("\n") if p.strip()]
    keep = set()
    for i, paragraph in enumerate(paragraphs):
        if _TECHNIQUE_ID.search(paragraph):
            keep.update(range(max(0, i - near), min(len(paragraphs), i + near + 1)))
    return "\n".join([title] + [paragraphs[i] for i in sorted(keep)])


def analyse_post(post: Dict, groups: List[Dict]) -> Dict:
    """The post with what the report analyser and the matchers found; industry-independent."""
    from archer.parsers.blog_analyzer import analyze_blog_post

    result = analyze_blog_post(post["url"], include_text=True)
    if not result.get("success"):
        return {**post, "error": result.get("error") or "could not be read", "analysed": time.time()}
    text = result.get("text") or ""
    full = f"{post['title']}\n{text}"
    context = technique_context(post["title"], text)
    named = [g for g in groups if g["pattern"].search(context)]
    iocs = result.get("iocs") or {}
    return {
        **post,
        "techniques": result.get("techniques", [])[:60],
        "procedures": len(result.get("procedures") or []),
        "iocs": sum(len(v) for v in iocs.values() if isinstance(v, list)),
        "cves": sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", full)))[:20],
        "groups": [{"id": g["id"], "name": g["name"], "sectors": g["sectors"],
                    "opportunistic": g["opportunistic"]} for g in named][:15],
        "sectors": _sector_mentions(text, post["title"]),
        "opportunistic": sorted({reason for pattern, reason in OPPORTUNISTIC if pattern.search(full)}),
        "analysed": time.time(), "version": ANALYSIS_VERSION,
    }


def classify(post: Dict, industries: Iterable[str]) -> Optional[Dict]:
    """Why the post matters to these industries ({"industry": [...], "opportunistic": [...]}), or None."""
    if post.get("error"):
        return None
    # The analyser's "procedures" are sentences with attack verbs: product posts have them too
    technical = post.get("techniques") or post.get("iocs", 0) >= 3 or post.get("groups") or post.get("cves")
    if not technical:
        return None
    wanted = set(industries)
    industry = []
    for g in post.get("groups", []):
        hit = [s for s in g["sectors"] if s in wanted]
        if hit:
            industry.append(f"{g['name']} ({g['id']}) targets {', '.join(map(industry_label, hit))}")
    for label, n in sorted(post.get("sectors", {}).items(), key=lambda kv: -kv[1]):
        if label in wanted and n >= 4:
            industry.append(f"names {industry_label(label)} ({n}×)")
    opportunistic = list(post.get("opportunistic") or [])
    opportunistic += [f"{g['name']}: ransomware or extortion" for g in post.get("groups", []) if g["opportunistic"]]
    if not industry and not opportunistic:
        return None
    return {"industry": industry, "opportunistic": opportunistic}


# ---------------------------------------------------------------- cache and refresh

def _load() -> Dict:
    try:
        with open(CACHE_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"posts": {}, "last_refresh": None}


def _save(data: Dict) -> None:
    os.makedirs(FEED_DIR, exist_ok=True)
    tmp = CACHE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, CACHE_PATH)


def refresh(bundle, group_meta: Dict, days: int = FEED_DAYS, workers: int = 6) -> Dict:
    """Fetch the sources, analyse new posts, drop ones older than the window. Returns the cache."""
    global _refreshing
    with _lock:
        if _refreshing:
            return _load()
        _refreshing = True
    _status.update(refreshing=True, error=None)
    try:
        data = _load()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        posts = {u: p for u, p in data.get("posts", {}).items() if (p.get("published") or "") >= cutoff}
        fresh = [p for p in fetch_sources(days) if p["url"] not in posts or posts[p["url"]].get("error")
                 or posts[p["url"]].get("version") != ANALYSIS_VERSION]
        groups = group_index(bundle, group_meta)
        print(f"Threat feed: analysing {len(fresh)} new post(s)")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for post in pool.map(lambda p: analyse_post(p, groups), fresh):
                posts[post["url"]] = post
        data = {"posts": posts, "last_refresh": time.time()}
        _save(data)
        _status["last_refresh"] = data["last_refresh"]
        return data
    except Exception as e:
        _status["error"] = str(e)
        raise
    finally:
        _status["refreshing"] = False
        _refreshing = False


def refresh_in_background(bundle, group_meta: Dict, force: bool = False) -> bool:
    """Start a refresh unless one is running or the cache is fresh. True when one was started."""
    last = _load().get("last_refresh") or 0
    if _refreshing or (not force and time.time() - last < REFRESH_EVERY):
        return False

    def run():
        try:
            refresh(bundle, group_meta)
        except Exception as e:
            print(f"Threat feed refresh failed: {e}")

    threading.Thread(target=run, daemon=True, name="threat-feed").start()
    return True


def view(industries: Iterable[str], days: int = FEED_DAYS) -> Dict:
    """This user's feed: matching posts, newest first, split into industry and opportunistic."""
    industries = [i for i in industries if i in INDUSTRIES]
    data = _load()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    industry, opportunistic, considered = [], [], 0
    for post in sorted(data.get("posts", {}).values(), key=lambda p: p.get("published") or "", reverse=True):
        if (post.get("published") or "") < cutoff:
            continue
        considered += 1
        why = classify(post, industries)
        if not why:
            continue
        entry = {k: post.get(k) for k in ("title", "url", "source", "published", "summary", "techniques",
                                          "cves", "procedures", "iocs")}
        entry["groups"] = [g["name"] for g in post.get("groups", [])]
        entry["why"] = why
        (industry if why["industry"] else opportunistic).append(entry)
    return {"industries": industries, "labels": [industry_label(i) for i in industries], "days": days,
            "industry": industry, "opportunistic": opportunistic, "considered": considered,
            "last_refresh": data.get("last_refresh"), "refreshing": _status["refreshing"],
            "sources": [name for name, _ in SOURCES]}

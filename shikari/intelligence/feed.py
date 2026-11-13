"""
Threat feed: the last week's research from reputable sources, as a wall of posts tagged
with the industries targeted, the attacker's nation, and opportunistic or financially
motivated activity. No AI is involved: regular expressions over the text plus ATT&CK's
own group data.

Each post in the sources' RSS/Atom feeds from the last FEED_DAYS days is fetched and run
through the report analyser (shikari.parsers.blog_analyzer: technique IDs, IOCs), then
tagged from its title and its technical paragraphs only: those with a technique ID, hash,
IP, defanged domain, file name, command or registry key (or a CVE, when the post has one of
those too), and the paragraph either side. A passing mention in a policy piece or a "related reading" list doesn't count.

- Industries: the targeting (group_metadata's target_sectors) of each ATT&CK group named
  there (name or alias); the industries a nation's groups mostly target, when the
  activity is attributed to that nation ("China-nexus", "DPRK", "Russian GRU"); and
  industries the post itself names twice or in its title.
- Nations: those attributed in that text, and the nexus of each named group.
- Actors ATT&CK doesn't have yet (Storm-2603, UNC6040, "… Typhoon", "… Spider"): the
  vendors' naming schemes give their nation or financial motive (ACTOR_NAMES).
- Opportunistic: supply-chain and package-registry compromise, reported exploitation,
  ransomware-as-a-service, infostealers, botnets, malvertising, initial access brokers.
- Financially motivated: ransomware, extortion, BEC, crypto theft or mining, banking
  trojans, or a named group whose ATT&CK objective is financial.

Posts with no technical content at all (no technique ID, IOCs or named group, and no CVE
alongside another indicator) are left out: product news and webinars. Each post also gets a two-to-three sentence
description, from its RSS summary or, when that is thin or boilerplate, its opening
paragraphs.

The analysis is user-independent and cached (data/feed/posts.json), so a refresh only
fetches posts it hasn't seen; it runs when Shikari starts and on demand.
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

from shikari.config import DATA_DIR
from shikari.intelligence.tech_stack import as_stack, label, products_named, targets_in

FEED_DAYS = 7
ANALYSIS_VERSION = 9        # bump when the matchers change: cached posts are analysed again
REFRESH_EVERY = 6 * 3600
FEED_DIR = os.path.join(DATA_DIR, "feed")
CACHE_PATH = os.path.join(FEED_DIR, "posts.json")
# CISA's CDN refuses requests' default Accept/Accept-Encoding with a 403
HEADERS = {"User-Agent": "Shikari/1.0", "Accept": "*/*", "Accept-Encoding": "identity"}

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
    ("Elastic Security Labs", "https://www.elastic.co/security-labs/rss/feed.xml"),
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("NCSC (UK)", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"),
    ("Recorded Future", "https://www.recordedfuture.com/feed"),
    ("Trend Micro Research", "https://feeds.feedburner.com/TrendMicroResearch"),
    ("Rapid7", "https://www.rapid7.com/rss.xml"),
    ("FortiGuard Labs", "https://feeds.fortinet.com/fortinet/blog/threat-research"),
    ("Symantec Threat Hunter", "https://www.security.com/rss/v1/blogs/rss.xml/221"),
    ("Volexity", "https://www.volexity.com/feed/"),
    ("Zscaler ThreatLabz", "https://www.zscaler.com/blogs/feeds/security-research"),
    ("Sekoia", "https://blog.sekoia.io/feed/"),
    ("Group-IB", "https://www.group-ib.com/blog/feed/"),
    ("Bitdefender Labs", "https://www.bitdefender.com/blog/api/rss/labs/"),
    ("JPCERT/CC", "https://blogs.jpcert.or.jp/en/atom.xml"),
]
# Sources an admin adds on the Feed page (add_source): this installation's, not committed
CUSTOM_SOURCES_PATH = os.path.join(DATA_DIR, "feed", "sources.json")

# Industries a user can follow and posts are tagged with
INDUSTRIES = [
    "Aerospace", "Critical Infrastructure", "Energy", "Education", "Finance", "Government", "Healthcare",
    "Logistics", "Manufacturing", "Media", "Military / Defence", "NGO", "Retail", "Technology",
    "Telecommunications",
]

# The sector labels ATT&CK groups are tagged with (shikari.mitre.group_metadata), and the
# industry each counts as. Think tanks have no industry of their own here.
SECTOR_INDUSTRY = {
    "Aerospace / Aviation": "Aerospace", "Critical Infrastructure": "Critical Infrastructure",
    "Energy / Utilities": "Energy", "Education / Research": "Education", "Finance / Banking": "Finance",
    "Government": "Government", "Healthcare / Pharma": "Healthcare", "Transport / Logistics": "Logistics",
    "Manufacturing / Industrial": "Manufacturing", "Media / Entertainment": "Media",
    "Defense / Military": "Military / Defence", "NGO / Civil Society": "NGO", "Retail / Hospitality": "Retail",
    "Technology": "Technology", "Telecommunications": "Telecommunications",
}


def as_industries(names: Iterable[str]) -> List[str]:
    """Industries from saved choices or sector labels (older profiles saved sector labels), in list order."""
    chosen = {SECTOR_INDUSTRY.get(n, n) for n in names}
    return [i for i in INDUSTRIES if i in chosen]


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

# Paragraphs either side of a technical one that still count as its context
NEAR_TECHNICAL = 1
FETCH_TIMEOUT = 15
# A paragraph with any of these is technical: technique ID, hash, IPv4, defanged domain or
# URL, file name, command-line tool, registry key, command-line switch
_INDICATOR = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b|\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b"
    r"|\b\d{1,3}(?:\[?\.\]?\d{1,3}){3}\b|\[\.\]|hxxps?://"
    r"|\b[\w-]+\.(?:exe|dll|ps1|bat|vbs|hta|lnk|msi|sh|jar|scr|iso|zip)\b"
    r"|\b(?:cmd\.exe|powershell|rundll32|regsvr32|mshta|wmic|schtasks|certutil|bitsadmin|curl|wget|chmod|crontab|osascript)\b"
    r"|\bHK(?:LM|CU|EY_[A-Z_]+)\\|(?<=\s)--?[a-z][\w-]{0,20}(?=\s)", re.I)
# A CVE is technical only alongside one of those somewhere in the post: newsletters and policy
# pieces cite CVEs in passing
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")

# Attribution to a nation: "China-nexus", "Chinese state-sponsored", "DPRK hackers"; a bare
# country name is usually geography (the victim), not the attacker. In scope: every state the
# IISS assesses in Cyber Capabilities and National Power (2021; tier one: United States; tier
# two: Australia, Canada, China, France, Israel, Russia, United Kingdom; tier three: India,
# Indonesia, Iran, Japan, Malaysia, North Korea, Vietnam) and its volume 2 (2023: Brazil,
# Estonia, Germany, Netherlands, Nigeria, Saudi Arabia, Singapore, South Africa, Türkiye,
# UAE); those ATT&CK attributes groups to; and the origins vendors' actor names encode
# (ACTOR_NAMES). Acronyms are case-sensitive, so "us" isn't the US.
NATIONS = {
    "China": r"China|Chinese|(?-i:PRC)",
    "Russia": r"Russia|Russian|(?-i:GRU|FSB|SVR)",
    "Iran": r"Iran|Iranian|(?-i:IRGC|MOIS)",
    "North Korea": r"North Korea|North Korean|(?-i:DPRK)",
    "United States": r"United States|American|(?-i:US|U\.S\.|USA|NSA|CIA)",
    "United Kingdom": r"United Kingdom|British|(?-i:UK|U\.K\.|GCHQ)",
    "Australia": r"Australia|Australian", "Canada": r"Canada|Canadian", "France": r"France|French",
    "Israel": r"Israel|Israeli", "India": r"India|Indian", "Indonesia": r"Indonesia|Indonesian",
    "Japan": r"Japan|Japanese", "Malaysia": r"Malaysia|Malaysian", "Vietnam": r"Vietnam|Vietnamese|Viet Nam",
    # IISS volume 2 (2023)
    "Brazil": r"Brazil|Brazilian", "Estonia": r"Estonia|Estonian", "Germany": r"Germany|German",
    "Netherlands": r"Netherlands|Dutch", "Nigeria": r"Nigeria|Nigerian", "Saudi Arabia": r"Saudi Arabia|Saudi",
    "Singapore": r"Singapore|Singaporean", "South Africa": r"South Africa|South African",
    "Turkey": r"Turkey|Turkish|Türkiye|Turkiye", "United Arab Emirates": r"United Arab Emirates|Emirati|(?-i:UAE)",
    # Not assessed by the IISS, but ATT&CK attributes groups to them, or vendors' names do
    "Pakistan": r"Pakistan|Pakistani", "Belarus": r"Belarus|Belarusian", "Lebanon": r"Lebanon|Lebanese",
    "South Korea": r"South Korea|South Korean",
}
# The four with long ATT&CK records keep the broad wording ("Chinese operators", "Iran-based
# cluster"). Elsewhere it must be unmistakable attribution: "US-based", "UK groups", "French
# intelligence" and "American operators" are usually victims, vendors or the advisory's
# co-signers (a joint CISA/NCSC advisory names both)
_BROAD = {"China", "Russia", "Iran", "North Korea"}
_ATTRIBUTED = (r"(?:-|\s)(?:nexus|linked|based|backed|sponsored|state[- ]sponsored|affiliated|aligned|government[- ]linked"
               r"|nation[- ]state|APT|threat actors?|hackers|actors?|operators|groups?|cluster|intelligence)")
_ATTRIBUTED_STRICT = (r"(?:-|\s)(?:nexus|backed|(?:state|government)[- ]sponsored|sponsored|government[- ]linked"
                      r"|nation[- ]state|APT|threat actors?|hackers|espionage (?:group|actor|campaign)s?)")
NATION_PATTERNS = {
    n: re.compile(rf"\b(?:{alt}){_ATTRIBUTED if n in _BROAD else _ATTRIBUTED_STRICT}\b"
                  rf"|\b(?:state[- ]sponsored|nation[- ]state)\s+(?:{alt})\b", re.I)
    for n, alt in NATIONS.items()}
# "-nexus" is only ever attribution, so any country before it counts ("Kazakhstan-nexus")
_ANY_NEXUS = re.compile(r"\b([A-Z][a-z]+(?: [A-Z][a-z]+)?)-nexus\b")
_NEXUS_ALIASES = {"PRC": "China", "DPRK": "North Korea", "US": "United States", "UK": "United Kingdom",
                  "UAE": "United Arab Emirates", "Turkiye": "Turkey", "Türkiye": "Turkey"}


def nations_in(text: str) -> List[str]:
    """Nations the text attributes activity to: NATION_PATTERNS, and any "<Country>-nexus"."""
    found = {n for n, pattern in NATION_PATTERNS.items() if pattern.search(text)}
    for m in _ANY_NEXUS.finditer(text):
        name = m.group(1)
        name = _NEXUS_ALIASES.get(name, name)
        # Demonyms: "Chinese-nexus" is China's, already found above
        if not any(re.fullmatch(alt, name, re.I) for alt in NATIONS.values()):
            found.add(name)
    return sorted(found)


# A nation's industries: those at least this share of its ATT&CK groups target, when it has
# enough groups for a share to mean anything
MIN_PROFILE_GROUPS = 5
NATION_SECTOR_SHARE = 0.3

FINANCIAL = re.compile(r"financially[- ]motivated|\bransomware\b|\bextortion\b|business email compromise|\bBEC\b"
                       r"|crypto(?:currency)?[- ](?:theft|heist|drain)|cryptomin(?:er|ing)|\bXMRig\b|banking trojan"
                       r"|\bcarding\b|payment card (?:theft|skimm)", re.I)

# Threat actors ATT&CK doesn't (yet) have: vendors name new clusters months or years before
# ATT&CK adds a group, and their naming schemes say the nation or motive. (pattern, nation,
# financial)
_CAP = r"[A-Z][a-z]{2,}"
ACTOR_NAMES = [
    # Microsoft: <weather> family by origin; Storm-#### unattributed
    (rf"\b{_CAP} Typhoon\b", "China", False), (rf"\b{_CAP} Blizzard\b", "Russia", False),
    (rf"\b{_CAP} Sandstorm\b", "Iran", False), (rf"\b{_CAP} Sleet\b", "North Korea", False),
    (rf"\b{_CAP} Hail\b", "South Korea", False), (rf"\b{_CAP} Dust\b", "Turkey", False),
    (rf"\b{_CAP} Cyclone\b", "Vietnam", False), (rf"\b{_CAP} Tempest\b", None, True),
    (r"\bStorm-\d{4}\b", None, False),
    # CrowdStrike: <animal> by origin; Spider is eCrime
    (rf"\b{_CAP} Panda\b", "China", False), (rf"\b{_CAP} Bear\b", "Russia", False),
    (rf"\b{_CAP} Kitten\b", "Iran", False), (rf"\b{_CAP} Chollima\b", "North Korea", False),
    (rf"\b{_CAP} Spider\b", None, True),
    # Unit 42: <constellation> by origin or motive; CL-STA (state), CL-CRI (criminal)
    (rf"\b{_CAP} Taurus\b", "China", False), (rf"\b{_CAP} Ursa\b", "Russia", False),
    (rf"\b{_CAP} Serpens\b", "Iran", False), (rf"\b{_CAP} Pisces\b", "North Korea", False),
    (rf"\b{_CAP} (?:Libra|Scorpius)\b", None, True),
    (r"\b(?:CL|TGR)-STA-\d{3,}\b", None, False), (r"\b(?:CL|TGR)-CRI-\d{3,}\b", None, True),
    # Numbered clusters: Mandiant UNC/FIN, Proofpoint TA, Talos UAT, Recorded Future TAG
    (r"\bUNC\d{3,5}\b", None, False), (r"\bFIN\d{1,3}\b", None, True), (r"\bTA\d{3,4}\b", None, False),
    (r"\bUAT-?\d{3,5}\b", None, False), (r"\bTAG-\d{2,4}\b", None, False),
]
ACTOR_PATTERNS = [(re.compile(p), nation, financial) for p, nation, financial in ACTOR_NAMES]
# "Teddy Bear", "Red Panda" and the like aren't actors
_NOT_ACTORS = {"Teddy Bear", "Red Panda", "Giant Panda", "Polar Bear", "Brown Bear", "Black Bear", "Grizzly Bear",
               "Sand Storm", "Dust Storm"}


def actors(context: str, known: Iterable[str] = ()) -> List[Dict]:
    """Vendor-named actors in the technical text, ATT&CK groups (`known` names) excluded."""
    known = {k.lower() for k in known}
    out, seen = [], set()
    for pattern, nation, financial in ACTOR_PATTERNS:
        for m in pattern.finditer(context):
            name = m.group(0)
            if name in _NOT_ACTORS or name.lower() in known or name in seen:
                continue
            seen.add(name)
            out.append({"name": name, "nation": nation, "financial": financial})
    return out[:15]


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
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        # One bad character (Rapid7's feed has some) shouldn't lose the whole feed: lxml's
        # recovering parser keeps every item it can read
        from lxml import etree
        root = ET.fromstring(etree.tostring(etree.fromstring(xml, etree.XMLParser(recover=True, huge_tree=True))))
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


def custom_sources() -> List[tuple]:
    try:
        with open(CUSTOM_SOURCES_PATH, encoding="utf-8") as f:
            return [(s["name"], s["url"]) for s in json.load(f) if s.get("name") and s.get("url")]
    except (OSError, ValueError, TypeError, KeyError):
        return []


def all_sources() -> List[tuple]:
    return list(SOURCES) + custom_sources()


def _public_url(url: str) -> Optional[str]:
    """Why the server shouldn't fetch this URL, or None: http(s) to a public address only."""
    import ipaddress
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return "Use an http or https URL"
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(parsed.hostname, parsed.port or None)}
    except OSError:
        return f"{parsed.hostname} doesn't resolve"
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return f"{parsed.hostname} is a private or local address"
    return None


def _why(e: Exception) -> str:
    """A failed fetch, said plainly."""
    import requests

    if isinstance(e, requests.HTTPError) and e.response is not None:
        return f"the server answered {e.response.status_code}"
    if isinstance(e, (requests.Timeout, requests.ConnectionError)):
        return "no response"
    if isinstance(e, requests.RequestException):
        return "couldn't be fetched"
    return "not an RSS or Atom feed"


def check_source(url: str) -> Dict:
    """Fetch and parse a feed: {ok, items, latest} or {ok: False, error}."""
    import requests

    why = _public_url(url)
    if why:
        return {"ok": False, "error": why}
    try:
        r = requests.get(url, timeout=FETCH_TIMEOUT, headers=HEADERS)
        r.raise_for_status()
        posts = parse_feed(r.content, "")
    except Exception as e:
        return {"ok": False, "error": f"That URL: {_why(e)}"}
    if not posts:
        return {"ok": False, "error": "It's a feed, but has no posts with links"}
    return {"ok": True, "items": len(posts), "latest": max((p["published"] or "" for p in posts), default=None)}


def add_source(name: str, url: str) -> Dict:
    """Add a custom source once it reads as a feed. {ok, ...check_source} or {ok: False, error}."""
    name, url = (name or "").strip()[:80], (url or "").strip()
    if not name or not url:
        return {"ok": False, "error": "Give it a name and a feed URL"}
    taken = all_sources()
    if any(n.lower() == name.lower() for n, _ in taken):
        return {"ok": False, "error": f"There's already a source called {name}"}
    if any(u.rstrip("/") == url.rstrip("/") for _, u in taken):
        return {"ok": False, "error": "That feed is already a source"}
    result = check_source(url)
    if result["ok"]:
        os.makedirs(os.path.dirname(CUSTOM_SOURCES_PATH), exist_ok=True)
        custom = [{"name": n, "url": u} for n, u in custom_sources()] + [{"name": name, "url": url}]
        tmp = CUSTOM_SOURCES_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(custom, f, indent=1)
        os.replace(tmp, CUSTOM_SOURCES_PATH)
    return result


def remove_source(url: str) -> bool:
    """Remove a custom source (built-in ones stay). Whether it was there."""
    custom = custom_sources()
    kept = [(n, u) for n, u in custom if u != url]
    if len(kept) == len(custom):
        return False
    with open(CUSTOM_SOURCES_PATH, "w", encoding="utf-8") as f:
        json.dump([{"name": n, "url": u} for n, u in kept], f, indent=1)
    return True


# Each source's last collection: {name: {ok, posts, error, checked}}
_source_status: Dict[str, Dict] = {}


def fetch_sources(days: int = FEED_DAYS, sources=None) -> List[Dict]:
    import requests

    since = datetime.now(timezone.utc) - timedelta(days=days)
    everything: List[Dict] = []  # the whole of each feed, for the research archive

    def one(src):
        name, url = src
        try:
            r = requests.get(url, timeout=FETCH_TIMEOUT, headers=HEADERS)
            r.raise_for_status()
            items = parse_feed(r.content, name)
            everything.extend(items)
            recent = [p for p in items if p["published"] and datetime.fromisoformat(p["published"]) >= since]
            _source_status[name] = {"ok": True, "posts": len(recent), "checked": time.time()}
            return recent
        except Exception as e:
            print(f"Threat feed: {name} unavailable: {e}")
            _source_status[name] = {"ok": False, "error": _why(e), "checked": time.time()}
            return []

    with ThreadPoolExecutor(max_workers=8) as pool:
        posts = [p for batch in pool.map(one, sources if sources is not None else all_sources()) for p in batch]
    try:
        from shikari.intelligence.research_search import archive

        archive(everything)
    except Exception as e:
        print(f"Research archive not updated: {e}")
    seen, unique = set(), []
    for p in sorted(posts, key=lambda p: p["published"], reverse=True):
        if p["url"] not in seen:
            seen.add(p["url"])
            unique.append(p)
    return unique


# ---------------------------------------------------------------- analysis

def group_index(bundle, group_meta: Dict) -> List[Dict]:
    """ATT&CK groups as {id, name, aliases, pattern, sectors, nexus, financial} for matching in prose."""
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
            "id": gid, "name": obj.get("name"), "aliases": sorted(names),
            # Case-sensitive: aliases are proper nouns, and lower-case matches are usually words
            "pattern": re.compile(r"(?<![\w-])(?:" + "|".join(map(re.escape, sorted(names, key=len, reverse=True)))
                                  + r")(?![\w-])"),
            "sectors": sectors,
            "nexus": meta.get("nexus") or "",
            "financial": "Ransomware" in objectives or "Financial" in objectives,
        })
    return groups


def nation_profiles(group_meta: Dict, share: float = NATION_SECTOR_SHARE) -> Dict[str, List[str]]:
    """Industries most of each nation's ATT&CK groups target (none for a nation with too few groups)."""
    profiles = {}
    groups = [v for k, v in group_meta.items() if k.startswith("G")]
    for nation in NATIONS:
        members = [g for g in groups if g.get("nexus") == nation]
        counts: Dict[str, int] = {}
        for g in members:
            for sector in {s.strip() for s in (g.get("target_sectors") or "").split(";") if s.strip()}:
                counts[sector] = counts.get(sector, 0) + 1
        profiles[nation] = (sorted(s for s, n in counts.items() if n / len(members) >= share)
                            if len(members) >= MIN_PROFILE_GROUPS else [])
    return profiles


def _sector_mentions(text: str, title: str) -> Dict[str, int]:
    from shikari.mitre.group_metadata import _SECTORS

    out = {}
    for pattern, label in _SECTORS:
        n = len(pattern.findall(text))
        if pattern.search(title):
            n += 2
        if n:
            out[label] = out.get(label, 0) + n
    return out


def has_indicators(title: str, text: str) -> bool:
    """Any indicator other than a CVE in the post (_INDICATOR)."""
    return bool(_INDICATOR.search(title) or _INDICATOR.search(text))


def technical_context(title: str, text: str, near: int = NEAR_TECHNICAL) -> str:
    """
    The title plus each technical paragraph and the `near` paragraphs either side. A technical
    paragraph has an indicator (_INDICATOR), or a CVE when the post has an indicator elsewhere.
    """
    paragraphs = [p for p in text.split("\n") if p.strip()]
    cves_count = has_indicators(title, text)
    keep = set()
    for i, paragraph in enumerate(paragraphs):
        if _INDICATOR.search(paragraph) or (cves_count and _CVE.search(paragraph)):
            keep.update(range(max(0, i - near), min(len(paragraphs), i + near + 1)))
    return "\n".join([title] + [paragraphs[i] for i in sorted(keep)])


_BOILERPLATE = re.compile(r"appeared first on|advisory at a glance|read more|subscribe|cookie|all rights reserved"
                          r"|click here|sign up|table of contents|share this|\bwebinar\b", re.I)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"“(])")


def describe(summary: str, text: str, title: str = "", max_sentences: int = 3, max_chars: int = 420) -> str:
    """Two or three sentences: the RSS summary, or the article's opening when that's thin or boilerplate."""
    def sentences(block: str) -> List[str]:
        return [x.strip() for x in _SENTENCE_END.split(re.sub(r"\s+", " ", block).strip()) if x.strip()]

    def usable(paragraph: str) -> bool:
        words = paragraph.split()
        return len(words) >= 12 and paragraph.rstrip()[-1:] in ".!?\"”)" and not _BOILERPLATE.search(paragraph) \
            and paragraph.strip() != title.strip()

    candidates = []
    if summary and len(summary) >= 120 and not _BOILERPLATE.search(summary):
        candidates.append(summary)
    candidates += [p for p in text.split("\n")[:60] if usable(p)]
    out: List[str] = []
    for block in candidates:
        for sentence in sentences(block):
            if len(" ".join(out + [sentence])) > max_chars and out:
                return " ".join(out)
            if sentence not in out:
                out.append(sentence)
            if len(out) >= max_sentences:
                return " ".join(out)
        if len(out) >= 2:
            break
    return " ".join(out) or (summary or "")[:max_chars]


def analyse_post(post: Dict, groups: List[Dict], profiles: Optional[Dict[str, List[str]]] = None) -> Dict:
    """The post with its tags and description; user-independent (cached)."""
    from shikari.parsers.blog_analyzer import analyze_blog_post

    result = analyze_blog_post(post["url"], include_text=True, timeout=FETCH_TIMEOUT)
    if not result.get("success"):
        return {**post, "error": result.get("error") or "could not be read", "analysed": time.time(),
                "version": ANALYSIS_VERSION}
    text = result.get("text") or ""
    context = technical_context(post["title"], text)
    named = [g for g in groups if g["pattern"].search(context)]
    # Every name and alias of the ATT&CK groups found, so a vendor name that is an alias isn't counted twice
    known = [n for g in named for n in [g["name"]] + g.get("aliases", [])]
    others = actors(context, known)
    iocs = result.get("iocs") or {}

    reasons: Dict[str, List[str]] = {}

    def because(sector: str, why: str) -> None:
        industry = SECTOR_INDUSTRY.get(sector, sector)
        if industry in INDUSTRIES and why not in reasons.setdefault(industry, []):
            reasons[industry].append(why)

    for g in named:
        for sector in g["sectors"]:
            because(sector, f"{g['name']} ({g['id']})")
    nations = nations_in(context)
    for nation in nations:
        for sector in (profiles or {}).get(nation, []):
            because(sector, f"{nation}-nexus activity")
    for label, n in _sector_mentions(technical_context("", text), post["title"]).items():
        if n >= 2:
            because(label, "named in the post")
    for a in others:
        for sector in (profiles or {}).get(a["nation"], []):
            because(sector, f"{a['name']} ({a['nation']}-nexus)")
    nations = sorted(set(nations) | {g["nexus"] for g in named if g["nexus"]} | {a["nation"] for a in others if a["nation"]})
    opportunistic = sorted({reason for pattern, reason in OPPORTUNISTIC if pattern.search(context)})
    financial = sorted({m.group(0).lower() for m in FINANCIAL.finditer(context)}
                       | {f"{g['name']} (financial)" for g in named if g["financial"]}
                       | {f"{a['name']} (financial)" for a in others if a["financial"]})
    return {
        **post,
        "description": describe(post.get("summary") or "", text, post["title"]),
        "techniques": result.get("techniques", [])[:60],
        "iocs": sum(len(v) for v in iocs.values() if isinstance(v, list)),
        "cves": sorted(set(_CVE.findall(f"{post['title']}\n{text}")))[:20],
        "indicators": has_indicators(post["title"], text),
        "groups": [{"id": g["id"], "name": g["name"], "nexus": g["nexus"]} for g in named][:15],
        "actors": others,
        "industries": reasons,
        "products": products_named(f"{post['title']}\n{context}"),
        "nations": nations,
        "opportunistic": opportunistic,
        "financial": financial[:8],
        "analysed": time.time(), "version": ANALYSIS_VERSION,
    }


def technical(post: Dict) -> bool:
    """
    Whether the post has anything to hunt with: technique IDs, IOCs, a named group or actor, or CVEs
    alongside other indicators (a CVE on its own is usually a passing citation).
    """
    return not post.get("error") and bool(post.get("techniques") or post.get("iocs", 0) >= 3
                                          or post.get("groups") or post.get("actors")
                                          or (post.get("cves") and post.get("indicators")))


def tags(post: Dict) -> Dict:
    motives = (["Opportunistic"] if post.get("opportunistic") else []) + \
              (["Financially motivated"] if post.get("financial") else [])
    return {"industries": [i for i in INDUSTRIES if i in post.get("industries", {})],
            "nations": post.get("nations", []), "motives": motives}


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


def refresh(bundle, group_meta: Dict, days: int = FEED_DAYS, workers: int = 10) -> Dict:
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
        profiles = nation_profiles(group_meta)
        print(f"Threat feed: analysing {len(fresh)} new post(s)")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for post in pool.map(lambda p: analyse_post(p, groups, profiles), fresh):
                posts[post["url"]] = post
        data = {"posts": posts, "last_refresh": time.time(), "sources": dict(_source_status)}
        _save(data)
        try:
            from shikari.intelligence.research_search import archive

            archive([], posts)  # the analysed descriptions, so searches reach the article text
        except Exception as e:
            print(f"Research archive not updated: {e}")
        try:
            from shikari.intelligence.watchlists import check_all

            found = check_all(bundle)
            if found:
                print(f"Watchlists: {found} new match(es)")
        except Exception as e:
            print(f"Watchlists not checked: {e}")
        _status["last_refresh"] = data["last_refresh"]
        return data
    except Exception as e:
        _status["error"] = str(e)
        raise
    finally:
        _status["refreshing"] = False
        _refreshing = False


def refresh_in_background(bundle, group_meta: Dict, force: bool = False, every: int = REFRESH_EVERY) -> bool:
    """
    Start a refresh unless one is running or the cache is younger than every seconds (the
    watchlist collector passes the shortest interval any user chose). True when one was started.
    """
    last = _load().get("last_refresh") or 0
    if _refreshing or (not force and time.time() - last < every):
        return False

    def run():
        try:
            refresh(bundle, group_meta)
        except Exception as e:
            print(f"Threat feed refresh failed: {e}")

    threading.Thread(target=run, daemon=True, name="threat-feed").start()
    return True


def view(industries: Iterable[str], days: int = FEED_DAYS, stack: Iterable[str] = ()) -> Dict:
    """
    The wall: every technical post of the window, newest first, with its tags. relevant: it
    targets one of the user's industries, or it's opportunistic or financially motivated
    (which can land in any industry), or it names a product in the user's technology stack;
    and it isn't aimed only at products the stack doesn't have (shikari.intelligence.tech_stack).
    """
    industries = as_industries(industries)
    stack = as_stack(stack)
    data = _load()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    posts, considered = [], 0
    for post in sorted(data.get("posts", {}).values(), key=lambda p: p.get("published") or "", reverse=True):
        if (post.get("published") or "") < cutoff or post.get("version") != ANALYSIS_VERSION:
            continue
        considered += 1
        if not technical(post):
            continue
        yours = {i: post["industries"][i] for i in industries if i in post.get("industries", {})}
        # Posts analysed before products were recorded: their title and description
        named = post.get("products")
        if named is None:
            named = products_named(f"{post.get('title', '')}\n{post.get('description') or ''}")
        in_stack = [label(p) for p in named if p in stack]
        off = bool(stack) and not in_stack and bool(targets_in(named))
        posts.append({
            **{k: post.get(k) for k in ("title", "url", "source", "published", "description", "techniques", "cves", "iocs")},
            "groups": [g["name"] for g in post.get("groups", [])] + [a["name"] for a in post.get("actors", [])],
            "tags": tags(post),
            "yours": yours,
            "opportunistic": post.get("opportunistic", []),
            "financial": post.get("financial", []),
            "stack": in_stack,
            "off_stack": [label(p) for p in targets_in(named)] if off else [],
            "relevant": bool(yours or post.get("opportunistic") or post.get("financial") or in_stack) and not off,
        })
    return {"industries": industries, "labels": industries, "days": days, "stack": [label(p) for p in stack],
            "posts": posts, "relevant": sum(1 for p in posts if p["relevant"]), "considered": considered,
            "last_refresh": data.get("last_refresh"), "refreshing": _status["refreshing"],
            "sources": [{"name": n, "url": u, "custom": (n, u) not in SOURCES, **(data.get("sources") or {}).get(n, {})}
                        for n, u in all_sources()]}

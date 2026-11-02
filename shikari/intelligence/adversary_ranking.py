"""
Ordered Adversary List (#30-adjacent): the ATT&CK groups most likely to target an organisation,
ranked from three signals already in its saved profile — industry, geography and exposed OSINT.

No AI, no network at render time. The signals come from data Shikari already holds:

  industry   org sector            -> group target_sectors   (data/cache/group_metadata.json)
  geography  org country -> region -> group target_regions   (same cache, + "Global")
  exposure   OSINT findings -> initial-access techniques (T1190/T1133/T1078/T1566)
             -> groups that use them (data/mitre_procedures.csv), plus a product-keyword
             match of the exposed tech stack against the group's ATT&CK description.
  incidents  demonstrated real-world activity: named ATT&CK campaigns and recency
             (shikari.mitre.group_metadata), the company's own public breaches (profile
             breach_surface), and — when supplied — curated incidents on the company and its
             sector peers from bespoke/mappings/incidents.json (actor -> victims/sectors/last_seen).

Each score is explainable: the per-dimension points and a short reason per group are returned so
the /exposure (and /review) list can show why an actor ranks where it does. The group metadata is
description-parsed structure (shikari.mitre.group_metadata), so this inherits its coverage and its
limits — a group whose description never names a sector simply won't match on industry.

The incidents dimension is honest about its inputs: ATT&CK carries no actor->victim-company map, so
true "who hit this company / its competitors" attribution comes only from the optional bespoke file.
Without it, incidents falls back to demonstrated-activity and the company's own breach history — a
proxy for "an operator with a real track record", not named competitor incidents.
"""

from __future__ import annotations

import csv
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from shikari import paths
from shikari.mitre.group_metadata import load_group_metadata

_META_CACHE = paths.DATA / "cache" / "group_metadata.json"
_CSV = paths.DATA / "mitre_procedures.csv"

# ── Dimension weights (max points each can add to a group's raw score) ──────────
W_INDUSTRY = 38      # the org's sector is in the group's target sectors
W_REGION = 22        # the org's region is in the group's target regions
W_REGION_GLOBAL = 10 # the group targets "Global" but not the org's region specifically
W_EXPOSURE_TECH = 7  # per matched initial-access technique the org actually exposes (capped below)
W_EXPOSURE_TECH_CAP = 26
W_PRODUCT = 4        # per exposed product named in the group's description (capped below)
W_PRODUCT_CAP = 12
W_INCIDENT_DIRECT = 22   # a curated public incident names this organisation
W_INCIDENT_SECTOR = 10   # a curated public incident hit a sector peer (competitor)
W_ACTIVITY_CAMPAIGN = 6  # the group has named ATT&CK campaigns (demonstrated operations)
W_ACTIVITY_RECENT = 4    # the group has been active within _RECENT_YEARS
W_INCIDENTS_CAP = 28
_RECENT_YEARS = 3        # "recent" = active no longer ago than this many years

_INCIDENTS_FILE = paths.ROOT / "bespoke" / "mappings" / "incidents.json"

# ── Sector: Shikari's detected sector -> the controlled vocab in the metadata cache ──
# The cache's sector labels (right) are matched when any synonym (left) appears in the
# org's detected sector or its other sectors.
_SECTOR_SYNONYMS = {
    "Finance / Banking": ("financ", "bank", "fintech", "payment", "insur", "capital", "trading"),
    "Healthcare / Pharma": ("health", "medical", "hospital", "pharma", "clinic", "biotech", "care"),
    "Technology": ("tech", "software", "saas", "cloud", "it ", "information technology", "data", "cyber", "digital"),
    "Energy / Utilities": ("energy", "oil", "gas", "power", "electric", "utility", "utilities", "nuclear"),
    "Defense / Military": ("defen", "military", "weapon", "armed forces"),
    "Aerospace / Aviation": ("aerospace", "aviation", "airline", "aircraft", "space"),
    "Government": ("government", "gov", "public sector", "federal", "ministry", "diplomat", "state"),
    "Education / Research": ("education", "universit", "academ", "school", "research", "scientific"),
    "Manufacturing / Industrial": ("manufactur", "industrial", "factory", "ics", "scada", "ot "),
    "Telecommunications": ("telecom", "communication", "isp", "mobile", "wireless", "5g"),
    "Retail / Hospitality": ("retail", "ecommerce", "e-commerce", "commerce", "shop", "store", "hospitality", "hotel", "consumer"),
    "Transport / Logistics": ("transport", "logistic", "shipping", "maritime", "rail", "freight"),
    "Media / Entertainment": ("media", "news", "broadcast", "entertainment", "publishing", "gaming"),
    "Critical Infrastructure": ("critical infrastructure", "water", "grid"),
    "Think Tank / Policy": ("think tank", "policy institute"),
    "NGO / Civil Society": ("ngo", "non-profit", "nonprofit", "civil society", "charity", "humanitarian"),
}

# ── Geography: country -> the region buckets used in the metadata cache ──────────
_COUNTRY_REGION = {
    "united kingdom": "Europe", "uk": "Europe", "england": "Europe", "scotland": "Europe",
    "wales": "Europe", "ireland": "Europe", "germany": "Europe", "france": "Europe",
    "italy": "Europe", "spain": "Europe", "netherlands": "Europe", "belgium": "Europe",
    "switzerland": "Europe", "sweden": "Europe", "norway": "Europe", "finland": "Europe",
    "denmark": "Europe", "poland": "Europe", "austria": "Europe", "portugal": "Europe",
    "greece": "Europe", "czech republic": "Europe", "romania": "Europe", "ukraine": "Europe",
    "united states": "North America", "usa": "North America", "us": "North America",
    "canada": "North America", "mexico": "North America",
    "russia": "Russia / CIS", "belarus": "Russia / CIS", "kazakhstan": "Central Asia",
    "uzbekistan": "Central Asia", "kyrgyzstan": "Central Asia",
    "japan": "Asia Pacific", "china": "Asia Pacific", "south korea": "Asia Pacific",
    "taiwan": "Asia Pacific", "australia": "Asia Pacific", "new zealand": "Asia Pacific",
    "hong kong": "Asia Pacific",
    "vietnam": "Southeast Asia", "thailand": "Southeast Asia", "philippines": "Southeast Asia",
    "indonesia": "Southeast Asia", "malaysia": "Southeast Asia", "singapore": "Southeast Asia",
    "myanmar": "Southeast Asia", "cambodia": "Southeast Asia",
    "india": "South Asia", "pakistan": "South Asia", "bangladesh": "South Asia",
    "sri lanka": "South Asia", "nepal": "South Asia", "afghanistan": "South Asia",
    "israel": "Middle East", "saudi arabia": "Middle East", "united arab emirates": "Middle East",
    "uae": "Middle East", "iran": "Middle East", "iraq": "Middle East", "turkey": "Middle East",
    "qatar": "Middle East", "kuwait": "Middle East", "jordan": "Middle East", "egypt": "Middle East",
    "lebanon": "Middle East", "syria": "Middle East",
    "south africa": "Africa", "nigeria": "Africa", "kenya": "Africa", "morocco": "Africa",
    "ethiopia": "Africa", "ghana": "Africa",
    "brazil": "South America", "argentina": "South America", "chile": "South America",
    "colombia": "South America", "peru": "South America", "venezuela": "South America",
}

# ── Exposure: initial-access techniques and the ports/keywords that imply them ───
_REMOTE_PORTS = {22, 3389, 5900, 5901, 1194, 500, 4500, 990, 992, 1723}
_REMOTE_KW = ("vpn", "rdp", "remote desktop", "citrix", "fortinet", "fortigate", "pulse",
              "anyconnect", "globalprotect", "openvpn", "ivanti", "sonicwall", "teamviewer")
# Base technique ids (sub-techniques fold to their parent for the "group uses it" check)
T_PUBLIC_APP = "T1190"      # Exploit Public-Facing Application
T_REMOTE = "T1133"          # External Remote Services
T_VALID_ACCT = "T1078"      # Valid Accounts
T_PHISH = "T1566"           # Phishing

# Generic tech that says nothing about a specific adversary — kept out of product matching
_GENERIC_PRODUCT = {"nginx", "apache", "iis", "cloudflare", "akamai", "fastly", "varnish",
                    "openssl", "php", "node.js", "nodejs", "jquery", "bootstrap", "react",
                    "linux", "windows", "ubuntu", "debian", "centos", "http", "https", "tls",
                    "amazon", "aws", "azure", "google", "gcp", "cdn"}

# In-process memoisation: the CSV group->techniques map and the bundle descriptions are read
# once and reused. Keyed by the CSV's mtime so a rebuild is picked up without a restart.
_tech_cache: Tuple[float, Dict[str, set]] = (0.0, {})
_desc_cache: Optional[Dict[str, str]] = None
_incidents_cache: Tuple[float, Dict[str, Dict]] = (0.0, {})


def _clean(text: str) -> str:
    return (text or "").strip().lower()


def _group_techniques() -> Dict[str, set]:
    """{group_name_lower: {base technique ids}} from the MITRESaw CSV, memoised by mtime."""
    global _tech_cache
    try:
        mtime = os.path.getmtime(_CSV)
    except OSError:
        return {}
    if _tech_cache[0] == mtime:
        return _tech_cache[1]
    out: Dict[str, set] = {}
    try:
        with open(_CSV, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                name = _clean(row.get("group_sw_name"))
                tid = (row.get("technique_id") or "").split(".")[0].strip().upper()
                if name and tid.startswith("T"):
                    out.setdefault(name, set()).add(tid)
    except OSError:
        return _tech_cache[1]
    _tech_cache = (mtime, out)
    return out


def _group_descriptions() -> Dict[str, str]:
    """{group_name_lower: description_lower} from the local ATT&CK bundle, loaded once (offline)."""
    global _desc_cache
    if _desc_cache is not None:
        return _desc_cache
    import json
    out: Dict[str, str] = {}
    try:
        with open(paths.CACHE / "enterprise-attack.json", encoding="utf-8") as fh:
            for obj in json.load(fh).get("objects", []):
                if obj.get("type") == "intrusion-set" and not obj.get("revoked"):
                    name = _clean(obj.get("name"))
                    if name:
                        out[name] = _clean(obj.get("description"))
    except (OSError, ValueError):
        out = {}  # product dimension degrades to 0; the rest of the ranking still works
    _desc_cache = out
    return out


def _merge_incident(out: Dict[str, Dict], name: str, victims, sectors, last_seen) -> None:
    """Union one actor's victims/sectors into the incident map, keeping the most recent year."""
    key = _clean(name)
    if not key:
        return
    rec = out.setdefault(key, {"victims": set(), "sectors": set(), "last_seen": None})
    rec["victims"].update(_clean(v) for v in (victims or []) if v)
    rec["sectors"].update(str(s).strip() for s in (sectors or []) if s)
    if isinstance(last_seen, int) and (rec["last_seen"] is None or last_seen > rec["last_seen"]):
        rec["last_seen"] = last_seen


def _bespoke_incidents() -> Dict[str, Dict]:
    """The analyst's own curated incidents from bespoke/mappings/incidents.json, memoised by mtime."""
    global _incidents_cache
    try:
        mtime = os.path.getmtime(_INCIDENTS_FILE)
    except OSError:
        _incidents_cache = (0.0, {})
        return {}
    if _incidents_cache[0] == mtime:
        return _incidents_cache[1]
    import json
    out: Dict[str, Dict] = {}
    try:
        with open(_INCIDENTS_FILE, encoding="utf-8") as fh:
            rows = json.load(fh)
        for row in rows if isinstance(rows, list) else []:
            _merge_incident(out, row.get("group"), row.get("victims"), row.get("sectors"), row.get("last_seen"))
    except (OSError, ValueError, AttributeError):
        out = {}
    _incidents_cache = (mtime, out)
    return out


def _load_incidents() -> Dict[str, Dict]:
    """
    Public-incident map {group_name_lower: {"victims": set, "sectors": set, "last_seen": int}},
    merged from the analyst's bespoke file and the reputable feeds Shikari caches
    (shikari.intelligence.incident_sources): VCDB and ransomware.live. Each source is optional; a
    missing cache simply contributes nothing. Keyed by actor name, so it only boosts an ATT&CK group
    when a source actually names that group — sector prevalence without a named actor is context, not
    a per-actor score.
    """
    from shikari.intelligence import incident_sources

    out: Dict[str, Dict] = {}
    for src in (incident_sources.load_vcdb().get("groups"), incident_sources.load_ransomware().get("groups")):
        for name, rec in (src or {}).items():
            _merge_incident(out, name, rec.get("victims"), rec.get("sectors"), rec.get("last_seen"))
    # Bespoke last so a curated entry reinforces (unions with) anything a feed already had
    for name, rec in _bespoke_incidents().items():
        _merge_incident(out, name, rec.get("victims"), rec.get("sectors"), rec.get("last_seen"))
    return out


SECTOR_LABELS = tuple(_SECTOR_SYNONYMS)  # the controlled vocab, shared with incident_sources


def match_sectors(text: str) -> set:
    """The metadata sector labels a free-text sector/industry string maps to (keyword match)."""
    t = (text or "").lower()
    return {label for label, kws in _SECTOR_SYNONYMS.items() if any(k in t for k in kws)}


def _org_sectors(profile: Dict) -> List[str]:
    """The metadata sector labels the org's detected sector maps to."""
    ind = ((profile.get("threat_profile") or {}).get("industry")) or {}
    text = " ".join(filter(None, [ind.get("sector") or "", ind.get("subsector") or "",
                                  " ".join(ind.get("other_sectors") or [])]))
    return list(match_sectors(text))


def _org_region(profile: Dict) -> str:
    """The region bucket for the org's country, or "" if unknown."""
    tp = profile.get("threat_profile") or {}
    ci = profile.get("company_info") or {}
    country = _clean((tp.get("geography") or {}).get("country") or ci.get("country"))
    return _COUNTRY_REGION.get(country, "")


def _exposure_techniques(profile: Dict) -> Dict[str, Dict]:
    """
    Which initial-access techniques the OSINT says the org exposes, each with a 0..1 weight and a
    short reason. A group that is known to use the technique earns points proportional to the weight.
    """
    osint = profile.get("osint") or {}
    svc = profile.get("exposed_services") or {}
    ci = profile.get("company_info") or {}
    tech = ((profile.get("threat_profile") or {}).get("tech_stack")) or {}
    out: Dict[str, Dict] = {}

    vulns = svc.get("vulns") or []
    assets = osint.get("exposed_assets") or []
    ports = [int(p) for p in (svc.get("ports") or []) if str(p).isdigit()]
    cpes = " ".join(str(c) for c in (svc.get("cpes") or [])).lower()
    tech_blob = (" ".join(str(t) for t in (tech.get("technologies") or []))
                 + " " + str(tech.get("web_server") or "") + " " + cpes).lower()

    # T1190 — exposed, potentially vulnerable public-facing services. Exposed CVEs that CISA KEV
    # lists as actively exploited in the wild weigh much more than unconfirmed ones.
    if vulns or assets or any(p in (80, 443, 8080, 8443, 8000, 8888) for p in ports):
        if vulns:
            from shikari.intelligence import incident_sources
            kev = (incident_sources.load_kev().get("cves")) or {}
            exploited = [c for c in vulns if str(c).upper() in kev]
            ransom = [c for c in exploited if kev[str(c).upper()].get("ransomware")]
            if exploited:
                weight = min(1.0, 0.7 + 0.1 * len(exploited))
                why = f"{len(exploited)} of {len(vulns)} exposed CVE(s) actively exploited (CISA KEV)"
                if ransom:
                    why += f", {len(ransom)} in ransomware campaigns"
            else:
                weight, why = min(1.0, 0.5 + 0.1 * len(vulns)), f"{len(vulns)} known CVE(s) on exposed services"
        else:
            weight, why = 0.5, f"{len(assets) or len(ports)} public-facing service(s) exposed"
        out[T_PUBLIC_APP] = {"weight": weight, "reason": "Exploits public-facing apps — " + why}

    # T1133 — exposed remote access
    if any(p in _REMOTE_PORTS for p in ports) or any(k in tech_blob for k in _REMOTE_KW):
        out[T_REMOTE] = {"weight": 0.8, "reason": "Abuses external remote services — exposed RDP/VPN"}

    # T1078 — credentials in the open
    leaks = osint.get("github_leaks") or []
    secrets = osint.get("exposed_secrets") or []
    breaches = (profile.get("breach_surface") or {}).get("count") or 0
    if leaks or secrets or breaches:
        bits = []
        if secrets or leaks:
            bits.append(f"{len(secrets) + len(leaks)} secret(s)/leak(s) on GitHub")
        if breaches:
            bits.append(f"{breaches} breach record(s)")
        out[T_VALID_ACCT] = {"weight": 0.7, "reason": "Uses valid accounts — " + ", ".join(bits)}

    # T1566 — phishable mail surface
    auth = ci.get("email_auth") or {}
    if ci.get("mx") or auth.get("spoofable"):
        spoof = auth.get("spoofable")
        out[T_PHISH] = {"weight": 0.9 if spoof else 0.4,
                        "reason": "Phishing — " + ("spoofable email (weak SPF/DMARC)" if spoof else "exposed mail surface")}
    return out


def _exposed_products(profile: Dict) -> List[str]:
    """Distinct, non-generic product keywords from the org's exposed tech stack."""
    tech = ((profile.get("threat_profile") or {}).get("tech_stack")) or {}
    svc = profile.get("exposed_services") or {}
    raw: List[str] = []
    raw += list(tech.get("technologies") or [])
    raw += [tech.get("web_server") or "", tech.get("cdn") or "", tech.get("cloud_provider") or ""]
    for cpe in (svc.get("cpes") or []):
        # cpe:/a:microsoft:exchange_server -> "microsoft", "exchange server"
        parts = str(cpe).replace("cpe:/a:", "").replace("cpe:/o:", "").split(":")
        raw += [p.replace("_", " ") for p in parts[:2]]
    out: List[str] = []
    for item in raw:
        name = str(item).strip().lower()
        name = re.sub(r"[/\d.].*$", "", name).strip()  # drop version suffixes
        if len(name) >= 3 and name not in _GENERIC_PRODUCT and name not in out:
            out.append(name)
    return out


def rank_adversaries(profile: Dict, limit: int = 10) -> List[Dict]:
    """
    The top `limit` ATT&CK groups most likely to target this organisation, ordered by likelihood.
    Returns [] when the profile carries no industry, region or exposure signal to rank on.
    """
    if not isinstance(profile, dict):
        return []
    meta = load_group_metadata(_META_CACHE)
    if not meta:
        return []

    import datetime

    org_sectors = set(_org_sectors(profile))
    org_region = _org_region(profile)
    exposure = _exposure_techniques(profile)
    products = _exposed_products(profile)
    incidents = _load_incidents()
    ci = profile.get("company_info") or {}
    org_domain = _clean(profile.get("domain") or ci.get("domain"))
    org_ids = {i for i in (org_domain, _clean(ci.get("company_name"))) if i}
    this_year = datetime.date.today().year
    group_techs = _group_techniques() if exposure else {}
    descriptions = _group_descriptions() if products else {}

    # Gate on the org's own signals, not the global incident feeds: the feeds and the campaign/
    # activity amplifier only matter relative to this organisation, so a thin profile ranks nothing.
    if not (org_sectors or org_region or exposure or products or org_ids):
        return []

    scored: List[Dict] = []
    for gid, g in meta.items():
        if not gid.startswith("G"):  # the cache also keys by STIX id; skip the duplicates
            continue
        name = g.get("group_name") or ""
        if not name:
            continue
        g_sectors = {s.strip() for s in (g.get("target_sectors") or "").split(";") if s.strip()}
        g_regions = {r.strip() for r in (g.get("target_regions") or "").split(";") if r.strip()}
        breakdown = {"industry": 0, "geography": 0, "exposure": 0, "incidents": 0}
        reasons: List[str] = []

        # Industry
        hit_sectors = org_sectors & g_sectors
        if hit_sectors:
            breakdown["industry"] = W_INDUSTRY
            reasons.append("Targets " + ", ".join(sorted(hit_sectors)))

        # Geography
        if org_region and org_region in g_regions:
            breakdown["geography"] = W_REGION
            reasons.append(f"Targets {org_region}")
        elif "Global" in g_regions and (org_region or org_sectors):
            breakdown["geography"] = W_REGION_GLOBAL
            reasons.append("Targets victims globally")

        # Exposure — initial-access techniques the org exposes that this group uses
        techs = group_techs.get(name.lower(), set())
        if techs:
            tech_pts = 0.0
            for tid, info in exposure.items():
                if tid in techs:
                    tech_pts += W_EXPOSURE_TECH * info["weight"]
                    reasons.append(info["reason"])
            breakdown["exposure"] += min(W_EXPOSURE_TECH_CAP, round(tech_pts))

        # Exposure — exposed products named in this group's ATT&CK description
        desc = descriptions.get(name.lower(), "")
        if desc and products:
            named = [p for p in products if p in desc][:3]
            if named:
                breakdown["exposure"] += min(W_PRODUCT_CAP, W_PRODUCT * len(named))
                reasons.append("ATT&CK notes it targeting " + ", ".join(named))

        # Incidents — curated public incidents on the org or its sector peers, plus demonstrated
        # real-world activity (named campaigns, recency). Curated data is the only source that can
        # attribute an incident to a company; without it this is a track-record proxy, not history.
        inc_pts = 0
        rec = incidents.get(name.lower())
        if rec:
            if org_ids & set(rec["victims"]):
                inc_pts += W_INCIDENT_DIRECT
                reasons.insert(0, f"Named in a public incident at {org_domain or 'this organisation'}")
            elif org_sectors & set(rec["sectors"]):
                inc_pts += W_INCIDENT_SECTOR
                reasons.append("Public incident at a sector peer")
            if isinstance(rec.get("last_seen"), int) and rec["last_seen"] >= this_year - _RECENT_YEARS:
                inc_pts += W_ACTIVITY_RECENT
                reasons.append(f"Active as recently as {rec['last_seen']}")
        breakdown["incidents"] = min(W_INCIDENTS_CAP, inc_pts)

        # Demonstrated-activity amplifier: named ATT&CK campaigns lift an actor that is already
        # relevant to this org (never one with no other signal — that would just be a busy group).
        relevant = breakdown["industry"] + breakdown["geography"] + breakdown["exposure"] + breakdown["incidents"]
        campaigns = (g.get("campaigns") or "").strip()
        if relevant > 0 and campaigns:
            breakdown["incidents"] = min(W_INCIDENTS_CAP, breakdown["incidents"] + W_ACTIVITY_CAMPAIGN)
            reasons.append("Named campaign: " + campaigns.split(";")[0].strip())

        raw = breakdown["industry"] + breakdown["geography"] + breakdown["exposure"] + breakdown["incidents"]
        if raw <= 0:
            continue
        likelihood = min(96, round(raw))
        # Bands are calibrated to the dimension weights: matching only sector or only region is
        # Low; strong targeting (sector + region) is Medium; targeting plus a real exposure or a
        # demonstrated incident is High. So "High" means the org's own attack surface is in play.
        band = "High" if likelihood >= 78 else "Medium" if likelihood >= 55 else "Low"
        sources = [k for k, v in breakdown.items() if v > 0]
        scored.append({
            "name": name, "group_id": gid, "nexus": g.get("nexus") or "",
            "likelihood": likelihood, "band": band, "breakdown": breakdown,
            "sources": sources, "reasons": reasons[:3],
        })

    scored.sort(key=lambda d: (-d["likelihood"], d["name"]))
    top = scored[:limit]
    for i, d in enumerate(top, 1):
        d["rank"] = i
    return top

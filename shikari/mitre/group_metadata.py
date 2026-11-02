"""
shikari.mitre.group_metadata
===========================

Enriches MITRE ATT&CK intrusion-set objects with structured metadata
derived entirely from the STIX bundle — no external APIs required.

Fields produced per group:
  nexus                 Country/region attribution nexus
  sponsor               Sponsoring government body / affiliation type
  activity_since        Earliest year of observed activity
  primary_objectives    Espionage / Financial / Ransomware / Disruption …
  target_regions        Geographic regions targeted
  target_sectors        Industry sectors targeted
  attribution_confidence High / Medium / Low
  tools_malware         Software used (from STIX uses-relationships)
  campaigns             Campaign names attributed to the group

Cache file: data/cache/group_metadata.json
  Keyed by ATT&CK group ID (e.g. "G0064") for fast direct lookup.
  Rebuilt automatically on first run and whenever the STIX bundle changes.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Nexus (country/region attribution) ───────────────────────────────────────

_NEXUS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'\b(China|Chinese|PRC|People\'s Republic of China)\b', re.I),          "China"),
    (re.compile(r'\b(Russia|Russian|Kremlin|GRU|FSB|SVR|Sandworm)\b', re.I),           "Russia"),
    (re.compile(r'\b(North Korea|North Korean|DPRK|Pyongyang)\b', re.I),               "North Korea"),
    (re.compile(r'\b(Iran|Iranian|IRGC|MOIS|Tehran)\b', re.I),                         "Iran"),
    (re.compile(r'\b(Pakistan|Pakistani|ISI)\b', re.I),                                 "Pakistan"),
    (re.compile(r'\b(Vietnam|Vietnamese)\b', re.I),                                     "Vietnam"),
    (re.compile(r'\b(India|Indian)\b', re.I),                                           "India"),
    (re.compile(r'\b(Israel|Israeli)\b', re.I),                                         "Israel"),
    (re.compile(r'\b(Turkey|Turkish|Ankara)\b', re.I),                                  "Turkey"),
    (re.compile(r'\b(Lebanon|Lebanese|Hezbollah)\b', re.I),                             "Lebanon"),
    (re.compile(r'\b(Belarus|Belarusian|Lukashenko)\b', re.I),                          "Belarus"),
    (re.compile(r'\b(Ukraine|Ukrainian)\b', re.I),                                      "Ukraine"),
    (re.compile(r'\b(United States|U\.S\.|American|NSA|CIA)\b', re.I),                 "United States"),
    (re.compile(r'\b(United Kingdom|UK|British|GCHQ)\b', re.I),                        "United Kingdom"),
    (re.compile(r'\b(Saudi Arabia|Saudi)\b', re.I),                                     "Saudi Arabia"),
    (re.compile(r'\b(Azerbaijan|Azerbaijani)\b', re.I),                                 "Azerbaijan"),
    (re.compile(r'\b(Georgia\b)(?!.*\bstate\b)', re.I),                                "Georgia"),
]

_ATTRIBUTION_CTX = re.compile(
    r'attributed|sponsored|nexus|linked|believed|assessed|operating|nation.state|'
    r'state.sponsored|espionage|intelligence service|threat actor|threat group',
    re.I,
)


def _extract_nexus(desc: str) -> str:
    for pat, country in _NEXUS:
        m = pat.search(desc)
        if not m:
            continue
        # prefer matches near attribution language
        start = max(0, m.start() - 400)
        end   = min(len(desc), m.end() + 400)
        if _ATTRIBUTION_CTX.search(desc[start:end]):
            return country
    # fallback: any mention
    for pat, country in _NEXUS:
        if pat.search(desc):
            return country
    return ""


# ── Sponsor / Affiliation ─────────────────────────────────────────────────────

_SPONSOR: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'Ministry of State Security|MSS\b', re.I),                "China MSS"),
    (re.compile(r"People'?s Liberation Army|PLA\b", re.I),                 "China PLA"),
    (re.compile(r'\bGRU\b', re.I),                                          "Russia GRU"),
    (re.compile(r'\bFSB\b', re.I),                                          "Russia FSB"),
    (re.compile(r'\bSVR\b', re.I),                                          "Russia SVR"),
    (re.compile(r'IRGC|Islamic Revolutionary Guard', re.I),                 "Iran IRGC"),
    (re.compile(r'Ministry of Intelligence|MOIS\b', re.I),                  "Iran MOIS"),
    (re.compile(r'Reconnaissance General Bureau|RGB\b', re.I),              "North Korea RGB"),
    (re.compile(r'Lazarus Group|HIDDEN COBRA', re.I),                       "North Korea RGB"),
    (re.compile(r'\bISI\b', re.I),                                          "Pakistan ISI"),
    (re.compile(r'cybercriminal|financially motivated|criminal group', re.I), "Criminal / Cybercrime"),
    (re.compile(r'hacktivist|hacktivism', re.I),                            "Hacktivist"),
    (re.compile(r'nation.state|state.sponsored|government.sponsored', re.I), "Nation-State"),
]


def _extract_sponsor(desc: str) -> str:
    for pat, label in _SPONSOR:
        if pat.search(desc):
            return label
    return ""


# ── Activity since ────────────────────────────────────────────────────────────

_SINCE_PATS: List[re.Pattern] = [
    re.compile(r'since (?:at least |early )?(\d{4})', re.I),
    re.compile(r'as early as (\d{4})', re.I),
    re.compile(r'first (?:observed|identified|seen|detected|reported)(?: in)? (\d{4})', re.I),
    re.compile(r'active since (\d{4})', re.I),
    re.compile(r'(?:operations?|activity|campaigns?)\s+(?:dating )?(?:back )?(?:to |since )(?:at least )?(\d{4})', re.I),
    re.compile(r'at least (?:as early as )?(\d{4})\b', re.I),
    re.compile(r'(?:conducted|carried out|launched)\s+.*?(?:since|from)\s+(?:at least\s+)?(\d{4})', re.I),
]


def _extract_activity_since(desc: str) -> str:
    years = []
    for pat in _SINCE_PATS:
        for m in pat.finditer(desc):
            try:
                y = int(m.group(1))
                if 1990 <= y <= 2030:
                    years.append(y)
            except (IndexError, ValueError):
                pass
    return str(min(years)) if years else ""


# ── Primary objectives ────────────────────────────────────────────────────────

_OBJECTIVES: List[Tuple[re.Pattern, str]] = [
    (re.compile(
        r'espionage|intelligence collect|cyber espionage|steal.*credential|exfiltrat|'
        r'collect.*(?:information|data|intelligence)|sensitive.*information|'
        r'intellectual property|covert.*intelligence|classified.*information|'
        r'targeted.*espionage|data theft|information theft|credential theft|'
        r'gather.*(?:intelligence|information)|targeting.*(?:government|diplomatic|'
        r'research institute|think tank|classified|military network)|'
        r'persistent.*access|long.term.*access|covert.*access',
        re.I), "Espionage"),
    (re.compile(r'financial.*gain|financially motivated|monetar|profit|heist|'
                r'bank.*theft|wire.*fraud|credit card|atm|cryptocurrency.*theft',
                re.I),                                                                               "Financial Crime"),
    (re.compile(r'ransomware|extortion|ransom demand|encrypt.*file|ransom.*payment', re.I),           "Ransomware / Extortion"),
    (re.compile(r'disrupt|sabotage|destructive|wiper|destroy.*data|disk.*wip|'
                r'denial.of.service|ddos|defac|render.*inoperable|destructive malware',
                re.I),                                                                               "Disruption / Sabotage"),
    (re.compile(r'propaganda|disinformation|influence operat|information operat|'
                r'hack.and.leak|doxing',
                re.I),                                                                               "Influence Operations"),
    (re.compile(r'supply chain', re.I),                                                               "Supply Chain Compromise"),
]


def _extract_objectives(desc: str) -> str:
    seen: list = []
    labels: set = set()
    for pat, label in _OBJECTIVES:
        if label not in labels and pat.search(desc):
            seen.append(label)
            labels.add(label)
    return "; ".join(seen)


# ── Target sectors ────────────────────────────────────────────────────────────

_SECTORS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'\baerosp(?:ace)?\b|\baviation\b', re.I),                           "Aerospace / Aviation"),
    (re.compile(r'\bdefense\b|\bmilitary\b|\barms\b', re.I),                         "Defense / Military"),
    (re.compile(r'\bgovernment\b|\bpublic sector\b|\bministry\b|\bministries\b', re.I), "Government"),
    (re.compile(r'\benergy\b|\boil\b|\bgas\b|\bpower grid\b|\butilities\b', re.I),   "Energy / Utilities"),
    (re.compile(r'\bfinance\b|\bfinancial\b|\bbanking\b|\bbank\b|\bcryptocurrenc', re.I), "Finance / Banking"),
    (re.compile(r'\bhealthcare\b|\bhealth\b|\bpharmaceutical\b|\bmedical\b', re.I),  "Healthcare / Pharma"),
    (re.compile(r'\btechnology\b|\btech\b|\bIT\b|\bsoftware\b|\bhardware\b', re.I),  "Technology"),
    (re.compile(r'\btelecommunication\b|\btelecom\b|\bISP\b', re.I),                 "Telecommunications"),
    (re.compile(r'\beducation\b|\bacademic\b|\buniversit\b|\bresearch institute', re.I), "Education / Research"),
    (re.compile(r'\bmanufacturing\b|\bindustrial\b|\bICS\b|\bSCADA\b|\bOT\b', re.I),"Manufacturing / Industrial"),
    (re.compile(r'\bretail\b|\bhospitalit\b|\btourism\b', re.I),                     "Retail / Hospitality"),
    (re.compile(r'\bmedia\b|\bnews\b|\bjournalism\b|\bentertainment\b', re.I),       "Media / Entertainment"),
    (re.compile(r'\btransport\b|\blogistics\b|\bshipping\b|\baviation\b', re.I),     "Transport / Logistics"),
    (re.compile(r'\bcritical infrastructure\b', re.I),                               "Critical Infrastructure"),
    (re.compile(r'\bnon.?profit\b|\bNGO\b|\bcivil society\b|\bactivist\b', re.I),   "NGO / Civil Society"),
    (re.compile(r'\bthink.?tank\b|\bpolicy\b|\bdiplomac\b', re.I),                  "Think Tank / Policy"),
]


def _extract_sectors(desc: str) -> str:
    seen: list = []
    labels: set = set()
    for pat, label in _SECTORS:
        if label not in labels and pat.search(desc):
            seen.append(label)
            labels.add(label)
    return "; ".join(seen[:8])  # cap to keep cells readable


# ── Target regions ────────────────────────────────────────────────────────────

_REGIONS: List[Tuple[str, re.Pattern]] = [
    ("Middle East",    re.compile(r'Middle East|Saudi Arabia|UAE|United Arab Emirates|Qatar|Iraq|Syria|Jordan|Kuwait|Yemen|Bahrain|Oman|Egypt', re.I)),
    ("Europe",         re.compile(r'Europe(?:an)?|Germany|France|United Kingdom|UK|Italy|Spain|Poland|Netherlands|Belgium|Sweden|Norway|Denmark|Finland|Czech|Romania|Hungary', re.I)),
    ("North America",  re.compile(r'United States|U\.S\.|Canada|North America', re.I)),
    ("Asia Pacific",   re.compile(r'Asia.?Pacific|Japan|South Korea|Australia|Singapore|Taiwan|Hong Kong|New Zealand', re.I)),
    ("Southeast Asia", re.compile(r'Southeast Asia|Vietnam|Philippines|Thailand|Malaysia|Indonesia|Myanmar|Cambodia|Laos', re.I)),
    ("South Asia",     re.compile(r'South Asia|Pakistan|India|Bangladesh|Sri Lanka|Afghanistan|Nepal', re.I)),
    ("Central Asia",   re.compile(r'Central Asia|Kazakhstan|Uzbekistan|Kyrgyzstan|Tajikistan|Turkmenistan', re.I)),
    ("Africa",         re.compile(r'Africa(?:n)?|Nigeria|Kenya|South Africa|Ethiopia|Algeria|Morocco|Tunisia', re.I)),
    ("South America",  re.compile(r'South America|Latin America|Brazil|Argentina|Colombia|Chile|Venezuela|Peru', re.I)),
    ("Russia / CIS",   re.compile(r"Russia(?:n)?|Ukraine|Belarus|Georgia(?!.*\bstate\b)|Armenia|Azerbaijan", re.I)),
    ("Global",         re.compile(r'global(?:ly)?|world.?wide|internationally|multinational|multiple countries', re.I)),
]


def _extract_regions(desc: str) -> str:
    seen: list = []
    labels: set = set()
    for region, pat in _REGIONS:
        if region not in labels and pat.search(desc):
            seen.append(region)
            labels.add(region)
    return "; ".join(seen)


# ── Attribution confidence ────────────────────────────────────────────────────

_HIGH_CONF = re.compile(r'high confidence|definitively|firmly attributed|confirmed|assessed.*certain', re.I)
_LOW_CONF  = re.compile(r'possibly|possibly|may be|might be|uncertain|unconfirmed|we cannot confirm', re.I)
_MED_CONF  = re.compile(r'suspected|likely|believed|assessed|reportedly|thought to be|probably|with moderate', re.I)


def _extract_confidence(desc: str) -> str:
    if _HIGH_CONF.search(desc):
        return "High"
    if _LOW_CONF.search(desc):
        return "Low"
    if _MED_CONF.search(desc):
        return "Medium"
    return ""


# ── Core enrichment ───────────────────────────────────────────────────────────

def enrich_group(
    group_obj: dict,
    grp_software: Dict[str, set],
    grp_campaigns: Dict[str, set],
) -> dict:
    """
    Return enriched metadata dict for a single MITRE intrusion-set object.

    grp_software  : pre-built {stix_id → set of tool/malware names}}
    grp_campaigns : pre-built {group stix_id → set of campaign names}
    """
    desc    = group_obj.get("description", "") or ""
    stix_id = group_obj.get("id", "")

    tools      = grp_software.get(stix_id, set())
    camp_names = grp_campaigns.get(stix_id, set())

    return {
        "nexus":                  _extract_nexus(desc),
        "sponsor":                _extract_sponsor(desc),
        "activity_since":         _extract_activity_since(desc),
        "primary_objectives":     _extract_objectives(desc),
        "target_regions":         _extract_regions(desc),
        "target_sectors":         _extract_sectors(desc),
        "attribution_confidence": _extract_confidence(desc),
        "tools_malware":          "; ".join(sorted(tools)),
        "campaigns":              "; ".join(sorted(camp_names)),
    }


# ── Cache build / load ────────────────────────────────────────────────────────

def build_group_metadata_cache(objects: list, output_path) -> dict:
    """
    Enrich all MITRE intrusion-set objects and write to a JSON cache.

    Single O(N) pass over the STIX objects to build relationship indexes,
    then one description-parse per group (O(G)).

    Returns the metadata dict keyed by ATT&CK group ID ("G0064").
    Also writes stix_id keys for fast secondary lookup.
    """
    from shikari.mitre.procedures import _build_indexes, _attack_id

    groups_idx, _, software_idx, campaigns_idx = _build_indexes(objects)

    # Pre-build relationship lookups in a single O(N) pass
    grp_software: Dict[str, set]  = {}   # group stix_id → set of sw names
    grp_campaigns: Dict[str, set] = {}   # group stix_id → set of camp names

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel = obj.get("relationship_type", "")
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")

        if rel == "uses" and src in groups_idx and tgt in software_idx:
            name = software_idx[tgt].get("name", "")
            if name:
                grp_software.setdefault(src, set()).add(name)

        if rel == "attributed-to" and src in campaigns_idx and tgt in groups_idx:
            name = campaigns_idx[src].get("name", "")
            if name:
                grp_campaigns.setdefault(tgt, set()).add(name)

    # Enrich each group (description parse only — fast)
    metadata: dict = {}
    for stix_id, grp in groups_idx.items():
        att_id = _attack_id(grp)
        if not att_id:
            continue
        enriched = enrich_group(grp, grp_software, grp_campaigns)
        enriched["group_name"]     = grp.get("name", "")
        enriched["mitre_group_id"] = att_id
        # Primary key: ATT&CK ID; secondary key: STIX ID
        metadata[att_id]  = enriched
        metadata[stix_id] = enriched

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    group_count = sum(1 for k in metadata if k.startswith("G"))
    logger.info("Group metadata cache written: %s (%d groups)", output_path, group_count)
    return metadata


def load_group_metadata(cache_path) -> dict:
    """Load cached group metadata. Returns empty dict if cache is absent."""
    cache_path = Path(cache_path)
    if not cache_path.exists():
        return {}
    try:
        with open(cache_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Failed to load group metadata cache %s: %s", cache_path, exc)
        return {}

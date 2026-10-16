"""
Per-country picture for the Cyber Powers map, from ATT&CK's own group descriptions (no AI):

- Attribution: the nations each group is attributed to, and how firmly the description puts
  it. High names a government body or unit, or an indictment ("attributed to Russia's GRU
  ... unit 26165"); Moderate states it plainly ("a North Korea-based group", "China-linked"),
  or names a body but hedges; Low hedges ("a suspected Chinese group", "likely Iranian").
- Targets: the countries the description says a group targets ("has targeted organisations
  in South Korea and Japan"), other than its own.
- Motivation: the objectives (archer.mitre.group_metadata) of a country's groups, or of the
  groups targeting it.

Mentions are matched as country names, demonyms and agencies; a country named as the
target ("targeting the Ukrainian government") isn't read as the attacker.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Dict, Iterable, List, Optional

# Names on the map (Natural Earth) mapped to how prose names them: demonyms, other names,
# acronyms (case-sensitive). The map's own name is always a term.
TERMS: Dict[str, List[str]] = {
    "United States of America": ["United States", "(?<!South )(?<!Latin )(?<!Central )(?<!North )American",
                                 "(?-i:US|U\\.S\\.|USA)"],
    "United Kingdom": ["British", "Britain", "(?-i:UK|U\\.K\\.)"],
    "China": ["Chinese", "People's Republic of China", "People’s Republic of China", "(?-i:PRC)"],
    "Russia": ["Russian", "Russian Federation"], "Iran": ["Iranian"],
    "North Korea": ["North Korean", "(?-i:DPRK)"], "South Korea": ["South Korean", "(?<!People's )(?<!People’s )Republic of Korea"],
    "Taiwan": ["Taiwanese"], "Japan": ["Japanese"], "Vietnam": ["Vietnamese"], "India": ["Indian"],
    "Pakistan": ["Pakistani"], "Israel": ["Israeli"], "Turkey": ["Turkish", "Türkiye", "Turkiye"],
    "Lebanon": ["Lebanese"], "Belarus": ["Belarusian"], "Ukraine": ["Ukrainian"], "Syria": ["Syrian"],
    "Saudi Arabia": ["Saudi"], "United Arab Emirates": ["Emirati", "(?-i:UAE)"], "Palestine": ["Palestinian", "Gaza"],
    "Kazakhstan": ["Kazakh", "Kazakhstani"], "Azerbaijan": ["Azerbaijani"], "Armenia": ["Armenian"],
    "Georgia": ["Georgian"], "Mongolia": ["Mongolian"], "Afghanistan": ["Afghan"], "Iraq": ["Iraqi"],
    "Kuwait": ["Kuwaiti"], "Qatar": ["Qatari"], "Jordan": ["Jordanian"], "Egypt": ["Egyptian"],
    "Yemen": ["Yemeni"], "Oman": ["Omani"], "Philippines": ["Philippine", "Filipino"], "Thailand": ["Thai"],
    "Myanmar": ["Burmese", "Burma"], "Cambodia": ["Cambodian"], "Laos": ["Laotian"], "Malaysia": ["Malaysian"],
    "Indonesia": ["Indonesian"], "Bangladesh": ["Bangladeshi"], "Sri Lanka": ["Sri Lankan"], "Nepal": ["Nepalese"],
    "Australia": ["Australian"], "New Zealand": [], "Canada": ["Canadian"], "Mexico": ["Mexican"],
    "Brazil": ["Brazilian"], "Argentina": ["Argentinian", "Argentine"], "Chile": ["Chilean"],
    "Colombia": ["Colombian"], "Venezuela": ["Venezuelan"], "Peru": ["Peruvian"], "Ecuador": ["Ecuadorian"],
    "Germany": ["German"], "France": ["French"], "Italy": ["Italian"], "Spain": ["Spanish"],
    "Netherlands": ["Dutch"], "Belgium": ["Belgian"], "Switzerland": ["Swiss"], "Austria": ["Austrian"],
    "Poland": ["Polish"], "Czechia": ["Czech Republic", "Czech"], "Hungary": ["Hungarian"],
    "Romania": ["Romanian"], "Bulgaria": ["Bulgarian"], "Serbia": ["Serbian"], "Greece": ["Greek"],
    "Cyprus": ["Cypriot"], "Norway": ["Norwegian"], "Sweden": ["Swedish"], "Finland": ["Finnish"],
    "Denmark": ["Danish"], "Estonia": ["Estonian"], "Latvia": ["Latvian"], "Lithuania": ["Lithuanian"],
    "Moldova": ["Moldovan"], "Ireland": ["Irish"], "Portugal": ["Portuguese"],
    "Uzbekistan": ["Uzbek"], "Tajikistan": ["Tajik"], "Kyrgyzstan": ["Kyrgyz"], "Turkmenistan": ["Turkmen"],
    "Nigeria": ["Nigerian"], "South Africa": ["South African"], "Kenya": ["Kenyan"], "Ethiopia": ["Ethiopian"],
    "Morocco": ["Moroccan"], "Algeria": ["Algerian"], "Tunisia": ["Tunisian"], "Libya": ["Libyan"],
    "Sudan": ["Sudanese"], "Dem. Rep. Congo": ["Democratic Republic of the Congo", "(?-i:DRC)"],
    "Bosnia and Herz.": ["Bosnia"], "Macedonia": ["North Macedonia"], "Côte d'Ivoire": ["Ivory Coast"],
}
# Government bodies and the like: naming one is attribution to its state
AGENCIES = {
    "Russia": r"\b(?-i:GRU|FSB|SVR|GTsSS)\b|Main Intelligence Directorate|Foreign Intelligence Service|Federal Security Service"
              r"|\bunit 26165\b|\bunit 74455\b|\bunit 29155\b",
    "China": r"\b(?-i:MSS|PLA)\b|Ministry of State Security|People's Liberation Army|People’s Liberation Army"
             r"|Strategic Support Force|\bUnit 61398\b",
    "North Korea": r"\b(?-i:RGB)\b|Reconnaissance General Bureau|Lazarus Group",
    "Iran": r"\b(?-i:IRGC|MOIS)\b|Islamic Revolutionary Guard|Ministry of Intelligence and Security|Ministry of Intelligence",
    "Pakistan": r"\b(?-i:ISI)\b|Inter-Services Intelligence",
    "Israel": r"\bUnit 8200\b",
    "United States of America": r"\b(?-i:NSA|CIA)\b|National Security Agency|Central Intelligence Agency",
    "United Kingdom": r"\b(?-i:GCHQ)\b",
    "Lebanon": r"\bHezbollah\b",
    "Palestine": r"\bHamas\b",
    "Belarus": r"\b(?-i:KGB) of Belarus\b|Belarusian (?:government|military|intelligence)",
}

_HEDGE = re.compile(r"\b(?:suspected|likely|possibly|probably|probable|possible|believed|assessed|may|might|reportedly"
                    r"|thought|potential(?:ly)?|alleged(?:ly)?|appears?|presumed|suggest(?:s|ed)?)\b", re.I)
_PROOF = re.compile(r"\bindict(?:ed|ment)|\bcharged\b|Department of Justice|\bDOJ\b|sanctioned by", re.I)
_TARGETING = re.compile(r"\b(?:target(?:s|ed|ing)?|against|victims?|compromis(?:e|ed|ing)|attack(?:s|ed|ing)?|intrusions?"
                        r"|focus(?:es|ed|ing)? on|spied on|spying on|surveil\w*|aimed at|operations in|entities in"
                        r"|organi[sz]ations in|in the (?:government|energy|defen[cs]e))\b", re.I)
# A country named just before is the target, not the attacker ("targeting the Ukrainian government")
_TARGET_BEFORE = re.compile(r"\b(?:target(?:s|ed|ing)?|against|victims? in|attacks? on|including|in|on|of)\s+(?:the\s+)?(?:\w+\s+){0,3}$", re.I)
# "People's Republic of China (PRC) state-sponsored", "PRC)-aligned", "North Korea–aligned". Not
# "-speaking" (a language isn't a state: Machete is "Spanish-speaking"), and not a bare
# "<demonym> government / military": that's as often the target or the accuser ("Israeli
# military assets", "the Ukrainian government publicly attributed Gamaredon to Russia's FSB")
_ATTR_AFTER = (r"(?:\s*\([^)]{1,12}\))?\)?(?:[-–—]|\s)(?:based|nexus|linked|backed|sponsored|state[- ](?:sponsored|backed)"
               r"|(?:government|military|state)[- ](?:sponsored|backed|linked)|aligned|affiliated|origins?)\b")
_ACTOR_NOUN = r"(?:\s+[\w-]+){0,3}?\s+(?:threat|cyber|espionage|APT|group|actor|actors|operators|hackers|entity|cluster)\b"


def _alt(country: str) -> str:
    return "|".join([re.escape(country)] + TERMS.get(country, []))


_PATTERNS = {c: re.compile(rf"(?<![\w-])(?:{_alt(c)})(?![\w])", re.I) for c in TERMS}


def _clean(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text or "")
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    return re.sub(r"\s+", " ", text)


def _sentences(text: str) -> List[str]:
    return [s for s in re.split(r"(?<=[.!?])\s+(?=[A-Z\[])", text) if s.strip()]


def attribution(description: str, names: Iterable[str] = ()) -> Dict[str, str]:
    """{country: "High" | "Moderate" | "Low"} the group is attributed to. Only sentences about
    the group itself count: the first, one naming it (`names`: name and aliases), or one
    opening "The group", "They", "It" ... ("Sidewinder, a suspected Indian threat group" in
    SideCopy's description is about Sidewinder)."""
    own = [re.compile(rf"(?<![\w-]){re.escape(n)}(?![\w-])") for n in names if n]
    about_it = re.compile(r"^(?:The|This) (?:group|actor|threat|cluster)|^(?:They|It|Its|Their)\b|^Circumstantial|^While")
    rank = {"Low": 1, "Moderate": 2, "High": 3}
    out: Dict[str, str] = {}

    def note(country: str, level: str) -> None:
        if rank[level] > rank.get(out.get(country, ""), 0):
            out[country] = level

    for i, sentence in enumerate(_sentences(_clean(description))):
        if own and i and not about_it.search(sentence) and not any(p.search(sentence) for p in own):
            continue
        hedged = bool(_HEDGE.search(sentence))
        proof = bool(_PROOF.search(sentence))
        for country, pattern in AGENCIES.items():
            if re.search(pattern, sentence, re.I):
                note(country, "Moderate" if hedged and not proof else "High")
        for country, pattern in _PATTERNS.items():
            for m in pattern.finditer(sentence):
                after = sentence[m.end():]
                before = sentence[max(0, m.start() - 40):m.start()]
                # "attributed to actors operating out of China" first: "out of" isn't a target
                by_before = re.search(r"(?:attributed to|on behalf of|sponsored by|backed by|tied to|ties to"
                                      r"|linked to|operat\w* (?:out of|from)|out of|connections to|nexus to|link between this group and)"
                                      r"\s+(?:the\s+)?(?:[\w-]+\s+){0,3}?(?:of\s+)?$", before, re.I)
                if not by_before and _TARGET_BEFORE.search(sentence[max(0, m.start() - 60):m.start()]):
                    continue
                # "..., Sidewinder, a suspected Indian threat group": about another group
                other = re.search(r"([A-Z][\w.-]+(?: [A-Z][\w.-]+)?),\s+(?:a|an)\s+(?:[\w-]+\s+){0,2}$", before)
                if other and own and not any(p.fullmatch(other.group(1)) for p in own):
                    continue
                attributed = by_before or re.match(_ATTR_AFTER, after, re.I) or re.match(_ACTOR_NOUN, after, re.I)
                if attributed:
                    note(country, "High" if proof else "Low" if hedged else "Moderate")
    return out


def targets(description: str, own: Iterable[str] = ()) -> List[str]:
    """Countries the description says the group targets, its own excluded."""
    own = set(own)
    found = set()
    for sentence in _sentences(_clean(description)):
        if not _TARGETING.search(sentence):
            continue
        for country, pattern in _PATTERNS.items():
            if country not in own and pattern.search(sentence):
                found.add(country)
    return sorted(found)


MOTIVES = {"Espionage": "Espionage", "Financial Crime": "Financial", "Ransomware / Extortion": "Financial",
           "Disruption / Sabotage": "Disruption", "Influence Operations": "Influence"}


def motivation(objectives: Iterable[str]) -> List[Dict]:
    """[{motive, share}] across the groups' objectives, commonest first."""
    per_group = [{MOTIVES[o.strip()] for o in (obj or "").split(";") if o.strip() in MOTIVES} for obj in objectives]
    per_group = [m for m in per_group if m]
    if not per_group:
        return []
    counts = Counter(m for motives in per_group for m in motives)
    return [{"motive": m, "share": round(100 * n / len(per_group))} for m, n in counts.most_common()]


def profiles(bundle, group_meta: Dict) -> Dict[str, Dict]:
    """{map country name: {groups: [...], confidence, attributed: {High, Moderate, Low},
    motivation, targeted_by: [...], target_motivation, attackers}} from ATT&CK's groups."""
    groups = []
    for obj in getattr(bundle, "objects", None) or (bundle or {}).get("objects", []) if bundle else []:
        if obj.get("type") != "intrusion-set" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        gid = next((r.get("external_id") for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        description = obj.get("description") or ""
        attributed = attribution(description, [obj.get("name", "")] + list(obj.get("aliases") or []))
        groups.append({"id": gid, "name": obj.get("name"), "attributed": attributed,
                       "targets": targets(description, attributed),
                       "objectives": (group_meta.get(gid) or {}).get("primary_objectives", "")})
    out: Dict[str, Dict] = {}
    rank = {"High": 3, "Moderate": 2, "Low": 1}
    for g in groups:
        for country, level in g["attributed"].items():
            c = out.setdefault(country, {})
            c.setdefault("groups", []).append({"name": g["name"], "id": g["id"], "confidence": level,
                                               "objectives": g["objectives"]})
        for country in g["targets"]:
            out.setdefault(country, {}).setdefault("targeted_by", []).append(g)
    for country, c in out.items():
        own = sorted(c.get("groups", []), key=lambda g: (-rank[g["confidence"]], g["name"]))
        c["groups"] = [{"name": g["name"], "id": g["id"], "confidence": g["confidence"]} for g in own]
        c["attributed"] = dict(Counter(g["confidence"] for g in own))
        c["confidence"] = own[0]["confidence"] if own else None
        c["motivation"] = motivation(g["objectives"] for g in own)
        by = sorted(c.pop("targeted_by", []), key=lambda g: g["name"])
        c["targeted_by"] = [g["name"] for g in by]
        c["target_motivation"] = motivation(g["objectives"] for g in by)
        c["attackers"] = [n for n, _ in Counter(a for g in by for a in g["attributed"]).most_common(5)]
    return out


_cache: Dict = {"key": None, "value": None}


def cached_profiles(bundle, group_meta: Dict) -> Dict[str, Dict]:
    key = (id(bundle), len(group_meta or {}))
    if _cache["key"] != key:
        _cache.update(key=key, value=profiles(bundle, group_meta or {}))
    return _cache["value"]

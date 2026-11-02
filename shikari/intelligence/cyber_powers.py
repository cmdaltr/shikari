"""
National cyber power: the IISS's tiers (Cyber Capabilities and National Power, volume 1, 2021,
and volume 2, 2023), and the other states threat reporting attributes activity to (the
feed's NATIONS that the IISS hasn't assessed). Drawn on the Cyber Powers page.
"""

import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

MAP_PATH = Path(__file__).resolve().parents[2] / "static" / "images" / "world_equal_earth.svg"

IISS_SOURCES = [
    ("Volume 1 (2021)", "https://www.iiss.org/research-paper/2021/06/cyber-power---tier-one/"),
    ("Volume 2 (2023)", "https://www.iiss.org/research-paper/2023/09/cyber-capabilities-national-power-volume-2/"),
]

TIERS = [
    {"tier": 1, "label": "Tier One", "summary": "World-leading strengths in all categories",
     "states": ["United States"]},
    {"tier": 2, "label": "Tier Two", "summary": "World-leading strengths in some categories",
     "states": ["Australia", "Canada", "China", "France", "Germany", "Israel", "Netherlands", "Russia",
                "United Kingdom"]},
    {"tier": 3, "label": "Tier Three",
     "summary": "Strengths or potential strengths in some categories, significant weaknesses in others",
     "states": ["Brazil", "Estonia", "India", "Indonesia", "Iran", "Japan", "Malaysia", "Nigeria", "North Korea",
                "Saudi Arabia", "Singapore", "South Africa", "Turkey", "United Arab Emirates", "Vietnam"]},
]
# Volume 2's states, for the "assessed in" note
VOLUME_2 = {"Brazil", "Estonia", "Germany", "Netherlands", "Nigeria", "Saudi Arabia", "Singapore", "South Africa",
            "Turkey", "United Arab Emirates"}

# Names the map (Natural Earth) uses where they differ from Shikari's
MAP_NAMES = {"United States": "United States of America"}
# Natural Earth's abbreviations, in full, for people to read
DISPLAY = {"United States of America": "United States", "Bosnia and Herz.": "Bosnia and Herzegovina",
           "Central African Rep.": "Central African Republic", "Dem. Rep. Congo": "Democratic Republic of the Congo",
           "Congo": "Republic of the Congo", "Dominican Rep.": "Dominican Republic", "Eq. Guinea": "Equatorial Guinea",
           "Falkland Is.": "Falkland Islands", "Fr. S. Antarctic Lands": "French Southern and Antarctic Lands",
           "Macedonia": "North Macedonia", "N. Cyprus": "Northern Cyprus", "S. Sudan": "South Sudan",
           "Solomon Is.": "Solomon Islands", "W. Sahara": "Western Sahara", "eSwatini": "Eswatini", "Turkey": "Türkiye"}


FLAGS_URL = "/static/vendor/flag-icons/4x3"
# No ISO code, so no flag-icons file: drawn by scripts/data/vendor_flags.py
OWN_FLAGS = {"Somaliland": "somaliland", "N. Cyprus": "northern-cyprus"}


def flag(map_name: str, iso: str) -> str:
    """The country's flag image (static/vendor/flag-icons, 4x3 SVG), or "" if it has none."""
    name = OWN_FLAGS.get(map_name) or (iso.lower() if len(iso or "") == 2 else "")
    return f"{FLAGS_URL}/{name}.svg" if name else ""


@lru_cache(maxsize=1)
def countries() -> List[Dict]:
    """Every country on the map, as {map, name, iso, flag}, by name: the Profile country choices."""
    found = dict(re.findall(r'data-name="([^"]+)" data-iso="([A-Z]*)"', MAP_PATH.read_text(encoding="utf-8")))
    return sorted(({"map": n, "name": DISPLAY.get(n, n), "iso": iso, "flag": flag(n, iso)} for n, iso in found.items()),
                  key=lambda c: c["name"])


def is_country(map_name: Optional[str]) -> bool:
    return any(c["map"] == map_name for c in countries())


def powers() -> Dict:
    """Tiers, then the states attributed in threat reporting but not assessed, with map names."""
    from shikari.intelligence.feed import NATIONS

    assessed = {s for t in TIERS for s in t["states"]}
    groups: List[Dict] = [
        {**t, "key": f"tier-{t['tier']}",
         "states": [{"name": s, "map": MAP_NAMES.get(s, s), "volume": 2 if s in VOLUME_2 else 1} for s in t["states"]]}
        for t in TIERS]
    others = sorted(n for n in NATIONS if n not in assessed)
    groups.append({"tier": None, "key": "attributed", "label": "Attributed, not assessed",
                   "summary": "Not assessed by the IISS; threat reporting and ATT&CK attribute activity to them",
                   "states": [{"name": s, "map": MAP_NAMES.get(s, s), "volume": None} for s in others]})
    return {"groups": groups, "sources": IISS_SOURCES}


def page_data(bundle, group_meta: Dict, home: Optional[str] = None, sample: int = 8) -> Dict:
    """Everything the map draws and its tooltips say, per country (map names)."""
    from shikari.intelligence.country_profiles import cached_profiles

    profiles = cached_profiles(bundle, group_meta)
    tier_of = {s["map"]: (g["tier"], g["label"], s["volume"]) for g in powers()["groups"] if g["tier"]
               for s in g["states"]}
    data = {}
    for c in countries():
        p = profiles.get(c["map"], {})
        tier = tier_of.get(c["map"])
        entry = {"name": c["name"], "flag": c["flag"]}
        if tier:
            entry.update(tier=tier[0], tier_label=tier[1], volume=tier[2])
        if p.get("groups"):
            entry.update(confidence=p["confidence"], attributed=p["attributed"], motivation=p["motivation"],
                         groups=[f"{g['name']} ({g['confidence'][0]})" for g in p["groups"][:sample]],
                         group_count=len(p["groups"]))
        if p.get("targeted_by"):
            entry.update(targeted=len(p["targeted_by"]), targeted_by=p["targeted_by"][:sample],
                         target_motivation=p["target_motivation"],
                         attackers=[DISPLAY.get(a, a) for a in p["attackers"]])
        data[c["map"]] = entry
    return {"countries": data, "home": home if is_country(home) else None,
            "tiers": [{"key": g["key"], "label": g["label"], "summary": g["summary"]} for g in powers()["groups"] if g["tier"]]}

"""
National cyber power: the IISS's tiers (Cyber Capabilities and National Power, volume 1, 2021,
and volume 2, 2023), and the other states threat reporting attributes activity to (the
feed's NATIONS that the IISS hasn't assessed). Drawn on the Cyber Powers page.
"""

from typing import Dict, List

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

# Names the map (Natural Earth) uses where they differ from Archer's
MAP_NAMES = {"United States": "United States of America"}


def powers() -> Dict:
    """Tiers, then the states attributed in threat reporting but not assessed, with map names."""
    from archer.intelligence.feed import NATIONS

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

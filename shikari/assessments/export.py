"""
Export assessment results (#24): a CSV of outcomes, and an ATT&CK Navigator layer.

The Navigator layer scores each technique by its blue outcome, so the matrix shades from "not
logged" through "logged" and "alerted" to "prevented" — the defensive picture a campaign leaves.
The layer is built by `samarkand.navigator`, the suite's shared builder, and names the ATT&CK
version and platforms of the bundle Shikari has loaded, not a fixed release.
"""

import csv
import io
import json
import logging
from typing import Dict, Iterable, List, Optional

from samarkand import navigator

logger = logging.getLogger(__name__)

# Only when Shikari has no ATT&CK data at all (no cached bundle, no built procedures CSV): the
# release and Enterprise platforms a layer then names
FALLBACK_ATTACK_VERSION = "17"
FALLBACK_PLATFORMS = ("Containers", "ESXi", "IaaS", "Identity Provider", "Linux", "Network Devices",
                      "Office Suite", "PRE", "SaaS", "Windows", "macOS")

# Blue outcome -> (Navigator score, colour). Red is carried in the comment.
_BLUE_SCORE = {
    "prevented": (4, "#2e7d32"),
    "alerted": (3, "#66bb6a"),
    "logged": (2, "#fff176"),
    "not_logged": (1, "#e57373"),
    "not_assessed": (0, "#bdbdbd"),
}

CSV_COLUMNS = ["technique_id", "technique_name", "tactic", "red_outcome", "blue_outcome",
               "detection_file", "notes"]


def results_to_csv(results: List[Dict]) -> str:
    """Assessment results as CSV text (DXA-free; plain rows for any tool)."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for r in results:
        writer.writerow({k: r.get(k, "") for k in CSV_COLUMNS})
    return buf.getvalue()


def _attack_data() -> tuple:
    """(ATT&CK version, Enterprise platforms) from the bundle Shikari has loaded."""
    from shikari.mitre import procedures

    release = procedures.bundle_release()
    if release is not None:
        return release.version, release.platforms.get(navigator.ENTERPRISE) or list(FALLBACK_PLATFORMS)
    version = procedures.built_version()
    if not version:
        logger.warning("No ATT&CK data loaded: the Navigator layer names ATT&CK %s", FALLBACK_ATTACK_VERSION)
    return version or FALLBACK_ATTACK_VERSION, list(FALLBACK_PLATFORMS)


def results_to_navigator(name: str, results: List[Dict], attack_version: Optional[str] = None,
                         platforms: Optional[Iterable[str]] = None) -> str:
    """Results as an ATT&CK Navigator 4.5 layer, scored and coloured by blue outcome. The ATT&CK
    version and platforms are the loaded bundle's unless given."""
    if attack_version is None or platforms is None:
        loaded_version, loaded_platforms = _attack_data()
        attack_version = attack_version or loaded_version
        platforms = loaded_platforms if platforms is None else platforms
    marks = {}
    for r in results:
        tid = r.get("technique_id")
        if not tid:
            continue
        score, colour = _BLUE_SCORE.get(r.get("blue_outcome", "not_assessed"), (0, "#bdbdbd"))
        comment = f"Red: {r.get('red_outcome', 'not_run')}; Blue: {r.get('blue_outcome', 'not_assessed')}"
        if r.get("detection_file"):
            comment += f"; detection: {r['detection_file']}"
        if r.get("notes"):
            comment += f"; {r['notes']}"
        marks[tid] = navigator.Mark(colour, comment, score=score)
    layer = navigator.build_layer(
        name,
        navigator.ENTERPRISE,
        marks,
        attack_version=attack_version,
        platforms=platforms,
        description="Shikari assessment outcomes, scored by blue result.",
        gradient={"colors": ["#e57373", "#fff176", "#2e7d32"], "minValue": 1, "maxValue": 4},
        legend=[
            {"label": "Prevented", "color": "#2e7d32"},
            {"label": "Alerted", "color": "#66bb6a"},
            {"label": "Logged", "color": "#fff176"},
            {"label": "Not logged", "color": "#e57373"},
        ],
    )
    return json.dumps(layer, indent=2)

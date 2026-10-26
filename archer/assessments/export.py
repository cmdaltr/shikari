"""
Export assessment results (#24): a CSV of outcomes, and an ATT&CK Navigator layer.

The Navigator layer scores each technique by its blue outcome, so the matrix shades from "not
logged" through "logged" and "alerted" to "prevented" — the defensive picture a campaign leaves.
"""

import csv
import io
import json
from typing import Dict, List

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


def results_to_navigator(name: str, results: List[Dict], attack_version: str = "17") -> str:
    """Results as an ATT&CK Navigator 4.5 layer, scored and coloured by blue outcome."""
    techniques = []
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
        techniques.append({"techniqueID": tid, "score": score, "color": colour,
                           "comment": comment, "enabled": True})
    layer = {
        "name": name,
        "versions": {"attack": attack_version, "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Archer assessment outcomes, scored by blue result.",
        "techniques": techniques,
        "gradient": {"colors": ["#e57373", "#fff176", "#2e7d32"], "minValue": 1, "maxValue": 4},
        "legendItems": [
            {"label": "Prevented", "color": "#2e7d32"},
            {"label": "Alerted", "color": "#66bb6a"},
            {"label": "Logged", "color": "#fff176"},
            {"label": "Not logged", "color": "#e57373"},
        ],
    }
    return json.dumps(layer, indent=2)

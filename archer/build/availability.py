"""
Per-tenant data-source availability (#12).

A detection names the data sources it needs in ``requiredDataConnectors[].dataTypes`` — MDE tables
(``DeviceProcessEvents``), SecOps UDM event types (``PROCESS_LAUNCH``). An estate may not ingest all
of them (an MDE→SecOps feed, for instance, may carry file and registry events but not process). This
module records which sources the estate ingests per SIEM and flags a detection that needs one it
doesn't, so Results can badge it and the deploy paths (detections-as-code export, SIEM push) can
exclude it.

The flag is derived live from the config, not written into the detection — change the config and the
badge changes without regenerating. A SIEM absent from the config is not gated (every source counts
as ingested), so with no config nothing is flagged and behaviour is unchanged.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from archer.build.schema_overrides import load_active_schema

_MAPPINGS_DIR = Path(__file__).resolve().parent.parent.parent / "bespoke" / "mappings"
_PATH = _MAPPINGS_DIR / "availability.json"

# connectorId in a detection's requiredDataConnectors -> SIEM key
CONNECTOR_SIEM = {
    "MicrosoftThreatProtection": "mde",
    "GoogleSecOps": "secops",
    "Splunk": "splunk",
    "Elastic": "elastic",
}
# SIEMs for which availability is expressed as a data-source list (tables / UDM event types).
GATED_SIEMS = ("mde", "secops")


def load() -> Dict[str, List[str]]:
    """{siem: [ingested source, …]} as saved. A SIEM not present here is not gated."""
    try:
        with open(_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return {k: list(v) for k, v in data.items() if k in GATED_SIEMS and isinstance(v, list)}
    except (OSError, ValueError):
        return {}


def save(ingested: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Persist the ingested-source lists (only the gated SIEMs are kept)."""
    clean = {k: sorted(set(map(str, v))) for k, v in (ingested or {}).items()
             if k in GATED_SIEMS and isinstance(v, list)}
    os.makedirs(_MAPPINGS_DIR, exist_ok=True)
    with open(_PATH, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2)
    return clean


def is_gated_siem(siem: str, cfg: Optional[Dict] = None) -> bool:
    """True when availability is configured for this SIEM (so its detections can be flagged)."""
    cfg = load() if cfg is None else cfg
    return siem in cfg


def missing_sources(doc: Dict, cfg: Optional[Dict] = None) -> List[Dict]:
    """For a detection YAML dict, the required sources the estate doesn't ingest.

    Returns a list of {siem, connector, dataType}. Empty means every source it needs is ingested
    (or its SIEM isn't gated)."""
    cfg = load() if cfg is None else cfg
    out: List[Dict] = []
    for conn in doc.get("requiredDataConnectors") or []:
        if not isinstance(conn, dict):
            continue
        siem = CONNECTOR_SIEM.get(conn.get("connectorId", ""))
        if not siem or siem not in cfg:
            continue  # SIEM not gated -> everything counts as ingested
        ingested = set(cfg[siem])
        for dt in conn.get("dataTypes") or []:
            if dt not in ingested:
                out.append({"siem": siem, "connector": conn.get("connectorId", ""), "dataType": dt})
    return out


def is_available(doc: Dict, cfg: Optional[Dict] = None) -> bool:
    """True when the estate ingests everything the detection needs (so it can fire)."""
    return not missing_sources(doc, cfg)


def source_catalogue(generate_dir: str) -> Dict[str, List[str]]:
    """The universe of gate-able sources to offer in the config UI, per SIEM.

    MDE: the documented Advanced Hunting tables from the base schema. SecOps: the UDM event types
    that actually appear across generated detections (so the list reflects what Archer emits)."""
    mde = sorted((load_active_schema("mde") or {}).keys())
    secops: set = set()
    try:
        from archer.config import GENERATE_DIR  # noqa: F401
    except Exception:
        pass
    try:
        import yaml

        for name in os.listdir(generate_dir):
            if not name.endswith((".yaml", ".yml")):
                continue
            try:
                with open(os.path.join(generate_dir, name), encoding="utf-8") as f:
                    doc = yaml.safe_load(f)
            except (OSError, ValueError):
                continue
            if not isinstance(doc, dict):
                continue
            for conn in doc.get("requiredDataConnectors") or []:
                if isinstance(conn, dict) and conn.get("connectorId") == "GoogleSecOps":
                    secops.update(str(d) for d in conn.get("dataTypes") or [])
    except OSError:
        pass
    return {"mde": mde, "secops": sorted(secops)}

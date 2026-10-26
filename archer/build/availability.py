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
# Drop the authoritative UDM metadata.event_type list here (a JSON array of strings) to offer the
# full set in the config checklist. Absent, the curated default below is used, unioned with whatever
# the current runs emit, so nothing in use is ever missing from the list.
_UDM_REF_FILE = _MAPPINGS_DIR / "udm_event_types.json"

# A documented-subset default of SecOps UDM metadata.event_type values. Overridable by the file above.
_DEFAULT_UDM_EVENT_TYPES = [
    "PROCESS_LAUNCH", "PROCESS_OPEN", "PROCESS_TERMINATION", "PROCESS_INJECTION",
    "PROCESS_MODULE_LOAD", "PROCESS_PRIVILEGE_ESCALATION", "PROCESS_UNCATEGORIZED",
    "FILE_CREATION", "FILE_DELETION", "FILE_MODIFICATION", "FILE_READ", "FILE_OPEN",
    "FILE_COPY", "FILE_MOVE", "FILE_SYNC", "FILE_UNCATEGORIZED",
    "REGISTRY_CREATION", "REGISTRY_DELETION", "REGISTRY_MODIFICATION", "REGISTRY_UNCATEGORIZED",
    "NETWORK_CONNECTION", "NETWORK_FLOW", "NETWORK_DNS", "NETWORK_HTTP", "NETWORK_DHCP",
    "NETWORK_FTP", "NETWORK_SMTP", "NETWORK_UNCATEGORIZED",
    "USER_LOGIN", "USER_LOGOUT", "USER_CREATION", "USER_DELETION", "USER_CHANGE_PASSWORD",
    "USER_CHANGE_PERMISSIONS", "USER_RESOURCE_ACCESS", "USER_RESOURCE_CREATION",
    "USER_RESOURCE_DELETION", "USER_RESOURCE_UPDATE_CONTENT", "USER_RESOURCE_UPDATE_PERMISSIONS",
    "USER_COMMUNICATION", "USER_BADGE_IN", "USER_STATS", "USER_UNCATEGORIZED",
    "EMAIL_TRANSACTION", "EMAIL_URL_CLICK",
    "SCAN_FILE", "SCAN_HOST", "SCAN_NETWORK", "SCAN_PROCESS", "SCAN_VULN_HOST",
    "SCAN_VULN_NETWORK", "SCAN_UNCATEGORIZED",
    "SCHEDULED_TASK_CREATION", "SCHEDULED_TASK_DELETION", "SCHEDULED_TASK_ENABLE",
    "SCHEDULED_TASK_DISABLE", "SCHEDULED_TASK_MODIFICATION", "SCHEDULED_TASK_UNCATEGORIZED",
    "SERVICE_CREATION", "SERVICE_DELETION", "SERVICE_MODIFICATION", "SERVICE_START",
    "SERVICE_STOP", "SERVICE_UNCATEGORIZED",
    "SETTING_CREATION", "SETTING_DELETION", "SETTING_MODIFICATION", "SETTING_UNCATEGORIZED",
    "MUTEX_CREATION", "MUTEX_UNCATEGORIZED",
    "RESOURCE_CREATION", "RESOURCE_DELETION", "RESOURCE_PERMISSIONS_CHANGE", "RESOURCE_READ",
    "RESOURCE_WRITTEN", "RESOURCE_UNCATEGORIZED",
    "GROUP_CREATION", "GROUP_DELETION", "GROUP_MODIFICATION", "GROUP_UNCATEGORIZED",
    "STATUS_HEARTBEAT", "STATUS_STARTUP", "STATUS_SHUTDOWN", "STATUS_UPDATE",
    "SYSTEM_AUDIT_LOG_UNCATEGORIZED", "SYSTEM_AUDIT_LOG_WIPE",
    "ALLOW_STRONG_AUTHENTICATION", "ENFORCE_STRONG_AUTHENTICATION", "GENERIC_EVENT",
]

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


def udm_event_type_catalogue() -> List[str]:
    """The documented UDM metadata.event_type values to offer. The override file if present (the
    authoritative set an operator drops in), else the curated default."""
    try:
        with open(_UDM_REF_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list) and data:
            return [str(v) for v in data]
    except (OSError, ValueError):
        pass
    return list(_DEFAULT_UDM_EVENT_TYPES)


def source_catalogue(generate_dir: str) -> Dict[str, List[str]]:
    """The universe of gate-able sources to offer in the config UI, per SIEM.

    MDE: the documented Advanced Hunting tables from the base schema. SecOps: the documented UDM
    event types (override file or default), unioned with whatever the current runs emit, so the list
    is complete and nothing in use is missing."""
    mde = sorted((load_active_schema("mde") or {}).keys())
    secops: set = set(udm_event_type_catalogue())
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

"""
Mode 2 — Fallback query generation without LLM.

Extracts indicators from MITRESaw evidence data and inserts them into
SIEM query templates using the bespoke mapping files. Produces structured
Splunk SPL and MDE KQL queries directly from indicator values.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from shikari import paths


# ---------------------------------------------------------------------------
# Mapping loaders
# ---------------------------------------------------------------------------

_BESPOKE_DIR = paths.BESPOKE
_MAPPINGS_DIR = _BESPOKE_DIR / "mappings"
_SCHEMAS_DIR = _MAPPINGS_DIR / "schemas"
_SOURCES_DIR = _MAPPINGS_DIR / "sources"


def _load_json(filename: str, subdir: Path = None) -> dict:
    """Load a JSON file from the bespoke mappings directory (or a subdirectory)."""
    base = subdir if subdir is not None else _MAPPINGS_DIR
    path = base / filename
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def load_indicator_mapping() -> dict:
    return _load_json("indicatorMapping.json")


def load_data_sources() -> dict:
    return _load_json("dataSources.json", _SOURCES_DIR)


def load_splunk_schema() -> dict:
    return _load_json("schemaSplunk.json", _SCHEMAS_DIR)


def load_mde_schema() -> dict:
    return _load_json("schemaMDE.json", _SCHEMAS_DIR)


def load_log_source_categories() -> dict:
    return _load_json("logSourceCategories.json", _SOURCES_DIR)


# ---------------------------------------------------------------------------
# Evidence parsing (from MITRESaw CSV/XLSX data)
# ---------------------------------------------------------------------------

# MITRESaw evidence keys → bespoke indicator types
_EVIDENCE_TYPE_MAP = {
    "cmd": "cmd",
    "reg": "reg",
    "evt": "evt",
    "cve": "cmd",       # CVE IDs treated as searchable strings
    "ports": "port",
    "software": "sw",
    "filepath": "cmd",   # File paths searchable in command line fields
}


def parse_evidence(evidence_json: str) -> Dict[str, List[str]]:
    """Parse MITRESaw evidence JSON into indicator type → values mapping.

    Args:
        evidence_json: JSON string from the evidence column.

    Returns:
        Dict mapping bespoke indicator types to lists of indicator values.
    """
    if not evidence_json or evidence_json == "{}":
        return {}

    try:
        evidence = json.loads(evidence_json) if isinstance(evidence_json, str) else evidence_json
    except (json.JSONDecodeError, TypeError):
        return {}

    indicators = {}
    for ev_key, values in evidence.items():
        if not values:
            continue

        bespoke_type = _EVIDENCE_TYPE_MAP.get(ev_key)
        if not bespoke_type:
            continue

        if bespoke_type not in indicators:
            indicators[bespoke_type] = []

        for val in values:
            if isinstance(val, dict):
                # CVE entries: {"CVE-ID": "description"}
                indicators[bespoke_type].extend(val.keys())
            elif isinstance(val, str) and len(val.strip()) >= 3:
                indicators[bespoke_type].append(val.strip())

    return indicators


# ---------------------------------------------------------------------------
# Splunk query builder (Mode 2)
# ---------------------------------------------------------------------------

def _escape_splunk(value: str) -> str:
    """Escape a value for use in Splunk SPL."""
    # Escape backslashes and double quotes
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_splunk_query(
    index_name: str,
    field_values: Dict[str, List[str]],
    technique_name: str = "",
    technique_id: str = "",
) -> str:
    """Build a Splunk SPL query from field-value mappings.

    Args:
        index_name: Splunk index name (e.g. "windows_events").
        field_values: Dict of field_name → list of values to search.
        technique_name: For the technique eval at the end.
        technique_id: For reference comment.

    Returns:
        Complete SPL query string.
    """
    if not field_values:
        return ""

    # Build search clauses
    clauses = []
    for field, values in field_values.items():
        if not values:
            continue
        escaped = [_escape_splunk(v) for v in values[:20]]  # cap at 20 values
        if len(escaped) == 1:
            clauses.append(f'{field}="*{escaped[0]}*"')
        else:
            or_terms = " OR ".join(f'{field}="*{v}*"' for v in escaped)
            clauses.append(f"({or_terms})")

    if not clauses:
        return ""

    search_clause = " OR ".join(clauses)

    # Build the full query
    lines = [
        f'index="{index_name}" earliest=-3d@d ({search_clause})',
        '  NOT Tanium AND NOT "sb-sim" AND NOT sbsimulation',
    ]

    if technique_name:
        clean_name = technique_name.replace('"', '\\"')
        lines.append(f'| eval technique="{clean_name}"')

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MDE query builder (Mode 2)
# ---------------------------------------------------------------------------

def _escape_kql(value: str) -> str:
    """Escape a value for use in KQL."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")


def build_mde_query(
    table_name: str,
    field_values: Dict[str, List[str]],
    mde_schema: dict,
    technique_name: str = "",
) -> str:
    """Build an MDE KQL query from field-value mappings.

    Args:
        table_name: MDE table name (e.g. "DeviceProcessEvents").
        field_values: Dict of field_name → list of values to search.
        mde_schema: Schema dict with table → summarize fields.
        technique_name: For extend clause.

    Returns:
        Complete KQL query string.
    """
    if not field_values:
        return ""

    # Build where clauses
    where_parts = []
    for field, values in field_values.items():
        if not values:
            continue
        escaped = [_escape_kql(v) for v in values[:20]]
        conditions = " or ".join(f'{field} contains "{v}"' for v in escaped)
        where_parts.append(f"({conditions})")

    if not where_parts:
        return ""

    where_clause = " or ".join(where_parts)

    # Get summarize fields from schema
    summarize = mde_schema.get(table_name, "")

    lines = [
        table_name,
        f"| where {where_clause}",
    ]

    if summarize:
        lines.append(summarize.strip())

    if technique_name:
        clean_name = technique_name.replace('"', '\\"')
        lines.append(f'| extend technique = "{clean_name}"')

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main Mode 2 entry point
# ---------------------------------------------------------------------------

def generate_fallback_queries(
    technique_id: str,
    technique_name: str,
    tactic: str,
    evidence_json: str,
    platforms: List[str],
    detectable_via: str = "",
) -> List[Dict]:
    """Generate detection queries without LLM using bespoke mappings.

    This is Mode 2 (fallback). It maps MITRESaw evidence indicators to
    SIEM field names using the bespoke mapping files and builds structured
    queries.

    Args:
        technique_id: ATT&CK technique ID (e.g. "T1059.001").
        technique_name: Technique name.
        tactic: ATT&CK tactic.
        evidence_json: JSON string from MITRESaw evidence column.
        platforms: List of platforms (e.g. ["Windows", "Linux"]).
        detectable_via: MITRESaw log source string.

    Returns:
        List of dicts, each with keys:
        - platform: "Splunk" or "MDE"
        - data_source: index or table name
        - query: the generated query string
        - indicator_type: which evidence type drove this query
        - indicators_used: list of indicator values used
    """
    # Parse evidence into indicator types
    indicators = parse_evidence(evidence_json)
    if not indicators:
        return []
    return _queries_from_indicators(indicators, technique_id, technique_name, tactic)


def _queries_from_indicators(
    indicators: Dict[str, List[str]],
    technique_id: str,
    technique_name: str,
    tactic: str,
) -> List[Dict]:
    """Build Splunk + MDE queries from an {indicator type → values} mapping, via the bespoke
    indicator→schema mapping. Shared by the MITRESaw-evidence path and the telemetry-grounded path (#27)."""
    indicator_mapping = load_indicator_mapping()
    mde_schema = load_mde_schema()

    queries = []
    for ind_type, ind_values in indicators.items():
        if not ind_values or ind_type not in indicator_mapping:
            continue
        mapping = indicator_mapping[ind_type]
        if not isinstance(mapping, dict):
            continue

        for index_name, fields in (mapping.get("Splunk") or {}).items():
            field_values = {field: ind_values for field in fields}
            query = build_splunk_query(index_name, field_values, technique_name, technique_id)
            if query:
                queries.append({"platform": "Splunk", "data_source": index_name, "query": query,
                                "indicator_type": ind_type, "indicators_used": ind_values[:10],
                                "technique_id": technique_id, "technique_name": technique_name, "tactic": tactic})

        for table_name, fields in (mapping.get("MDE") or {}).items():
            field_values = {field: ind_values for field in fields}
            query = build_mde_query(table_name, field_values, mde_schema, technique_name)
            if query:
                queries.append({"platform": "MDE", "data_source": table_name, "query": query,
                                "indicator_type": ind_type, "indicators_used": ind_values[:10],
                                "technique_id": technique_id, "technique_name": technique_name, "tactic": tactic})

    return queries


# ---------------------------------------------------------------------------
# Telemetry-grounded generation (#27): queries from a recording's observed events
# ---------------------------------------------------------------------------

# A recorded event field (shikari.telemetry.datasets.FIELDS group) → the bespoke indicator type whose
# schema mapping fits it. "file" images map to the software (sw) indicators; "other" (service, account,
# task names) to generic events (evt).
_GROUP_TO_INDICATOR = {"cmd": "cmd", "file": "sw", "reg": "reg", "network": "network", "other": "evt"}


def generate_from_telemetry(
    values: Dict[str, Dict[str, List[str]]],
    technique_id: str = "",
    technique_name: str = "",
    tactic: str = "",
    max_per_type: int = 40,
) -> List[Dict]:
    """Generate detection queries grounded in a recording's own telemetry, not MITRESaw evidence (#27).

    `values` is a recording's summarised events: {event type: {field: [distinct values]}} (as
    shikari.telemetry.datasets.values() stores them). Each field is bucketed to a bespoke indicator type
    by the same field groups the recordings use, then the shared builder produces Splunk + MDE queries.
    This lets Shikari detect a novel/undocumented behaviour that has no public procedure example.
    """
    from shikari.telemetry.datasets import FIELDS

    field_group = {field: group for group, fields in FIELDS.items() for field in fields}
    indicators: Dict[str, List[str]] = {}
    for _etype, fields in (values or {}).items():
        for field, vals in (fields or {}).items():
            ind_type = _GROUP_TO_INDICATOR.get(field_group.get(field, "other"), "evt")
            bucket = indicators.setdefault(ind_type, [])
            for v in vals:
                v = (v or "").strip()
                if len(v) >= 3 and v not in bucket and len(bucket) < max_per_type:
                    bucket.append(v)

    indicators = {k: v for k, v in indicators.items() if v}
    if not indicators:
        return []
    return _queries_from_indicators(indicators, technique_id, technique_name, tactic)

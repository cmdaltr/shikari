"""
Per-environment SIEM schema overrides (#12).

Each SIEM has a base field/table schema under ``bespoke/mappings/schemas/`` and an optional
per-tenant override ``schema<SIEM>_custom.json`` beside it. ``collate.py`` and ``queries.py``
already prefer the Splunk and MDE overrides; this module is the one place that resolves the active
file for *every* SIEM, so the SecOps and Elastic builders honour an override too rather than always
reading the base. With no override present the base is returned, so behaviour is unchanged until an
admin saves one. The override is organisation-specific and lives gitignored in ``bespoke/``.
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional

_SCHEMAS_DIR = Path(__file__).resolve().parent.parent.parent / "bespoke" / "mappings" / "schemas"

# Canonical SIEM key -> base schema filename.
_BASE = {
    "splunk": "schemaSplunk.json",
    "mde": "schemaMDE.json",
    "secops": "schemaGoogleSecOps.json",
    "elastic": "schemaElastic.json",
}
# The many spellings the rest of the code uses for each SIEM.
_ALIAS = {
    "googlesecops": "secops", "google_secops": "secops", "google secops": "secops",
    "chronicle": "secops", "microsoftthreatprotection": "mde", "defender": "mde",
    "microsoft defender": "mde", "mdethreatprotection": "mde",
}


def _key(siem: str) -> str:
    s = (siem or "").strip().lower()
    return _ALIAS.get(s, s)


def base_filename(siem: str) -> str:
    """The base schema filename for a SIEM, raising KeyError for an unknown one."""
    return _BASE[_key(siem)]


def custom_filename(siem: str) -> str:
    """The override filename (``schema<SIEM>_custom.json``) for a SIEM."""
    return base_filename(siem).replace(".json", "_custom.json")


def active_schema_path(siem: str, schemas_dir: Optional[os.PathLike] = None) -> Path:
    """The override file if it exists, else the base schema file."""
    d = Path(schemas_dir) if schemas_dir else _SCHEMAS_DIR
    custom = d / custom_filename(siem)
    return custom if custom.exists() else d / base_filename(siem)


def has_override(siem: str, schemas_dir: Optional[os.PathLike] = None) -> bool:
    """True when a per-tenant override is in place for this SIEM."""
    d = Path(schemas_dir) if schemas_dir else _SCHEMAS_DIR
    return (d / custom_filename(siem)).exists()


def load_active_schema(siem: str, schemas_dir: Optional[os.PathLike] = None) -> Dict:
    """Parse the active schema (override or base). Returns {} if the file is missing or invalid."""
    try:
        with open(active_schema_path(siem, schemas_dir), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, KeyError):
        return {}

"""
archer.mitre.procedures
=======================

Standalone module for extracting complete group-technique mappings from
MITRE ATT&CK data using all three official attribution paths:

  PATH 1 — Direct:     intrusion-set --[uses]--> attack-pattern
  PATH 2 — Software:   intrusion-set --[uses]--> tool/malware --[uses]--> attack-pattern
  PATH 3 — Campaign:   campaign --[attributed-to]--> intrusion-set
                       campaign --[uses]--> attack-pattern

Can be used three ways:

  1. Imported by Archer internals:
       from archer.mitre.procedures import get_group_techniques, build_procedures_csv

  2. Run as a module (refreshes data/mitre_procedures.csv):
       python -m archer.mitre.procedures

  3. Called from the standalone CLI script:
       python scripts/data/extract_mitre_procedures.py

MITRE-official sources only:
  - STIX bundle:     https://github.com/mitre-attack/attack-stix-data
  - XLSX (cross-ref): https://attack.mitre.org/docs/attack-excel-files/...
"""

from __future__ import annotations

import csv
import json
import logging
import os
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Source URLs
# ---------------------------------------------------------------------------

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)

XLSX_URL = (
    "https://attack.mitre.org/docs/attack-excel-files/v18.1"
    "/enterprise-attack/enterprise-attack-v18.1-relationships.xlsx"
)

# Default output path (relative to project root)
_DEFAULT_CSV = Path(__file__).parent.parent.parent / "data" / "mitre_procedures.csv"

# CSV column order
FIELDNAMES: List[str] = [
    "technique_id",
    "technique_name",
    "tactic",
    "group_id",
    "group_name",
    "procedure_example",
    "group_description",
    "technique_description",
    "attribution_type",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _attack_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _clean(text: Optional[str]) -> str:
    if not text:
        return ""
    return text.replace("\n", " ").replace("\r", " ").strip()


def _tactics(obj: dict) -> List[str]:
    out = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            name = phase.get("phase_name", "").replace("-", " ").title()
            if name:
                out.append(name)
    return out


def _build_indexes(
    objects: List[dict],
) -> Tuple[Dict, Dict, Dict, Dict]:
    """Return (groups, techniques, software, campaigns) dicts keyed by STIX id."""
    groups: Dict[str, dict] = {}
    techniques: Dict[str, dict] = {}
    software: Dict[str, dict] = {}
    campaigns: Dict[str, dict] = {}

    for obj in objects:
        oid = obj.get("id", "")
        t = obj.get("type", "")
        if t == "intrusion-set" and _attack_id(obj).startswith("G"):
            groups[oid] = obj
        elif t == "attack-pattern":
            techniques[oid] = obj
        elif t in ("tool", "malware"):
            software[oid] = obj
        elif t == "campaign":
            campaigns[oid] = obj

    return groups, techniques, software, campaigns


# ---------------------------------------------------------------------------
# Public: fetch STIX
# ---------------------------------------------------------------------------

def fetch_stix(url: str = STIX_URL, timeout: int = 120) -> dict:
    """
    Download and return the raw STIX bundle JSON dict.
    Raises requests.HTTPError on non-200 responses.
    """
    logger.info("Downloading STIX bundle from %s", url)
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    version = next(
        (o.get("x_mitre_version") for o in data.get("objects", [])
         if o.get("type") == "x-mitre-collection"),
        "unknown",
    )
    logger.info("Downloaded ATT&CK v%s (%d objects)", version, len(data.get("objects", [])))
    return data


# ---------------------------------------------------------------------------
# Public: technique extraction
# ---------------------------------------------------------------------------

def get_group_techniques(
    bundle: dict,
    group_id_or_name: str,
) -> List[Dict]:
    """
    Return all technique records for a group, following all three attribution paths.

    Args:
        bundle: Raw STIX bundle dict (from fetch_stix or json.load).
        group_id_or_name: ATT&CK group ID (e.g. "G1015") or group name
                          (e.g. "Scattered Spider"). Case-insensitive.

    Returns:
        List of dicts with keys matching FIELDNAMES. Each entry represents
        one (technique, tactic, attribution_path) combination for the group.
        Multiple rows per technique are emitted when a technique spans
        multiple tactics.
    """
    objects = bundle.get("objects", [])
    groups, techniques, software, campaigns = _build_indexes(objects)

    # Resolve group STIX ID
    target_stix_id = _resolve_group(groups, group_id_or_name)
    if not target_stix_id:
        raise ValueError(f"Group not found in ATT&CK bundle: {group_id_or_name!r}")

    rows: List[dict] = []
    seen: Set[Tuple] = set()
    group_obj = groups[target_stix_id]

    _walk_path1(objects, {target_stix_id: group_obj}, techniques, rows, seen)
    _walk_path2(objects, {target_stix_id: group_obj}, techniques, software, rows, seen)
    _walk_path3(objects, {target_stix_id: group_obj}, techniques, campaigns, rows, seen)

    return rows


def get_all_procedures(bundle: dict) -> List[Dict]:
    """
    Return all group-technique rows for every group in the bundle.
    Follows all three attribution paths. Used to build mitre_procedures.csv.
    """
    objects = bundle.get("objects", [])
    groups, techniques, software, campaigns = _build_indexes(objects)

    rows: List[dict] = []
    seen: Set[Tuple] = set()

    _walk_path1(objects, groups, techniques, rows, seen)
    _walk_path2(objects, groups, techniques, software, rows, seen)
    _walk_path3(objects, groups, techniques, campaigns, rows, seen)

    return rows


def get_group_coverage(group: str, generate_dir) -> Optional[Dict]:
    """
    Load mitre_procedures.csv, filter by group name or ATT&CK ID, and check
    which techniques already have detection YAML files in generate_dir.

    Args:
        group: Group name (e.g. "Scattered Spider") or ATT&CK ID (e.g. "G1015")
        generate_dir: Path to the directory containing generated detection YAMLs

    Returns:
        Dict with keys: group_name, group_id, total, covered_count, gap_count,
        covered (list), gaps (list). Returns None if group not found in CSV.
    """
    import csv as _csv
    import glob as _glob

    csv_path = _DEFAULT_CSV
    if not csv_path.exists():
        return None

    rows = []
    group_lower = group.lower()
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = _csv.DictReader(f)
        for row in reader:
            if (row.get("group_id", "").upper() == group.upper() or
                    row.get("group_name", "").lower() == group_lower):
                rows.append(row)

    if not rows:
        return None

    group_name = rows[0]["group_name"]
    group_id = rows[0]["group_id"]

    # Deduplicate by technique_id — keep first occurrence per technique
    seen: Dict[str, dict] = {}
    for row in rows:
        tid = row["technique_id"]
        if tid not in seen:
            seen[tid] = {
                "technique_id": tid,
                "technique_name": row["technique_name"],
                "tactic": row["tactic"],
                "attribution_type": row["attribution_type"],
                "covered": False,
            }

    # Check coverage: any YAML whose filename starts with the technique ID
    generate_path = Path(str(generate_dir))
    for tid, data in seen.items():
        safe_id = tid.replace(".", "-")
        pattern = str(generate_path / f"{safe_id}*.yaml")
        data["covered"] = bool(_glob.glob(pattern))

    techniques = list(seen.values())
    covered = [t for t in techniques if t["covered"]]
    gaps = [t for t in techniques if not t["covered"]]

    return {
        "group_name": group_name,
        "group_id": group_id,
        "total": len(techniques),
        "covered_count": len(covered),
        "gap_count": len(gaps),
        "covered": covered,
        "gaps": gaps,
    }


def _resolve_group(groups: Dict[str, dict], identifier: str) -> Optional[str]:
    """Resolve an ATT&CK ID (G1015) or name to a STIX object ID."""
    ident_lower = identifier.lower()
    for stix_id, obj in groups.items():
        if _attack_id(obj).lower() == ident_lower:
            return stix_id
        if obj.get("name", "").lower() == ident_lower:
            return stix_id
        aliases = obj.get("aliases", [])
        if any(a.lower() == ident_lower for a in aliases):
            return stix_id
    return None


def _emit(
    rows: List[dict],
    seen: Set[Tuple],
    group_obj: dict,
    tech_obj: dict,
    attribution_type: str,
    description: str,
) -> None:
    group_id = _attack_id(group_obj)
    tech_id = _attack_id(tech_obj)
    if not group_id or not tech_id:
        return

    tactic_list = _tactics(tech_obj) or [""]
    for tactic in tactic_list:
        key = (tech_id, tactic, group_id, attribution_type)
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "technique_id": tech_id,
            "technique_name": tech_obj.get("name", ""),
            "tactic": tactic,
            "group_id": group_id,
            "group_name": group_obj.get("name", ""),
            "procedure_example": _clean(description),
            "group_description": _clean(group_obj.get("description", "")),
            "technique_description": _clean(tech_obj.get("description", "")),
            "attribution_type": attribution_type,
        })


def _walk_path1(objects, groups, techniques, rows, seen):
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
        if src in groups and tgt in techniques:
            _emit(rows, seen, groups[src], techniques[tgt], "direct",
                  obj.get("description", ""))


def _walk_path2(objects, groups, techniques, software, rows, seen):
    sw_to_techs: Dict[str, List[Tuple[str, str]]] = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
        if src in software and tgt in techniques:
            sw_to_techs.setdefault(src, []).append((tgt, obj.get("description", "")))

    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
        if src in groups and tgt in software:
            sw_name = software[tgt].get("name", tgt)
            grp_desc = obj.get("description", "")
            for tech_ref, tech_desc in sw_to_techs.get(tgt, []):
                combined = " ".join(filter(None, [grp_desc, tech_desc]))
                _emit(rows, seen, groups[src], techniques[tech_ref],
                      f"via_software:{sw_name}", combined)


def _walk_path3(objects, groups, techniques, campaigns, rows, seen):
    camp_to_groups: Dict[str, Set[str]] = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "attributed-to":
            continue
        src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
        if src in campaigns and tgt in groups:
            camp_to_groups.setdefault(src, set()).add(tgt)

    camp_to_techs: Dict[str, List[Tuple[str, str]]] = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
        if src in campaigns and tgt in techniques:
            camp_to_techs.setdefault(src, []).append((tgt, obj.get("description", "")))

    for camp_id, grp_ids in camp_to_groups.items():
        camp_name = campaigns[camp_id].get("name", camp_id)
        for tech_ref, desc in camp_to_techs.get(camp_id, []):
            for grp_id in grp_ids:
                _emit(rows, seen, groups[grp_id], techniques[tech_ref],
                      f"via_campaign:{camp_name}", desc)


# ---------------------------------------------------------------------------
# Public: XLSX cross-reference
# ---------------------------------------------------------------------------

def fetch_xlsx_relationships(
    url: str = XLSX_URL,
    timeout: int = 120,
) -> Optional[Set[Tuple[str, str]]]:
    """
    Download the ATT&CK relationships XLSX and return a set of
    (source_attack_id, target_attack_id) pairs for cross-validation.
    Returns None if openpyxl is not installed or download fails.
    """
    try:
        import io
        import openpyxl
    except ImportError:
        logger.info("openpyxl not installed — XLSX cross-reference skipped")
        return None

    logger.info("Downloading XLSX relationships from %s", url)
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("XLSX download failed (%s) — skipping cross-reference", exc)
        return None

    wb = openpyxl.load_workbook(io.BytesIO(resp.content), read_only=True, data_only=True)
    ws = next(
        (wb[n] for n in wb.sheetnames if "relation" in n.lower()),
        wb.active,
    )
    header = None
    pairs: Set[Tuple[str, str]] = set()
    for row in ws.iter_rows(values_only=True):
        if header is None:
            header = [str(c).lower().strip() if c else "" for c in row]
            continue
        rd = dict(zip(header, row))
        src = str(rd.get("source id", "") or "").strip()
        tgt = str(rd.get("target id", "") or "").strip()
        if src and tgt:
            pairs.add((src, tgt))

    logger.info("Loaded %d relationship pairs from XLSX", len(pairs))
    return pairs


def cross_reference(
    rows: List[dict],
    xlsx_pairs: Optional[Set[Tuple[str, str]]],
) -> List[Tuple[str, str]]:
    """
    Compare extracted rows against XLSX pairs.
    Returns list of (group_id, technique_id) pairs found in XLSX but not in rows.
    """
    if xlsx_pairs is None:
        return []
    stix_pairs = {(r["group_id"], r["technique_id"]) for r in rows}
    return sorted(
        (src, tgt)
        for src, tgt in xlsx_pairs
        if src.startswith("G") and tgt.startswith("T")
        and (src, tgt) not in stix_pairs
    )


# ---------------------------------------------------------------------------
# Public: CSV builder
# ---------------------------------------------------------------------------

def build_procedures_csv(
    output_path: Optional[Path] = None,
    stix_url: str = STIX_URL,
    xlsx_url: str = XLSX_URL,
    validate: bool = True,
) -> Path:
    """
    Download the latest ATT&CK STIX bundle, extract all group-technique
    procedures via all three attribution paths, and write to CSV.

    Args:
        output_path: Where to write the CSV. Defaults to data/mitre_procedures.csv.
        stix_url:    STIX bundle URL (defaults to canonical mitre-attack/attack-stix-data).
        xlsx_url:    XLSX relationships URL for cross-validation.
        validate:    If True, download XLSX and report any gaps.

    Returns:
        Path to the written CSV file.
    """
    if output_path is None:
        output_path = _DEFAULT_CSV

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    bundle = fetch_stix(stix_url)
    rows = get_all_procedures(bundle)

    if validate:
        xlsx_pairs = fetch_xlsx_relationships(xlsx_url)
        gaps = cross_reference(rows, xlsx_pairs)
        if gaps:
            logger.warning(
                "XLSX cross-reference: %d pairs in XLSX not found in STIX: %s",
                len(gaps), gaps[:5],
            )
        else:
            logger.info("XLSX cross-reference: all pairs present in STIX ✓")

    sorted_rows = sorted(rows, key=lambda r: (r["technique_id"], r["tactic"], r["group_id"]))
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(sorted_rows)

    logger.info("Saved %d rows to %s", len(sorted_rows), output_path)
    return output_path


# ---------------------------------------------------------------------------
# CLI entry point  (python -m archer.mitre.procedures)
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(
        description="Rebuild data/mitre_procedures.csv from MITRE ATT&CK STIX data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m archer.mitre.procedures
  python -m archer.mitre.procedures --output /tmp/procedures.csv
  python -m archer.mitre.procedures --stix-url https://...custom.../enterprise-attack.json
  python -m archer.mitre.procedures --no-validate
        """,
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help=f"Output CSV path (default: {_DEFAULT_CSV})",
    )
    parser.add_argument(
        "--stix-url",
        default=STIX_URL,
        help="STIX bundle URL (default: canonical mitre-attack/attack-stix-data)",
    )
    parser.add_argument(
        "--xlsx-url",
        default=XLSX_URL,
        help="XLSX relationships URL for cross-validation",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip XLSX cross-reference validation",
    )
    parser.add_argument(
        "--group",
        help="Show technique count for a specific group after build (e.g. G1015)",
    )
    args = parser.parse_args()

    out = build_procedures_csv(
        output_path=args.output,
        stix_url=args.stix_url,
        xlsx_url=args.xlsx_url,
        validate=not args.no_validate,
    )

    print(f"\n✓ Written to {out}")

    if args.group:
        bundle = fetch_stix(args.stix_url)
        rows = get_group_techniques(bundle, args.group)
        unique = len({r["technique_id"] for r in rows})
        print(f"  {args.group}: {unique} unique techniques")


if __name__ == "__main__":
    _cli()

"""
archer.mitre.procedures
=======================

Adapter module that delegates MITRE ATT&CK data extraction to MITRESaw
(included as a git submodule at ./MITRESaw/) and provides the interface
that Archer internals expect.

Data generation (CSV / XLSX):
    Runs MITRESaw CLI:  python MITRESaw/MITRESaw.py -d -E -R
    Output: mitre_procedures.csv + mitre_procedures.xlsx

Real-time STIX operations (used by app.py hunter/export routes):
    _build_indexes, _resolve_group, _walk_path1/2/3, _attack_id, _clean
    These work on the in-memory STIX bundle (app.state.bundle) and are
    retained here because MITRESaw's architecture uses MitreAttackData
    rather than raw STIX dicts.
"""

from __future__ import annotations

import csv
import glob as _glob
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Source URLs (kept for fetch_stix which is used by app.py at startup)
# ---------------------------------------------------------------------------

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)

XLSX_URL = (
    "https://attack.mitre.org/docs/attack-excel-files/v18.1"
    "/enterprise-attack/enterprise-attack-v18.1-relationships.xlsx"
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).parent.parent.parent
_DEFAULT_CSV = _PROJECT_ROOT / "data" / "mitre_procedures.csv"
_DEFAULT_XLSX = _PROJECT_ROOT / "data" / "mitre_procedures.xlsx"
_MITRESAW_DIR = _PROJECT_ROOT / "MITRESaw"

# ---------------------------------------------------------------------------
# MITRESaw CSV column order (12 columns)
# ---------------------------------------------------------------------------

FIELDNAMES: List[str] = [
    "group_sw_id",
    "group_sw_name",
    "group_sw_description",
    "technique_id",
    "technique_name",
    "technique_description",
    "tactic",
    "platforms",
    "framework",
    "procedure_example",
    "evidence",
    "detectable_via",
]

# Mapping from MITRESaw column names to Archer's legacy names (for callers
# that reference the old schema). Used by get_group_coverage().
_LEGACY_MAP = {
    "group_sw_id": "group_id",
    "group_sw_name": "group_name",
}


# ---------------------------------------------------------------------------
# Internal helpers (used by app.py for real-time STIX operations)
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
        group_name = group_obj.get("name", "")
        group_desc = _clean(group_obj.get("description", ""))
        platforms = ", ".join(tech_obj.get("x_mitre_platforms", []))
        rows.append({
            # MITRESaw column names (FIELDNAMES order)
            "group_sw_id": group_id,
            "group_sw_name": group_name,
            "group_sw_description": group_desc,
            "technique_id": tech_id,
            "technique_name": tech_obj.get("name", ""),
            "technique_description": _clean(tech_obj.get("description", "")),
            "tactic": tactic,
            "platforms": platforms,
            "framework": "Enterprise",
            "procedure_example": _clean(description),
            "evidence": "{}",
            "detectable_via": "",
            # Extra fields for in-memory callers
            "attribution_type": attribution_type,
            # Legacy aliases
            "group_id": group_id,
            "group_name": group_name,
            "group_description": group_desc,
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
# Public: fetch STIX (used by app.py at startup for in-memory bundle)
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
# Cache staleness helpers
# ---------------------------------------------------------------------------

CACHE_TTL_SECONDS: int = 7 * 24 * 3600  # 7 days


def is_cache_stale(csv_path: Optional[Path] = None) -> bool:
    """
    Return True if the MITRESaw CSV cache is missing or older than 7 days.

    The cache is the mitre_procedures.csv in Archer's data directory —
    the file written by run_mitresaw() / run_mitresaw_detection().
    """
    path = Path(csv_path) if csv_path is not None else _DEFAULT_CSV
    if not path.exists():
        return True
    age = time.time() - path.stat().st_mtime
    return age > CACHE_TTL_SECONDS


# ---------------------------------------------------------------------------
# Public: run MITRESaw with detection flags (used by detection generation)
# ---------------------------------------------------------------------------

def run_mitresaw_detection(
    output_csv: Optional[Path] = None,
    output_xlsx: Optional[Path] = None,
    force: bool = False,
) -> Tuple[Path, Optional[Path]]:
    """
    Run MITRESaw to produce the detection-enriched CSV and evidence XLSX.

    Normal run  (cache is fresh, ≤7 days):
        MITRESaw.py -d -E -q
        Equivalent to the user's shorthand: -DEC

    Force/stale run (cache is >7 days or force=True):
        MITRESaw.py -d -E -F -q
        Equivalent to the user's shorthand: -DECF --clear-cache
        (-F forces a fresh STIX download; --clear-cache is reserved for
        future MITRESaw versions and is omitted here)

    Flags used:
        -d   --default          Express CSV with key detection columns
        -E   --evidence-report  Generate styled XLSX evidence report
        -F   --fetch            Force fresh ATT&CK STIX download
        -q   --quiet            Suppress per-identifier console output

    Returns (csv_path, xlsx_path). xlsx_path may be None if XLSX was not produced.
    """
    if output_csv is None:
        output_csv = _DEFAULT_CSV
    if output_xlsx is None:
        output_xlsx = _DEFAULT_XLSX

    output_csv = Path(output_csv)
    output_xlsx = Path(output_xlsx)
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    mitresaw_script = _MITRESAW_DIR / "MITRESaw.py"
    if not mitresaw_script.exists():
        raise FileNotFoundError(
            f"MITRESaw not found at {mitresaw_script}. "
            "Run: git submodule update --init --recursive"
        )

    flags = ["-d", "-E", "-q"]
    if force:
        flags.append("-F")

    logger.info(
        "Running MITRESaw detection extraction: %s %s",
        mitresaw_script,
        " ".join(flags),
    )

    result = subprocess.run(
        [sys.executable, str(mitresaw_script)] + flags,
        cwd=str(_MITRESAW_DIR),
        capture_output=True,
        text=True,
        timeout=600,
    )

    if result.returncode != 0:
        logger.error(
            "MITRESaw detection run failed (exit %d):\n%s",
            result.returncode,
            result.stderr,
        )
        raise RuntimeError(
            f"MITRESaw exited with code {result.returncode}: {result.stderr}"
        )

    logger.info(
        "MITRESaw output:\n%s", result.stdout[-500:] if result.stdout else "(empty)"
    )

    # Locate output — MITRESaw writes to ./YYYY-MM-DD/ under its own directory
    today = datetime.now().strftime("%Y-%m-%d")
    mitresaw_date_dir = _MITRESAW_DIR / today

    src_csv = mitresaw_date_dir / "mitre_procedures.csv"
    src_xlsx = mitresaw_date_dir / "mitre_procedures.xlsx"

    if not src_csv.exists():
        candidates = list(_MITRESAW_DIR.glob("*/mitre_procedures.csv"))
        if candidates:
            candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            src_csv = candidates[0]
            src_xlsx = src_csv.parent / "mitre_procedures.xlsx"
        else:
            raise FileNotFoundError(
                f"MITRESaw did not produce mitre_procedures.csv. "
                f"Looked in {mitresaw_date_dir}. stdout: {result.stdout[-200:]}"
            )

    shutil.copy2(str(src_csv), str(output_csv))
    logger.info("Copied MITRESaw detection CSV to %s", output_csv)

    xlsx_result: Optional[Path] = None
    if src_xlsx.exists():
        shutil.copy2(str(src_xlsx), str(output_xlsx))
        logger.info("Copied MITRESaw evidence XLSX to %s", output_xlsx)
        xlsx_result = output_xlsx

    return output_csv, xlsx_result


# ---------------------------------------------------------------------------
# Public: run MITRESaw to generate CSV + XLSX
# ---------------------------------------------------------------------------

def run_mitresaw(
    output_csv: Optional[Path] = None,
    output_xlsx: Optional[Path] = None,
) -> Tuple[Path, Optional[Path]]:
    """
    Run MITRESaw CLI (./MITRESaw.py -d -E -R) and copy the output files
    to Archer's data directory.

    Args:
        output_csv:  Destination for mitre_procedures.csv (default: data/mitre_procedures.csv)
        output_xlsx: Destination for mitre_procedures.xlsx (default: data/mitre_procedures.xlsx)

    Returns:
        Tuple of (csv_path, xlsx_path). xlsx_path may be None if generation failed.
    """
    if output_csv is None:
        output_csv = _DEFAULT_CSV
    if output_xlsx is None:
        output_xlsx = _DEFAULT_XLSX

    output_csv = Path(output_csv)
    output_xlsx = Path(output_xlsx)
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    mitresaw_script = _MITRESAW_DIR / "MITRESaw.py"
    if not mitresaw_script.exists():
        raise FileNotFoundError(
            f"MITRESaw not found at {mitresaw_script}. "
            "Run: git submodule update --init --recursive"
        )

    logger.info("Running MITRESaw: %s -d -E -R", mitresaw_script)

    result = subprocess.run(
        [sys.executable, str(mitresaw_script), "-d", "-E", "-R", "-q"],
        cwd=str(_MITRESAW_DIR),
        capture_output=True,
        text=True,
        timeout=600,
    )

    if result.returncode != 0:
        logger.error("MITRESaw failed (exit %d):\n%s", result.returncode, result.stderr)
        raise RuntimeError(f"MITRESaw exited with code {result.returncode}: {result.stderr}")

    logger.info("MITRESaw output:\n%s", result.stdout[-500:] if result.stdout else "(empty)")

    # Find the output directory: MITRESaw creates ./YYYY-MM-DD/
    today = datetime.now().strftime("%Y-%m-%d")
    mitresaw_date_dir = _MITRESAW_DIR / today

    # MITRESaw with -d -E puts mitre_procedures.csv and .xlsx in the date dir
    src_csv = mitresaw_date_dir / "mitre_procedures.csv"
    src_xlsx = mitresaw_date_dir / "mitre_procedures.xlsx"

    if not src_csv.exists():
        # Fallback: search for any mitre_procedures.csv under MITRESaw/
        candidates = list(_MITRESAW_DIR.glob("*/mitre_procedures.csv"))
        if candidates:
            candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            src_csv = candidates[0]
            src_xlsx = src_csv.parent / "mitre_procedures.xlsx"
        else:
            raise FileNotFoundError(
                f"MITRESaw did not produce mitre_procedures.csv. "
                f"Looked in {mitresaw_date_dir} and searched {_MITRESAW_DIR}/*/. "
                f"stdout: {result.stdout[-200:]}"
            )

    # Copy to Archer's data directory
    shutil.copy2(str(src_csv), str(output_csv))
    logger.info("Copied MITRESaw CSV to %s", output_csv)

    xlsx_result = None
    if src_xlsx.exists():
        shutil.copy2(str(src_xlsx), str(output_xlsx))
        logger.info("Copied MITRESaw XLSX to %s", output_xlsx)
        xlsx_result = output_xlsx

    return output_csv, xlsx_result


def build_procedures_csv(
    output_path: Optional[Path] = None,
    stix_url: str = STIX_URL,
    xlsx_url: str = XLSX_URL,
    validate: bool = True,
) -> Path:
    """
    Generate mitre_procedures.csv by running MITRESaw.

    This replaces the previous implementation that duplicated MITRESaw's
    STIX extraction logic. The stix_url, xlsx_url, and validate parameters
    are accepted for backward compatibility but are not used — MITRESaw
    handles its own STIX fetching and validation.

    Args:
        output_path: Where to write the CSV. Defaults to data/mitre_procedures.csv.
        stix_url:    Ignored (kept for API compatibility).
        xlsx_url:    Ignored (kept for API compatibility).
        validate:    Ignored (kept for API compatibility).

    Returns:
        Path to the written CSV file.
    """
    csv_path, _ = run_mitresaw(output_csv=output_path)
    return csv_path


# ---------------------------------------------------------------------------
# Public: coverage check (reads MITRESaw's CSV output)
# ---------------------------------------------------------------------------

_TECHNIQUE_LINE = re.compile(r"^(?:technique_id:|\s*-)\s*['\"]?(T\d{4}(?:\.\d{3})?)\b", re.M)


def _detected_technique_ids(generate_path: Path) -> set:
    ids = set()
    for path in _glob.glob(str(generate_path / "*.yaml")):
        try:
            with open(path, encoding="utf-8") as fh:
                head = fh.read(4000)  # technique_id/techniques sit near the top
        except OSError:
            continue
        ids.update(_TECHNIQUE_LINE.findall(head))
    return ids


def get_group_coverage(group: str, generate_dir) -> Optional[Dict]:
    """
    Load mitre_procedures.csv (generated by MITRESaw), filter by group name
    or ATT&CK ID, and check which techniques already have detection YAML
    files in generate_dir.

    Args:
        group: Group name (e.g. "Scattered Spider") or ATT&CK ID (e.g. "G1015")
        generate_dir: Path to the directory containing generated detection YAMLs

    Returns:
        Dict with keys: group_name, group_id, total, covered_count, gap_count,
        covered (list), gaps (list). Returns None if group not found in CSV.
    """
    csv_path = _DEFAULT_CSV
    if not csv_path.exists():
        return None

    rows = []
    group_lower = group.lower()
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # MITRESaw's 12-column CSV, or the older 9-column one (group_id/group_name)
            gid = (row.get("group_sw_id") or row.get("group_id") or "").upper()
            gname = (row.get("group_sw_name") or row.get("group_name") or "").lower()
            if gid == group.upper() or gname == group_lower:
                rows.append(row)

    if not rows:
        return None

    group_name = rows[0].get("group_sw_name") or rows[0].get("group_name")
    group_id = rows[0].get("group_sw_id") or rows[0].get("group_id")

    # Deduplicate by technique_id — keep first occurrence per technique
    seen: Dict[str, dict] = {}
    for row in rows:
        tid = row["technique_id"]
        if tid not in seen:
            seen[tid] = {
                "technique_id": tid,
                "technique_name": row["technique_name"],
                "tactic": row["tactic"],
                # The 12-column CSV doesn't carry it; its rows are direct attributions
                "attribution_type": row.get("attribution_type") or "direct",
                "covered": False,
            }

    # Coverage: a detection file names the technique (technique_id, or the techniques
    # list of bespoke files). Files are named after the technique *name*, so the old
    # filename-prefix check never matched
    covered_ids = _detected_technique_ids(Path(str(generate_dir)))
    for tid, data in seen.items():
        data["covered"] = tid in covered_ids

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


# ---------------------------------------------------------------------------
# Kept for backward compatibility — these were part of the old public API
# but are no longer used for CSV generation. They use the in-memory STIX
# bundle for real-time lookups.
# ---------------------------------------------------------------------------

def get_group_techniques(
    bundle: dict,
    group_id_or_name: str,
) -> List[Dict]:
    """
    Return all technique records for a group, following all three attribution paths.
    Uses the in-memory STIX bundle (not MITRESaw CLI).
    """
    objects = bundle.get("objects", [])
    groups, techniques, software, campaigns = _build_indexes(objects)

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
    Kept for backward compatibility. Prefer run_mitresaw() for CSV generation.
    """
    objects = bundle.get("objects", [])
    groups, techniques, software, campaigns = _build_indexes(objects)

    rows: List[dict] = []
    seen: Set[Tuple] = set()

    _walk_path1(objects, groups, techniques, rows, seen)
    _walk_path2(objects, groups, techniques, software, rows, seen)
    _walk_path3(objects, groups, techniques, campaigns, rows, seen)

    return rows


# ---------------------------------------------------------------------------
# XLSX cross-reference (kept for backward compatibility)
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
    stix_pairs = {(r.get("group_sw_id", r.get("group_id", "")), r["technique_id"]) for r in rows}
    return sorted(
        (src, tgt)
        for src, tgt in xlsx_pairs
        if src.startswith("G") and tgt.startswith("T")
        and (src, tgt) not in stix_pairs
    )


# ---------------------------------------------------------------------------
# CLI entry point  (python -m archer.mitre.procedures)
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(
        description="Rebuild data/mitre_procedures.csv by running MITRESaw.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m archer.mitre.procedures
  python -m archer.mitre.procedures --output /tmp/procedures.csv
        """,
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help=f"Output CSV path (default: {_DEFAULT_CSV})",
    )
    args = parser.parse_args()

    csv_path, xlsx_path = run_mitresaw(output_csv=args.output)
    print(f"\n✓ CSV written to {csv_path}")
    if xlsx_path:
        print(f"✓ XLSX written to {xlsx_path}")


if __name__ == "__main__":
    _cli()

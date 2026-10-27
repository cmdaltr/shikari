"""
archer.detection.splunk
=======================

Generates MITRE ATT&CK-aligned Splunk detection queries from MITRESaw output.

Workflow
--------
1. Check if the Archer-side MITRESaw cache (data/mitre_procedures.csv) is
   older than 7 days.
     - Fresh  (≤7 days): run  MITRESaw.py -d -E -q         (user shorthand: -DEC)
     - Stale  (>7 days): run  MITRESaw.py -d -E -F -q      (user shorthand: -DECF)

2. Read the unique MITRE ATT&CK techniques from the resulting CSV.

3. For each technique call the configured LLM (Mode 1) using:
     - bespoke/prompts/CloudLLM_Master.md  (cloud providers)
       or
       bespoke/prompts/LocalLLM_Master.md  (Ollama)
     - bespoke/prompts/DetectionGeneration_Templates.md  (query templates)
   The LLM is instructed to only generate queries for the Splunk indexes
   that are defined in bespoke/mappings/schemas/schemaSplunk.json.

4. Validate and save each result as JSON to data/detections/splunk/.

If no LLM is available the run still updates the cache but skips generation,
returning a summary with skipped_count = total_techniques (Mode 2 — template
insertion from MITRESaw evidence column — is a future extension).
"""

from __future__ import annotations

import csv
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from archer import paths

logger = logging.getLogger(__name__)

_PROJECT_ROOT = paths.HOME
_BESPOKE_DIR = _PROJECT_ROOT / "bespoke"
_DEFAULT_CSV = _PROJECT_ROOT / "data" / "mitre_procedures.csv"
_DETECTIONS_DIR = _PROJECT_ROOT / "data" / "detections" / "splunk"


# ---------------------------------------------------------------------------
# Bespoke helpers
# ---------------------------------------------------------------------------

def get_available_indexes(bespoke_dir: Optional[Path] = None) -> List[str]:
    """
    Return the Splunk index names available for this organisation.

    Reads bespoke/mappings/schemas/schemaSplunk.json.  The file is a dict keyed by
    indicator type (cmd, reg, evt, sw, cve, api …); each value is itself a
    dict keyed by index name.  We collect and deduplicate all index names.
    """
    if bespoke_dir is None:
        bespoke_dir = _BESPOKE_DIR
    schema_path = Path(bespoke_dir) / "mappings" / "schemas" / "schemaSplunk.json"
    if not schema_path.exists():
        logger.warning("schemaSplunk.json not found at %s — no index filtering", schema_path)
        return []
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)
    indexes: set[str] = set()
    for category_map in schema.values():
        if isinstance(category_map, dict):
            indexes.update(category_map.keys())
    return sorted(indexes)


def load_detection_prompts(
    bespoke_dir: Optional[Path] = None,
    llm_type: str = "cloud",
) -> Tuple[str, str]:
    """
    Load the master prompt and unified template prompt from bespoke/prompts/.

    llm_type="cloud"  → CloudLLM_Master.md
    llm_type="local"  → LocalLLM_Master.md
    """
    if bespoke_dir is None:
        bespoke_dir = _BESPOKE_DIR
    prompts_dir = Path(bespoke_dir) / "prompts"

    master_file = "CloudLLM_Master.md" if llm_type == "cloud" else "LocalLLM_Master.md"
    master_path = prompts_dir / master_file
    template_path = prompts_dir / "DetectionGeneration_Templates.md"

    master_prompt = ""
    if master_path.exists():
        master_prompt = master_path.read_text(encoding="utf-8")
    else:
        logger.warning("Master prompt not found: %s", master_path)

    template_prompt = ""
    if template_path.exists():
        template_prompt = template_path.read_text(encoding="utf-8")
    else:
        logger.warning("Template prompt not found: %s", template_path)

    return master_prompt, template_prompt


# ---------------------------------------------------------------------------
# MITRESaw CSV reader
# ---------------------------------------------------------------------------

def get_unique_techniques(
    csv_path: Optional[Path] = None,
    group_filter: Optional[str] = None,
) -> List[Dict[str, str]]:
    """
    Read mitre_procedures.csv and return one record per unique technique_id.

    If group_filter is supplied (ATT&CK group ID or name, case-insensitive)
    only techniques attributed to that group are returned.

    Each record contains:
        technique_id, technique_name, tactic, platforms,
        evidence, detectable_via, procedure_example
    """
    path = Path(csv_path) if csv_path is not None else _DEFAULT_CSV
    if not path.exists():
        logger.warning("mitre_procedures.csv not found at %s", path)
        return []

    group_lower = group_filter.lower().strip() if group_filter else None
    seen: Dict[str, Dict[str, str]] = {}

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Group filter
            if group_lower:
                gid = row.get("group_sw_id", "").upper()
                gname = row.get("group_sw_name", "").lower()
                if gid != group_filter.upper() and gname != group_lower:
                    continue

            tid = row.get("technique_id", "").strip()
            if not tid or tid in seen:
                continue

            seen[tid] = {
                "technique_id": tid,
                "technique_name": row.get("technique_name", "").strip(),
                "tactic": row.get("tactic", "").strip(),
                "platforms": row.get("platforms", "").strip(),
                "evidence": row.get("evidence", "").strip(),
                "detectable_via": row.get("detectable_via", "").strip(),
                "procedure_example": row.get("procedure_example", "").strip(),
            }

    return list(seen.values())


# ---------------------------------------------------------------------------
# LLM generation helpers
# ---------------------------------------------------------------------------

def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    return text.strip()


def _parse_llm_output(raw: str) -> Optional[Dict[str, Any]]:
    """Parse JSON from LLM output, tolerating markdown code fences and prose."""
    cleaned = _strip_code_fences(raw)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Try extracting the first JSON object from surrounding prose
        match = re.search(r"(\{.*\})", cleaned, flags=re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
    logger.debug("Could not parse JSON from LLM output (first 200 chars): %s", raw[:200])
    return None


def _validate_detection_output(obj: Dict[str, Any]) -> bool:
    """Confirm the LLM response has the required Detection Generation structure."""
    required = ["technique_name", "full_technique_name", "queries"]
    if not all(k in obj for k in required):
        return False
    if not isinstance(obj.get("queries"), list):
        return False
    for q in obj["queries"]:
        if not isinstance(q, dict):
            return False
        if "source_index" not in q or "query" not in q:
            return False
    return True


def _build_index_restriction(available_indexes: List[str]) -> str:
    """Return a prompt clause restricting query generation to available indexes."""
    if not available_indexes:
        return ""
    index_list = "\n".join(f"  - {idx}" for idx in available_indexes)
    return (
        "\n\n## AVAILABLE INDEXES (STRICT CONSTRAINT)\n\n"
        "You MUST only generate queries for the following Splunk indexes.\n"
        "Do NOT generate queries for any index not listed here.\n"
        "If a technique has no meaningful coverage in these indexes, return an "
        "empty queries array.\n\n"
        f"{index_list}\n"
    )


def generate_for_technique(
    technique: Dict[str, str],
    llm: Any,
    master_prompt: str,
    template_prompt: str,
    available_indexes: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Call the LLM to generate Splunk detections for a single ATT&CK technique.

    Returns the parsed JSON detection object (conforming to the Detection
    Generation schema) enriched with MITRESaw metadata, or None on failure.
    """
    index_clause = _build_index_restriction(available_indexes or [])

    system = (
        master_prompt.strip()
        + index_clause
        + "\n\nThe unified detection template document is provided below and must "
        "be used as the source of truth for query structure."
    )
    user = (
        "Unified detection template document:\n\n"
        + template_prompt.strip()
        + "\n\n"
        + f"Technique name: {technique['technique_name']}\n"
        + "Output: JSON only\n"
    )

    try:
        response = llm.generate(
            user,
            system_prompt=system,
            temperature=0.1,
            max_tokens=8192,
        )
        parsed = _parse_llm_output(response.content)
        if parsed is None:
            logger.warning(
                "LLM returned unparseable output for %s", technique["technique_id"]
            )
            return None
        if not _validate_detection_output(parsed):
            logger.warning(
                "LLM output failed schema validation for %s", technique["technique_id"]
            )
            return None

        # Enrich with MITRESaw metadata
        parsed.setdefault("technique_id", technique["technique_id"])
        parsed.setdefault("tactic", technique["tactic"])
        parsed.setdefault("platforms", technique["platforms"])
        parsed["mitresaw_evidence"] = technique["evidence"]
        parsed["mitresaw_detectable_via"] = technique["detectable_via"]

        # Filter queries to only available indexes (belt-and-suspenders)
        if available_indexes:
            available_set = set(available_indexes)
            filtered = [
                q for q in parsed["queries"]
                if q.get("source_index", "") in available_set
            ]
            if len(filtered) < len(parsed["queries"]):
                dropped = len(parsed["queries"]) - len(filtered)
                logger.debug(
                    "Dropped %d out-of-scope index queries for %s",
                    dropped,
                    technique["technique_id"],
                )
            parsed["queries"] = filtered

        return parsed

    except Exception as exc:
        logger.error(
            "LLM call failed for technique %s: %s",
            technique["technique_id"],
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# Output persistence
# ---------------------------------------------------------------------------

def _slugify(name: str) -> str:
    slug = name.strip().lower()
    slug = re.sub(r"[^a-z0-9_-]", "_", slug)
    slug = re.sub(r"_+", "_", slug)
    return slug.strip("_") or "unknown"


def save_detection(
    obj: Dict[str, Any],
    outdir: Optional[Path] = None,
) -> Path:
    """
    Write detection JSON to outdir/<technique_id>_<technique_slug>.json.

    Returns the written path.
    """
    if outdir is None:
        outdir = _DETECTIONS_DIR
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    tid = obj.get("technique_id", "unknown").replace(".", "-")
    slug = _slugify(obj.get("technique_name", "unknown"))
    dest = outdir / f"{tid}_{slug}.json"
    dest.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    return dest


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_splunk_detection_generation(
    llm: Any = None,
    llm_type: str = "cloud",
    force_refresh: bool = False,
    group_filter: Optional[str] = None,
    bespoke_dir: Optional[Path] = None,
    outdir: Optional[Path] = None,
    skip_existing: bool = True,
) -> Dict[str, Any]:
    """
    Orchestrate the full Splunk detection generation pipeline.

    Parameters
    ----------
    llm : LLMProvider instance or None
        If None, MITRESaw is still refreshed but query generation is skipped.
    llm_type : "cloud" | "local"
        Selects CloudLLM_Master.md or LocalLLM_Master.md from bespoke/prompts/.
    force_refresh : bool
        Force a MITRESaw re-run regardless of cache age.
    group_filter : str or None
        ATT&CK group name or ID (e.g. "APT29", "G0016").  When set, only
        techniques attributed to that group are processed.
    bespoke_dir : Path or None
        Override for the bespoke/ directory root.
    outdir : Path or None
        Override for the output directory (default: data/detections/splunk/).
    skip_existing : bool
        If True, skip techniques that already have an output file in outdir.

    Returns
    -------
    dict with keys:
        cache_refreshed, total_techniques, generated, skipped, failed, files
    """
    from archer.mitre.procedures import is_cache_stale, run_mitresaw_detection

    if bespoke_dir is None:
        bespoke_dir = _BESPOKE_DIR
    if outdir is None:
        outdir = _DETECTIONS_DIR

    # ----- Step 1: Cache check + MITRESaw run --------------------------------
    stale = force_refresh or is_cache_stale()
    logger.info(
        "MITRESaw cache is %s — running with %s flags",
        "stale" if stale else "fresh",
        "force (-d -E -F -q)" if stale else "normal (-d -E -q)",
    )
    # A forced refresh collects every group; otherwise only those ATT&CK changed
    run_mitresaw_detection(force=stale, full=force_refresh)
    logger.info("MITRESaw detection extraction complete")

    # ----- Step 2: Read techniques -------------------------------------------
    techniques = get_unique_techniques(group_filter=group_filter)
    logger.info(
        "Found %d unique techniques%s",
        len(techniques),
        f" for group '{group_filter}'" if group_filter else "",
    )

    if not techniques:
        return {
            "cache_refreshed": stale,
            "total_techniques": 0,
            "generated": 0,
            "skipped": 0,
            "failed": 0,
            "files": [],
        }

    # ----- Step 3: Resolve available indexes ---------------------------------
    available_indexes = get_available_indexes(bespoke_dir)
    if available_indexes:
        logger.info(
            "Restricting queries to %d available Splunk indexes: %s",
            len(available_indexes),
            ", ".join(available_indexes),
        )
    else:
        logger.warning(
            "No available indexes found in schemaSplunk.json — "
            "LLM will select indexes without restriction"
        )

    # ----- Step 4: Load prompts (only needed when LLM is available) ----------
    master_prompt = template_prompt = ""
    if llm is not None:
        master_prompt, template_prompt = load_detection_prompts(bespoke_dir, llm_type)
        if not master_prompt:
            logger.error(
                "Master prompt missing from %s/prompts/ — "
                "cannot generate queries without it",
                bespoke_dir,
            )
            llm = None  # fall through to skip

    # ----- Step 5: Generate per technique ------------------------------------
    generated_files: List[str] = []
    skipped = 0
    failed = 0

    outdir_path = Path(outdir)
    outdir_path.mkdir(parents=True, exist_ok=True)

    for technique in techniques:
        tid = technique["technique_id"].replace(".", "-")
        slug = _slugify(technique["technique_name"])
        expected_file = outdir_path / f"{tid}_{slug}.json"

        if skip_existing and expected_file.exists():
            logger.debug("Skipping existing detection for %s", technique["technique_id"])
            skipped += 1
            continue

        if llm is None:
            skipped += 1
            continue

        result = generate_for_technique(
            technique,
            llm,
            master_prompt,
            template_prompt,
            available_indexes,
        )

        if result is None:
            failed += 1
            continue

        dest = save_detection(result, outdir_path)
        generated_files.append(str(dest))
        logger.info("Saved detection: %s", dest.name)

    return {
        "cache_refreshed": stale,
        "total_techniques": len(techniques),
        "generated": len(generated_files),
        "skipped": skipped,
        "failed": failed,
        "files": generated_files,
    }

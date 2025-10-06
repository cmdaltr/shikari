"""
Detection Enrichment from Emulation Data

Enhances Archer detection queries with evidence from adversary emulation executions.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from .parser import EmulationParser


def enrich_detections_with_emulation(
    technique_id: str,
    yaml_dir: str = "data/generate",
    emulation_dir: str = "data/emulation",
) -> Dict[str, Any]:
    """
    Enrich detection queries with emulation evidence.

    Args:
        technique_id: MITRE ATT&CK technique ID
        yaml_dir: Directory containing YAML detection files
        emulation_dir: Directory containing emulation results

    Returns:
        Dictionary with enrichment summary
    """
    yaml_path = Path(yaml_dir)
    emulation_path = Path(emulation_dir)

    # Find all YAML files for this technique
    technique_clean = technique_id.replace(".", "")
    yaml_files = list(yaml_path.glob(f"*{technique_clean}*.yaml"))

    if not yaml_files:
        return {
            "status": "no_detections",
            "message": f"No detection YAMLs found for {technique_id}",
        }

    # Find emulation results for this technique
    result_files = list(emulation_path.glob(f"{technique_id}_atomic_*.json"))

    if not result_files:
        return {
            "status": "no_emulation_data",
            "message": f"No emulation results found for {technique_id}",
        }

    # Use the most recent result file
    latest_result = max(result_files, key=lambda p: p.stat().st_mtime)

    # Parse emulation results
    indicators = EmulationParser.parse_atomic_results(latest_result)

    # Enrich each YAML file
    enriched_files = []
    for yaml_file in yaml_files:
        success = EmulationParser.enrich_yaml_with_evidence(yaml_file, indicators)
        if success:
            enriched_files.append(str(yaml_file))

    # Generate additional queries from indicators
    additional_queries = EmulationParser.generate_kql_from_indicators(indicators)

    return {
        "status": "success",
        "technique_id": technique_id,
        "enriched_files": enriched_files,
        "emulation_source": str(latest_result),
        "indicators_found": {
            "processes": len(indicators.get("processes", [])),
            "commands": len(indicators.get("commands", [])),
            "files": len(indicators.get("files", [])),
            "registry_keys": len(indicators.get("registry_keys", [])),
        },
        "additional_queries_generated": len(additional_queries),
        "additional_queries": additional_queries,
    }


def bulk_enrich_from_emulation(
    yaml_dir: str = "data/generate",
    emulation_dir: str = "data/emulation",
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enrich all detections with available emulation data.

    Args:
        yaml_dir: Directory containing YAML detection files
        emulation_dir: Directory containing emulation results
        output_file: Optional path to save enrichment summary

    Returns:
        Dictionary with bulk enrichment summary
    """
    emulation_path = Path(emulation_dir)

    # Find all emulation result files
    result_files = list(emulation_path.glob("T*_atomic_*.json"))

    if not result_files:
        return {
            "status": "no_emulation_data",
            "message": "No emulation results found",
        }

    # Extract unique technique IDs
    technique_ids = set()
    for result_file in result_files:
        # Parse technique ID from filename (e.g., T1059.001_atomic_20250105.json)
        parts = result_file.stem.split("_atomic_")
        if parts:
            technique_ids.add(parts[0])

    # Enrich each technique
    results = {
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        "techniques_processed": [],
        "total_files_enriched": 0,
        "total_queries_generated": 0,
    }

    for technique_id in sorted(technique_ids):
        print(f"Enriching {technique_id}...")
        result = enrich_detections_with_emulation(technique_id, yaml_dir, emulation_dir)

        if result["status"] == "success":
            results["techniques_processed"].append(
                {
                    "technique_id": technique_id,
                    "files_enriched": len(result["enriched_files"]),
                    "queries_generated": result["additional_queries_generated"],
                    "indicators": result["indicators_found"],
                }
            )
            results["total_files_enriched"] += len(result["enriched_files"])
            results["total_queries_generated"] += result[
                "additional_queries_generated"
            ]

    # Save summary if output file specified
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"✅ Enrichment summary saved to {output_file}")

    return results

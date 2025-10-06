"""
Detection Enrichment from Emulation Data

Enhances Archer detection queries with evidence from adversary emulation executions.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
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


def enrich_from_group_emulation(
    threat_group: str,
    yaml_dir: str = "data/generate",
    emulation_dir: str = "data/emulation",
) -> Dict[str, Any]:
    """
    Enrich detections using threat group emulation results.

    Args:
        threat_group: Threat group name
        yaml_dir: Directory containing YAML detection files
        emulation_dir: Directory containing emulation results

    Returns:
        Dictionary with enrichment summary
    """
    emulation_path = Path(emulation_dir)

    # Find group emulation result file
    group_files = list(emulation_path.glob(f"{threat_group}_group_emulation_*.json"))

    if not group_files:
        return {
            "status": "no_group_emulation",
            "message": f"No group emulation results found for {threat_group}",
        }

    # Use most recent result
    latest_result = max(group_files, key=lambda p: p.stat().st_mtime)

    print(f"Loading group emulation results from {latest_result}")

    with open(latest_result, "r", encoding="utf-8") as f:
        group_data = json.load(f)

    # Get all techniques that were tested
    technique_results = group_data.get("technique_results", [])

    if not technique_results:
        return {
            "status": "no_techniques",
            "message": "No technique results in group emulation data",
        }

    print(
        f"Found {len(technique_results)} techniques from {threat_group} emulation\n"
    )

    # Enrich detections for each technique
    enrichment_results = {
        "threat_group": threat_group,
        "timestamp": datetime.utcnow().isoformat(),
        "techniques_enriched": [],
        "total_files_enriched": 0,
        "total_queries_generated": 0,
    }

    for tech_result in technique_results:
        technique_id = tech_result.get("technique_id")

        if not technique_id or tech_result.get("status") == "error":
            continue

        print(f"Enriching detections for {technique_id}...")

        try:
            result = enrich_detections_with_emulation(
                technique_id, yaml_dir, emulation_dir
            )

            if result["status"] == "success":
                enrichment_results["techniques_enriched"].append(
                    {
                        "technique_id": technique_id,
                        "files_enriched": len(result["enriched_files"]),
                        "queries_generated": result["additional_queries_generated"],
                        "indicators": result["indicators_found"],
                    }
                )
                enrichment_results["total_files_enriched"] += len(
                    result["enriched_files"]
                )
                enrichment_results["total_queries_generated"] += result[
                    "additional_queries_generated"
                ]

        except Exception as e:
            print(f"  ⚠️  Error enriching {technique_id}: {e}")

    # Save summary
    summary_file = emulation_path / f"{threat_group}_enrichment_summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(enrichment_results, f, indent=2)

    print()
    print("=" * 70)
    print("ENRICHMENT SUMMARY")
    print("=" * 70)
    print(f"Threat Group: {threat_group}")
    print(f"Techniques Enriched: {len(enrichment_results['techniques_enriched'])}")
    print(f"Files Updated: {enrichment_results['total_files_enriched']}")
    print(f"Queries Generated: {enrichment_results['total_queries_generated']}")
    print()
    print(f"✅ Summary saved to {summary_file}")

    return enrichment_results

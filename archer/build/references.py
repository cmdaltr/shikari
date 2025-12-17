"""
Reference Query Loader for Archer Detection Generation

This module loads production-tested reference queries that are used as:
1. Templates for generating new queries with similar structure
2. Few-shot examples for LLM-based query generation

Reference queries are stored in data/bespoke/references/
"""

import os
import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path


class ReferenceQueryLoader:
    """Loads and manages reference queries for detection generation."""

    def __init__(self, base_dir: str = None):
        """
        Initialize the reference query loader.

        Args:
            base_dir: Base directory for reference queries.
                      Defaults to data/bespoke/references/
        """
        if base_dir is None:
            # Find the data directory relative to this file
            current_file = Path(__file__)
            archer_root = current_file.parent.parent.parent
            base_dir = archer_root / "data" / "bespoke" / "references"

        self.base_dir = Path(base_dir)
        self._cache: Dict[str, Any] = {}

    def load_splunk_references(self) -> Dict[str, Any]:
        """
        Load all Splunk reference queries.

        Returns:
            Dictionary containing all Splunk reference queries organized by category.
        """
        if "splunk" in self._cache:
            return self._cache["splunk"]

        splunk_dir = self.base_dir / "Splunk"
        if not splunk_dir.exists():
            return {}

        # Load the consolidated file first
        all_queries_file = splunk_dir / "all_references.yaml"
        if all_queries_file.exists():
            with open(all_queries_file, "r") as f:
                # Handle multiple YAML documents in one file
                docs = list(yaml.safe_load_all(f))
                # Merge all documents into one dict
                merged = {}
                for doc in docs:
                    if doc:
                        merged.update(doc)
                self._cache["splunk"] = merged
                return merged

        # Fall back to loading individual files
        queries = {"queries": []}
        for yaml_file in splunk_dir.glob("*.yaml"):
            if yaml_file.name != "all_references.yaml":
                with open(yaml_file, "r") as f:
                    query_data = yaml.safe_load(f)
                    if query_data:
                        queries["queries"].append(query_data)

        self._cache["splunk"] = queries
        return queries

    def load_mde_references(self) -> List[Dict[str, Any]]:
        """
        Load all MDE (Microsoft Defender for Endpoint) reference queries.

        Returns:
            List of MDE reference query dictionaries.
        """
        if "mde" in self._cache:
            return self._cache["mde"]

        mde_dir = self.base_dir / "MDE"
        if not mde_dir.exists():
            return []

        queries = []
        for yaml_file in mde_dir.glob("*.yaml"):
            with open(yaml_file, "r") as f:
                query_data = yaml.safe_load(f)
                if query_data:
                    queries.append(query_data)

        self._cache["mde"] = queries
        return queries

    def get_queries_by_technique(
        self, technique_id: str, vendor: str = None
    ) -> List[Dict[str, Any]]:
        """
        Get reference queries for a specific MITRE ATT&CK technique.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1021.001")
            vendor: Optional vendor filter ("Splunk", "MDE", etc.)

        Returns:
            List of matching reference queries.
        """
        matches = []

        if vendor is None or vendor.lower() == "splunk":
            splunk_refs = self.load_splunk_references()
            for category in [
                "aws_queries",
                "azure_queries",
                "defender_queries",
                "o365_queries",
                "unix_queries",
                "windows_queries",
            ]:
                if category in splunk_refs:
                    for query in splunk_refs[category]:
                        if query.get("technique_id") == technique_id:
                            query["vendor"] = "Splunk"
                            matches.append(query)

        if vendor is None or vendor.lower() in ["mde", "kql"]:
            mde_refs = self.load_mde_references()
            for query in mde_refs:
                if query.get("technique_id") == technique_id:
                    query["vendor"] = "MDE"
                    matches.append(query)

        return matches

    def get_queries_by_log_source(self, log_source: str) -> List[Dict[str, Any]]:
        """
        Get reference queries for a specific log source/index.

        Args:
            log_source: Log source name (e.g., "aws_cloudtrail", "DeviceProcessEvents")

        Returns:
            List of matching reference queries.
        """
        matches = []
        log_source_lower = log_source.lower()

        # Search Splunk references
        splunk_refs = self.load_splunk_references()
        for category in [
            "aws_queries",
            "azure_queries",
            "defender_queries",
            "o365_queries",
            "unix_queries",
            "windows_queries",
        ]:
            if category in splunk_refs:
                for query in splunk_refs[category]:
                    if query.get("log_source", "").lower() == log_source_lower:
                        query["vendor"] = "Splunk"
                        matches.append(query)

        # Search MDE references
        mde_refs = self.load_mde_references()
        for query in mde_refs:
            data_types = []
            for connector in query.get("requiredDataConnectors", []):
                data_types.extend(connector.get("dataTypes", []))
            if log_source in data_types:
                query["vendor"] = "MDE"
                matches.append(query)

        return matches

    def get_few_shot_examples(
        self, vendor: str, count: int = 3, technique_id: str = None
    ) -> List[Dict[str, Any]]:
        """
        Get few-shot examples for LLM query generation.

        Args:
            vendor: Target vendor ("Splunk" or "MDE")
            count: Number of examples to return
            technique_id: Optional technique ID to prioritize similar examples

        Returns:
            List of reference queries suitable as few-shot examples.
        """
        examples = []

        # If technique_id provided, try to get matching examples first
        if technique_id:
            technique_matches = self.get_queries_by_technique(technique_id, vendor)
            examples.extend(technique_matches[:count])

        # Fill remaining slots with diverse examples
        if len(examples) < count:
            if vendor.lower() == "splunk":
                splunk_refs = self.load_splunk_references()
                # Get one from each category for diversity
                categories = ["aws_queries", "azure_queries", "defender_queries", "o365_queries"]
                for category in categories:
                    if len(examples) >= count:
                        break
                    if category in splunk_refs and splunk_refs[category]:
                        query = splunk_refs[category][0]
                        query["vendor"] = "Splunk"
                        if query not in examples:
                            examples.append(query)

            elif vendor.lower() in ["mde", "kql"]:
                mde_refs = self.load_mde_references()
                for query in mde_refs[: count - len(examples)]:
                    query["vendor"] = "MDE"
                    if query not in examples:
                        examples.append(query)

        return examples[:count]

    def get_query_patterns(self, vendor: str) -> Dict[str, List[str]]:
        """
        Get common query patterns for a vendor.

        Args:
            vendor: Target vendor ("Splunk" or "MDE")

        Returns:
            Dictionary of pattern categories and their examples.
        """
        if vendor.lower() == "splunk":
            splunk_refs = self.load_splunk_references()
            return splunk_refs.get("query_patterns", {})

        # For MDE, extract patterns from the queries themselves
        patterns = {
            "time_filter": ["| where Timestamp > ago(30d)"],
            "summarize": [],
            "exclusions": [],
        }

        mde_refs = self.load_mde_references()
        for query in mde_refs:
            query_text = query.get("query", "")
            # Extract summarize patterns
            if "summarize" in query_text.lower():
                for line in query_text.split("\n"):
                    if "summarize" in line.lower():
                        patterns["summarize"].append(line.strip())
            # Extract exclusion patterns
            if "not(" in query_text.lower() or "has_any" in query_text.lower():
                for line in query_text.split("\n"):
                    if "not(" in line.lower() or "has_any" in line.lower():
                        patterns["exclusions"].append(line.strip())

        return patterns

    def format_as_prompt_examples(self, examples: List[Dict[str, Any]], vendor: str) -> str:
        """
        Format reference queries as examples for LLM prompts.

        Args:
            examples: List of reference queries
            vendor: Target vendor

        Returns:
            Formatted string suitable for inclusion in LLM prompts.
        """
        if not examples:
            return ""

        prompt_parts = [f"## Reference {vendor} Detection Queries\n"]
        prompt_parts.append(
            "Use these production-tested queries as examples of good detection patterns:\n"
        )

        for i, example in enumerate(examples, 1):
            prompt_parts.append(f"\n### Example {i}: {example.get('name', 'Unknown')}")
            prompt_parts.append(f"**Technique:** {example.get('technique_id', 'N/A')}")

            if "description" in example:
                prompt_parts.append(f"**Description:** {example['description'][:200]}...")

            if "indicators" in example:
                indicators = example["indicators"]
                if isinstance(indicators, list):
                    prompt_parts.append(f"**Key Indicators:** {', '.join(indicators[:5])}")
                elif isinstance(indicators, dict):
                    for ind_type, ind_values in list(indicators.items())[:2]:
                        if isinstance(ind_values, list):
                            prompt_parts.append(
                                f"**{ind_type} Indicators:** {', '.join(str(v) for v in ind_values[:3])}"
                            )

            prompt_parts.append(
                f"**Query:**\n```{vendor.lower()}\n{example.get('query', '')}\n```\n"
            )

        return "\n".join(prompt_parts)

    def clear_cache(self):
        """Clear the internal cache."""
        self._cache = {}

    def get_coverage_map(self) -> Dict[str, Any]:
        """
        Build a coverage map showing which techniques/platforms have reference queries.

        Returns:
            Dictionary with coverage statistics and detailed breakdown.
        """
        coverage = {
            "summary": {
                "total_queries": 0,
                "techniques_covered": set(),
                "platforms_covered": set(),
                "vendors": {},
            },
            "by_technique": {},  # technique_id -> {vendors, platforms, count}
            "by_platform": {},  # platform -> {techniques, count}
            "by_vendor": {},  # vendor -> {techniques, platforms, count}
            "gaps": {
                "techniques_without_splunk": [],
                "techniques_without_mde": [],
            },
        }

        # Process Splunk queries
        splunk_refs = self.load_splunk_references()
        splunk_techniques = set()
        splunk_platforms = set()

        for category in [
            "aws_queries",
            "azure_queries",
            "defender_queries",
            "o365_queries",
            "unix_queries",
            "windows_queries",
        ]:
            if category in splunk_refs:
                for query in splunk_refs[category]:
                    tech_id = query.get("technique_id", "Unknown")
                    platform = query.get("platform", category.replace("_queries", "").title())

                    coverage["summary"]["total_queries"] += 1
                    coverage["summary"]["techniques_covered"].add(tech_id)
                    coverage["summary"]["platforms_covered"].add(platform)
                    splunk_techniques.add(tech_id)
                    splunk_platforms.add(platform)

                    # By technique
                    if tech_id not in coverage["by_technique"]:
                        coverage["by_technique"][tech_id] = {
                            "vendors": set(),
                            "platforms": set(),
                            "queries": [],
                            "count": 0,
                        }
                    coverage["by_technique"][tech_id]["vendors"].add("Splunk")
                    coverage["by_technique"][tech_id]["platforms"].add(platform)
                    coverage["by_technique"][tech_id]["queries"].append(
                        {
                            "name": query.get("name", "Unknown"),
                            "vendor": "Splunk",
                            "platform": platform,
                            "log_source": query.get("log_source", ""),
                        }
                    )
                    coverage["by_technique"][tech_id]["count"] += 1

                    # By platform
                    if platform not in coverage["by_platform"]:
                        coverage["by_platform"][platform] = {
                            "techniques": set(),
                            "vendors": set(),
                            "count": 0,
                        }
                    coverage["by_platform"][platform]["techniques"].add(tech_id)
                    coverage["by_platform"][platform]["vendors"].add("Splunk")
                    coverage["by_platform"][platform]["count"] += 1

        coverage["by_vendor"]["Splunk"] = {
            "techniques": list(splunk_techniques),
            "platforms": list(splunk_platforms),
            "count": sum(
                1
                for cat in [
                    "aws_queries",
                    "azure_queries",
                    "defender_queries",
                    "o365_queries",
                    "unix_queries",
                    "windows_queries",
                ]
                if cat in splunk_refs
                for _ in splunk_refs.get(cat, [])
            ),
        }

        # Process MDE queries
        mde_refs = self.load_mde_references()
        mde_techniques = set()
        mde_platforms = set()

        for query in mde_refs:
            tech_id = query.get("technique_id", "Unknown")
            # Extract data types as platforms
            data_types = []
            for connector in query.get("requiredDataConnectors", []):
                data_types.extend(connector.get("dataTypes", []))
            platform = ", ".join(data_types) if data_types else "MDE"

            coverage["summary"]["total_queries"] += 1
            coverage["summary"]["techniques_covered"].add(tech_id)
            coverage["summary"]["platforms_covered"].add("MDE")
            mde_techniques.add(tech_id)
            mde_platforms.update(data_types if data_types else ["MDE"])

            # By technique
            if tech_id not in coverage["by_technique"]:
                coverage["by_technique"][tech_id] = {
                    "vendors": set(),
                    "platforms": set(),
                    "queries": [],
                    "count": 0,
                }
            coverage["by_technique"][tech_id]["vendors"].add("MDE")
            coverage["by_technique"][tech_id]["platforms"].add(platform)
            coverage["by_technique"][tech_id]["queries"].append(
                {
                    "name": query.get("name", "Unknown"),
                    "vendor": "MDE",
                    "platform": platform,
                    "log_source": platform,
                }
            )
            coverage["by_technique"][tech_id]["count"] += 1

            # By platform
            for dt in data_types if data_types else ["MDE"]:
                if dt not in coverage["by_platform"]:
                    coverage["by_platform"][dt] = {
                        "techniques": set(),
                        "vendors": set(),
                        "count": 0,
                    }
                coverage["by_platform"][dt]["techniques"].add(tech_id)
                coverage["by_platform"][dt]["vendors"].add("MDE")
                coverage["by_platform"][dt]["count"] += 1

        coverage["by_vendor"]["MDE"] = {
            "techniques": list(mde_techniques),
            "platforms": list(mde_platforms),
            "count": len(mde_refs),
        }

        # Find gaps
        all_techniques = coverage["summary"]["techniques_covered"]
        coverage["gaps"]["techniques_without_splunk"] = list(all_techniques - splunk_techniques)
        coverage["gaps"]["techniques_without_mde"] = list(all_techniques - mde_techniques)

        # Convert sets to lists for JSON serialization
        coverage["summary"]["techniques_covered"] = list(coverage["summary"]["techniques_covered"])
        coverage["summary"]["platforms_covered"] = list(coverage["summary"]["platforms_covered"])
        coverage["summary"]["vendors"] = {
            "Splunk": coverage["by_vendor"].get("Splunk", {}).get("count", 0),
            "MDE": coverage["by_vendor"].get("MDE", {}).get("count", 0),
        }

        for tech_id in coverage["by_technique"]:
            coverage["by_technique"][tech_id]["vendors"] = list(
                coverage["by_technique"][tech_id]["vendors"]
            )
            coverage["by_technique"][tech_id]["platforms"] = list(
                coverage["by_technique"][tech_id]["platforms"]
            )

        for platform in coverage["by_platform"]:
            coverage["by_platform"][platform]["techniques"] = list(
                coverage["by_platform"][platform]["techniques"]
            )
            coverage["by_platform"][platform]["vendors"] = list(
                coverage["by_platform"][platform]["vendors"]
            )

        return coverage


# Module-level instance for convenience
_loader: Optional[ReferenceQueryLoader] = None


def get_loader() -> ReferenceQueryLoader:
    """Get the singleton reference query loader instance."""
    global _loader
    if _loader is None:
        _loader = ReferenceQueryLoader()
    return _loader


def get_references(
    technique_id: str = None, vendor: str = None, log_source: str = None
) -> List[Dict[str, Any]]:
    """
    Convenience function to get reference queries.

    Args:
        technique_id: Optional MITRE ATT&CK technique ID
        vendor: Optional vendor filter
        log_source: Optional log source filter

    Returns:
        List of matching reference queries.
    """
    loader = get_loader()

    if technique_id:
        return loader.get_queries_by_technique(technique_id, vendor)
    elif log_source:
        return loader.get_queries_by_log_source(log_source)
    else:
        # Return all queries
        results = []
        if vendor is None or vendor.lower() == "splunk":
            splunk_refs = loader.load_splunk_references()
            for category in [
                "aws_queries",
                "azure_queries",
                "defender_queries",
                "o365_queries",
                "unix_queries",
                "windows_queries",
            ]:
                if category in splunk_refs:
                    results.extend(splunk_refs[category])

        if vendor is None or vendor.lower() in ["mde", "kql"]:
            results.extend(loader.load_mde_references())

        return results


def get_few_shot_examples(vendor: str, count: int = 3, technique_id: str = None) -> str:
    """
    Convenience function to get formatted few-shot examples for LLM prompts.

    Args:
        vendor: Target vendor ("Splunk" or "MDE")
        count: Number of examples
        technique_id: Optional technique ID for relevance

    Returns:
        Formatted prompt string with examples.
    """
    loader = get_loader()
    examples = loader.get_few_shot_examples(vendor, count, technique_id)
    return loader.format_as_prompt_examples(examples, vendor)


def get_coverage_map() -> Dict[str, Any]:
    """
    Get the reference query coverage map.

    Returns:
        Dictionary with coverage statistics and detailed breakdown.
    """
    loader = get_loader()
    return loader.get_coverage_map()

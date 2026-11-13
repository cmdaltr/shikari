"""
Reference Query Loader for Shikari Detection Generation

This module loads production-tested reference queries that are used as:
1. Templates for generating new queries with similar structure
2. Few-shot examples for LLM-based query generation

Reference queries are stored in bespoke/llm_references/
"""

import os
import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path
from shikari import paths

# MITRE ATT&CK Tactics in kill chain order
MITRE_TACTICS = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]

# Mapping of tactic IDs to display names
TACTIC_DISPLAY_NAMES = {tactic_id: name for tactic_id, name in MITRE_TACTICS}


class ReferenceQueryLoader:
    """Loads and manages reference queries for detection generation."""

    def __init__(self, base_dir: str = None):
        """
        Initialize the reference query loader.

        Args:
            base_dir: Base directory for reference queries.
                      Defaults to bespoke/llm_references/
        """
        if base_dir is None:
            # Find the data directory relative to this file
            base_dir = paths.BESPOKE / "llm_references"

        self.base_dir = Path(base_dir)
        self._cache: Dict[str, Any] = {}
        self._technique_tactics: Dict[str, List[str]] = {}  # Cache for technique-to-tactic mapping

    def _load_technique_tactics(self) -> Dict[str, List[str]]:
        """
        Load technique-to-tactic mapping from MITRE STIX data.

        Returns:
            Dictionary mapping technique IDs to list of tactic names.
        """
        if self._technique_tactics:
            return self._technique_tactics

        try:
            from shikari.mitre.enterprise import get_stix_data

            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            bundle = get_stix_data(url)

            for obj in bundle.objects:
                if obj.get("type") == "attack-pattern":
                    # Get technique ID
                    tech_id = None
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            tech_id = ref.get("external_id")
                            break

                    if tech_id:
                        # Get tactics from kill chain phases
                        tactics = []
                        for phase in obj.get("kill_chain_phases", []):
                            if phase.get("kill_chain_name") == "mitre-attack":
                                tactic_id = phase.get("phase_name")
                                if tactic_id in TACTIC_DISPLAY_NAMES:
                                    tactics.append(TACTIC_DISPLAY_NAMES[tactic_id])

                        if tactics:
                            self._technique_tactics[tech_id] = tactics

        except Exception as e:
            print(f"Warning: Could not load technique-tactic mapping: {e}")

        return self._technique_tactics

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
        all_queries_file = splunk_dir / "all_reference_queries.yaml"
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
            if yaml_file.name != "all_reference_queries.yaml":
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
        return self._load_folder("mde", "MDE")

    def load_secops_references(self) -> List[Dict[str, Any]]:
        """Google SecOps (YARA-L / UDM search) reference queries, from GoogleSecOps/."""
        return self._load_folder("secops", "GoogleSecOps")

    def load_elastic_references(self) -> List[Dict[str, Any]]:
        """Elastic (ES|QL / EQL / KQL) reference queries, from Elastic/."""
        return self._load_folder("elastic", "Elastic")

    def _load_folder(self, key: str, dirname: str) -> List[Dict[str, Any]]:
        """Every query in a vendor's folder: one per YAML file, or a list of them in one file."""
        if key in self._cache:
            return self._cache[key]
        folder = self.base_dir / dirname
        if not folder.exists():
            return []
        queries = []
        for yaml_file in sorted(folder.glob("*.yaml")):
            with open(yaml_file, "r") as f:
                data = yaml.safe_load(f)
            if isinstance(data, list):
                queries.extend(q for q in data if isinstance(q, dict))
            elif isinstance(data, dict):
                queries.append(data)
        self._cache[key] = queries
        return queries

    # The folder-per-SIEM vendors beyond Splunk: (loader, the vendor name the Coverage page shows,
    # the names a caller may filter on)
    def _folder_vendors(self):
        return [
            (self.load_mde_references, "MDE", ("mde", "kql")),
            (self.load_secops_references, "Google SecOps", ("google secops", "googlesecops", "secops", "udm", "yaral", "yara-l")),
            (self.load_elastic_references, "Elastic", ("elastic", "esql", "es|ql")),
        ]

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

        for load, name, aliases in self._folder_vendors():
            if vendor is None or vendor.lower() in aliases:
                for query in load():
                    if query.get("technique_id") == technique_id:
                        query["vendor"] = name
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

            else:
                for load, name, aliases in self._folder_vendors():
                    if vendor.lower() in aliases:
                        for query in load()[: count - len(examples)]:
                            query["vendor"] = name
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
            "by_technique": {},  # technique_id -> {vendors, platforms, count, tactics}
            "by_platform": {},  # platform -> {techniques, count}
            "by_vendor": {},  # vendor -> {techniques, platforms, count}
            "by_tactic": {},  # tactic_name -> {techniques: [{id, name, count}, ...]}
            "tactics_list": [name for _, name in MITRE_TACTICS],  # Ordered list of tactics
            "gaps": {
                "techniques_without_splunk": [],
                "techniques_without_mde": [],
            },
        }

        # Load technique-to-tactic mapping
        tech_tactics = self._load_technique_tactics()

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
                            "tactics": tech_tactics.get(tech_id, []),
                            "name": query.get("technique_name", tech_id),
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
                    "tactics": tech_tactics.get(tech_id, []),
                    "name": query.get("name", tech_id),
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

        # Google SecOps and Elastic: a query's platform is what it names, else the SIEM itself
        for load, vendor_name, _aliases in self._folder_vendors()[1:]:
            refs = load()
            techniques, platforms = set(), set()
            for query in refs:
                tech_id = query.get("technique_id", "Unknown")
                platform = query.get("platform") or query.get("log_source") or vendor_name
                coverage["summary"]["total_queries"] += 1
                coverage["summary"]["techniques_covered"].add(tech_id)
                coverage["summary"]["platforms_covered"].add(platform)
                techniques.add(tech_id)
                platforms.add(platform)
                entry = coverage["by_technique"].setdefault(tech_id, {
                    "vendors": set(), "platforms": set(), "queries": [], "count": 0,
                    "tactics": tech_tactics.get(tech_id, []), "name": query.get("name", tech_id),
                })
                entry["vendors"].add(vendor_name)
                entry["platforms"].add(platform)
                entry["queries"].append({"name": query.get("name", "Unknown"), "vendor": vendor_name,
                                         "platform": platform, "log_source": query.get("log_source", platform)})
                entry["count"] += 1
                by_platform = coverage["by_platform"].setdefault(platform, {"techniques": set(), "vendors": set(), "count": 0})
                by_platform["techniques"].add(tech_id)
                by_platform["vendors"].add(vendor_name)
                by_platform["count"] += 1
            coverage["by_vendor"][vendor_name] = {"techniques": list(techniques), "platforms": list(platforms),
                                                  "count": len(refs)}

        # Find gaps
        all_techniques = coverage["summary"]["techniques_covered"]
        coverage["gaps"]["techniques_without_splunk"] = list(all_techniques - splunk_techniques)
        coverage["gaps"]["techniques_without_mde"] = list(all_techniques - mde_techniques)

        # Build by_tactic groupings
        for tactic_name in coverage["tactics_list"]:
            coverage["by_tactic"][tactic_name] = {"techniques": []}

        for tech_id, tech_info in coverage["by_technique"].items():
            tactics = tech_info.get("tactics", [])
            for tactic in tactics:
                if tactic in coverage["by_tactic"]:
                    coverage["by_tactic"][tactic]["techniques"].append({
                        "id": tech_id,
                        "name": tech_info.get("name", tech_id),
                        "count": tech_info.get("count", 0),
                        "vendors": list(tech_info.get("vendors", set())),
                    })

        # Sort techniques within each tactic by ID
        for tactic in coverage["by_tactic"]:
            coverage["by_tactic"][tactic]["techniques"].sort(key=lambda x: x["id"])

        # Convert sets to lists for JSON serialization
        coverage["summary"]["techniques_covered"] = list(coverage["summary"]["techniques_covered"])
        coverage["summary"]["platforms_covered"] = list(coverage["summary"]["platforms_covered"])
        coverage["summary"]["vendors"] = {
            "Splunk": coverage["by_vendor"].get("Splunk", {}).get("count", 0),
            "MDE": coverage["by_vendor"].get("MDE", {}).get("count", 0),
            "Google SecOps": coverage["by_vendor"].get("Google SecOps", {}).get("count", 0),
            "Elastic": coverage["by_vendor"].get("Elastic", {}).get("count", 0),
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

        for load, _name, aliases in loader._folder_vendors():
            if vendor is None or vendor.lower() in aliases:
                results.extend(load())

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

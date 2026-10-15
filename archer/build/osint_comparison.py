"""
OSINT Comparison Module

This module provides functionality to compare detection patterns with additional open-source
intelligence when MITRE ATT&CK data doesn't provide sufficient indicators.

REQUIREMENTS:
1. When a detection has 0 indicators extracted from MITRE:
   - Search additional OSINT sources for detection methods
   - If found: Create detection marked "Needs Review - compared with additional OSINT sources" (orange badge)
   - If NOT found: DO NOT create the detection at all

2. OSINT Sources to Search:
   - Threat intelligence blogs (Mandiant, CrowdStrike, Microsoft, etc.)
   - GitHub repositories (detection-as-code repos)
   - Elastic Detection Rules
   - Splunk Security Content
   - Atomic Red Team test cases
   - LOLBAs, GTFOBins for technique execution methods

3. Metadata to Track:
   - osint_compared: bool (True if enriched with OSINT)
   - osint_sources: list[str] (URLs/references to OSINT sources used)
   - osint_indicators: dict (Any indicators found from OSINT)
   - comparison_date: str (ISO timestamp of when enrichment was performed)

4. Integration Points:
   - Call from compile_query() in detections.py when identifiers == {} or None
   - Store metadata in YAML file via construct_yaml()
   - Display orange badge in results.html for osint_compared=True detections
"""

from typing import Dict, List, Optional, Tuple
import requests
from datetime import datetime
import re
import json
import time
import os
import hashlib
from pathlib import Path
import yaml as yaml_lib


# Cache directory for OSINT results
from ..config import OSINT_CACHE_DIR as OSINT_CACHE_DIR_STR, OSINT_REPOS_DIR
OSINT_CACHE_DIR = Path(OSINT_CACHE_DIR_STR)
OSINT_CACHE_DIR.mkdir(parents=True, exist_ok=True)


def get_cache_key(technique_id: str) -> str:
    """Generate a cache key for a technique."""
    return hashlib.md5(technique_id.encode()).hexdigest()


def load_from_cache(technique_id: str) -> Optional[Dict]:
    """Load OSINT results from cache if available and not expired (24 hours)."""
    cache_key = get_cache_key(technique_id)
    cache_file = OSINT_CACHE_DIR / f"{cache_key}.json"

    if cache_file.exists():
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)

            # Check if cache is expired (24 hours)
            cached_time = datetime.fromisoformat(cached_data.get("cached_at", ""))
            age = (datetime.utcnow() - cached_time).total_seconds()

            if age < 86400:  # 24 hours
                print(f"  ✓ Using cached OSINT results (age: {age/3600:.1f} hours)")
                return cached_data.get("data")
            else:
                print(f"  ⚠ Cache expired (age: {age/3600:.1f} hours)")
        except Exception as e:
            print(f"  ⚠ Error reading cache: {e}")

    return None


def save_to_cache(technique_id: str, data: Dict):
    """Save OSINT results to cache."""
    cache_key = get_cache_key(technique_id)
    cache_file = OSINT_CACHE_DIR / f"{cache_key}.json"

    try:
        cache_data = {
            "technique_id": technique_id,
            "cached_at": datetime.utcnow().isoformat(),
            "data": data
        }
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
        print(f"  ✓ Cached OSINT results")
    except Exception as e:
        print(f"  ⚠ Error saving cache: {e}")


def _entries_to_sources_and_indicators(entries: List[Dict], source_label: str) -> Tuple[List[str], List[Dict]]:
    """Convert prebuilt index entries into the (sources, indicators) shape the live searches return."""
    sources = [e["source_url"] for e in entries]
    indicators = [
        {
            "source": source_label,
            "source_url": e["source_url"],
            "rule_name": e["name"],
            "query_snippet": e["query_snippet"],
        }
        for e in entries
    ]
    return sources, indicators


def search_elastic_rules(technique_id: str) -> Tuple[List[str], List[Dict]]:
    """
    Look up Elastic Detection Rules for a technique.

    Uses the prebuilt OSINT technique index (archer.build.osint_index) when
    available, an O(1) lookup (build it with scripts/data/build_osint_index.py). Falls back to a live grep across the
    cloned repo if the index hasn't been built yet.

    Returns: (sources: List[str], indicators: List[Dict])
    """
    from .osint_index import load_index, lookup as index_lookup

    if load_index() is not None:
        entries = index_lookup(technique_id, "elastic")
        if entries:
            print(f"  \u2713 Found {len(entries)} Elastic rules for {technique_id} (from index)")
        return _entries_to_sources_and_indicators(entries, "Elastic")

    return _live_search_elastic_rules(technique_id)


def _live_search_elastic_rules(technique_id: str) -> Tuple[List[str], List[Dict]]:
    """
    Search Elastic Detection Rules repository (LOCAL).

    Returns: (sources: List[str], indicators: List[Dict])
    """
    from archer.build.osint_repos import search_repo_for_technique
    import toml

    sources = []
    indicators = []

    try:
        # Search local Elastic repository
        files = search_repo_for_technique("elastic", technique_id)

        if files:
            print(f"  ✓ Found {len(files)} Elastic rules for {technique_id}")

            # Process first few files
            for file_path in files[:15]:  # Increased from 5 to 15
                try:
                    # Elastic rules are in TOML format
                    with open(file_path, 'r') as f:
                        if file_path.endswith('.toml'):
                            rule_data = toml.load(f)
                        else:
                            continue

                    # Convert to GitHub URL
                    relative_path = file_path.replace(str(Path(OSINT_REPOS_DIR) / "elastic"), "")
                    # Ensure forward slashes for URLs (in case of Windows backslashes)
                    relative_path = relative_path.replace("\\", "/")
                    github_url = f"https://github.com/elastic/detection-rules/blob/main{relative_path}"
                    sources.append(github_url)

                    # Extract query/indicators
                    # Query is nested under rule.query in the TOML structure
                    rule_section = rule_data.get("rule", {})
                    query = rule_section.get("query", "")

                    if query:
                        indicators.append({
                            "source": "Elastic",
                            "source_url": github_url,  # Include the source URL
                            "rule_name": rule_section.get("name", file_path.split("/")[-1]),
                            "query_snippet": query[:500]  # Increased from 200 to 500 chars
                        })

                except Exception as e:
                    # Silent failure for individual files
                    continue

    except Exception as e:
        print(f"  ⚠ Error searching Elastic rules: {e}")

    return sources, indicators


def search_splunk_content(technique_id: str) -> Tuple[List[str], List[Dict]]:
    """
    Look up Splunk Security Content detections for a technique.

    Uses the prebuilt OSINT technique index (archer.build.osint_index) when
    available, an O(1) lookup (build it with scripts/data/build_osint_index.py). Falls back to a live grep across the
    cloned repo if the index hasn't been built yet.

    Returns: (sources: List[str], indicators: List[Dict])
    """
    from .osint_index import load_index, lookup as index_lookup

    if load_index() is not None:
        entries = index_lookup(technique_id, "splunk")
        if entries:
            print(f"  \u2713 Found {len(entries)} Splunk detections for {technique_id} (from index)")
        return _entries_to_sources_and_indicators(entries, "Splunk")

    return _live_search_splunk_content(technique_id)


def _live_search_splunk_content(technique_id: str) -> Tuple[List[str], List[Dict]]:
    """
    Search Splunk Security Content repository (LOCAL).

    Returns: (sources: List[str], indicators: List[Dict])
    """
    from archer.build.osint_repos import search_repo_for_technique

    sources = []
    indicators = []

    try:
        # Search local Splunk repository
        files = search_repo_for_technique("splunk", technique_id)

        if files:
            print(f"  ✓ Found {len(files)} Splunk detections for {technique_id}")

            # Process first few files
            for file_path in files[:15]:  # Increased from 5 to 15
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        detection_data = yaml_lib.safe_load(content)

                    # Convert to GitHub URL
                    relative_path = file_path.replace(str(Path(OSINT_REPOS_DIR) / "splunk"), "")
                    # Ensure forward slashes for URLs (in case of Windows backslashes)
                    relative_path = relative_path.replace("\\", "/")
                    github_url = f"https://github.com/splunk/security_content/blob/develop{relative_path}"
                    sources.append(github_url)

                    # Extract search query
                    search_query = detection_data.get("search", "")
                    if search_query:
                        indicators.append({
                            "source": "Splunk",
                            "source_url": github_url,  # Include the source URL
                            "detection_name": detection_data.get("name", file_path.split("/")[-1]),
                            "search_snippet": search_query[:500]  # Increased from 200 to 500 chars
                        })

                except Exception as e:
                    # Silent failure for individual files
                    continue

    except Exception as e:
        print(f"  ⚠ Error searching Splunk content: {e}")

    return sources, indicators


def search_azure_sentinel(technique_id: str) -> Tuple[List[str], List[Dict]]:
    """
    Look up Azure Sentinel rules for a technique.

    Uses the prebuilt OSINT technique index (archer.build.osint_index) when
    available, an O(1) lookup (build it with scripts/data/build_osint_index.py). Falls back to a live grep across the
    cloned repo if the index hasn't been built yet.

    Returns: (sources: List[str], indicators: List[Dict])
    """
    from .osint_index import load_index, lookup as index_lookup

    if load_index() is not None:
        entries = index_lookup(technique_id, "azure_sentinel")
        if entries:
            print(f"  \u2713 Found {len(entries)} Azure Sentinel rules for {technique_id} (from index)")
        return _entries_to_sources_and_indicators(entries, "Azure Sentinel")

    return _live_search_azure_sentinel(technique_id)


def _live_search_azure_sentinel(technique_id: str) -> Tuple[List[str], List[Dict]]:
    """
    Search Azure Sentinel repository (LOCAL).

    Returns: (sources: List[str], indicators: List[Dict])
    """
    from archer.build.osint_repos import search_repo_for_technique

    sources = []
    indicators = []

    try:
        # Search local Azure Sentinel repository
        files = search_repo_for_technique("azure_sentinel", technique_id)

        if files:
            print(f"  ✓ Found {len(files)} Azure Sentinel rules for {technique_id}")

            # Process first few files
            for file_path in files[:15]:  # Increased from 5 to 15
                try:
                    # Azure Sentinel rules can be in YAML or JSON
                    with open(file_path, 'r') as f:
                        content = f.read()

                    # Try YAML first, then JSON
                    try:
                        rule_data = yaml_lib.safe_load(content)
                    except:
                        import json
                        rule_data = json.loads(content)

                    # Convert to GitHub URL
                    relative_path = file_path.replace(str(Path(OSINT_REPOS_DIR) / "azure_sentinel"), "")
                    # Ensure forward slashes for URLs (in case of Windows backslashes)
                    relative_path = relative_path.replace("\\", "/")
                    github_url = f"https://github.com/Azure/Azure-Sentinel/blob/master{relative_path}"
                    sources.append(github_url)

                    # Extract query
                    query = rule_data.get("query", rule_data.get("Query", ""))
                    if query:
                        indicators.append({
                            "source": "Azure Sentinel",
                            "rule_name": rule_data.get("name", rule_data.get("displayName", file_path.split("/")[-1])),
                            "query_snippet": query[:500]  # Increased from 200 to 500 chars
                        })

                except Exception as e:
                    # Silent failure for individual files
                    continue

    except Exception as e:
        print(f"  ⚠ Error searching Azure Sentinel: {e}")

    return sources, indicators


def extract_indicators_from_sources(indicators_data: List[Dict]) -> Dict[str, List[str]]:
    """
    Extract actual IOCs/patterns from the found sources.

    Returns: Dictionary of indicator types and values matching Splunk schema:
    - cmd: command line indicators
    - sw: software/process indicators (files and processes)
    - reg: registry indicators
    - evt: event codes
    """
    extracted = {
        "cmd": [],
        "sw": [],
        "reg": [],
        "query_snippets": []
    }

    for indicator_info in indicators_data:
        source = indicator_info.get("source", "")

        # Extract indicators (strip backslashes from all indicators)
        if "cmd" in indicator_info:
            extracted["cmd"].extend([x.replace('\\', '') for x in indicator_info["cmd"]])
        if "file" in indicator_info:
            extracted["sw"].extend([x.replace('\\', '') for x in indicator_info["file"]])  # Process images go to sw (software)
        if "target_files" in indicator_info:
            extracted["sw"].extend([x.replace('\\', '') for x in indicator_info["target_files"]])  # Target files also go to sw
        if "registry" in indicator_info:
            extracted["reg"].extend([x.replace('\\', '') for x in indicator_info["registry"]])

        # Extract from Elastic/Splunk query snippets
        # Format: [Source] snippet|||source_url (using ||| as delimiter)
        if "query_snippet" in indicator_info:
            snippet = indicator_info["query_snippet"]
            source_url = indicator_info.get("source_url", "")
            if snippet and len(snippet) > 20:  # Only include meaningful snippets
                # Remove newlines and extra whitespace to keep snippet on one line
                snippet = " ".join(snippet.split())
                extracted["query_snippets"].append(f"[{source}] {snippet}|||{source_url}")

        if "search_snippet" in indicator_info:
            snippet = indicator_info["search_snippet"]
            source_url = indicator_info.get("source_url", "")
            if snippet and len(snippet) > 20:
                # Remove newlines and extra whitespace to keep snippet on one line
                snippet = " ".join(snippet.split())
                extracted["query_snippets"].append(f"[{source}] {snippet}|||{source_url}")

    # Remove duplicates and empty values, limit to reasonable numbers
    for key in extracted:
        extracted[key] = list(set([x for x in extracted[key] if x]))[:100]  # Max 100 per category

    # Remove empty categories
    extracted = {k: v for k, v in extracted.items() if v}

    return extracted


def search_osint_for_technique(
    technique_id: str,
    technique_name: str,
    technique_description: str,
    platforms: List[str]
) -> Tuple[bool, Dict]:
    """
    Search OSINT sources for additional detection methods for a technique.

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1078")
        technique_name: Technique name (e.g., "Valid Accounts")
        technique_description: Description of the technique from MITRE
        platforms: List of applicable platforms (e.g., ["Windows", "Linux"])

    Returns:
        Tuple of (found: bool, enrichment_data: dict)
    """
    # OSINT repos should be cloned/updated manually or during app initialization
    # Not during detection generation to avoid blocking
    # from archer.build.osint_repos import ensure_repos_ready
    # ensure_repos_ready()

    # Check cache first
    cached_result = load_from_cache(technique_id)
    if cached_result:
        # Return cached result
        is_enriched = cached_result.get("osint_compared", False)
        return is_enriched, cached_result

    enrichment_data = {
        "osint_compared": False,
        "osint_sources": [],
        "osint_indicators": {},
        "comparison_date": datetime.utcnow().isoformat() + "Z",
        "enrichment_notes": ""
    }

    all_sources = []
    all_indicators_data = []
    notes = []

    # 1. Search Elastic Detection Rules
    print(f"  Searching Elastic Detection Rules...")
    elastic_sources, elastic_indicators = search_elastic_rules(technique_id)
    if elastic_sources:
        all_sources.extend(elastic_sources)
        all_indicators_data.extend(elastic_indicators)
        notes.append(f"Found {len(elastic_sources)} Elastic rule(s)")

    # 2. Search Splunk Security Content
    print(f"  Searching Splunk Security Content...")
    splunk_sources, splunk_indicators = search_splunk_content(technique_id)
    if splunk_sources:
        all_sources.extend(splunk_sources)
        all_indicators_data.extend(splunk_indicators)
        notes.append(f"Found {len(splunk_sources)} Splunk detection(s)")

    # 3. Search Azure Sentinel
    print(f"  Searching Azure Sentinel...")
    sentinel_sources, sentinel_indicators = search_azure_sentinel(technique_id)
    if sentinel_sources:
        all_sources.extend(sentinel_sources)
        all_indicators_data.extend(sentinel_indicators)
        notes.append(f"Found {len(sentinel_sources)} Azure Sentinel rule(s)")

    # Extract actual indicators from found sources
    if all_indicators_data:
        extracted_indicators = extract_indicators_from_sources(all_indicators_data)

        # Only include indicator types that have values
        for ind_type, values in extracted_indicators.items():
            if values:
                enrichment_data["osint_indicators"][ind_type] = values

    # Determine if enrichment was successful
    if all_sources:
        enrichment_data["osint_compared"] = True
        enrichment_data["osint_sources"] = all_sources[:10]  # Limit to 10 sources
        enrichment_data["enrichment_notes"] = "; ".join(notes)

        print(f"  ✅ OSINT enrichment successful: {len(all_sources)} sources found")
        if enrichment_data["osint_indicators"]:
            total_indicators = sum(len(v) for v in enrichment_data["osint_indicators"].values())
            print(f"  ✅ Extracted {total_indicators} indicators from sources")

        # Cache the successful result
        save_to_cache(technique_id, enrichment_data)

        return True, enrichment_data
    else:
        print(f"  ❌ No OSINT sources found for {technique_id}")

        # Cache the negative result too (to avoid repeated failed searches)
        save_to_cache(technique_id, enrichment_data)

        return False, enrichment_data


def should_create_detection(has_mitre_indicators: bool, osint_found: bool) -> bool:
    """
    Determine if a detection should be created based on available indicators.

    Args:
        has_mitre_indicators: True if indicators were extracted from MITRE
        osint_found: True if OSINT enrichment found detection methods

    Returns:
        True if detection should be created, False otherwise

    Logic:
        - MITRE indicators exist: Create detection (normal flow)
        - No MITRE indicators but OSINT found: Create detection (with orange badge)
        - No MITRE indicators and no OSINT: DO NOT create detection
    """
    if has_mitre_indicators:
        return True  # Normal detection creation
    elif osint_found:
        return True  # Create with OSINT enrichment
    else:
        return False  # Skip creation entirely


# Color coding for badges:
# YELLOW: "Needs Review" - detections with indicators but may need validation
# ORANGE: "Needs Review - compared with additional OSINT sources" - detections created from OSINT only
# (No badge): Normal detections with indicators from MITRE


def filter_osint_indicators_by_relevance(
    osint_indicators: Dict[str, List[str]],
    technique_id: str,
    platform: str,
    min_relevance_score: float = 0.7
) -> Dict[str, List[str]]:
    """
    Filter OSINT indicators by relevance to technique and platform.

    Uses platform_indicator_validator to check if indicators are valid for the
    technique and platform combination.

    Args:
        osint_indicators: Dict of {indicator_type: [values]}
        technique_id: MITRE ATT&CK technique ID
        platform: Target platform (Windows, Linux, Azure AD, AWS, etc.)
        min_relevance_score: Minimum score to include (0.0-1.0)

    Returns:
        Filtered indicators dict with only relevant indicators
    """
    try:
        from .platform_indicator_validator import validate_indicators_for_platform

        # Validate all indicators
        _, error_messages, filtered_indicators = validate_indicators_for_platform(
            osint_indicators,
            platform,
            technique_id
        )

        if error_messages:
            logger.info(f"Filtered {len(error_messages)} OSINT indicators for {technique_id} on {platform}")
            for msg in error_messages[:3]:
                logger.debug(f"  - {msg}")

        return filtered_indicators

    except ImportError:
        logger.warning("Platform indicator validator not available, skipping OSINT filtering")
        return osint_indicators


def score_osint_indicator_relevance(
    indicator: str,
    indicator_type: str,
    technique_id: str,
    platform: str,
    osint_source: str = ""
) -> float:
    """
    Score how relevant an OSINT indicator is to the current detection.

    Returns 0.0-1.0 where:
    - 1.0 = Perfect match (valid for technique and platform)
    - 0.5 = Partial match (valid for technique but generic)
    - 0.0 = Invalid (wrong platform or unrelated)

    Args:
        indicator: The indicator value
        indicator_type: Type (cmd, evt, sw, api, operation)
        technique_id: MITRE ATT&CK technique ID
        platform: Target platform
        osint_source: Source of the indicator (Elastic, Splunk, Sentinel)

    Returns:
        Relevance score (0.0-1.0)
    """
    try:
        from .platform_indicator_validator import validate_indicator_for_platform

        # Check if indicator is valid for this technique/platform
        is_valid, reason = validate_indicator_for_platform(
            indicator,
            indicator_type,
            platform,
            technique_id
        )

        if not is_valid:
            # Invalid indicator = 0 score
            return 0.0

        # Valid indicator = base score of 0.7
        score = 0.7

        # Boost score for specific sources
        if "Elastic" in osint_source:
            score += 0.1  # Elastic rules are well-tested

        # Cap at 1.0
        return min(score, 1.0)

    except ImportError:
        # Can't validate, return neutral score
        return 0.5


def extract_operations_from_osint_snippets(osint_indicators: Dict) -> Dict[str, List[str]]:
    """
    Extract structured API calls from OSINT query snippets.

    This function parses query snippets to extract Azure operations, AWS API calls,
    and other structured indicators that can be used directly in Splunk queries.

    Args:
        osint_indicators: Dictionary from OSINT comparison containing 'query_snippets'

    Returns:
        Dictionary with structured indicators by type:
        - api: Azure operations (operation_name, operationName) and AWS API calls (event_name, api_call)
        - cmd: Command line patterns
    """
    structured_indicators = {}

    if not osint_indicators or "query_snippets" not in osint_indicators:
        return structured_indicators

    api_patterns = []  # Combined Azure operations and AWS API calls
    cmd_patterns = []

    for snippet_entry in osint_indicators["query_snippets"]:
        # Format: [Source] snippet|||source_url
        if "|||" not in snippet_entry:
            continue

        snippet = snippet_entry.split("|||")[0]

        # Extract Azure operations from operation_name or operationName fields
        # Patterns: operation_name:"Add member to role", operationName="Update role setting in PIM"
        azure_op_patterns = [
            r'operation_name[=:]"([^"]+)"',
            r'operationName[=:]"([^"]+)"',
            r'operation_name[=:]([A-Z][A-Za-z\s]+)',
            r'operationName[=:]([A-Z][A-Za-z\s]+)'
        ]

        for pattern in azure_op_patterns:
            matches = re.findall(pattern, snippet)
            for match in matches:
                # Clean up the operation name (strip backslashes)
                op = match.strip().replace('\\', '')
                if len(op) > 5 and not op.startswith("*"):  # Valid operation names
                    api_patterns.append(op)

        # Extract Azure activity_display_name or activityDisplayName
        activity_patterns = [
            r'activity_display_name[=:]"([^"]+)"',
            r'activityDisplayName[=:]"([^"]+)"'
        ]

        for pattern in activity_patterns:
            matches = re.findall(pattern, snippet)
            for match in matches:
                op = match.strip().replace('\\', '')
                if len(op) > 5 and not op.startswith("*"):
                    api_patterns.append(op)

        # Extract AWS API calls from event.action or eventName
        aws_api_patterns = [
            r'event\.action[=:]"?([A-Z][A-Za-z]+)"?',
            r'eventName[=:]"?([A-Z][A-Za-z]+)"?',
            r'api\.operation[=:]"?([A-Z][A-Za-z]+)"?'
        ]

        for pattern in aws_api_patterns:
            matches = re.findall(pattern, snippet)
            for match in matches:
                api = match.strip().replace('\\', '')
                # AWS API calls typically start with uppercase
                if len(api) > 3 and api[0].isupper():
                    api_patterns.append(api)

        # Extract command line patterns from process or command fields
        cmd_field_patterns = [
            r'process[=:]"([^"]+)"',
            r'command[=:]"([^"]+)"',
            r'CommandLine[=:]"([^"]+)"'
        ]

        for pattern in cmd_field_patterns:
            matches = re.findall(pattern, snippet)
            for match in matches:
                cmd = match.strip().replace('\\', '')
                if len(cmd) > 3:
                    cmd_patterns.append(cmd)

    # Remove duplicates and add to structured indicators
    if api_patterns:
        structured_indicators["api"] = list(set(api_patterns))
    if cmd_patterns:
        structured_indicators["cmd"] = list(set(cmd_patterns))

    return structured_indicators

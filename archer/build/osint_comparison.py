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
   - GitHub repositories (sigma rules, detection-as-code repos)
   - MITRE CAR (Cyber Analytics Repository)
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
OSINT_CACHE_DIR = Path("data/osint_cache")
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


def search_sigma_rules(technique_id: str) -> Tuple[List[str], List[Dict]]:
    """
    Search Sigma rules repository (LOCAL) for detections related to a technique.

    Returns: (sources: List[str], indicators: List[Dict])
    """
    from archer.build.osint_repos import search_repo_for_technique

    sources = []
    indicators = []

    try:
        # Search local Sigma repository
        files = search_repo_for_technique("sigma", technique_id)

        if files:
            print(f"  ✓ Found {len(files)} Sigma rules for {technique_id}")

            # Process first few files to extract indicators
            for file_path in files[:5]:  # Limit to first 5 rules
                try:
                    with open(file_path, 'r') as f:
                        rule_content = f.read()
                        rule_data = yaml_lib.safe_load(rule_content)

                    # Convert to GitHub URL
                    relative_path = file_path.replace(str(Path("data/osint_repos/sigma")), "")
                    github_url = f"https://github.com/SigmaHQ/sigma/blob/master{relative_path}"
                    sources.append(github_url)

                    # Extract indicators from Sigma rule
                    detection = rule_data.get("detection", {})
                    if detection:
                        # Extract patterns from all selection blocks
                        cmd_patterns = []
                        image_patterns = []
                        file_patterns = []
                        registry_patterns = []

                        for key, value in detection.items():
                            if isinstance(value, dict):
                                # Check what fields are in this selection block
                                fields_in_block = set()
                                for field_key in value.keys():
                                    # Extract base field name (before pipe modifier)
                                    base_field = field_key.split('|')[0].lower()
                                    fields_in_block.add(base_field)

                                # Categorize based on field names
                                if any(f in fields_in_block for f in ['commandline', 'command', 'processcommandline']):
                                    cmd_patterns.extend(extract_sigma_patterns(value))
                                if any(f in fields_in_block for f in ['image', 'process', 'processname', 'newprocessname']):
                                    image_patterns.extend(extract_sigma_patterns(value))
                                if any(f in fields_in_block for f in ['targetfilename', 'filename', 'filepath']):
                                    file_patterns.extend(extract_sigma_patterns(value))
                                if any(f in fields_in_block for f in ['targetobject', 'registrykey', 'registryvaluename']):
                                    registry_patterns.extend(extract_sigma_patterns(value))

                        if cmd_patterns or image_patterns or file_patterns or registry_patterns:
                            indicator_data = {
                                "source": "Sigma",
                                "rule_name": rule_data.get("title", file_path.split("/")[-1])
                            }
                            if cmd_patterns:
                                indicator_data["cmd"] = cmd_patterns[:5]  # Limit to 5
                            if image_patterns:
                                indicator_data["file"] = image_patterns[:5]
                            if file_patterns:
                                indicator_data["target_files"] = file_patterns[:5]
                            if registry_patterns:
                                indicator_data["registry"] = registry_patterns[:5]

                            indicators.append(indicator_data)

                except Exception as e:
                    # Silent failure for individual files
                    continue

    except Exception as e:
        print(f"  ⚠ Error searching Sigma rules: {e}")

    return sources, indicators


def extract_sigma_patterns(detection_dict: dict) -> list:
    """
    Extract patterns from Sigma detection dict.
    Handles Sigma field modifiers like |contains, |endswith, etc.
    """
    patterns = []

    for key, value in detection_dict.items():
        # Skip condition and filter keys
        if key in ['condition', 'filter', 'timeframe']:
            continue

        # Handle list values
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item:
                    # Clean up the value (remove special chars if too many)
                    cleaned = item.strip()
                    if len(cleaned) > 2 and cleaned not in ['*', '?', '-']:
                        patterns.append(cleaned)
        # Handle string values
        elif isinstance(value, str) and value:
            cleaned = value.strip()
            if len(cleaned) > 2 and cleaned not in ['*', '?', '-']:
                patterns.append(cleaned)
        # Handle nested dicts (common in Sigma selection blocks)
        elif isinstance(value, dict):
            patterns.extend(extract_sigma_patterns(value))

    return patterns


def search_mitre_car(technique_id: str) -> Tuple[List[str], List[Dict]]:
    """
    Search MITRE CAR (Cyber Analytics Repository) for analytics.

    Returns: (sources: List[str], indicators: List[Dict])
    """
    sources = []
    indicators = []

    try:
        # MITRE CAR analytics API
        url = f"https://raw.githubusercontent.com/mitre-attack/car/master/analytics.json"

        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            analytics = response.json()

            # Search for technique ID in analytics
            for analytic_id, analytic_data in analytics.items():
                coverage = analytic_data.get("coverage", [])
                for cov in coverage:
                    if isinstance(cov, dict) and cov.get("technique") == technique_id:
                        print(f"  ✓ Found MITRE CAR analytic: {analytic_id}")
                        sources.append(f"https://car.mitre.org/analytics/{analytic_id}")

                        # Extract pseudocode/implementations
                        implementations = analytic_data.get("implementations", [])
                        if implementations:
                            indicators.append({
                                "source": "MITRE CAR",
                                "analytic_id": analytic_id,
                                "name": analytic_data.get("title", ""),
                                "implementations": len(implementations)
                            })
                        break

        time.sleep(0.5)  # Rate limiting

    except Exception as e:
        print(f"  ⚠ Error searching MITRE CAR: {e}")

    return sources, indicators


def search_elastic_rules(technique_id: str) -> Tuple[List[str], List[Dict]]:
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
            for file_path in files[:5]:  # Limit to first 5
                try:
                    # Elastic rules are in TOML format
                    with open(file_path, 'r') as f:
                        if file_path.endswith('.toml'):
                            rule_data = toml.load(f)
                        else:
                            continue

                    # Convert to GitHub URL
                    relative_path = file_path.replace(str(Path("data/osint_repos/elastic")), "")
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
                            "query_snippet": query[:200]  # First 200 chars
                        })

                except Exception as e:
                    # Silent failure for individual files
                    continue

    except Exception as e:
        print(f"  ⚠ Error searching Elastic rules: {e}")

    return sources, indicators


def search_splunk_content(technique_id: str) -> Tuple[List[str], List[Dict]]:
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
            for file_path in files[:5]:  # Limit to first 5
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        detection_data = yaml_lib.safe_load(content)

                    # Convert to GitHub URL
                    relative_path = file_path.replace(str(Path("data/osint_repos/splunk")), "")
                    github_url = f"https://github.com/splunk/security_content/blob/develop{relative_path}"
                    sources.append(github_url)

                    # Extract search query
                    search_query = detection_data.get("search", "")
                    if search_query:
                        indicators.append({
                            "source": "Splunk",
                            "source_url": github_url,  # Include the source URL
                            "detection_name": detection_data.get("name", file_path.split("/")[-1]),
                            "search_snippet": search_query[:200]
                        })

                except Exception as e:
                    # Silent failure for individual files
                    continue

    except Exception as e:
        print(f"  ⚠ Error searching Splunk content: {e}")

    return sources, indicators


def search_azure_sentinel(technique_id: str) -> Tuple[List[str], List[Dict]]:
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
            for file_path in files[:5]:  # Limit to first 5
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
                    relative_path = file_path.replace(str(Path("data/osint_repos/azure_sentinel")), "")
                    github_url = f"https://github.com/Azure/Azure-Sentinel/blob/master{relative_path}"
                    sources.append(github_url)

                    # Extract query
                    query = rule_data.get("query", rule_data.get("Query", ""))
                    if query:
                        indicators.append({
                            "source": "Azure Sentinel",
                            "rule_name": rule_data.get("name", rule_data.get("displayName", file_path.split("/")[-1])),
                            "query_snippet": query[:200]
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

        # Extract from Sigma indicators
        if "cmd" in indicator_info:
            extracted["cmd"].extend(indicator_info["cmd"])
        if "file" in indicator_info:
            extracted["sw"].extend(indicator_info["file"])  # Process images go to sw (software)
        if "target_files" in indicator_info:
            extracted["sw"].extend(indicator_info["target_files"])  # Target files also go to sw
        if "registry" in indicator_info:
            extracted["reg"].extend(indicator_info["registry"])

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
        extracted[key] = list(set([x for x in extracted[key] if x]))[:15]  # Max 15 per category

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
    print(f"🔍 OSINT Comparison: Searching for detection methods for {technique_id} ({technique_name})")

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

    # 1. Search Sigma Rules
    print(f"  Searching Sigma rules...")
    sigma_sources, sigma_indicators = search_sigma_rules(technique_id)
    if sigma_sources:
        all_sources.extend(sigma_sources)
        all_indicators_data.extend(sigma_indicators)
        notes.append(f"Found {len(sigma_sources)} Sigma rule(s)")

    # 2. Search MITRE CAR
    print(f"  Searching MITRE CAR...")
    car_sources, car_indicators = search_mitre_car(technique_id)
    if car_sources:
        all_sources.extend(car_sources)
        all_indicators_data.extend(car_indicators)
        notes.append(f"Found {len(car_sources)} MITRE CAR analytic(s)")

    # 3. Search Elastic Detection Rules
    print(f"  Searching Elastic Detection Rules...")
    elastic_sources, elastic_indicators = search_elastic_rules(technique_id)
    if elastic_sources:
        all_sources.extend(elastic_sources)
        all_indicators_data.extend(elastic_indicators)
        notes.append(f"Found {len(elastic_sources)} Elastic rule(s)")

    # 4. Search Splunk Security Content
    print(f"  Searching Splunk Security Content...")
    splunk_sources, splunk_indicators = search_splunk_content(technique_id)
    if splunk_sources:
        all_sources.extend(splunk_sources)
        all_indicators_data.extend(splunk_indicators)
        notes.append(f"Found {len(splunk_sources)} Splunk detection(s)")

    # 5. Search Azure Sentinel
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

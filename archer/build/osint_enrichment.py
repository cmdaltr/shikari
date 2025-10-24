"""
OSINT Enrichment Module

This module provides functionality to enrich detections with additional open-source
intelligence when MITRE ATT&CK data doesn't provide sufficient indicators.

REQUIREMENTS:
1. When a detection has 0 indicators extracted from MITRE:
   - Search additional OSINT sources for detection methods
   - If found: Create detection marked "Needs Review - enriched with additional OSINT" (orange badge)
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
   - osint_enriched: bool (True if enriched with OSINT)
   - osint_sources: list[str] (URLs/references to OSINT sources used)
   - osint_indicators: dict (Any indicators found from OSINT)
   - enrichment_date: str (ISO timestamp of when enrichment was performed)

4. Integration Points:
   - Call from compile_query() in detections.py when identifiers == {} or None
   - Store metadata in YAML file via construct_yaml()
   - Display orange badge in results.html for osint_enriched=True detections
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
    Search Sigma rules repository for detections related to a technique.

    Returns: (sources: List[str], indicators: List[Dict])
    """
    sources = []
    indicators = []

    try:
        # Search GitHub Sigma repository
        url = f"https://api.github.com/search/code?q={technique_id}+in:file+repo:SigmaHQ/sigma+path:rules"
        headers = {"Accept": "application/vnd.github.v3+json"}

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            if data.get("total_count", 0) > 0:
                print(f"  ✓ Found {data['total_count']} Sigma rules for {technique_id}")

                # Get first few results
                for item in data.get("items", [])[:3]:
                    sources.append(item["html_url"])

                    # Try to fetch the file content to extract indicators
                    try:
                        file_url = item["url"]
                        file_resp = requests.get(file_url, headers=headers, timeout=10)
                        if file_resp.status_code == 200:
                            content = file_resp.json().get("content", "")
                            # Decode base64 content
                            import base64
                            decoded = base64.b64decode(content).decode('utf-8')

                            # Extract selection patterns from Sigma rules
                            if "selection:" in decoded or "CommandLine:" in decoded or "Image:" in decoded:
                                # Found potential indicators
                                indicators.append({
                                    "source": "Sigma",
                                    "rule_name": item["name"],
                                    "content": decoded[:500]  # First 500 chars
                                })
                    except Exception as e:
                        print(f"    Warning: Could not fetch Sigma rule content: {e}")
                        continue

        elif response.status_code == 403:
            print(f"  ⚠ GitHub API rate limit reached - skipping Sigma search")

        time.sleep(0.5)  # Rate limiting

    except Exception as e:
        print(f"  ⚠ Error searching Sigma rules: {e}")

    return sources, indicators


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
    Search Elastic Detection Rules repository.

    Returns: (sources: List[str], indicators: List[Dict])
    """
    sources = []
    indicators = []

    try:
        # Search GitHub Elastic detection-rules repository
        url = f"https://api.github.com/search/code?q={technique_id}+in:file+repo:elastic/detection-rules+path:rules"
        headers = {"Accept": "application/vnd.github.v3+json"}

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            if data.get("total_count", 0) > 0:
                print(f"  ✓ Found {data['total_count']} Elastic rules for {technique_id}")

                # Get first few results
                for item in data.get("items", [])[:2]:
                    sources.append(item["html_url"])
                    indicators.append({
                        "source": "Elastic",
                        "rule_name": item["name"]
                    })

        elif response.status_code == 403:
            print(f"  ⚠ GitHub API rate limit reached - skipping Elastic search")

        time.sleep(0.5)  # Rate limiting

    except Exception as e:
        print(f"  ⚠ Error searching Elastic rules: {e}")

    return sources, indicators


def extract_indicators_from_sources(indicators_data: List[Dict]) -> Dict[str, List[str]]:
    """
    Extract actual IOCs/patterns from the found sources.

    Returns: Dictionary of indicator types and values
    """
    extracted = {
        "cmd": [],
        "file": [],
        "reg": [],
        "net": [],
        "evt": []
    }

    for indicator_info in indicators_data:
        content = indicator_info.get("content", "")

        if not content:
            continue

        # Extract command line patterns
        cmd_patterns = re.findall(r'CommandLine[:|=]\s*[\'"]([^\'"]+)[\'"]', content, re.IGNORECASE)
        extracted["cmd"].extend(cmd_patterns[:3])  # Limit to 3

        # Extract file paths
        file_patterns = re.findall(r'Image[:|=]\s*[\'"]([^\'"]+)[\'"]', content, re.IGNORECASE)
        file_patterns += re.findall(r'TargetFilename[:|=]\s*[\'"]([^\'"]+)[\'"]', content, re.IGNORECASE)
        extracted["file"].extend(file_patterns[:3])

        # Extract process names
        process_patterns = re.findall(r'(?:ProcessName|process)[:|=]\s*[\'"]([^\'"]+)[\'"]', content, re.IGNORECASE)
        extracted["cmd"].extend(process_patterns[:2])

    # Remove duplicates and empty values
    for key in extracted:
        extracted[key] = list(set([x for x in extracted[key] if x]))

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
    print(f"🔍 OSINT Enrichment: Searching for detection methods for {technique_id} ({technique_name})")

    # Check cache first
    cached_result = load_from_cache(technique_id)
    if cached_result:
        # Return cached result
        is_enriched = cached_result.get("osint_enriched", False)
        return is_enriched, cached_result

    enrichment_data = {
        "osint_enriched": False,
        "osint_sources": [],
        "osint_indicators": {},
        "enrichment_date": datetime.utcnow().isoformat() + "Z",
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

    # Extract actual indicators from found sources
    if all_indicators_data:
        extracted_indicators = extract_indicators_from_sources(all_indicators_data)

        # Only include indicator types that have values
        for ind_type, values in extracted_indicators.items():
            if values:
                enrichment_data["osint_indicators"][ind_type] = values

    # Determine if enrichment was successful
    if all_sources:
        enrichment_data["osint_enriched"] = True
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
# ORANGE: "Needs Review - enriched with additional OSINT" - detections created from OSINT only
# (No badge): Normal detections with indicators from MITRE

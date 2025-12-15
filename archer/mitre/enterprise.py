#!/usr/bin/env python3 -tt
from .extract import extract_red, extract_blue
import re
import requests
import stix2
from pathlib import Path
from datetime import datetime, timedelta


def get_stix_data(url, cache_days=7):
    """
    Fetch MITRE ATT&CK STIX data with local caching.

    Args:
        url: URL to fetch STIX data from
        cache_days: Number of days to cache the data (default: 7)

    Returns:
        STIX bundle object
    """
    # Create cache directory inside the archer application
    # Use __file__ to find the archer module directory, then go up to project root
    archer_module_dir = Path(__file__).parent.parent
    cache_dir = archer_module_dir / "data" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Create cache file path based on URL
    cache_filename = url.split("/")[-1]
    cache_path = cache_dir / cache_filename

    # Check if cache exists and is fresh
    if cache_path.exists():
        cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        if cache_age < timedelta(days=cache_days):
            try:
                print(f"Loading MITRE ATT&CK data from cache ({cache_path})")
                with open(cache_path, "r", encoding="utf-8") as f:
                    return stix2.parse(f.read(), allow_custom=True)
            except Exception as e:
                print(f"Cache read error: {e}, fetching fresh data...")

    # Try to fetch from network
    try:
        # First attempt with SSL verification
        print(f"Fetching MITRE ATT&CK data from {url}...")
        response = requests.get(url, verify=True, timeout=30)
        response.raise_for_status()
        print("✓ MITRE ATT&CK data fetched with SSL verification")

        # Save to cache
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(response.text)
            print(f"Cached MITRE ATT&CK data to {cache_path}")
        except Exception as e:
            print(f"Warning: Could not cache data: {e}")

        # Load the STIX bundle
        return stix2.parse(response.text, allow_custom=True)

    except requests.exceptions.SSLError as ssl_err:
        # Fallback: retry without SSL verification
        import warnings
        warnings.warn(f"SSL verification failed: {ssl_err}. Retrying without SSL verification...")
        print("⚠️  SSL verification failed, retrying without verification")
        try:
            response = requests.get(url, verify=False, timeout=30)
            response.raise_for_status()
            print("✓ MITRE ATT&CK data fetched (SSL verification disabled)")

            # Save to cache
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    f.write(response.text)
                print(f"Cached MITRE ATT&CK data to {cache_path}")
            except Exception as e:
                print(f"Warning: Could not cache data: {e}")

            # Load the STIX bundle
            return stix2.parse(response.text, allow_custom=True)

        except Exception as e2:
            print(f"❌ Failed to fetch MITRE ATT&CK data even without SSL: {e2}")
            raise

    except (requests.RequestException, requests.exceptions.ConnectionError) as e:
        # Network error - try to use stale cache if available
        print(f"Network error fetching MITRE data: {e}")
        if cache_path.exists():
            print(f"Using stale cache from {cache_path}")
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    return stix2.parse(f.read(), allow_custom=True)
            except Exception as cache_err:
                print(f"Error reading stale cache: {cache_err}")

        # No cache available
        raise ConnectionError(
            f"Unable to fetch MITRE ATT&CK data and no cache available. "
            f"Please check your internet connection or download the file manually to {cache_path}"
        ) from e


def obtain_all_techniques(bundle):
    techniques = []
    for obj in bundle.objects:
        if obj.get("type") == "attack-pattern":
            technique_name = obj.get("name")
            external_id = [
                ref["external_id"]
                for ref in obj.get("external_references", [])
                if "external_id" in ref
            ]
            techniques.append(f"{external_id[0]}: {technique_name}")
    techniques = sorted(list(set(techniques)))  # Remove duplicates

    return techniques


def obtain_technique_descriptions(bundle):
    descriptions = []
    for obj in bundle.objects:
        if obj.get("type") == "attack-pattern":
            technique_description = obj.get("description")
            external_id = [
                ref["external_id"]
                for ref in obj.get("external_references", [])
                if "external_id" in ref
            ]
            descriptions.append(f"{external_id[0]}: {technique_description}")
    descriptions = sorted(list(set(descriptions)))  # Remove duplicates

    return descriptions


def check_group_in_mitre(bundle, group):
    for obj in bundle.objects:
        if obj.get("type") == "intrusion-set":
            group_name = obj.get("name").lower()
            aliases = str(obj.get("aliases")).lower()
            if group.lower() == group_name or group.lower() in aliases:
                return "Y"

    return "N"


def find_procedure_evidence(group_procedure_desc, procedure_desc, detection):
    combined_desc = f"{group_procedure_desc}\n\n{procedure_desc}"
    # add this information to the red/blue team sections of the Template Test Case
    red_info = extract_red(combined_desc)
    blue_info = extract_blue(combined_desc, detection)

    return red_info, blue_info


def consolidate_tactics(phases):
    tactics = []
    phase_names = re.findall(
        r"kill_chain_name='mitre-attack', phase_name='([^']+)", str(phases)
    )
    for phase_name in phase_names:
        tactics.append(phase_name.title().replace("-", " ").replace("_", " "))

    return sorted(list(set(tactics)))


def merge_detect_guidance(data_source, blue_info):
    data_sources = []
    detection_sources = re.findall(r"'[^:]+: ([^']+)'", str(data_source))
    for source in detection_sources:
        data_sources.append(source)

    return (data_sources, blue_info)

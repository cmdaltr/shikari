#!/usr/bin/env python3 -tt
from .extract import extract_red, extract_blue
import json
import re
import time
import requests
import stix2
from pathlib import Path
from datetime import datetime, timedelta
from archer import paths


# What the last load found: the ATT&CK version in use, the one before it, and where it
# came from. The server shows it and acts on a version change (archer.app startup).
LAST_LOAD: dict = {}


def _cache_path(url) -> Path:
    cache_dir = paths.CACHE
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / url.split("/")[-1]


def _meta_path(cache_path: Path) -> Path:
    return cache_path.with_name(cache_path.name + ".meta.json")


def _read_meta(cache_path: Path) -> dict:
    try:
        return json.loads(_meta_path(cache_path).read_text())
    except (OSError, ValueError):
        return {}


def _write_meta(cache_path: Path, meta: dict) -> None:
    try:
        _meta_path(cache_path).write_text(json.dumps(meta, indent=2))
    except OSError as e:
        print(f"Warning: could not record the ATT&CK cache state: {e}")


def bundle_version(text: str) -> str:
    """x_mitre_version of the bundle's collection object, e.g. "19.2" ("" if none)."""
    m = re.search(r'"type":\s*"x-mitre-collection".*?"x_mitre_version":\s*"([^"]+)"', text, re.S)
    if not m:
        m = re.search(r'"x_mitre_version":\s*"([^"]+)"[^{}]*"type":\s*"x-mitre-collection"', text, re.S)
    return m.group(1) if m else ""


def _parse(text: str, cache_path: Path, source: str, previous: str = ""):
    version = bundle_version(text)
    LAST_LOAD.clear()
    LAST_LOAD.update(version=version, previous=previous or version, source=source,
                     updated=bool(previous) and previous != version, cache_path=str(cache_path))
    return stix2.parse(text, allow_custom=True)


def get_stix_data(url, cache_days=7, check_latest=False):
    """
    Fetch MITRE ATT&CK STIX data with local caching.

    check_latest (server startup): always ask upstream whether there's a newer bundle,
    with the cached ETag/Last-Modified, so an unchanged bundle costs one small request.
    Otherwise the cache is used while it was fetched or confirmed within cache_days.
    Offline, or behind a failing TLS proxy, the cache is used however old it is.
    """
    cache_path = _cache_path(url)
    meta = _read_meta(cache_path)
    previous = meta.get("version", "")

    def from_cache(note):
        print(f"Loading MITRE ATT&CK data from cache ({cache_path}){note}")
        with open(cache_path, "r", encoding="utf-8") as f:
            return _parse(f.read(), cache_path, "cache", previous)

    if cache_path.exists() and not check_latest:
        checked = max(cache_path.stat().st_mtime, meta.get("checked", 0))
        if datetime.now() - datetime.fromtimestamp(checked) < timedelta(days=cache_days):
            try:
                return from_cache("")
            except Exception as e:
                print(f"Cache read error: {e}, fetching fresh data...")

    headers = {}
    if cache_path.exists():
        if meta.get("etag"):
            headers["If-None-Match"] = meta["etag"]
        if meta.get("last_modified"):
            headers["If-Modified-Since"] = meta["last_modified"]

    try:
        print(f"Checking for the latest MITRE ATT&CK data at {url}...")
        response = requests.get(url, verify=True, timeout=30, headers=headers)
        if response.status_code == 304 and cache_path.exists():
            meta["checked"] = time.time()
            _write_meta(cache_path, meta)
            return from_cache(f": unchanged upstream (ATT&CK v{previous})" if previous else ": unchanged upstream")
        response.raise_for_status()
        version = bundle_version(response.text)
        print(f"✓ MITRE ATT&CK v{version or '?'} fetched" +
              (f" (was v{previous})" if previous and previous != version else ""))
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(response.text)
            _write_meta(cache_path, {"etag": response.headers.get("ETag", ""),
                                     "last_modified": response.headers.get("Last-Modified", ""),
                                     "checked": time.time(), "version": version})
            print(f"Cached MITRE ATT&CK data to {cache_path}")
        except Exception as e:
            print(f"Warning: Could not cache data: {e}")
        return _parse(response.text, cache_path, "network", previous)

    except requests.exceptions.SSLError as ssl_err:
        # No silent downgrade: an unverified bundle would be cached and trusted for cache_days.
        # Behind a TLS-inspecting proxy, point REQUESTS_CA_BUNDLE at the proxy CA instead.
        print(f"❌ SSL verification failed fetching MITRE ATT&CK data: {ssl_err}")
        print("   Set REQUESTS_CA_BUNDLE to your proxy's CA bundle if you are behind TLS inspection.")
        if cache_path.exists():
            return from_cache(" (stale)")
        raise

    except (requests.RequestException, requests.exceptions.ConnectionError) as e:
        # Network error - try to use stale cache if available
        print(f"Network error fetching MITRE data: {e}")
        if cache_path.exists():
            try:
                return from_cache(" (stale)")
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

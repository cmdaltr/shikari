from fastapi import FastAPI, Form, Request, UploadFile, File, Cookie, Response, HTTPException, Body, Query
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from archer.security import sanitize_filename, validate_safe_path, sanitize_group_name
from archer.build.group_files import group_yaml_files
from archer.build.attack_mapping import rule_name as attack_rule_name
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from typing import List, Optional
from archer import paths

# Before archer.build.queries is imported: it reads the Splunk schema at import
paths.seed_bespoke()

# -----------------------------------------------------------------------------
# Archer service - main FastAPI application
#
# This module wires up the web application, mounts static assets, loads
# MITRE ATT&CK data into `app.state` on startup, and exposes the public
# HTTP endpoints used by the front-end templates (index, generate,
# manual submission, draft saving/loading, and progress). Comments in
# this file explain the purpose of each handler and the shape of data
# passed between client and server.
# -----------------------------------------------------------------------------

from archer.mitre import (
    get_stix_data,
    obtain_all_techniques,
    obtain_technique_descriptions,
)
from archer.mitre.enterprise import check_group_in_mitre
from archer.build.orchestrator import process_group
from datetime import datetime
import os
import functools
import json
import logging
import subprocess
import threading
import re
import html
from urllib.parse import quote, urlencode, urlparse
import yaml

from archer import yaml_cache
from archer.build.progress import read_progress, start_progress, write_progress
from archer.config import (
    DATA_DIR,
    GENERATE_DIR,
    CORRELATE_DIR,
    DRAFTS_DIR,
    UPLOADS_DIR,
    BLOG_DIR,
    ATTACK_FLOWS_DIR,
    PROGRESS_DIR,
    PROFILE_PICS_DIR,
    SEVERITY_ORDER,
    EMULATION_ENABLED,
)

# Configure logger
logger = logging.getLogger(__name__)
from archer.database.db import init_db, get_db
from archer.auth import (
    verify_password,
    create_session,
    get_user_from_session_id,
    delete_session,
    encrypt_api_key,
    decrypt_api_key,
    create_password_reset_request,
    validate_reset_token,
    reset_password_with_token,
    admin_reset_password,
    validate_password,
)
from archer.database.models import User, UserRole, APIKey, at_least
from archer.validation.query_syntax_validator import validate_query_syntax
from archer.validation import get_validation_router
from archer.chat import router as chat_router
from archer.visualization.frameworks import FRAMEWORKS as FLOW_FRAMEWORKS


templates = Jinja2Templates(directory=str(paths.TEMPLATES))
# Attack flow tabs (partials/attack_flow.html): the Cyber Kill Chain and Targeted Attack Lifecycle mappings
templates.env.globals["flow_frameworks"] = FLOW_FRAMEWORKS

# Data source display name mapping (used for detection titles and correlation displays)
DATA_SOURCE_DISPLAY_NAMES = {
    "aws cloudtrail": "AWS CloudTrail",
    "aws guardduty": "AWS GuardDuty",
    "aws_waf": "AWS WAF",
    "azure activedirectory": "Entra ID",
    "azure activitylog": "Azure",
    "deviceevents": "DeviceEvents",
    "devicefileevents": "DeviceFileEvents",
    "deviceimageloadevents": "DeviceImageLoadEvents",
    "devicenetworkevents": "DeviceNetworkEvents",
    "deviceprocessevents": "DeviceProcessEvents",
    "device_events": "DeviceEvents",
    "device_file_events": "DeviceFileEvents",
    "device_image_load_events": "DeviceImageLoadEvents",
    "device_network_events": "DeviceNetworkEvents",
    "device_process_events": "DeviceProcessEvents",
    "gcp_audit": "GCP Audit Logs",
    "microsoft defender": "Defender XDR",
    "microsoft_defender": "Defender XDR",
    "edr_events": "Defender XDR",
    "mde": "Defender XDR",
    "googlesecops": "Google SecOps",
    "microsoft windows": "Windows Event Logs",
    "microsoft_o365": "M365",
    "splunk": "Splunk",
    "unix": "Unix",
}
# Names for the organisation's own products (WAFs, proxies, IPS) stay out of the code:
# bespoke/mappings/sources/display_names.json (gitignored) adds or overrides entries
try:
    with open(paths.BESPOKE / "mappings" / "sources" / "display_names.json") as _fh:
        DATA_SOURCE_DISPLAY_NAMES.update({k.lower(): v for k, v in json.load(_fh).items()})
except (OSError, ValueError):
    pass


def load_yaml_file(file_path: str) -> Optional[dict]:
    """
    Load and parse a YAML file safely.

    Args:
        file_path: Path to the YAML file

    Returns:
        Parsed YAML data as dictionary, or None if loading fails
    """
    try:
        return yaml_cache.load(file_path)
    except yaml.YAMLError as e:
        # YAML parsing error - log filename and specific error
        filename = os.path.basename(file_path)
        logger.warning(f"Skipping malformed YAML file {filename}: {str(e).split(chr(10))[0]}")
        return None
    except FileNotFoundError:
        logger.error(f"YAML file not found: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error loading YAML file {file_path}: {e}")
        return None


def calculate_detection_likelihood(
    indicators: list, query: str, technique: str, yaml_data: dict
) -> int:
    """
    Calculate the likelihood of successfully detecting this technique based on indicator strength,
    data source requirements, and query complexity.

    Scoring factors:
    - Strong indicators (hashes, IPs, domains, specific commands): +30
    - Medium indicators (file paths, generic commands): +20
    - Weak indicators (behavioral patterns, config files): +10
    - Common/reliable data sources (process, network, file): +20
    - Uncommon data sources (registry MFA, cloud audit): -10
    - OSINT enrichment: +15
    - Query specificity (not just "contains"): +10

    Args:
        indicators: List of extracted indicators
        query: The detection query
        technique: Technique ID
        yaml_data: Full YAML data including metadata

    Returns:
        Detection likelihood score (0-100)
    """
    score = 50  # Base score

    # Indicator strength analysis
    if indicators:
        strong_indicators = 0
        medium_indicators = 0
        weak_indicators = 0

        for indicator in indicators:
            indicator_lower = indicator.lower()

            # Strong indicators: hashes, specific malware names, specific commands
            if any(
                x in indicator_lower
                for x in [
                    "sha256",
                    "sha1",
                    "md5",
                    ".exe",
                    "mimikatz",
                    "powershell.exe",
                    "cmd.exe",
                    "psexec",
                    "cobalt",
                    "beacon",
                    "meterpreter",
                    "empire",
                ]
            ):
                strong_indicators += 1
            # Medium indicators: file paths, registry keys, specific patterns
            elif any(
                x in indicator_lower
                for x in [
                    ":\\\\",
                    "hkey",
                    "software\\\\",
                    "system32",
                    "appdata",
                    "temp\\\\",
                    ".dll",
                    ".bat",
                    ".ps1",
                    ".vbs",
                ]
            ):
                medium_indicators += 1
            # Weak indicators: generic terms, config files
            elif any(
                x in indicator_lower for x in ["hosts", "config", "settings", "user", "admin"]
            ):
                weak_indicators += 1
            else:
                medium_indicators += 1

        # Add points based on indicator strength
        score += min(strong_indicators * 8, 30)  # Cap at +30
        score += min(medium_indicators * 5, 20)  # Cap at +20
        score += min(weak_indicators * 2, 10)  # Cap at +10

    else:
        # No indicators extracted - behavioral detection
        score -= 20

    # Data source reliability analysis
    required_connectors = yaml_data.get("requiredDataConnectors", []) if yaml_data else []
    if required_connectors:
        for connector in required_connectors:
            connector_id = (
                connector.get("connectorId", "").lower()
                if isinstance(connector, dict)
                else str(connector).lower()
            )

            # Reliable, commonly available data sources
            if any(
                x in connector_id for x in ["threatprotection", "defender", "sysmon", "windows"]
            ):
                score += 10
            # Cloud/specialized data sources (may not be configured)
            elif any(
                x in connector_id for x in ["azureactivedirectory", "office365", "aws", "gcp"]
            ):
                score -= 5

    # Query specificity analysis
    if query:
        query_lower = query.lower()

        # Specific, high-fidelity queries
        if any(x in query_lower for x in ["sha256", "sha1", "md5", "==", "has_all"]):
            score += 10
        # Generic "contains" queries (higher false positive risk)
        elif query_lower.count("contains") > 3:
            score -= 5

        # Network-based detections (generally reliable if you have network monitoring)
        if any(
            x in query_lower
            for x in ["remoteip", "destinationip", "destinationport", "url", "domain"]
        ):
            score += 10

        # File/Process-based detections (very reliable)
        if any(
            x in query_lower
            for x in ["processcommandline", "filename", "filepath", "deviceprocessevents"]
        ):
            score += 10

    # Check for weak indicator patterns that reduce likelihood
    if indicators:
        for indicator in indicators:
            # MFA/hosts file example - very weak indicator
            if "hosts" in indicator.lower() and "etc" in indicator.lower():
                score -= 25  # Major penalty for weak indicators

            # Generic admin/system paths
            if indicator.lower() in ["admin", "administrator", "system", "user"]:
                score -= 10

    # OSINT enrichment adds confidence
    if yaml_data and yaml_data.get("osint_enriched"):
        score += 15

    # Ensure score is within 0-100 range
    final_score = max(0, min(100, score))

    # Debug output
    print(
        f"[LIKELIHOOD] Technique: {technique}, Indicators: {len(indicators)}, Score: {final_score}",
        flush=True,
    )

    return final_score


def extract_tables_indexes(query: str, vendor: str) -> list:
    """
    Extract table names (MDE) or index names (Splunk) from a correlation query.

    Args:
        query: The correlation query string
        vendor: The platform (mde, splunk, etc.)

    Returns:
        List of unique table/index names
    """
    import re

    tables_indexes = []

    if vendor.lower() == "mde":
        # Extract MDE table names - pattern: TableName | where ...
        # Common tables: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, etc.
        # Exclude column names like DeviceId, DeviceName
        pattern = r"\b(Device\w+Events|Device\w+Info|Identity\w+Events|Identity\w+Info|Email\w+Events|CloudApp\w+|Alert\w+)\b"
        matches = re.findall(pattern, query)

        # Filter out common column names that aren't tables
        column_names = {
            "DeviceId",
            "DeviceName",
            "DeviceType",
            "IdentityName",
            "EmailSender",
            "EmailRecipient",
        }
        tables_indexes = sorted([m for m in set(matches) if m not in column_names])

    elif vendor.lower() == "splunk":
        # Extract Splunk index names - pattern: index=indexname or index="indexname"
        pattern = r'index\s*=\s*["\']?([a-zA-Z0-9_\-]+)["\']?'
        matches = re.findall(pattern, query, re.IGNORECASE)
        tables_indexes = sorted(set(matches))

    elif vendor.lower() == "googlesecops":
        # UDM event types the SecOps search matches on
        tables_indexes = sorted(set(re.findall(r'metadata\.event_type\s*=\s*"([A-Z_]+)"', query)))

    return tables_indexes


def format_technique_name(name: str) -> str:
    """
    Format technique names by adding spaces to CamelCase names and fixing common issues.

    Examples:
        "CodeSigning" -> "Code Signing"
        "MultiFactorAuthentication" -> "Multi-Factor Authentication"
        "DatafromCloudStorage" -> "Data from Cloud Storage"
        "Exfiltrationto Cloud Storage" -> "Exfiltration to Cloud Storage"
        "TRUSTMODIFICATION" -> "Trust Modification"
        "NTDS" -> "NTDS" (keep acronyms)
        "Valid Accounts" -> "Valid Accounts" (already has spaces)

    Args:
        name: Technique name that may be in CamelCase

    Returns:
        Formatted technique name with spaces
    """
    if not name:
        return name

    # Keep short all-caps acronyms unchanged (like NTDS, LSASS, etc)
    if name.isupper() and len(name) <= 5 and " " not in name:
        return name

    # Handle longer all-caps names (like "TRUSTMODIFICATION")
    # Strategy: Use a simple English word list to detect boundaries
    if name.isupper() and len(name) > 5:  # Process longer all-caps strings
        # Common English words that might appear in technique names
        common_words = [
            "TRUST",
            "MODIFICATION",
            "DATA",
            "ENCRYPTED",
            "FOR",
            "IMPACT",
            "ACCESS",
            "ACCOUNT",
            "ADMIN",
            "APPLICATION",
            "AUTH",
            "AUTHENTICATION",
            "BACKUP",
            "BOOT",
            "BROWSER",
            "CACHE",
            "CERTIFICATE",
            "CLOUD",
            "CODE",
            "COMMAND",
            "COMMUNICATION",
            "COMPROMISE",
            "CONFIG",
            "CONFIGURATION",
            "CONTROL",
            "CREDENTIAL",
            "DEFENSE",
            "DISCOVERY",
            "DOMAIN",
            "ELEVATION",
            "ESCALATION",
            "EVASION",
            "EVENT",
            "EXECUTION",
            "EXPLOIT",
            "FILE",
            "FILTER",
            "FIREWALL",
            "GROUP",
            "HIJACK",
            "HOOK",
            "INJECTION",
            "LATERAL",
            "LOG",
            "LOGIN",
            "MALWARE",
            "MANAGEMENT",
            "MEMORY",
            "MOVEMENT",
            "NETWORK",
            "OBJECT",
            "PASSWORD",
            "PATH",
            "PERMISSION",
            "POLICY",
            "PORT",
            "PRIVILEGE",
            "PROCESS",
            "PROTOCOL",
            "PROXY",
            "REGISTRY",
            "REMOTE",
            "RESOURCE",
            "ROOT",
            "SCRIPT",
            "SECURITY",
            "SERVER",
            "SERVICE",
            "SESSION",
            "SHELL",
            "SOFTWARE",
            "STORAGE",
            "SYSTEM",
            "TASK",
            "TOKEN",
            "USER",
            "WEB",
            "WINDOWS",
        ]

        # Try to split the all-caps string using word boundaries
        words_found = []
        remaining = name

        while remaining:
            found = False
            # Try to match the longest possible word from the start
            for word in sorted(common_words, key=len, reverse=True):
                if remaining.startswith(word):
                    words_found.append(word)
                    remaining = remaining[len(word) :]
                    found = True
                    break

            # If no word matched, take the first character and continue
            if not found:
                if words_found:
                    # Append to last word if it exists
                    words_found[-1] += remaining[0]
                else:
                    words_found.append(remaining[0])
                remaining = remaining[1:]

        if len(words_found) > 1:
            # Successfully split into multiple words
            name = " ".join(words_found).title()
        else:
            # Couldn't split - just title case it
            name = name.title()

    # If already has spaces, clean up extra spaces and fix known issues
    if " " in name:
        # Fix "Multi- Factor" -> "Multi-Factor"
        result = re.sub(r"(\w+)-\s+(\w+)", r"\1-\2", name)
        # Fix "Data Encryptedfor" -> "Data Encrypted for"
        result = re.sub(r"([a-z])for\b", r"\1 for", result)
        result = re.sub(r"([a-z])to\b", r"\1 to", result)
        result = re.sub(r"([a-z])from\b", r"\1 from", result)
        # Fix "N T D S" -> "NTDS"
        result = re.sub(r"\b([A-Z])\s+([A-Z])\s+([A-Z])\s+([A-Z])\b", r"\1\2\3\4", result)
        result = re.sub(r"\b([A-Z])\s+([A-Z])\s+([A-Z])\b", r"\1\2\3", result)
        return result

    # Special case: PowerShell should stay as one word (not "Power Shell")
    if name == "PowerShell":
        return "PowerShell"

    # Special case: Windows Management Instrumentation (WMI) variations
    if name in ["WindowsManagementInstrumentation", "WMI"]:
        return "Windows Management Instrumentation"

    # Insert space before uppercase letters (except at start)
    result = re.sub(r"(?<!^)(?=[A-Z])", " ", name)

    # Special case: handle specific known lowercase words in the middle
    # "Datafrom Cloud Storage" -> "Data from Cloud Storage"
    # "Exfiltrationto Cloud Storage" -> "Exfiltration to Cloud Storage"
    result = re.sub(r"([a-z])(from)(?=[A-Z\s]|$)", r"\1 \2", result)
    result = re.sub(r"([a-z])(to)(?=[A-Z\s]|$)", r"\1 \2", result)
    result = re.sub(r"([a-z])(for)(?=[A-Z\s]|$)", r"\1 \2", result)

    # Fix hyphenated words: "Multi Factor" -> "Multi-Factor"
    result = re.sub(r"\bMulti\s+Factor\b", "Multi-Factor", result)
    result = re.sub(r"\bTwo\s+Factor\b", "Two-Factor", result)

    return result


def get_platform_from_data_source(data_source: str) -> str:
    """
    Map a data source to its platform/vendor.

    Examples:
        "microsoft_defender" -> "Defender XDR"
        "azure_activitylog" -> "Azure"
        "aws_cloudtrail" -> "AWS"
        "microsoft_windows" -> "Windows"

    Args:
        data_source: The data source identifier (e.g., "azure_activitylog")

    Returns:
        The platform/vendor name (e.g., "Azure")
    """
    data_source_lower = data_source.lower()

    # Check for specific platform patterns
    if "microsoft_defender" in data_source_lower or "device" in data_source_lower:
        return "Defender XDR"
    elif "azure" in data_source_lower:
        return "Azure"
    elif "aws" in data_source_lower:
        return "AWS"
    elif "microsoft_windows" in data_source_lower or "windows" in data_source_lower:
        return "Windows"
    elif "microsoft_365" in data_source_lower or "office365" in data_source_lower:
        return "Microsoft 365"
    elif "gcp" in data_source_lower or "google" in data_source_lower:
        return "GCP"
    elif "okta" in data_source_lower:
        return "Okta"
    elif "crowdstrike" in data_source_lower:
        return "CrowdStrike"
    elif "sentinel" in data_source_lower:
        return "Sentinel"
    elif "mcafee" in data_source_lower:
        return "McAfee"
    else:
        # Default: title case the data source
        return DATA_SOURCE_DISPLAY_NAMES.get(
            data_source_lower, data_source.replace("_", " ").title()
        )


def markdown_links_to_html(text):
    """
    Convert markdown links to HTML anchor tags.
    Example: [C0027](https://attack.mitre.org/campaigns/C0027) -> <a href="https://attack.mitre.org/campaigns/C0027" target="_blank">C0027</a>
    """
    # Output is rendered with |safe: escape everything, then allow http(s) links only
    text = html.escape(text or "", quote=True)
    pattern = r"\[([^\]]+)\]\((https?://[^)\s]+)\)"
    return re.sub(pattern, r'<a href="\2" target="_blank" rel="noopener noreferrer">\1</a>', text)


def library_description_html(content_data):
    """Rebuild a library item's description from client-supplied content; never trust its HTML."""
    text = content_data.get("description")
    if not text:
        # Older saves only carry description_html: turn anchors back into markdown, drop other tags
        text = re.sub(
            r'<a\s[^>]*href="([^"]*)"[^>]*>(.*?)</a>', r"[\2](\1)", content_data.get("description_html", ""), flags=re.S
        )
        text = html.unescape(re.sub(r"<[^>]+>", "", text))
    return markdown_links_to_html(text)


def markdown_links_to_plain(text):
    """
    Remove markdown link syntax, keeping only the link text.
    Example: [C0027](https://attack.mitre.org/campaigns/C0027) -> C0027
    """
    pattern = r"\[([^\]]+)\]\([^)]+\)"
    return re.sub(pattern, r"\1", text)


def without_osint(vendors):
    """
    The results page's detections for its save and export scripts, minus osint_data:
    that's most of a big run's page (14 MB of Scattered Spider's 16), so the server
    puts it back from the detection's file instead (with_osint).
    """
    def strip(items):
        return [{k: v for k, v in d.items() if k != "osint_data"} for d in items or []]

    return [dict(v, detections=strip(v.get("detections")), **({"all_files": strip(v["all_files"])} if "all_files" in v else {}))
            for v in vendors or []]


def library_content(raw):
    """
    A Library item's content, decoded. SecOps queries saved as YARA-L rules, before SecOps
    output moved to UDM Search, come out as the UDM searches they amount to
    (archer.build.udm); the stored copy is left as it is. OSINT snippets quote public
    YARA-L rules and stay as they are.
    """
    from archer.build.udm import from_yaral, is_yaral, normalise_join

    content = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(content, dict):
        return content
    convert = lambda q: normalise_join((from_yaral(q) or q) if is_yaral(q) else q) if isinstance(q, str) else q
    for key in ("query", "combined_query", "query_a", "query_b"):
        if key in content:
            content[key] = convert(content[key])
    if isinstance(content.get("queries"), list):
        content["queries"] = [convert(q) for q in content["queries"]]
    for part in (content.get("individual_queries") or []) + (content.get("techniques") or []):
        if isinstance(part, dict) and "query" in part:
            part["query"] = convert(part["query"])
    return content


def without_corr_osint(vendors):
    """The results page's correlations minus osint_data; with_osint rebuilds it from osint_files."""
    return [dict(v, correlations=[{k: c[k] for k in c if k != "osint_data"} for c in v.get("correlations") or []])
            for v in vendors or []]


def with_osint(content):
    """
    A detection or correlation the results page sent without osint_data, with it read back:
    a detection's from its YAML, a correlation's inherited from its parts' YAMLs.
    """
    if isinstance(content, dict) and "osint_data" not in content and content.get("osint_files"):
        from archer.build.correlation_osint import inherited

        paths = [os.path.join(GENERATE_DIR, os.path.basename(str(f))) for f in content["osint_files"]]
        osint = inherited([d for d in (load_yaml_file(p) for p in paths if os.path.isfile(p)) if d])
        return dict(content, osint_data={"indicators": {"query_snippets": osint["snippets"]}, "sources": osint["sources"]}
                    if osint["snippets"] or osint["sources"] else None)
    if not isinstance(content, dict) or "osint_data" in content or not content.get("file"):
        return content
    path = os.path.join(GENERATE_DIR, os.path.basename(str(content["file"])))
    if not os.path.isfile(path):
        return content
    return dict(content, osint_data=check_osint_enriched(path)[1])


templates.env.filters["without_osint"] = without_osint
templates.env.filters["without_corr_osint"] = without_corr_osint
def technique_key(name) -> str:
    """Technique names compared on letters and digits: 'Multi-Factor Authentication' == 'Multi-FactorAuthentication'."""
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


templates.env.filters["technique_key"] = technique_key


def unique_techniques(names) -> list:
    """Each technique once, however it's spelled, in the order given."""
    return list({technique_key(n): n for n in reversed(list(names or []))}.values())[::-1]


templates.env.filters["unique_techniques"] = unique_techniques


def check_osint_enriched(yaml_file, file_content=None):
    """
    Check if a YAML file has OSINT comparison/enhancement metadata.
    Returns tuple: (is_enhanced: bool, osint_data: dict)

    Args:
        yaml_file: Path to YAML file
        file_content: Optional pre-read file content (for performance)

    - is_enhanced: True if osint_enhanced=true (for orange badge)
    - osint_data: Contains OSINT data if osint_compared=true (for Show Details button)
    """
    try:
        if file_content is None:
            with open(yaml_file, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = file_content

        # OSINT comparison runs by default; enhancement is the optional checkbox
        if "osint_compared: true" not in content:
            return False, {}
        has_osint_enhancement = "osint_enhanced: true" in content
        osint_data = {}

        date_match = re.search(r"comparison_date:\s*(.+)", content)
        if date_match:
            osint_data["comparison_date"] = date_match.group(1).strip()

        sources = []
        in_sources = False
        for line in content.split("\n"):
            if "osint_sources:" in line:
                in_sources = True
                continue
            if in_sources:
                if line.strip().startswith("- "):
                    sources.append(line.strip()[2:])
                elif not line.strip().startswith(" ") and line.strip():
                    break
        if sources:
            osint_data["sources"] = sources

        try:
            yaml_data = yaml_cache.load(yaml_file, content)
            if yaml_data and yaml_data.get("osint_indicators"):
                osint_data["indicators"] = yaml_data["osint_indicators"]
        except yaml.YAMLError as e:
            logger.debug(f"Skipping OSINT indicators for {os.path.basename(yaml_file)}: {str(e).splitlines()[0]}")
            osint_data["indicators"] = {}
        except Exception as e:
            logger.warning(f"Error extracting OSINT indicators from {os.path.basename(yaml_file)}: {e}")
            osint_data["indicators"] = {}
        return has_osint_enhancement, osint_data
    except Exception as e:
        logger.error(f"Error checking OSINT in {yaml_file}: {e}")
    return False, {}


def extract_indicators_from_query(yaml_file):
    """
    Extract key indicators from the YAML query field to display as backtick-wrapped indicators.
    Returns a list of unique indicators found in the query.
    """
    indicators = []
    try:
        with open(yaml_file, "r") as f:
            lines = f.readlines()
            in_query = False
            query_lines = []

            for line in lines:
                # Found query field
                if line.strip().startswith("query:"):
                    content = line.split(":", 1)[1].strip()
                    if content in ("|", ">"):
                        in_query = True
                        continue
                    elif content:
                        query_lines.append(content)
                        break
                # Collect query content
                elif in_query:
                    # Stop if we hit a non-indented line
                    if line.strip() and not line.startswith(" ") and not line.startswith("\t"):
                        break
                    if line.strip():
                        query_lines.append(line.strip())

            query_text = " ".join(query_lines)

            # Extract common indicator patterns
            # Specific file names (e.g., NTDS.dit, SAM, SYSTEM, lsass.exe)
            important_files = re.findall(
                r"\b([A-Z][A-Za-z0-9_]*\.(?:dit|exe|dll|bat|ps1|vbs|js|jar|sh|py|dmp|log))\b",
                query_text,
            )
            indicators.extend(important_files)

            # Process names (e.g., cmd.exe, powershell.exe, rundll32.exe)
            process_pattern = r"\b(\w+\.(?:exe|dll|bat|ps1|vbs|js|jar|sh|py))\b"
            processes = re.findall(process_pattern, query_text, re.IGNORECASE)
            indicators.extend(processes)

            # Windows paths with environment variables (e.g., %SystemRoot%\NTDS\Ntds.dit)
            env_path_pattern = r'(%[A-Za-z]+%\\[^\s"\',)]+)'
            env_paths = re.findall(env_path_pattern, query_text)
            indicators.extend(env_paths)

            # Cloud API operations (e.g., CreatePolicyVersion, AttachUserPolicy, PutBucketPolicy)
            # Match patterns like *CreatePolicyVersion* or "CreatePolicyVersion"
            api_pattern = r'["\*]([A-Z][a-zA-Z]+(?:Policy|Role|User|Group|Bucket|Key|Access|Permission|Instance|Volume|Secret|Token|Session|Account|Identity|Resource|Credential)[A-Za-z]*)["\*]'
            api_calls = re.findall(api_pattern, query_text)
            indicators.extend(api_calls)

            # AWS/Azure/GCP operations - broader pattern for CamelCase API calls
            cloud_ops_pattern = r'["\*]([A-Z][a-z]+[A-Z][a-zA-Z]+)["\*]'
            cloud_ops = re.findall(cloud_ops_pattern, query_text)
            for op in cloud_ops:
                if len(op) > 4 and op not in indicators:
                    indicators.append(op)

            # Cloud service commands (e.g., Connect-AZAccount, Connect-MgGraph, gcloud)
            # Match PowerShell cmdlets and CLI commands
            cloud_cmd_pattern = r'["\*]+(Connect-[A-Z][A-Za-z]+|Set-[A-Z][A-Za-z]+|Get-[A-Z][A-Za-z]+|New-[A-Z][A-Za-z]+|Remove-[A-Z][A-Za-z]+|gcloud|aws\s+[a-z]+|az\s+[a-z]+)["\*]+'
            cloud_cmds = re.findall(cloud_cmd_pattern, query_text)
            indicators.extend(cloud_cmds)

            # ActionType values (common in MDE queries)
            action_pattern = r'ActionType\s*(?:==|=~|has|contains)\s*["\']([^"\']+)["\']'
            actions = re.findall(action_pattern, query_text, re.IGNORECASE)
            indicators.extend(actions)

            # KQL has_any() function - extract values from has_any("val1", "val2", ...)
            # Example: | where AdditionalFields has_any("wevtutil", "evtx")
            has_any_pattern = r'has_any\s*\(\s*"([^"]+)"(?:\s*,\s*"([^"]+)")*'
            has_any_matches = re.findall(has_any_pattern, query_text, re.IGNORECASE)
            for match in has_any_matches:
                # Match returns tuples, flatten and add non-empty values
                for val in match:
                    if val and len(val.strip()) >= 3:
                        cleaned = val.strip().strip("*").strip()
                        if cleaned:
                            indicators.append(cleaned)

            # KQL has_any() - alternate approach to catch all values in the parentheses
            has_any_full_pattern = r"has_any\s*\(([^)]+)\)"
            has_any_full_matches = re.findall(has_any_full_pattern, query_text, re.IGNORECASE)
            for match_group in has_any_full_matches:
                # Split by comma and extract quoted values
                values = re.findall(r'"([^"]+)"', match_group)
                for val in values:
                    if val and len(val.strip()) >= 3:
                        cleaned = val.strip().strip("*").strip()
                        if cleaned and cleaned not in indicators:
                            indicators.append(cleaned)

            # Splunk IN () syntax - extract values from IN ("val1", "val2", ...)
            # Example: | search process IN ("wevtutil", "evtx")
            in_pattern = r"\bIN\s*\(([^)]+)\)"
            in_matches = re.findall(in_pattern, query_text, re.IGNORECASE)
            for match_group in in_matches:
                # Extract quoted values
                values = re.findall(r'"([^"]+)"', match_group)
                for val in values:
                    if val and len(val.strip()) >= 3:
                        cleaned = val.strip().strip("*").strip()
                        if cleaned and cleaned not in indicators:
                            indicators.append(cleaned)

            # Command-line flags and switches (e.g., -enc, -encodedcommand, /c)
            flag_pattern = r"(?:^|\s)([-/]\w+)\b"
            flags = re.findall(flag_pattern, query_text)
            indicators.extend(flags)

            # Registry keys (e.g., HKLM\Software\...)
            registry_pattern = r'(HK[A-Z_]+\\[^\s"\']+)'
            registry = re.findall(registry_pattern, query_text, re.IGNORECASE)
            indicators.extend(registry)

            # File paths (e.g., C:\Windows\Temp\...)
            path_pattern = r'([A-Z]:\\[^\s"\',)]+)'
            paths = re.findall(path_pattern, query_text)
            indicators.extend(paths)

            # Unix/Linux paths (e.g., /var/run, /tmp, /etc/passwd)
            unix_path_pattern = r'["\']?(/[a-z_/]+)["\']?'
            unix_paths = re.findall(unix_path_pattern, query_text, re.IGNORECASE)
            # Filter to only include common Unix paths
            for path in unix_paths:
                if any(
                    common in path
                    for common in [
                        "/var/",
                        "/tmp/",
                        "/etc/",
                        "/home/",
                        "/usr/",
                        "/opt/",
                        "/bin/",
                        "/sbin/",
                        "/dev/",
                        "/proc/",
                        "/sys/",
                    ]
                ):
                    indicators.append(path)

            # File extensions and patterns (e.g., .pid, .lock, .log)
            extension_pattern = r'["\']?(\.[a-z]{2,5})["\']?'
            extensions = re.findall(extension_pattern, query_text, re.IGNORECASE)
            # Only include meaningful extensions
            meaningful_exts = [".pid", ".lock", ".log", ".tmp", ".conf", ".cfg", ".ini", ".dat"]
            for ext in extensions:
                if ext.lower() in meaningful_exts:
                    indicators.append(ext)

            # Event IDs (e.g., EventID 4624, EventCode=4688)
            event_pattern = r"\b(?:EventID|EventCode|event_id)[=\s]+(\d{4,5})\b"
            events = re.findall(event_pattern, query_text, re.IGNORECASE)
            for event in events:
                indicators.append(f"EventID {event}")

            # has_any, contains, or other query operators with values
            has_any_pattern = r'has_any\s*\(["\']([^"\']+)["\']'
            has_any_vals = re.findall(has_any_pattern, query_text, re.IGNORECASE)
            indicators.extend(has_any_vals)

            # Splunk field comparisons with wildcards (e.g., file_name="*AADInternals*", service="*Pacu*")
            # Matches patterns like field="*Value*" or field="Value"
            splunk_field_pattern = r'\w+\s*=\s*["\*]+([A-Z][A-Za-z0-9]+)["\*]+'
            splunk_fields = re.findall(splunk_field_pattern, query_text)
            for field_val in splunk_fields:
                # Only include if it looks like a tool/software name (CamelCase or all caps, length > 3)
                if len(field_val) > 3 and (field_val[0].isupper() or field_val.isupper()):
                    indicators.append(field_val)

            # Splunk field=value patterns (e.g., process="runas", command="cmd.exe", user="admin")
            # Match any field="value" pattern and extract the value
            simple_field_pattern = r'\w+\s*=\s*"([^"]+)"'
            field_values = re.findall(simple_field_pattern, query_text)
            for val in field_values:
                # Include values that are alphanumeric, not just generic words
                # Skip very short values (< 3 chars) and pure numbers
                # Strip asterisks and leading/trailing spaces (wildcards from queries)
                cleaned_val = val.strip().strip("*").strip()
                if (
                    len(cleaned_val) >= 3
                    and not cleaned_val.isdigit()
                    and cleaned_val.lower()
                    not in ["and", "or", "not", "null", "none", "true", "false"]
                ):
                    indicators.append(cleaned_val)

            # Common suspicious strings (base64, encoded, etc.)
            suspicious_patterns = [
                r"\b(base64)\b",
                r"\b(encoded)\b",
                r"\b(invoke-expression)\b",
                r"\b(downloadstring)\b",
                r"\b(webclient)\b",
                r"\b(credential)\b",
                r"\b(password)\b",
            ]
            for pattern in suspicious_patterns:
                matches = re.findall(pattern, query_text, re.IGNORECASE)
                indicators.extend(matches)

            # Remove duplicates while preserving order, limit to first 10
            # Also filter out overly generic terms and invalid indicators
            seen = set()
            unique_indicators = []

            # Generic terms that are too common to be useful indicators
            generic_terms = {
                "condition",
                "conditions",
                "value",
                "values",
                "data",
                "file",
                "process",
                "command",
                "user",
                "system",
                "event",
                "log",
                "entry",
                "action",
                "type",
                "name",
                "path",
                "string",
                "text",
                "info",
            }

            for item in indicators:
                # Strip whitespace AND asterisks for consistent deduplication
                item_str = str(item).strip().strip("*").strip()
                item_lower = item_str.lower()

                # Skip if empty or too short
                if len(item_str) < 3:
                    continue

                # Skip indicators that start with "index:"
                if item_lower.startswith("index:"):
                    continue

                # Skip overly generic single words
                if item_lower in generic_terms:
                    continue

                # Skip if already seen (using cleaned version for comparison)
                if item_lower in seen:
                    continue

                # Add to unique list (max 10)
                if len(unique_indicators) < 10:
                    seen.add(item_lower)
                    unique_indicators.append(item_str)

            return unique_indicators
    except:
        return []


def get_indicators_from_yaml(yaml_file, yaml_data=None):
    """
    Extract indicators from YAML file, prioritizing the 'indicators' section.
    Falls back to query extraction if no indicators section exists.

    Args:
        yaml_file: Path to YAML file
        yaml_data: Optional pre-parsed YAML data (for performance)

    Returns:
        List of indicator strings for display
    """
    import html
    import re

    try:
        # First, try to load the indicators section from YAML
        if yaml_data is None:
            yaml_data = load_yaml_file(yaml_file)
        if yaml_data and "indicators" in yaml_data:
            indicators_section = yaml_data["indicators"]
            if indicators_section and isinstance(indicators_section, dict):
                # Flatten all indicator categories into a single list
                all_indicators = []
                seen_indicators = set()  # Track duplicates

                for category, values in indicators_section.items():
                    if values and isinstance(values, list):
                        # Strip asterisks (wildcards) from indicators for display
                        for val in values:
                            cleaned = str(val).strip().strip("*").strip()

                            # Decode HTML entities (e.g., &lt; -> <, &gt; -> >)
                            cleaned = html.unescape(cleaned)

                            # Validate indicator - skip if:
                            # 1. Empty after cleaning
                            # 2. Just a common word (and, or, to, the, etc.)
                            # 3. Contains sentence patterns (ends with period, has "Citation:")
                            # 4. Too long (likely a description fragment)
                            # 5. Already seen (duplicate)

                            if not cleaned:
                                continue

                            # Skip common filler words
                            common_words = {
                                "and",
                                "or",
                                "to",
                                "the",
                                "a",
                                "an",
                                "in",
                                "on",
                                "at",
                                "for",
                                "with",
                                "from",
                            }
                            if cleaned.lower() in common_words:
                                continue

                            # Skip if it contains citation markers or ends with period (likely description)
                            if "Citation:" in cleaned or cleaned.endswith("."):
                                continue

                            # Skip if it looks like a sentence (contains "may", "can", "to the", etc.)
                            sentence_patterns = [
                                r"\bmay\b",
                                r"\bcan\b",
                                r"\bwill\b",
                                r"\bshould\b",
                                r"to the\b",
                                r"to ensure\b",
                                r"to modify\b",
                                r"Adversaries",
                                r"Users may",
                                r"file to\b",
                                r"\. And$",  # Ends with ". And"
                                r"memory is mapped",  # Descriptive phrase
                                r"virtual address space",  # Descriptive phrase
                            ]
                            if any(
                                re.search(pattern, cleaned, re.IGNORECASE)
                                for pattern in sentence_patterns
                            ):
                                continue

                            # Skip if too long (> 150 chars, likely a sentence)
                            if len(cleaned) > 150:
                                continue

                            # Skip duplicates (case-insensitive)
                            cleaned_lower = cleaned.lower()
                            if cleaned_lower in seen_indicators:
                                continue

                            seen_indicators.add(cleaned_lower)
                            all_indicators.append(cleaned)

                if all_indicators:
                    # Return first 10 indicators
                    return all_indicators[:10]

        # Fallback: extract from query if no indicators section
        return extract_indicators_from_query(yaml_file)
    except Exception as e:
        logger.error(f"Error getting indicators from {yaml_file}: {e}")
        # Final fallback: try query extraction
        return extract_indicators_from_query(yaml_file)


app = FastAPI(title="Archer Threat Hunting Service")
app.mount("/static", StaticFiles(directory=str(paths.STATIC)), name="static")


def _bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization") or ""
    return auth[7:].strip() if auth[:7].lower() == "bearer " else None


@app.middleware("http")
async def api_token_auth(request: Request, call_next):
    """
    Authorization: Bearer <API token> signs the request in as the token's owner. The token
    is swapped for that user's session cookie, so every route accepts it unchanged
    (archer/auth/tokens.py).
    """
    token = _bearer_token(request)
    if token is None:
        return await call_next(request)
    from starlette.concurrency import run_in_threadpool

    from archer.auth.tokens import session_for

    session_id = await run_in_threadpool(session_for, token)
    if not session_id:
        return JSONResponse({"error": "Invalid or revoked API token"}, status_code=401)
    cookies = [c for c in (request.headers.get("cookie") or "").split(";")
               if c.strip() and not c.strip().startswith("archer_session=")]
    headers = [(k, v) for k, v in request.scope["headers"] if k != b"cookie"]
    headers.append((b"cookie", "; ".join(cookies + [f"archer_session={session_id}"]).encode()))
    request.scope["headers"] = headers
    return await call_next(request)


# Include validation API router
app.include_router(get_validation_router())

# Include Ask Archer chat router
app.include_router(chat_router)

from archer.visualization.flow_layouts import router as flow_layout_router

app.include_router(flow_layout_router)

from archer.mitre.web import router as mitresaw_router
from archer.telemetry.web import router as telemetry_router
from archer.lab.web import router as lab_router
from archer.elevation import router as elevation_router

app.include_router(mitresaw_router)
app.include_router(telemetry_router)
app.include_router(lab_router)

from archer.runs_api import router as runs_router
from archer.webhooks import router as webhooks_router

app.include_router(runs_router)
app.include_router(webhooks_router)
app.include_router(elevation_router)


# Favicon route - ensure favicon is served from root with no-cache headers
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    favicon_path = paths.STATIC / "favicon-32.png"
    if favicon_path.exists():
        return FileResponse(
            favicon_path,
            media_type="image/png",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
    return HTMLResponse(status_code=404)


async def _sweep_expired_state():
    """Bound the in-memory CSRF and rate-limit stores and prune expired DB sessions."""
    import asyncio
    from archer.security.csrf import cleanup_expired_tokens
    from archer.security.rate_limit import cleanup_old_entries
    from archer.auth.session import cleanup_expired_sessions

    while True:
        await asyncio.sleep(600)
        try:
            cleanup_expired_tokens()
            cleanup_old_entries()
            await run_in_threadpool(cleanup_expired_sessions)
        except Exception as e:
            logger.warning(f"Expired-state sweep failed: {e}")


@app.on_event("startup")
async def start_expired_state_sweep():
    import asyncio

    app.state.expired_state_sweep = asyncio.create_task(_sweep_expired_state())


# Cache-busting token for static assets
@app.on_event("startup")
async def _set_asset_version():
    app.state.asset_version = datetime.now().strftime("%Y%m%d%H%M%S")


# Cleanup old drafts on startup (default: 30 days)
@app.on_event("startup")
def cleanup_old_drafts():
    """
    Remove draft files older than DRAFT_MAX_AGE_DAYS from data/drafts.

    This is a housekeeping task executed once during app startup. If the
    drafts directory doesn't exist we simply return. Any exceptions are
    caught and ignored because cleanup is non-fatal.
    """
    drafts_dir = DRAFTS_DIR
    if not os.path.exists(drafts_dir):
        return
    try:
        max_age_days = int(os.environ.get("DRAFT_MAX_AGE_DAYS", "30"))
        cutoff = (
            datetime.utcnow() - __import__("datetime").timedelta(days=max_age_days)
        ).timestamp()
        for root, dirs, files in os.walk(drafts_dir):
            for fname in files:
                path = os.path.join(root, fname)
                try:
                    if os.path.getmtime(path) < cutoff:
                        os.remove(path)
                except Exception:
                    # If a single file can't be removed, continue
                    pass
    except Exception:
        # non-fatal: don't prevent the app from starting if cleanup fails
        pass


# Initialize database on startup
@app.on_event("startup")
def initialize_database():
    """
    Initialize the authentication database.

    Creates all tables if they don't exist. Database is stored at data/archer.db.
    """
    init_db()


# Validate required mapping files on startup
@app.on_event("startup")
def validate_mapping_files():
    """
    Validate bespoke components using the centralised validator.

    Delegates to ``archer.build.bespoke.validate_bespoke_components()`` which
    checks all component categories (mappings, prompts, references, searches,
    config).  Missing critical components produce a warning; the app continues
    with degraded functionality rather than hard-exiting so that optional
    components (prompts, references, etc.) don't block startup.
    """
    from archer.build.bespoke import validate_bespoke_components

    report = validate_bespoke_components(verbose=True)

    if not report["all_critical_present"]:
        # Still warn loudly, but don't exit — generation will degrade gracefully
        missing = report["missing_critical"]
        print(
            f"\n  ⚠  {len(missing)} required bespoke mapping file(s) absent.  "
            "Query generation for affected platforms will be skipped.\n",
            flush=True,
        )


def get_mitre_lists():
    """
    Helper to return (tactics, techniques) used by templates.

    - tactics: ordered list of ATT&CK tactic names (filtered to an opinionated
      ordering defined by mitre_order).
    - techniques: cached list of technique display names stored in app.state
    """
    from .visualization.navigator import matrix

    # The Enterprise matrix's own order and names (v18: Stealth, Defense Impairment)
    tactics = [c["tactic"] for c in matrix(getattr(app.state, "bundle", None))]
    techniques = getattr(app.state, "techniques_to_choose", [])
    return tactics, techniques


def _newest_object(path) -> str:
    """The latest "modified" date in a STIX bundle: comparable across MITRE's feeds (the
    STIX 2.0 one MITRESaw reads carries no ATT&CK version number)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return max(re.findall(r'"modified":\s*"([^"]+)"', fh.read()), default="")
    except OSError:
        return ""


def _check_mitresaw_attack(archer_bundle) -> None:
    """MITRESaw runs on a copy of Archer's bundle: say so if its copy is older than Archer's
    (an older MITRESaw that fetched its own)."""
    from archer.mitre.procedures import _MITRESAW_DIR

    theirs = _newest_object(_MITRESAW_DIR / "data" / "stix" / "enterprise-attack.json")
    ours = _newest_object(archer_bundle)
    # The two feeds stamp the same release a day or so apart; a release apart is weeks
    lag = (datetime.fromisoformat(ours[:10]) - datetime.fromisoformat(theirs[:10])).days if theirs and ours else 0
    if lag > 7:
        print(f"Warning: MITRESaw's ATT&CK (newest object {theirs[:10]}) is older than Archer's "
              f"({ours[:10]}): mitre/cti may lag attack-stix-data")
    elif theirs and ours:
        print(f"✓ MITRESaw and Archer are on the same ATT&CK (newest objects {theirs[:10]} / {ours[:10]})")


def _refresh_procedures_if_stale(load: dict) -> None:
    """MITRESaw's procedures CSV (threat briefing, Splunk detections) follows ATT&CK: when
    the bundle is newer than the CSV, rebuild it in the background so startup isn't held."""
    from archer.mitre import procedures
    from archer.mitre.procedures import _DEFAULT_CSV, MitresawBusy, run_mitresaw_detection

    bundle_path = load.get("cache_path")
    csv_mtime = _DEFAULT_CSV.stat().st_mtime if _DEFAULT_CSV.exists() else 0
    if not (load.get("updated") or (bundle_path and os.path.getmtime(bundle_path) > csv_mtime)):
        return

    def run():
        try:
            print(f"Rebuilding the procedures CSV for ATT&CK v{load.get('version') or '?'} (MITRESaw)...")
            run_mitresaw_detection(force=True)
            plan = procedures.LAST_PLAN
            print("✓ Procedures CSV rebuilt" + (
                f" ({len(plan['run'])} groups ATT&CK changed collected again, {len(plan['drop'])} dropped)"
                if plan is not None else " (every group)"))
            _check_mitresaw_attack(bundle_path)
            if procedures.LAST_CHECK:
                ok = procedures.LAST_CHECK["ok"]
                print(("✓ " if ok else "Warning: ") + procedures.describe_check(procedures.LAST_CHECK))
        except MitresawBusy as e:
            print(f"Procedures CSV not rebuilt now: {e}")
        except Exception as e:
            print(f"Warning: procedures CSV not rebuilt: {e}")

    threading.Thread(target=run, name="mitresaw-refresh", daemon=True).start()


# Load MITRE data on startup and cache in app.state
@app.on_event("startup")
def load_mitre_data():
    # Download the MITRE ATT&CK STIX bundle and cache useful indexes in
    # app.state so template handlers can access them without repeated network
    # calls. These calls are synchronous during startup to ensure the data
    # is available for user requests.
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    # Always the latest ATT&CK: a conditional request, so an unchanged bundle costs little
    bundle = get_stix_data(url, check_latest=True)
    from archer.mitre.enterprise import LAST_LOAD

    app.state.attack = dict(LAST_LOAD)
    app.state.bundle = bundle
    _refresh_procedures_if_stale(LAST_LOAD)
    app.state.techniques_to_choose = obtain_all_techniques(bundle)
    app.state.technique_descriptions = obtain_technique_descriptions(bundle)

    # Techniques with nothing in ATT&CK to build a query from; rebuilt when ATT&CK changes
    from archer.build.technique_yield import ensure as ensure_technique_yield

    ensure_technique_yield(bundle)

    # Build / load enriched group metadata cache
    # (heuristic extraction from STIX descriptions — no external APIs needed)
    try:
        from archer.config import GROUP_METADATA_CACHE
        from archer.mitre.group_metadata import build_group_metadata_cache, load_group_metadata
        import os, json as _json

        cache_path = GROUP_METADATA_CACHE

        # Determine whether cache needs rebuilding:
        # rebuild if cache is absent or older than the STIX bundle cache
        stix_cache = LAST_LOAD.get("cache_path") or ""
        needs_build = not os.path.exists(cache_path)
        if not needs_build and os.path.exists(stix_cache):
            needs_build = os.path.getmtime(stix_cache) > os.path.getmtime(cache_path)

        if needs_build:
            print("Building group metadata cache from STIX bundle…")
            objects = list(bundle.objects)
            group_meta = build_group_metadata_cache(objects, cache_path)
            group_count = sum(1 for k in group_meta if k.startswith("G"))
            print(f"Group metadata cache built: {group_count} groups")
        else:
            group_meta = load_group_metadata(cache_path)

        app.state.group_metadata = group_meta

        # The threat feed, collected in the background on every start (only new posts are fetched)
        from archer.intelligence.feed import refresh_in_background as refresh_feed

        refresh_feed(bundle, group_meta, force=True)

        # The last 30 days of CVEs and KEV, daily; KEV and stack CVEs researched in advance
        from archer.intelligence.cve_feed import keep_current

        keep_current(_all_stacks)

        # Watchlists need collections nobody asks for: every REFRESH_EVERY while any exist
        from archer.intelligence.watchlists import keep_collecting

        keep_collecting(lambda: (getattr(app.state, "bundle", None), getattr(app.state, "group_metadata", {}) or {}))

    except Exception as _e:
        import traceback
        traceback.print_exc()
        print(f"Warning: group metadata enrichment failed: {_e}")
        app.state.group_metadata = {}


@app.on_event("startup")
async def initialize_osint_repos():
    """
    Initialize OSINT detection repositories on startup.

    Clones or updates Elastic, Splunk, Azure Sentinel and Google SecOps detection
    rule repositories locally for fast, offline searching without API rate
    limits. Repos are updated
    every hour automatically when searches are performed.

    This runs in the background to avoid blocking app startup.
    """
    import asyncio
    from archer.build.osint_repos import clone_or_update_repo, REPOS

    # Set initial status
    app.state.osint_ready = False
    app.state.osint_status = "Initializing OSINT detection repositories..."
    app.state.osint_repos = {}  # Track status per repo
    app.state.osint_failed_repos = []
    app.state.lol_status = {}
    app.state.osint_user_accepted_failures = False

    async def init_repos():
        try:
            app.state.osint_status = (
                "Cloning detection repositories (this may take 15-20 minutes on first run)..."
            )

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()

            # Clone each repo and track results
            failed_repos = []
            successful_repos = []

            for repo_name in REPOS.keys():
                app.state.osint_status = f"Cloning {repo_name}..."
                app.state.osint_repos[repo_name] = {"status": "cloning", "error": None}

                try:
                    success = await loop.run_in_executor(
                        None, clone_or_update_repo, repo_name, False
                    )

                    if success:
                        app.state.osint_repos[repo_name] = {"status": "ready", "error": None}
                        successful_repos.append(repo_name)
                    else:
                        # Check if it's a timeout by looking at the printed output
                        # The clone_or_update_repo function returns False for timeouts
                        app.state.osint_repos[repo_name] = {
                            "status": "failed",
                            "error": "Clone failed (possibly timeout)",
                        }
                        failed_repos.append(repo_name)
                except Exception as e:
                    error_msg = str(e)
                    if "Timeout" in error_msg or "timed out" in error_msg.lower():
                        error_msg = "Timeout while cloning (repo too large or slow connection)"
                    app.state.osint_repos[repo_name] = {"status": "failed", "error": error_msg}
                    failed_repos.append(repo_name)

            app.state.osint_failed_repos = failed_repos

            # LOLBAS / LOLRMM / LOLDrivers JSON (at most daily), then their index
            from archer.build import lol
            for name in lol.SOURCES:
                app.state.lol_status[name] = "cloning"
            try:
                lol_status = await loop.run_in_executor(None, lol.update)
                await loop.run_in_executor(None, lol.build_index)
                app.state.lol_status.update(lol_status)
            except Exception as e:
                app.state.lol_status.update({n: f"failed: {e}" for n in lol.SOURCES})

            if failed_repos:
                app.state.osint_ready = "partial"
                app.state.osint_status = f"⚠️ {len(successful_repos)}/{len(REPOS)} repos ready. Failed: {', '.join(failed_repos)}"
                print(f"⚠️  OSINT initialization completed with failures: {failed_repos}")
            else:
                app.state.osint_ready = True
                app.state.osint_status = "OSINT repositories ready"
                print("✓ OSINT repositories initialized successfully")

        except Exception as e:
            app.state.osint_ready = False
            app.state.osint_status = f"Failed to initialize OSINT repos: {e}"
            print(f"⚠️  Failed to initialize OSINT repos: {e}")

    # Start initialization in background
    asyncio.create_task(init_repos())


@app.on_event("startup")
async def detect_local_llm():
    """Detect available local LLM endpoints on startup."""
    import requests
    import asyncio

    # provider_id is what the Hunt-page AI picker and RemoteAPIGenerator use to
    # select a provider; "models_endpoint" marks endpoints that expose an
    # OpenAI-compatible /v1/models list (Ollama also supports this at /v1/models,
    # but its native /api/tags shape is checked below for backward compatibility).
    llm_endpoints = [
        ("Ollama", "ollama", "http://localhost:11434/api/tags", "http://localhost:11434", False),
        ("LM Studio", "lmstudio", "http://localhost:1234/v1/models", "http://localhost:1234", True),
        ("Llama.cpp", "llamacpp", "http://localhost:8080/health", "http://localhost:8080", False),
        ("Osaurus", "osaurus", "http://localhost:1337/v1/models", "http://localhost:1337", True),
    ]

    async def check_endpoint(name, provider_id, url, base_url, is_openai_models_endpoint):
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, lambda: requests.get(url, timeout=2))
            if response.ok:
                result = {
                    "name": name,
                    "provider": provider_id,
                    "url": url,
                    "base_url": base_url,
                    "available": True,
                    "models": [],
                    "model": None,
                }
                try:
                    data = response.json()
                    if name == "Ollama":
                        models = [m["name"] for m in data.get("models", []) if "name" in m]
                    elif is_openai_models_endpoint:
                        models = [m["id"] for m in data.get("data", []) if "id" in m]
                    else:
                        models = []
                    result["models"] = models
                    result["model"] = models[0] if models else None
                except Exception:
                    pass
                return result
        except:
            pass
        return None

    # Check all endpoints concurrently
    tasks = [check_endpoint(name, provider_id, url, base_url, is_models_ep)
             for name, provider_id, url, base_url, is_models_ep in llm_endpoints]
    results = await asyncio.gather(*tasks)

    available = [r for r in results if r]
    app.state.local_llm_endpoints = available

    # Preserve the original single-endpoint shape for the existing navbar modal
    # (base.html) and /api/llm/detect — first detected endpoint wins.
    if available:
        result = available[0]
        app.state.local_llm_detected = result
        model_info = f" (model: {result['model']})" if result.get("model") else ""
        models_info = f", {len(result['models'])} model(s) available" if result.get("models") else ""
        print(f"✓ Local LLM detected: {result['name']} at {result['url']}{model_info}{models_info}")
        if len(available) > 1:
            others = ", ".join(r["name"] for r in available[1:])
            print(f"  (also available: {others})")
    else:
        app.state.local_llm_detected = {"available": False}
        app.state.local_llm_endpoints = []
        print("ℹ️  No local LLM detected")


app.state.redetect_local_llm = detect_local_llm


@app.on_event("startup")
async def detect_network_connectivity():
    """
    Check general internet reachability and per-cloud-provider reachability at
    startup. Distinguishes "no internet at all" from "internet works but this
    specific AI vendor's domain is blocked" (common behind corporate proxies/
    firewalls) — both look identical to a user as "cloud AI doesn't work",
    but the fix is different (check your network vs. check your API key).
    """
    import asyncio
    from archer.ai.llm.connectivity import get_network_status

    loop = asyncio.get_event_loop()
    status = await loop.run_in_executor(None, get_network_status)
    app.state.network_status = status

    if status["internet_available"]:
        unreachable = [p for p, ok in status["provider_reachable"].items() if not ok]
        if unreachable:
            print(f"✓ Internet connectivity available (blocked for: {', '.join(unreachable)})")
        else:
            print("✓ Internet connectivity available — all cloud AI provider hosts reachable")
    else:
        print("⚠️  No internet connectivity detected — cloud AI providers will be unavailable (local LLMs may still work)")


@app.on_event("startup")
def check_docker_on_startup():
    """Check Docker availability at startup and log the result."""
    from archer.validation import check_docker_available
    available, message = check_docker_available()
    if available:
        print("✓ Docker is available — detection validation with SIEM containers is enabled")
    else:
        print(f"⚠  Detection validation unavailable: {message}")


@app.get("/api/llm/detect")
async def get_local_llm_status():
    """Get local LLM detection status, including available models for Ollama."""
    import requests as _req
    state = getattr(app.state, "local_llm_detected", {"available": False})
    # If Ollama detected but models weren't fetched at startup, grab them now
    if state.get("available") and state.get("name") == "Ollama" and not state.get("models"):
        try:
            r = _req.get("http://localhost:11434/api/tags", timeout=2)
            if r.ok:
                models = [m["name"] for m in r.json().get("models", []) if "name" in m]
                state = dict(state)
                state["models"] = models
                state["model"] = state.get("model") or (models[0] if models else None)
                state["base_url"] = "http://localhost:11434"
                app.state.local_llm_detected = state
        except Exception:
            pass
    return state


@app.get("/api/ai/availability")
async def get_ai_availability(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    What the Hunt page's AI prompt offers this user (GitHub #10): the providers in their
    profile that can generate detections, the one assigned to detection generation
    (preselected), and a remembered choice if they ticked "Remember". With none
    configured the page runs the hunt without asking.
    """
    from archer.ai.assignment import configured_providers, load_settings

    empty = {"any_available": False, "providers": [], "assigned": None, "remember": None, "ask_only": []}
    if not archer_session:
        return empty
    db = next(get_db())
    try:
        user = get_user_from_session_id(archer_session, db)
        if not user:
            return empty
        settings = load_settings(db, user.id)
        providers = configured_providers(db, user.id, settings)
    finally:
        db.close()
    usable = [{"id": p["id"], "label": p["label"], "model": p["model"]} for p in providers if p["detection"]]
    return {
        "any_available": bool(usable),
        "providers": usable,
        "assigned": settings.get("detection"),
        "remember": settings.get("remember"),
        "max_calls": settings.get("max_detection_calls"),
        # Configured but not offered, and why (shown as a note)
        "ask_only": [{"label": p["label"], "note": p.get("detection_note", "")} for p in providers if not p["detection"]],
    }


_KNOWN_AI_PROVIDERS = {"anthropic", "openai", "google", "deepseek", "qwen", "grok", "ollama", "osaurus"}
_LOCAL_AI_PROVIDERS = {"ollama", "osaurus"}


def _verify_local_model_available(base_url: str, provider: str, model: str) -> bool:
    """
    Live-check whether `model` is still loaded at the local endpoint. The
    availability check the AI prompt used could be stale by the time the hunt
    actually runs (model unloaded, server restarted with a different model,
    etc.) — this catches that instead of letting generation fail outright.
    """
    if not base_url or not model:
        return False
    import requests
    try:
        if provider == "ollama":
            # base_url from detection is the bare host (e.g. http://localhost:11434)
            resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=2)
            if resp.ok:
                names = [m.get("name") for m in resp.json().get("models", [])]
                return model in names
        else:
            # Osaurus (and any other OpenAI-compatible local server) exposes /v1/models
            models_url = base_url.rstrip("/")
            if not models_url.endswith("/v1"):
                models_url += "/v1"
            resp = requests.get(f"{models_url}/models", timeout=2)
            if resp.ok:
                ids = [m.get("id") for m in resp.json().get("data", [])]
                return model in ids
    except Exception:
        pass
    return False


def _hunt_llm_args(archer_session: Optional[str], ai_provider: Optional[str], ai_model: Optional[str]) -> dict:
    """
    process_group's use_llm/llm_config for the provider picked in the Hunt prompt
    (GitHub #10): resolved against the user's own profile keys and settings, so a
    choice the user hasn't configured, or a local model (Ask only, #9), runs without AI.
    """
    if not ai_provider or not archer_session:
        return {}
    from archer.ai.assignment import detection_llm_config, resolve

    db = next(get_db())
    try:
        user = get_user_from_session_id(archer_session, db)
        resolved = resolve(db, user.id, "detection", ai_provider, ai_model) if user else None
    finally:
        db.close()
    if not resolved:
        print(f"⚠️  AI provider '{ai_provider}' isn't available for detection generation — continuing without AI.")
        return {}
    print(f"🤖 Detection generation: {resolved['label']} / {resolved['model'] or 'default model'} "
          f"(up to {resolved['max_calls']} LLM calls this run)")
    return {"use_llm": "llm", "llm_config": detection_llm_config(resolved)}


# SIEMs a user can choose in Profile, and the vendor key process_group excludes them by
SIEM_PLATFORMS = {"secops": "googlesecops", "mde": "mde", "splunk": "splunk", "elastic": "elastic"}
SIEM_LABELS = {"secops": "Google SecOps", "mde": "Defender XDR", "splunk": "Splunk", "elastic": "Elastic"}
# Elastic now generates ES|QL detections (archer.build.elastic); nothing is Coming Soon
SIEM_COMING_SOON = {}


def _user_siems(user) -> list:
    try:
        chosen = json.loads(user.siem_platforms) if user and user.siem_platforms else []
    except (ValueError, TypeError):
        return []
    return [s for s in chosen if s in SIEM_PLATFORMS]


def _siem_args(archer_session: Optional[str], *extra_excluded: str) -> dict:
    """
    process_group's excluded_vendors for the SIEMs the user generates for (Profile → SIEM
    platforms; none chosen means all), plus any the request excludes itself.
    """
    excluded = set(extra_excluded)
    if archer_session:
        db = next(get_db())
        try:
            chosen = _user_siems(get_user_from_session_id(archer_session, db))
        finally:
            db.close()
        if chosen:
            excluded |= {v for k, v in SIEM_PLATFORMS.items() if k not in chosen}
    return {"excluded_vendors": sorted(excluded)} if excluded else {}


def _user_stack(user) -> list:
    from archer.intelligence.tech_stack import as_stack

    try:
        return as_stack(json.loads(user.tech_stack)) if user and user.tech_stack else []
    except (ValueError, TypeError):
        return []


def _all_stacks() -> list:
    """Every user's technology stack, for the CVEs researched in advance."""
    db = next(get_db())
    try:
        return [s for s in (_user_stack(u) for u in db.query(User).all()) if s]
    finally:
        db.close()


def _session_stack(archer_session: Optional[str]) -> list:
    if not archer_session:
        return []
    db = next(get_db())
    try:
        return _user_stack(get_user_from_session_id(archer_session, db))
    finally:
        db.close()


def _stack_args(archer_session: Optional[str], ignore: bool = False) -> dict:
    """process_group's tech_stack (Profile → Technology stack) for a group hunt; ignore: all of ATT&CK."""
    chosen = [] if ignore else _session_stack(archer_session)
    return {"tech_stack": chosen} if chosen else {}


def _warn_cve_off_stack(group_name: str, cve: str, nvd: dict, archer_session: Optional[str]) -> None:
    """A CVE hunt is generated anyway; the results page says when NVD's products aren't in the stack."""
    from archer.build import run_files
    from archer.intelligence.tech_stack import cpe_products, label

    chosen = _session_stack(archer_session)
    cpes = nvd.get("cpes") or ([f"cpe:2.3:a:{nvd['vendor']}:{nvd.get('product') or '*'}"] if nvd.get("vendor") else [])
    affected = cpe_products(cpes)
    if chosen and affected and not set(affected) & set(chosen):
        run_files.warn(group_name, f"{cve} affects {', '.join(label(p) for p in affected)}, "
                                   "which isn't in your technology stack")


def _report_ai_args(archer_session: Optional[str], extraction: dict) -> dict:
    """
    genai_mode and use_llm/llm_config for generating from an upload or blog post: the AI
    chosen in the prompt before it was read (saved with the extraction), as for a hunt.
    """
    provider, model = extraction.get("ai_provider") or None, extraction.get("ai_model") or None
    return {"genai_mode": _apply_ai_provider_choice(provider, model) or "semantic",
            **_hunt_llm_args(archer_session, provider, model)}


def _apply_ai_provider_choice(ai_provider: str, ai_model: str = None) -> str:
    """
    Given the provider id chosen in the Hunt-page AI prompt, configure the
    environment for RemoteAPIGenerator (archer/ai/genai/models.py) and return
    the genai_mode string the rest of the /generate pipeline expects.

    Re-verifies availability at the moment the hunt actually runs (network
    reachability for cloud, model-still-loaded for local) rather than trusting
    the earlier /api/ai/availability snapshot, which can go stale between the
    prompt being shown and the hunt being submitted. On any failure, logs a
    warning and returns None so the caller falls back to non-AI generation
    instead of the hunt failing outright.

    Returns None if ai_provider is empty/unrecognized/unavailable (caller
    should fall back to the legacy ai_generators/local_llm checkbox fields,
    which will also come up empty, ending in the plain semantic/heuristic mode).
    """
    if not ai_provider or ai_provider not in _KNOWN_AI_PROVIDERS:
        return None

    if ai_provider in _LOCAL_AI_PROVIDERS:
        matched = None
        for endpoint in getattr(app.state, "local_llm_endpoints", []) or []:
            if endpoint.get("provider") == ai_provider:
                matched = endpoint
                break
        if not matched:
            print(f"⚠️  AI provider '{ai_provider}' was selected but is no longer detected as running — continuing without AI.")
            return None

        base_url = matched.get("base_url", "")
        model = ai_model or matched.get("model") or ""
        if not _verify_local_model_available(base_url, ai_provider, model):
            print(f"⚠️  Model '{model}' is no longer loaded at {ai_provider} ({base_url}) — continuing without AI.")
            return None

        os.environ["GENAI_MODEL"] = ai_provider
        os.environ["AI_LOCAL_BASE_URL"] = base_url
        os.environ["AI_LOCAL_MODEL"] = model
        return "local_llm"

    # Cloud provider — re-verify network reachability before trusting it.
    from archer.ai.llm.connectivity import check_provider_reachable
    if not check_provider_reachable(ai_provider):
        print(f"⚠️  '{ai_provider}' API host is unreachable right now (network/firewall) — continuing without AI.")
        return None

    os.environ["GENAI_MODEL"] = ai_provider
    return "ai_generators"


@app.post("/api/llm/model")
async def set_llm_model(request: Request):
    """
    Set the active local LLM model.

    Body: {"model": "llama3.2:3b"}
    Updates app.state.local_llm_detected['model'] so all subsequent LLM
    calls use the selected model.
    """
    try:
        body = await request.json()
        model = body.get("model", "").strip()
        if not model:
            return JSONResponse({"success": False, "error": "model is required"}, status_code=400)

        state = getattr(app.state, "local_llm_detected", {})
        if not state.get("available"):
            return JSONResponse({"success": False, "error": "No local LLM available"}, status_code=400)

        available_models = state.get("models", [])
        if available_models and model not in available_models:
            return JSONResponse(
                {"success": False, "error": f"Model '{model}' not in available models: {available_models}"},
                status_code=400,
            )

        state["model"] = model
        app.state.local_llm_detected = state
        logger.info("Local LLM model set to: %s", model)
        return JSONResponse({"success": True, "model": model})
    except Exception as exc:
        return JSONResponse({"success": False, "error": str(exc)}, status_code=500)


@app.post("/api/llm/preference")
async def set_llm_preference(
    request: Request,
    use_local_llm: bool = Form(...),
    dont_ask_again: bool = Form(False),
    archer_session: Optional[str] = Cookie(None),
):
    """Save user preference for local LLM usage."""
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    user, db = auth_result

    # Store preference in database or user settings
    # For now, store in app.state (could be moved to database)
    if not hasattr(app.state, "user_llm_preferences"):
        app.state.user_llm_preferences = {}

    app.state.user_llm_preferences[user.id] = {
        "use_local_llm": use_local_llm,
        "dont_ask_again": dont_ask_again,
    }

    db.close()

    return {
        "success": True,
        "message": "LLM preference saved",
        "use_local_llm": use_local_llm,
    }


@app.get("/api/status/osint")
def get_osint_status():
    """Get OSINT repository initialization status, with each clone's last commit date."""
    from archer.config import OSINT_REPOS_DIR

    repos = {}
    for name, state in getattr(app.state, "osint_repos", {}).items():
        updated = None
        path = os.path.join(OSINT_REPOS_DIR, name)
        if os.path.isdir(os.path.join(path, ".git")):
            try:
                out = subprocess.run(["git", "-C", path, "log", "-1", "--format=%cs"],
                                     capture_output=True, text=True, timeout=5)
                updated = out.stdout.strip() or None
            except (OSError, subprocess.SubprocessError):
                pass
        else:
            from archer.build.osint_repos import commit_date
            updated = commit_date(name)
        repos[name] = {**state, "updated": updated}
    from archer.build import lol
    for name, state in getattr(app.state, "lol_status", {}).items():
        failed = state.startswith("failed")
        repos[name] = {"status": "failed" if failed else state, "error": state[8:] if failed else None,
                       "updated": lol.updated(name)}
    return {
        "ready": getattr(app.state, "osint_ready", False),
        "status": getattr(app.state, "osint_status", "Unknown"),
        "repos": repos,
        "failed_repos": getattr(app.state, "osint_failed_repos", []),
        "user_accepted_failures": getattr(app.state, "osint_user_accepted_failures", False),
    }


@app.post("/api/status/osint/accept-failures")
async def accept_osint_failures():
    """User accepts to continue without failed OSINT repos."""
    app.state.osint_user_accepted_failures = True
    # If we have at least one successful repo, consider it ready
    if app.state.osint_ready == "partial":
        app.state.osint_ready = True
    return {"accepted": True, "message": "Continuing without failed repositories"}


@app.get("/api/status/bespoke")
async def get_bespoke_status():
    """
    Get bespoke (organization-specific) configuration status including component validation.

    Returns information about:
    - Whether bespoke customization is enabled
    - Number of exclusions configured (processes, users, hosts, IPs)
    - Number of custom sample searches
    - Organization name if configured
    - Component validation: which mappings, prompts, references, and searches are present
    """
    try:
        from .build.bespoke import get_bespoke_status as _get_bespoke_status, validate_bespoke_components

        status = _get_bespoke_status()
        validation = validate_bespoke_components(verbose=False)
        status["validation"] = {
            "all_critical_present": validation["all_critical_present"],
            "missing_critical": validation["missing_critical"],
            "missing_optional": validation["missing_optional"],
            "components": [
                {"name": c["name"], "status": c["status"], "required": c["required"]}
                for c in validation["components"]
            ],
        }
        return status
    except ImportError:
        return {"enabled": False, "error": "Bespoke module not available"}
    except Exception as e:
        return {"enabled": False, "error": str(e)}


@app.get("/api/bespoke/sample-searches")
async def get_bespoke_sample_searches(technique_id: str = None, platform: str = None):
    """
    Get organization-specific sample searches.

    Args:
        technique_id: Filter by MITRE technique ID (e.g., T1003.001)
        platform: Filter by platform (MDE, Splunk, Elastic)
    """
    try:
        from .build.bespoke import get_sample_searches

        searches = get_sample_searches(technique_id=technique_id, platform=platform)
        return {"count": len(searches), "searches": searches}
    except ImportError:
        return {"count": 0, "searches": [], "error": "Bespoke module not available"}
    except Exception as e:
        return {"count": 0, "searches": [], "error": str(e)}


@app.post("/api/bespoke/reload")
async def reload_bespoke_config():
    """
    Reload bespoke configuration from disk.

    Use this after modifying exclusions.yaml or config.yaml to apply changes
    without restarting the server.
    """
    try:
        from .build.bespoke import clear_cache, get_bespoke_status

        clear_cache()
        status = get_bespoke_status()
        return {"success": True, "message": "Bespoke configuration reloaded", "status": status}
    except ImportError:
        return {"success": False, "error": "Bespoke module not available"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/coverage/detections")
def detection_coverage():
    """Your detections per tactic and technique, by the mapping in force: the Coverage
    matrix's "My detections" layer."""
    from .visualization.navigator import detections_by_tactic, legacy

    by_tactic = detections_by_tactic(GENERATE_DIR)
    seen = {tid for techs in by_tactic.values() for tid in techs}
    old = legacy(getattr(app.state, "bundle", None))
    return {"by_tactic": by_tactic, "legacy": {tid: v for tid, v in old.items() if tid in seen}}


@app.get("/api/reference/coverage")
async def get_reference_coverage():
    """
    Get reference query coverage map.
    Returns technique coverage by platform.
    """
    try:
        from .build.references import get_coverage_map
        from .visualization.navigator import matrix

        coverage = get_coverage_map()
        # Every ATT&CK tactic and technique, for the Navigator-style matrix
        coverage["matrix"] = matrix(getattr(app.state, "bundle", None))
        return coverage
    except ImportError:
        return {"error": "Reference queries module not available", "coverage": {}}
    except Exception as e:
        return {"error": str(e), "coverage": {}}


@app.get("/api/reference/queries")
async def get_references(technique_id: str = None, platform: str = None):
    """
    Get reference queries, optionally filtered by technique or platform.
    """
    try:
        from .build.references import get_references

        queries = get_references(technique_id=technique_id, platform=platform)
        return {"count": len(queries), "queries": queries}
    except ImportError:
        return {"count": 0, "queries": [], "error": "Reference queries module not available"}
    except Exception as e:
        return {"count": 0, "queries": [], "error": str(e)}


@app.get("/coverage", response_class=HTMLResponse)
async def coverage_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Reference query coverage visualization page."""
    # Check if user is logged in (but don't require it)
    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()
    return templates.TemplateResponse("coverage.html", {"request": request, "user": user})


@app.get("/mitresaw", response_class=HTMLResponse)
async def mitresaw_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """MITRESaw: the procedures CSV, its rebuild and its exclusions (archer.mitre.web)."""
    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()
    return templates.TemplateResponse("mitresaw.html", {"request": request, "user": user})


@app.get("/emulate", response_class=HTMLResponse)
async def emulate_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Recorded attack telemetry per technique and data source, and detections checked against it (archer.telemetry)."""
    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()
    # The SIEM the page shows tables or event types for: the first of the user's, SecOps first
    chosen = _user_siems(user)
    siem = next((s for s in ("secops", "mde") if s in chosen), "secops")
    return templates.TemplateResponse("emulate.html", {"request": request, "user": user, "siem": siem})


@app.get("/cyber-powers", response_class=HTMLResponse)
async def cyber_powers_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """World map of national cyber power: the IISS tiers and the states threat reporting names."""
    from archer.intelligence.cyber_powers import powers

    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()
    from archer.intelligence.cyber_powers import MAP_PATH, page_data

    data = page_data(getattr(request.app.state, "bundle", None), getattr(request.app.state, "group_metadata", {}) or {},
                     getattr(user, "country", None))
    return templates.TemplateResponse("cyber_powers.html", {"request": request, "user": user, "powers": powers(),
                                                            "map_svg": MAP_PATH.read_text(encoding="utf-8"), "data": data})


@app.get("/api/correlation/params")
async def get_correlation_params():
    """Get current correlation parameters from config files."""
    import re

    try:
        # Read config.py for threshold
        config_path = os.path.join(os.path.dirname(__file__), "config.py")
        with open(config_path, "r") as f:
            config_content = f.read()

        # Extract threshold
        threshold_match = re.search(
            r'correlation_min_relevance = float\(os\.getenv\("CORRELATION_MIN_RELEVANCE", "([0-9.]+)"\)\)',
            config_content,
        )
        threshold = float(threshold_match.group(1)) if threshold_match else 0.40

        # Read engine.py for per_vendor and tech_freq
        engine_path = os.path.join(os.path.dirname(__file__), "ai", "genai", "engine.py")
        with open(engine_path, "r") as f:
            engine_content = f.read()

        # Extract max_per_vendor
        per_vendor_match = re.search(r"max_per_vendor: int = (\d+)", engine_content)
        per_vendor = int(per_vendor_match.group(1)) if per_vendor_match else 25

        # Extract tech frequency limit
        tech_freq_match = re.search(
            r"if max_occurrences < (\d+):\s*#.*simple correlations", engine_content
        )
        tech_freq = int(tech_freq_match.group(1)) if tech_freq_match else 20

        return {
            "success": True,
            "threshold": threshold,
            "per_vendor": per_vendor,
            "tech_freq": tech_freq,
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "threshold": 0.40,
            "per_vendor": 25,
            "tech_freq": 20,
        }


@app.post("/api/correlation/params")
async def save_correlation_params(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Save correlation parameters to config files. Admin only: this rewrites source files."""
    import re

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"success": False, "message": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    if user.role != UserRole.ADMIN:
        return JSONResponse({"success": False, "message": "Admin access required"}, status_code=403)

    try:
        data = await request.json()
        threshold = float(data.get("threshold", 0.40))
        per_vendor = int(data.get("per_vendor", 25))
        tech_freq = int(data.get("tech_freq", 20))

        # Validate inputs
        if not (0.0 <= threshold <= 1.0):
            return {"success": False, "message": "Threshold must be between 0.0 and 1.0"}

        if per_vendor < 1:
            return {"success": False, "message": "Per-vendor limit must be at least 1"}

        if tech_freq < 1:
            return {"success": False, "message": "Tech frequency limit must be at least 1"}

        # Update config.py
        config_path = os.path.join(os.path.dirname(__file__), "config.py")
        with open(config_path, "r") as f:
            lines = f.readlines()

        for i, line in enumerate(lines):
            if 'correlation_min_relevance = float(os.getenv("CORRELATION_MIN_RELEVANCE"' in line:
                lines[i] = (
                    f'    correlation_min_relevance = float(os.getenv("CORRELATION_MIN_RELEVANCE", "{threshold}"))\n'
                )

        with open(config_path, "w") as f:
            f.writelines(lines)

        # Update engine.py
        engine_path = os.path.join(os.path.dirname(__file__), "ai", "genai", "engine.py")
        with open(engine_path, "r") as f:
            content = f.read()

        # Update max_per_vendor parameter default
        content = re.sub(
            r"max_per_vendor: int = \d+", f"max_per_vendor: int = {per_vendor}", content
        )

        # Update tech frequency limit
        lines = content.split("\n")
        for i, line in enumerate(lines):
            if "if max_occurrences <" in line and "simple correlations" in line:
                lines[i] = (
                    f"            if max_occurrences < {tech_freq}:  # Allow each technique in up to {tech_freq} simple correlations"
                )
                break

        with open(engine_path, "w") as f:
            f.write("\n".join(lines))

        return {
            "success": True,
            "message": "Correlation parameters updated successfully",
            "threshold": threshold,
            "per_vendor": per_vendor,
            "tech_freq": tech_freq,
        }

    except Exception as e:
        return {"success": False, "message": f"Error saving parameters: {str(e)}"}


@app.post("/api/status/osint/retry-failed")
async def retry_failed_osint_repos():
    """Retry cloning only the failed OSINT repositories."""
    import asyncio
    from archer.build.osint_repos import clone_or_update_repo

    failed_repos = getattr(app.state, "osint_failed_repos", [])

    if not failed_repos:
        return {"success": True, "message": "No failed repositories to retry", "retried": []}

    # Reset state for retry
    app.state.osint_ready = False
    app.state.osint_user_accepted_failures = False
    retried_repos = []

    async def retry_repos():
        loop = asyncio.get_event_loop()
        newly_failed = []
        newly_succeeded = []

        for repo_name in failed_repos:
            app.state.osint_status = f"Retrying {repo_name}..."
            app.state.osint_repos[repo_name] = {"status": "cloning", "error": None}

            try:
                success = await loop.run_in_executor(None, clone_or_update_repo, repo_name, True)

                if success:
                    app.state.osint_repos[repo_name] = {"status": "ready", "error": None}
                    newly_succeeded.append(repo_name)
                else:
                    app.state.osint_repos[repo_name] = {"status": "failed", "error": "Clone failed"}
                    newly_failed.append(repo_name)
            except Exception as e:
                error_msg = str(e)
                if "Timeout" in error_msg or "timed out" in error_msg.lower():
                    error_msg = "Timeout while cloning (repo too large or slow connection)"
                app.state.osint_repos[repo_name] = {"status": "failed", "error": error_msg}
                newly_failed.append(repo_name)

        # Update failed repos list
        app.state.osint_failed_repos = newly_failed

        # Update ready state
        if newly_failed:
            app.state.osint_ready = "partial"
            app.state.osint_status = f"⚠️ Retry complete. Still failed: {', '.join(newly_failed)}"
        else:
            app.state.osint_ready = True
            app.state.osint_status = "All repositories ready after retry"

    # Start retry in background
    asyncio.create_task(retry_repos())

    return {
        "success": True,
        "message": f"Retrying {len(failed_repos)} failed repository/repositories",
        "retried": failed_repos,
    }


@app.get("/", response_class=HTMLResponse)
def read_form(request: Request, archer_session: Optional[str] = Cookie(None)):
    # Render the index page where the user can enter a group name. The
    # template expects a `request` object and optionally lists of
    # techniques; other placeholders are provided for future features.

    # Check if user is logged in (but don't require it)
    user = None
    saved_keys = {}  # platform -> enabled (NULL/True treated as enabled)
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
            if user:
                saved_keys = {k.platform: (k.enabled is not False)
                              for k in db.query(APIKey.platform, APIKey.enabled).filter(APIKey.user_id == user.id)}
        finally:
            db.close()

    # Which OSINT keys are set (Profile → API Keys or the environment), for the Profile tab.
    # Only whether each is present; values never reach the page.
    osint_keys = [
        {"env": env, "platform": platform,
         "set": platform in saved_keys or bool(os.environ.get(env)),
         "in_vault": platform in saved_keys,
         "enabled": saved_keys.get(platform, True),
         "what": what, "url": url, "site": site}
        for env, platform, what, url, site in (
            ("SHODAN_API_KEY", "shodan", "Internet-facing assets", "https://account.shodan.io/register", "shodan.io"),
            ("SECURITYTRAILS_API_KEY", "securitytrails", "DNS history", "https://securitytrails.com/app/signup", "securitytrails.com"),
            ("HIBP_API_KEY", "hibp", "Breach exposure", "https://haveibeenpwned.com/API/Key", "haveibeenpwned.com"),
            ("GITHUB_TOKEN", "github", "Secret scanning", "https://github.com/settings/tokens", "github.com"),
            ("OPENAI_API_KEY", "openai", "AI Enhancement", "https://platform.openai.com/api-keys", "openai.com"),
        )
    ]

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "osint_keys": osint_keys,
            "techniques": getattr(app.state, "techniques_to_choose", []),
            "message": None,
            "actor_found": None,
            "wait_message": None,
            "js_script": None,
        },
    )


@app.get("/how-it-works", response_class=HTMLResponse)
def how_it_works(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Render the 'How Archer Works' documentation page."""

    # Check if user is logged in (but don't require it)
    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()

    return templates.TemplateResponse(
        "how_it_works.html",
        {"request": request, "user": user},
    )


# ==========================================
# AGENTS (archer/agents): a model in a loop with Archer's tools
# ==========================================

@app.get("/agents", response_class=HTMLResponse)
def agents_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    from archer.agents import AGENTS, agent_llm, agent_providers
    from archer.agents.tools import ToolContext

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return auth_result
    user, db = auth_result
    try:
        llm = agent_llm(db, user.id)
        providers = agent_providers(db, user.id)
    finally:
        db.close()
    agents = [{"agent": a, "tools": a.tools(ToolContext(client=None))} for a in AGENTS.values()]
    return templates.TemplateResponse("agents.html", {
        "request": request, "user": user, "agents": agents, "providers": providers,
        "model": llm["model"] if llm else None, "provider": llm["provider"] if llm else None,
    })


@app.get("/api/agents")
def list_agents(request: Request, archer_session: Optional[str] = Cookie(None)):
    from archer.agents import AGENTS, agent_llm, agent_providers
    from archer.agents.tools import ToolContext

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        llm = agent_llm(db, user.id)
        providers = agent_providers(db, user.id)
    finally:
        db.close()
    return {
        "model": llm["model"] if llm else None,
        "provider": llm["provider"] if llm else None,
        "providers": providers,
        "agents": [{"name": a.name, "title": a.title, "summary": a.summary, "inputs": a.inputs,
                    "tools": [{"name": t.name, "changes": t.changes} for t in a.tools(ToolContext(client=None))],
                    "max_turns": a.max_turns}
                   for a in AGENTS.values()],
    }


@app.post("/api/agents/{name}/start")
async def start_agent(name: str, request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Body: {"input": {...}, "auto_approve": false, "provider": "", "model": ""}. The agent
    acts as the signed-in user; provider/model default as agent_llm describes.
    """
    from archer.agents import AGENTS, NO_KEY, agent_llm, start
    from archer.agents.store import save as save_agent_session
    from archer.agents.tools import ToolContext
    from archer.client import ArcherClient

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    body = await request.json()
    try:
        llm = agent_llm(db, user.id, (body.get("provider") or "").strip() or None,
                        (body.get("model") or "").strip() or None)
    finally:
        db.close()
    agent = AGENTS.get(name)
    if not agent:
        return JSONResponse({"error": f"No agent named {name}"}, status_code=404)
    if not llm:
        return JSONResponse({"error": NO_KEY if not body.get("provider") else
                             f"{body['provider']} isn't configured in your profile (or has no model set)"},
                            status_code=400)
    # Tools call this server's own routes as the user, so an agent does what the web app does
    internal = os.getenv("ARCHER_INTERNAL_URL") or str(request.base_url)
    client = ArcherClient(url=internal, session_cookie=archer_session, timeout=300)
    try:
        session = start(agent, body.get("input") or {}, user_id=user.id, llm=llm, context=ToolContext(client=client),
                        auto_approve=bool(body.get("auto_approve")), persist=save_agent_session)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    print(f"🤖 Agent {agent.name} started for {user.email} on {llm['label']} {llm['model']} ({session.id[:8]})")
    return {"session_id": session.id, "model": llm["model"], "provider": llm["provider"]}


def _agent_session(request: Request, archer_session: Optional[str], session_id: str):
    """A session this server is running, else one saved before (read-only)."""
    from archer.agents import get_session
    from archer.agents.store import load

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return None, JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    session = get_session(session_id, user.id) or load(session_id, user.id)
    if not session:
        return None, JSONResponse({"error": "No such agent session"}, status_code=404)
    return session, None


@app.get("/api/agents/sessions")
def agent_sessions(request: Request, limit: int = 20, archer_session: Optional[str] = Cookie(None)):
    """The user's recent agent sessions, newest first (kept across restarts)."""
    from archer.agents import live_ids
    from archer.agents.store import recent

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    return {"sessions": recent(user.id, min(max(limit, 1), 100), live=live_ids())}


@app.get("/api/agents/sessions/{session_id}")
def agent_session_view(session_id: str, request: Request, since: int = 0, archer_session: Optional[str] = Cookie(None)):
    session, error = _agent_session(request, archer_session, session_id)
    return error or session.view(max(0, since))


@app.post("/api/agents/sessions/{session_id}/decision")
async def agent_decision(session_id: str, request: Request, archer_session: Optional[str] = Cookie(None)):
    session, error = _agent_session(request, archer_session, session_id)
    if error:
        return error
    if session.status != "needs_approval":
        return JSONResponse({"error": "Nothing is waiting for approval"}, status_code=409)
    session.decide(bool((await request.json()).get("approve")))
    return {"ok": True}


@app.post("/api/agents/sessions/{session_id}/resume")
async def agent_resume(session_id: str, request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Continue a session that was interrupted by a restart, stopped, or hit its turn limit, on
    the provider it ran on. Body (optional): {"auto_approve": false, "model": ""}.
    """
    from archer.agents import AGENTS, agent_llm, resume
    from archer.agents.store import load, save as save_agent_session
    from archer.agents.tools import ToolContext
    from archer.client import ArcherClient

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        body = await request.json()
    except Exception:
        body = {}
    saved = load(session_id, user.id)
    if not saved:
        db.close()
        return JSONResponse({"error": "No such agent session"}, status_code=404)
    if not saved.resumable:
        db.close()
        return JSONResponse({"error": "This session can't be continued: it finished, or ran before "
                                      "sessions kept their conversation"}, status_code=409)
    try:
        llm = agent_llm(db, user.id, saved.provider, (body.get("model") or "").strip() or saved.model)
    finally:
        db.close()
    agent = AGENTS.get(saved.agent_name)
    if not agent or not llm:
        return JSONResponse({"error": f"{saved.provider} isn't configured in your profile any more; "
                                      "the conversation can only continue on the provider it started on"},
                            status_code=400)
    internal = os.getenv("ARCHER_INTERNAL_URL") or str(request.base_url)
    client = ArcherClient(url=internal, session_cookie=archer_session, timeout=300)
    try:
        session = resume(saved, agent, llm=llm, context=ToolContext(client=client),
                         auto_approve=bool(body.get("auto_approve")), persist=save_agent_session)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=409)
    print(f"🤖 Agent {agent.name} continued for {user.email} on {llm['label']} {llm['model']} ({session.id[:8]})")
    return {"session_id": session.id, "model": llm["model"], "provider": llm["provider"]}


@app.post("/api/agents/sessions/{session_id}/stop")
def agent_stop(session_id: str, request: Request, archer_session: Optional[str] = Cookie(None)):
    session, error = _agent_session(request, archer_session, session_id)
    if error:
        return error
    session.stop()
    return {"ok": True}


# POST handler for Generate button
from fastapi.responses import RedirectResponse, JSONResponse
import json
import os


@app.post("/generate")
async def generate(
    request: Request,
    group_name: str = Form(...),
    advanced_parsing: str = Form(None),
    semantic: str = Form(None),
    ai_generators: str = Form(None),
    local_llm: str = Form(None),
    ai_provider: str = Form(None),
    ai_model: str = Form(None),
    run_correlation: str = Form(None),
    run_emulation: str = Form(None),
    emulation_mode: str = Form("simulate"),
    osint_enhancement: str = Form(None),
    lol_datasets: str = Form(None),
    osint_comparison: str = Form(None),
    merge_by_tactic: str = Form(None),
    merge_by_parent: str = Form(None),
    exclude_splunk: str = Form(None),
    exclude_mde: str = Form(None),
    exclude_secops: str = Form(None),
    exclude_elastic: str = Form(None),
    auto_validate: str = Form(None),
    regenerate: str = Form(None),
    ignore_stack: str = Form(None),
    archer_session: Optional[str] = Cookie(None),
):
    # Called when the user clicks Generate on the index page, or Regenerate on a results
    # page (regenerate=true: rewrite every detection the run reaches, hand edits included). We first
    # check whether the provided group name maps to a known MITRE actor.

    # Determine GENAI_MODE — an explicit ai_provider (from the Hunt-page AI
    # prompt) takes priority over the legacy ai_generators/local_llm checkboxes.
    # Default to semantic mode for best results (includes advanced parsing + behavioral grouping)
    genai_mode = _apply_ai_provider_choice(ai_provider, ai_model)
    if genai_mode is None:
        genai_mode = "semantic"
        if local_llm == "true":
            genai_mode = "local_llm"
        elif ai_generators == "true":
            genai_mode = "ai_generators"
    llm_args = _hunt_llm_args(archer_session, ai_provider, ai_model)

    actor_found = check_group_in_mitre(app.state.bundle, group_name)
    if actor_found == "Y":
        # Known actor: kick off processing in a background thread and immediately return a JSON
        # payload containing a redirect URL so the front-end can navigate to the progress page.
        hypothesis = "Generated from form"

        def _bg():
            try:
                # Profile → SIEM platforms, plus exclusions sent by API clients (archer.client)
                siem_args = _siem_args(archer_session, *[
                    vendor for flag, vendor in ((exclude_splunk, "splunk"), (exclude_mde, "mde"),
                                                (exclude_secops, "googlesecops"), (exclude_elastic, "elastic"))
                    if flag == "true"])

                # Use the modified wrapper instead of direct process_group
                modified_process_group_wrapper(
                    group_name,
                    hypothesis,
                    manual_data=None,
                    genai_mode=genai_mode,
                    run_correlation=True,  # Always enabled by default
                    # The Hunt tab's OSINT Enhancement box (ticked by default); a request without it keeps it on
                    osint_enhancement=(osint_enhancement != "false"),
                    osint_comparison=(osint_comparison == "true"),
                    lol_datasets=(lol_datasets != "false"),  # ticked by default
                    merge_by_tactic=(merge_by_tactic == "true"),
                    merge_by_parent=(merge_by_parent == "true"),
                    **siem_args,
                    **llm_args,
                    **_stack_args(archer_session, ignore=(ignore_stack == "true")),
                )

                # Run emulation if requested (feature-flagged — see _archive/REINTEGRATION.md)
                if run_emulation == "true" and EMULATION_ENABLED:
                    try:
                        from archer.config import EmulationConfig
                        from archer.emulation import AtomicRedTeam
                        from archer.emulation.enrich import enrich_from_group_emulation

                        if EmulationConfig.is_atomic_configured():
                            # Set execution mode
                            if emulation_mode == "live":
                                os.environ["EMULATION_EXECUTE_MODE"] = "live"
                            else:
                                os.environ["EMULATION_EXECUTE_MODE"] = "simulate"

                            # Run group emulation
                            atomic = AtomicRedTeam()
                            atomic.execute_threat_group(group_name)

                            # Enrich detections
                            enrich_from_group_emulation(group_name)
                    except Exception as e:
                        print(f"Emulation error: {e}")

                # Auto-validate detections if requested
                if auto_validate == "true":
                    try:
                        from archer.validation import check_docker_available
                        from archer.validation.orchestrator import get_orchestrator

                        docker_available, _ = check_docker_available()
                        if docker_available:
                            print(f"Auto-validating detections for {group_name}...")
                            write_progress(group_name, {"stage": "validating"})

                            orchestrator = get_orchestrator()
                            validation_results = {}

                            # Load generated detections from build folder
                            build_dir = Path("data/build") / group_name.replace(" ", "_")
                            if build_dir.exists():
                                for yaml_file in build_dir.glob("*.yaml"):
                                    try:
                                        import yaml
                                        with open(yaml_file) as f:
                                            detection_data = yaml.safe_load(f)

                                        if not detection_data:
                                            continue

                                        # Determine vendor from file name or content
                                        vendor = None
                                        filename = yaml_file.stem.lower()
                                        if "splunk" in filename or "spl" in filename:
                                            vendor = "splunk"
                                        elif "elastic" in filename or "eql" in filename:
                                            vendor = "elastic"
                                        elif "secops" in filename or "yaral" in filename:
                                            vendor = "secops"
                                        elif "mde" in filename or "kql" in filename:
                                            vendor = "mde"

                                        if vendor and vendor not in excluded:
                                            # Get query from detection
                                            query = detection_data.get("query") or detection_data.get("detection", {}).get("query")
                                            technique_id = detection_data.get("technique_id", "Unknown")
                                            technique_name = detection_data.get("technique_name", "Unknown")

                                            if query:
                                                # Create validation session
                                                session = orchestrator.create_session(
                                                    technique_id=technique_id,
                                                    technique_name=technique_name,
                                                    query=query,
                                                    vendor=vendor,
                                                )

                                                # Start SIEM (uses docker-compose if available)
                                                siem_result = orchestrator.start_siem(session.session_id)

                                                if siem_result.get("success"):
                                                    # Generate sample events
                                                    indicators = detection_data.get("indicators", {"cmd": [], "sw": []})
                                                    events_result = orchestrator.generate_events(
                                                        session_id=session.session_id,
                                                        indicators=indicators,
                                                        malicious_count=5,
                                                        benign_count=10,
                                                    )

                                                    if events_result.get("success"):
                                                        # Test detection
                                                        test_result = orchestrator.test_detection(session.session_id)

                                                        if test_result.get("success"):
                                                            validation_results[yaml_file.stem] = {
                                                                "vendor": vendor,
                                                                "technique_id": technique_id,
                                                                "passed": test_result["result"]["passed"],
                                                                "f1_score": test_result["result"].get("f1_score", 0),
                                                                "precision": test_result["result"].get("precision", 0),
                                                                "recall": test_result["result"].get("recall", 0),
                                                            }

                                                # Stop session (releases but doesn't stop compose containers)
                                                orchestrator.stop_session(session.session_id)

                                    except Exception as e:
                                        print(f"Validation error for {yaml_file.name}: {e}")

                            # Store validation results
                            if validation_results:
                                validation_file = build_dir / "validation_results.json"
                                import json
                                with open(validation_file, "w") as f:
                                    json.dump(validation_results, f, indent=2)
                                print(f"Validation complete: {len(validation_results)} detections validated")

                    except Exception as e:
                        print(f"Auto-validation error: {e}")

            except Exception as e:
                try:
                    write_progress(group_name, {"status": "failed", "error": str(e)})
                except Exception:
                    pass

        # Fresh record first, so the thread's own updates land after it
        try:
            start_progress(
                group_name,
                {
                    "status": "started",
                    "stage": "queued",
                    "created_yaml": 0,
                    "auto_validate_enabled": (auto_validate == "true"),
                    "regenerate": regenerate == "true",
                },
            )
        except Exception:
            pass
        threading.Thread(target=_bg, daemon=True).start()
        return JSONResponse({"redirect_url": f"/progress?group_name={quote(group_name)}"})
    else:
        # Group not in ATT&CK - search blogs automatically
        print(f"Group '{group_name}' not found in ATT&CK, searching security blogs...")

        try:
            from archer.parsers.blog_analyzer import auto_search_blogs

            blog_result = auto_search_blogs(group_name)

            if blog_result.get("success"):
                # Found blog post - redirect to manual entry with pre-filled data
                print(
                    f"Found blog post from {blog_result.get('source')}: {blog_result.get('source_url')}"
                )

                # Store blog results in session or pass as query params
                # For now, redirect to manual with a message
                return JSONResponse(
                    {
                        "redirect_url": f"/manual?group_name={quote(group_name)}&blog_found=true&source={quote(blog_result.get('source', ''))}"
                    }
                )
        except Exception as e:
            print(f"Blog search failed: {e}")

        # Fallback to manual entry
        return JSONResponse({"redirect_url": f"/manual?group_name={quote(group_name)}"})


@app.post("/generate/cve")
async def generate_cve(
    request: Request,
    cve_id: str = Form(...),
    osint_enhancement: str = Form(None),
    lol_datasets: str = Form(None),
    run_correlation: str = Form(None),
    semantic: str = Form(None),
    advanced_parsing: str = Form(None),
    ai_generators: str = Form(None),
    local_llm: str = Form(None),
    ai_provider: str = Form(None),
    ai_model: str = Form(None),
    archer_session: Optional[str] = Cookie(None),
):
    """Generate detection queries for CVE(s)."""
    import re
    from archer.intelligence.cve_hunter import research_and_hunt

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    user, db = auth_result
    user_id = user.id
    db.close()  # Close the DB session as we'll be using threading

    # Support multiple CVEs (comma-separated)
    cve_ids = [c.strip().upper() for c in cve_id.split(",") if c.strip()]

    if not cve_ids:
        return JSONResponse({"error": "No CVE IDs provided"}, status_code=400)

    # Validate CVE format: CVE-20XX-NNNN (must start with CVE-20, year 2000+)
    cve_pattern = re.compile(r"^CVE-20\d{2}-\d{4,}$", re.IGNORECASE)
    invalid_cves = [cve for cve in cve_ids if not cve_pattern.match(cve)]

    if invalid_cves:
        return JSONResponse(
            {
                "error": f"Invalid CVE format: {', '.join(invalid_cves)}. CVE IDs must follow format: CVE-20XX-NNNN (e.g., CVE-2021-44228)"
            },
            status_code=400,
        )

    try:  # kept in the recent-CVE cache past its 30 days: the results refer to it
        from archer.intelligence.cve_feed import mark_hunted

        mark_hunted(cve_ids)
    except Exception as e:
        print(f"Recent CVEs: {e}")

    # Use CVE ID directly as group name (no CVE_ prefix since it already starts with CVE-)
    if len(cve_ids) == 1:
        group_name = cve_ids[0]  # e.g., "CVE-2021-44228"
    else:
        group_name = f"{cve_ids[0]}_plus_{len(cve_ids)-1}"  # e.g., "CVE-2021-44228_plus_2"

    # Determine GENAI_MODE — an explicit ai_provider (from the Hunt-page AI
    # prompt) takes priority over the legacy ai_generators/local_llm checkboxes.
    # Default to semantic mode for best results (includes advanced parsing + behavioral grouping)
    genai_mode = _apply_ai_provider_choice(ai_provider, ai_model)
    if genai_mode is None:
        genai_mode = "semantic"
        if local_llm == "true":
            genai_mode = "local_llm"
        elif ai_generators == "true":
            genai_mode = "ai_generators"
    llm_args = _hunt_llm_args(archer_session, ai_provider, ai_model)
    siem_args = _siem_args(archer_session)

    def _bg():
        try:
            # print(f"========================================", flush=True)
            # print(f"CVE BACKGROUND THREAD STARTED", flush=True)
            # print(f"Group name: {group_name}", flush=True)
            # print(f"CVE IDs: {cve_ids}", flush=True)
            # print(f"========================================", flush=True)
            pass

            write_progress(
                group_name,
                {
                    "status": "researching_cve",
                    "phase": "preparing",
                    "stage": "CVE Research",
                    "created_yaml": 0,
                    "total_yaml": None,
                },
            )

            # Research each CVE
            all_techniques = []
            all_iocs = {
                "cmd": [],
                "file": [],
                "reg": [],
                "network": [],
                "hash": [],
                "ip": [],
                "domain": [],
            }

            from archer.build.ioc_flow import merge_mentions

            reference_iocs = {"ip": [], "domain": [], "hash": []}
            reference_sources = []
            reference_mentions = {}
            exploit, exploit_sources = {}, []
            from archer.intelligence.cve_hunter import CVEHunter

            # The Research card: each CVE's steps, then the sweeps, exploit and runtime detections
            per_cve = len(CVEHunter.STEPS)
            research_total = per_cve * len(cve_ids) + 3
            nvd_records = []
            exploit_names = {}

            def _research(done, label, item=None):
                write_progress(group_name, {"research_total": research_total, "research_done": done,
                                            "research_step": label, "research_item": item})

            for n, cve in enumerate(cve_ids):
                research = research_and_hunt(
                    cve, on_step=lambda i, label, n=n, cve=cve: _research(n * per_cve + i, label, cve))
                nvd_records.append(research.get("nvd_data") or {})
                exploit_names[cve] = research.get("exploit_name")

                # Collect techniques
                all_techniques.extend(research.get("techniques", []))

                # Collect IOCs
                for ioc_type in all_iocs:
                    all_iocs[ioc_type].extend(research.get("iocs", {}).get(ioc_type, []))
                refs = research.get("reference_iocs") or {}
                for ioc_type, values in (refs.get("iocs") or {}).items():
                    reference_iocs.setdefault(ioc_type, []).extend(values)
                reference_sources.extend(refs.get("sources") or [])
                reference_mentions = merge_mentions(reference_mentions, refs.get("mentions"))
                exp = research.get("exploit") or {}
                for kind, values in (exp.get("indicators") or {}).items():
                    exploit.setdefault(kind, []).extend(v for v in values if v not in exploit.get(kind, []))
                exploit_sources.extend(exp.get("sources") or [])
                # The shell run on the exploited host is a command indicator like any other
                all_iocs["cmd"].extend((exp.get("indicators") or {}).get("cmd", []))
                _warn_cve_off_stack(group_name, cve, research.get("nvd_data") or {}, archer_session)

            # What the run's detections and correlations start with: CVE-2026-109618_PHP2Shell
            from archer.intelligence.cve_label import label as cve_label

            run_label = cve_label(exploit_names)
            write_progress(group_name, {"run_label": run_label})

            # Exploitation indicators from the advisories and write-ups: one sweep per SIEM.
            # For an appliance CVE (PAN-OS, Ivanti, Citrix) these are the detections there are.
            from archer.build.ioc_sweep import write_ioc_sweeps

            _research(per_cve * len(cve_ids), "Building the IOC sweeps")
            source = "references for " + ", ".join(cve_ids)
            if reference_sources:
                source += " (" + ", ".join(sorted({urlparse(u).netloc for u in reference_sources})) + ")"
            sweeps = write_ioc_sweeps(group_name, reference_iocs, source, GENERATE_DIR, mentions=reference_mentions,
                                      run_label=run_label)
            if sweeps:
                print(f"IOC sweep detections: {', '.join(os.path.basename(p) for p in sweeps)}")
            write_progress(group_name, {"ioc_sweeps": len(sweeps)})

            # The exploit's own request, from the PoCs: the CVE-specific T1190 detection
            from archer.build.exploit_detection import write_exploit_detections

            _research(per_cve * len(cve_ids) + 1, "Building the exploit request detections")
            exploits = write_exploit_detections(group_name, cve_ids, exploit, exploit_sources, GENERATE_DIR,
                                                excluded_vendors=siem_args.get("excluded_vendors"), run_label=run_label)
            if exploits:
                print(f"Exploit request detections: {', '.join(os.path.basename(p) for p in exploits)}")

            # A code-execution CVE in a web runtime: its worker starting a shell (archer.build.runtime_detection)
            from archer.build.runtime_detection import write_runtime_detections

            _research(per_cve * len(cve_ids) + 2, "Building the runtime detections")
            runtime = write_runtime_detections(group_name, cve_ids, nvd_records, GENERATE_DIR,
                                               excluded_vendors=siem_args.get("excluded_vendors"), run_label=run_label)
            if runtime:
                print(f"Runtime detections: {', '.join(os.path.basename(p) for p in runtime)}")
            # Built here, not from a technique: the progress page counts them with the sweeps
            write_progress(group_name, {"cve_detections": len(exploits) + len(runtime)})
            _research(research_total, "Research complete")

            # Deduplicate
            all_techniques = list(set(all_techniques))
            for ioc_type in all_iocs:
                all_iocs[ioc_type] = list(set(all_iocs[ioc_type]))

            # print(f"Found {len(all_techniques)} unique techniques from {len(cve_ids)} CVE(s)")
            # print(f"DEBUG: Techniques list: {all_techniques}")
            # print(f"DEBUG: IOCs collected: {sum(len(v) for v in all_iocs.values())} total")

            # Build IOC guidance from collected IOCs
            ioc_guidance = []
            for ioc_type, values in all_iocs.items():
                if values:
                    ioc_guidance.append(
                        f"{ioc_type}: {', '.join(values[:5])}"
                    )  # Limit to 5 per type
            ioc_detect_guidance = "; ".join(ioc_guidance) if ioc_guidance else ""

            # CVE-based detection generation strategy:
            # Even if no ATT&CK techniques are found, we can still generate detections
            # based on CVE behavior, IOCs, and vulnerability characteristics

            if not all_techniques:
                print("INFO: No ATT&CK techniques mapped (CVE may be too new or not in ATT&CK)")
                print("INFO: Generating CVE-specific detections based on vulnerability behavior")

                # Use CVE metadata to build detections
                # Create a synthetic "technique" that represents this CVE
                synthetic_techniques = []
                for cve in cve_ids:
                    synthetic_techniques.append(f"CVE-{cve.split('-')[1]}-{cve.split('-')[2]}")
                all_techniques = synthetic_techniques
                print(f"INFO: Created synthetic technique identifiers: {all_techniques}")

            # Group techniques by tactic using _get_technique_info
            tactic_map = {}
            for tech_id in all_techniques:
                try:
                    # Check if this is an ATT&CK technique ID or synthetic CVE technique
                    if tech_id.startswith("T") and tech_id[1:].split(".")[0].isdigit():
                        # Real ATT&CK technique - try to get info
                        # print(f"DEBUG: Getting ATT&CK info for {tech_id}")
                        tech_info = _get_technique_info(tech_id)
                        if tech_info:
                            tactic = tech_info.get("tactic", "CVE Exploitation")
                            # print(f"DEBUG: {tech_id} → {tactic}")
                        else:
                            tactic = "CVE Exploitation"
                            # print(f"DEBUG: {tech_id} → CVE Exploitation (no ATT&CK mapping)")
                    else:
                        # Synthetic CVE-based technique
                        tactic = "CVE Exploitation"
                        # print(f"DEBUG: {tech_id} → CVE Exploitation (synthetic)")

                    if tactic not in tactic_map:
                        tactic_map[tactic] = []

                    # Build comprehensive detection guidance with IOCs
                    ioc_details = []
                    if all_iocs.get("cmd"):
                        ioc_details.append(f"Commands/Patterns: {', '.join(all_iocs['cmd'][:3])}")
                    if all_iocs.get("file"):
                        ioc_details.append(f"Files: {', '.join(all_iocs['file'][:3])}")
                    if all_iocs.get("network"):
                        ioc_details.append(f"Network: {', '.join(all_iocs['network'][:3])}")

                    comprehensive_guidance = f"Exploitation of {', '.join(cve_ids)}. "
                    if ioc_details:
                        comprehensive_guidance += "Key indicators: " + "; ".join(ioc_details)
                    else:
                        comprehensive_guidance += (
                            "Monitor for CVE-specific indicators and exploit patterns."
                        )

                    # Build IOC dictionary for detection engine
                    # The detection engine expects types: cmd, reg, evt, sw, network
                    # Map CVE IOC types to detection engine types
                    ioc_type_mapping = {
                        "cmd": "cmd",  # Commands stay as cmd
                        "file": "sw",  # Files map to software
                        "network": "network",  # Network protocols (ldap://, rmi://, ldaps://) get network category
                        "reg": "reg",  # Registry stays as reg
                        "hash": "sw",  # Hashes map to software
                        "ip": "network",  # IPs map to network
                        "domain": "network",  # Domains map to network
                    }

                    ioc_dict = {}
                    for ioc_type, values in all_iocs.items():
                        if values and ioc_type in ioc_type_mapping:
                            mapped_type = ioc_type_mapping[ioc_type]
                            # Merge into existing mapped type or create new
                            if mapped_type not in ioc_dict:
                                ioc_dict[mapped_type] = []
                            ioc_dict[mapped_type].extend(
                                values[:10]
                            )  # Limit to 10 per original type

                            # Network protocols (ldap://, rmi://, ldaps://) also go into cmd category
                            # since they appear in commands like ${jndi:ldap://attacker.com}
                            if ioc_type == "network":
                                if "cmd" not in ioc_dict:
                                    ioc_dict["cmd"] = []
                                ioc_dict["cmd"].extend(values[:10])

                    # DEBUG: Log the IOC dict structure before adding to tactic_map
                    # print(f"DEBUG [app.py]: Built ioc_dict for {tech_id}:")
                    # print(f"  - ioc_dict keys: {list(ioc_dict.keys())}")
                    # for key, vals in ioc_dict.items():
                    #     print(
                    #         f"  - {key}: type={type(vals)}, count={len(vals) if isinstance(vals, list) else 'N/A'}"
                    #     )

                    # Get platforms for this technique (required for platform validation)
                    tech_platforms = []
                    if tech_info and "platforms" in tech_info:
                        tech_platforms = tech_info["platforms"]
                    elif tech_id.startswith("T"):
                        # For real ATT&CK techniques without info, try fetching again
                        tech_info_retry = _get_technique_info(tech_id)
                        if tech_info_retry and "platforms" in tech_info_retry:
                            tech_platforms = tech_info_retry["platforms"]

                    # For CVE techniques or techniques with no platform data, use universal platforms
                    if not tech_platforms:
                        tech_platforms = ["Windows", "Linux", "macOS", "Containers"]

                    tactic_map[tactic].append(
                        {
                            "technique": tech_id,
                            "op_guidance": ioc_dict if ioc_dict else comprehensive_guidance,
                            "red_tool": {},
                            "detect_guidance": (
                                ioc_detect_guidance
                                if ioc_detect_guidance
                                else comprehensive_guidance
                            ),
                            "iocs": all_iocs,  # Pass full IOCs for reference
                            "procedure_platforms": tech_platforms,  # CRITICAL: Add platforms for validation
                            "software_platforms": {},  # Empty dict for software (not used in CVE detection)
                        }
                    )
                except Exception as e:
                    print(f"Warning: Could not process technique {tech_id}: {e}")
                    import traceback

                    traceback.print_exc()
                    # Add to CVE Exploitation tactic
                    if "CVE Exploitation" not in tactic_map:
                        tactic_map["CVE Exploitation"] = []
                    tactic_map["CVE Exploitation"].append(
                        {
                            "technique": tech_id,
                            "op_guidance": f"Exploitation of {', '.join(cve_ids)}",
                            "red_tool": "",
                            "detect_guidance": ioc_detect_guidance,
                        }
                    )

            # Build manual_data in the format process_group expects
            manual_data = []
            for tactic, techniques in tactic_map.items():
                manual_data.append({"tactic": tactic, "techniques": techniques})

            # print(f"DEBUG: Built manual_data with {len(manual_data)} tactics")
            # for entry in manual_data:
            #     print(f"  - Tactic: {entry['tactic']}, Techniques: {len(entry['techniques'])}")

            if not manual_data:
                print(f"ERROR: Failed to build manual_data even with fallbacks!")
                # print(f"  - CVE IDs: {cve_ids}")
                # print(f"  - Techniques: {all_techniques}")
                # print(f"  - IOCs: {all_iocs}")
                raise ValueError(f"CVE research failed to build detection data")

            # Process using existing pipeline
            modified_process_group_wrapper(
                group_name,
                hypothesis=f"CVE Hunting: {', '.join(cve_ids)}",
                manual_data=manual_data,
                genai_mode=genai_mode,
                run_correlation=True,  # Always enabled by default
                osint_enhancement=(osint_enhancement != "false"),  # The Hunt tab's box, ticked by default
                osint_comparison=False,  # Default to false for CVE hunting
                lol_datasets=(lol_datasets != "false"),
                **siem_args,
                **_stack_args(archer_session),
                **llm_args,
            )

        except Exception as e:
            print(f"CVE generation error: {e}", flush=True)
            import traceback

            traceback.print_exc()
            import sys

            sys.stderr.flush()
            sys.stdout.flush()
            try:
                write_progress(group_name, {"status": "failed", "error": str(e)})
            except Exception:
                pass

    # Fresh record first, so the thread's own updates land after it
    try:
        start_progress(
            group_name,
            {
                "status": "started",
                "stage": "CVE Research",
                "created_yaml": 0,
                "cve_ids": cve_ids,
                "user_id": user_id,
                "source_type": "cve",
            },
        )
    except Exception:
        pass
    threading.Thread(target=_bg, daemon=True).start()

    return JSONResponse({"redirect_url": f"/progress?group_name={quote(group_name)}"})


@app.post("/hunt/technique")
async def hunt_technique(
    request: Request,
    technique_ids: str = Form(...),
    merge_by_tactic: str = Form(None),
    merge_by_parent: str = Form(None),
    osint_enhancement: str = Form(None),
    lol_datasets: str = Form(None),
    osint_comparison: str = Form(None),
    ai_generators: str = Form(None),
    local_llm: str = Form(None),
    ai_provider: str = Form(None),
    ai_model: str = Form(None),
    correlation_min_relevance: str = Form(None),
    archer_session: Optional[str] = Cookie(None),
):
    """Generate detection queries for specific ATT&CK technique(s)."""
    import re

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    user, db = auth_result
    user_id = user.id
    db.close()

    # Parse technique IDs (comma-separated, case-insensitive)
    technique_id_list = [t.strip().upper() for t in technique_ids.split(",") if t.strip()]

    if not technique_id_list:
        return JSONResponse({"error": "No technique IDs provided"}, status_code=400)

    # Validate technique format: T####.### or T####
    technique_pattern = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
    invalid_techniques = [t for t in technique_id_list if not technique_pattern.match(t)]

    if invalid_techniques:
        return JSONResponse(
            {
                "error": f"Invalid technique format: {', '.join(invalid_techniques)}. "
                "Technique IDs must follow format: T#### or T####.### (e.g., T1003 or T1003.001)"
            },
            status_code=400,
        )

    # Create group name based on techniques
    if len(technique_id_list) == 1:
        group_name = f"Hunt_{technique_id_list[0]}"
    else:
        group_name = f"Hunt_{technique_id_list[0]}_plus_{len(technique_id_list)-1}"

    # Sanitize group name
    group_name = sanitize_group_name(group_name)

    # Parse options
    merge_tactic = merge_by_tactic == "true"
    merge_parent = merge_by_parent == "true"
    osint_enh = osint_enhancement == "true"
    osint_comp = osint_comparison == "true"

    # Determine GENAI_MODE — an explicit ai_provider (from the Hunt-page AI
    # prompt) takes priority over the legacy ai_generators/local_llm checkboxes.
    genai_mode = _apply_ai_provider_choice(ai_provider, ai_model)
    if genai_mode is None:
        genai_mode = "heuristic"
        if local_llm == "true":
            genai_mode = "local_llm"
        elif ai_generators == "true":
            genai_mode = "ai_generators"
    llm_args = _hunt_llm_args(archer_session, ai_provider, ai_model)
    siem_args = _siem_args(archer_session)

    # Techniques known to produce nothing in this mode (technique_yield): a run of only
    # those would spend its time for an empty results page
    from archer.build.technique_yield import preflight

    doomed = preflight(technique_id_list, ai=bool(llm_args.get("use_llm")), osint=osint_enh or osint_comp)
    if len(doomed) == len(technique_id_list):
        return JSONResponse({
            "error": "None of these techniques can produce a detection this way: "
                     + "; ".join(f"{t} ({d['text']})" for t, d in doomed.items()),
            "no_detection": doomed}, status_code=422)

    # Parse correlation threshold
    correlation_threshold = None
    if correlation_min_relevance:
        try:
            correlation_threshold = float(correlation_min_relevance)
        except ValueError:
            correlation_threshold = None

    def _bg():
        try:
            write_progress(
                group_name,
                {
                    "status": "researching_techniques",
                    "phase": "preparing",
                    "stage": "Technique Research",
                    "created_yaml": 0,
                    "total_yaml": None,
                },
            )

            # Build manual_data by looking up each technique
            tactic_map = {}

            for n, tech_id in enumerate(technique_id_list):
                write_progress(group_name, {"research_total": len(technique_id_list), "research_done": n,
                                            "research_step": "Looking up the technique in ATT&CK",
                                            "research_item": tech_id})
                tech_info = _get_technique_info(tech_id)

                if not tech_info:
                    print(f"Warning: Could not find information for technique {tech_id}")
                    # Add to "Unknown Tactic" as fallback
                    tactic = "Unknown Tactic"
                else:
                    tactic = tech_info.get("tactic", "Unknown Tactic")

                tactic_map.setdefault(tactic, []).extend(_technique_entries(tech_id, tech_info))

            write_progress(group_name, {"research_done": len(technique_id_list), "research_step": "Research complete",
                                        "research_item": None})

            # Convert tactic_map to manual_data format
            manual_data = []
            for tactic, techniques in tactic_map.items():
                manual_data.append({"tactic": tactic, "techniques": techniques})

            if not manual_data:
                raise ValueError(
                    f"Could not build detection data for techniques: {technique_id_list}"
                )

            # Process using existing pipeline
            modified_process_group_wrapper(
                group_name,
                hypothesis=f"Technique Hunt: {', '.join(technique_id_list)}",
                manual_data=manual_data,
                genai_mode=genai_mode,
                run_correlation=True,
                osint_enhancement=osint_enh,
                osint_comparison=osint_comp,
                lol_datasets=(lol_datasets != "false"),
                merge_by_tactic=merge_tactic,
                merge_by_parent=merge_parent,
                correlation_min_relevance=correlation_threshold,
                **siem_args,
                **_stack_args(archer_session),
                **llm_args,
            )

        except Exception as e:
            print(f"Technique hunt error: {e}", flush=True)
            import traceback

            traceback.print_exc()
            try:
                write_progress(group_name, {"status": "failed", "error": str(e)})
            except Exception:
                pass

    # Fresh record first, so the thread's own updates land after it
    try:
        start_progress(
            group_name,
            {
                "status": "started",
                "stage": "Technique Hunt",
                "created_yaml": 0,
                "technique_ids": technique_id_list,
                "user_id": user_id,
                "source_type": "technique_hunt",
            },
        )
    except Exception:
        pass
    threading.Thread(target=_bg, daemon=True).start()

    return JSONResponse({"redirect_url": f"/progress?group_name={quote(group_name)}", "no_detection": doomed})


# Technique names too generic to match safely in free text (they are ordinary words, or
# Reconnaissance sub-techniques whose names are everyday nouns)
_HYPOTHESIS_NAME_STOPLIST = {
    "impact", "collection", "discovery", "execution", "phishing", "automated collection",
    "data manipulation", "network sniffing", "file deletion", "account access removal",
    "credentials", "email addresses", "employee names", "domains", "software", "malware",
    "vulnerabilities", "ip addresses", "web services", "exploits", "digital certificates",
    "code signing", "default accounts", "local account", "domain account", "cloud account",
}


def _technique_name_index() -> dict:
    """{lowercased technique name: technique ID} from the ATT&CK bundle, built once."""
    idx = getattr(app.state, "_tech_name_index", None)
    if idx is not None:
        return idx
    idx = {}
    for obj in (getattr(app.state, "bundle", None) or {}).get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        tid = next((r.get("external_id", "") for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), "")
        name = (obj.get("name") or "").strip().lower()
        if tid and len(name) >= 6 and name not in _HYPOTHESIS_NAME_STOPLIST:
            idx[name] = tid
    app.state._tech_name_index = idx
    return idx


def _extract_from_hypothesis(text: str) -> dict:
    """Deterministically pull ATT&CK out of a free-text hypothesis (no AI).

    Matches explicit T-codes, technique names present in the text, tactics, a named group,
    and techniques implied by any commands. Returns {technique_ids, tactics, group, named}.
    """
    import re as _re

    from archer.parsers.blog_analyzer import (_extract_iocs, _extract_tactics,
                                              _extract_techniques, _mentions,
                                              attack_group_names)

    bundle = getattr(app.state, "bundle", None)
    tids = set(_extract_techniques(text))                       # explicit T1234(.001)
    low = (text or "").lower()
    name_hits = {}
    for name, tid in _technique_name_index().items():           # technique names in the prose
        if _re.search(r"(?<![a-z0-9])" + _re.escape(name) + r"(?![a-z0-9])", low):
            tids.add(tid)
            name_hits[name] = tid
    iocs = _extract_iocs(text)                                  # techniques implied by commands
    if bundle is not None and iocs.get("cmd"):
        from archer.parsers.command_techniques import techniques_for_commands
        tids |= set(techniques_for_commands(iocs["cmd"]))
    # Group: the first ATT&CK group whose name or alias is named in the text (whole-word)
    group = ""
    if bundle is not None:
        for alias, canonical in attack_group_names(bundle).items():
            if _mentions(alias, text):
                group = canonical
                break
    return {
        "technique_ids": sorted(tids),
        "tactics": _extract_tactics(text),
        "group": group,
        "named": sorted(name_hits.keys()),
    }


def _ai_refine_hypothesis(text: str, user_id: int, db) -> list:
    """Ask the user's LLM which ATT&CK techniques a hypothesis implies (empty if none/unavailable).

    This is the refine step: it reads intent the deterministic matcher can't — a vague hypothesis
    that names no techniques by T-code or name. Falls back silently to nothing if no provider answers.
    """
    import re as _re

    from archer import chat
    try:
        candidates, assigned = chat._provider_candidates(user_id, db)
    except Exception:
        candidates = []
        assigned = False
    if not candidates:
        return []
    system = ("You map a threat-hunting hypothesis to MITRE ATT&CK. Return only the technique IDs "
              "(T#### or T####.###) the hypothesis implies, comma-separated, most specific first — "
              "no prose. Prefer sub-techniques when the hypothesis is specific.")
    try:
        resp, _label = chat._generate(candidates, assigned, "hypothesis refine",
                                      prompt=f"Hypothesis: {text.strip()}", system_prompt=system,
                                      max_tokens=400, temperature=0)
    except Exception:
        return []
    return sorted(set(_re.findall(r"\bT\d{4}(?:\.\d{3})?\b", (resp.content or "").upper())))


def _profile_recommended_techniques(limit: int = 40) -> list:
    """The most recently profiled organisation's recommended technique IDs (industry/profile scope)."""
    import glob

    files = sorted(glob.glob(os.path.join("data", "profiles", "*_profile.json")),
                   key=os.path.getmtime, reverse=True)
    if not files:
        return []
    try:
        with open(files[0], encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception:
        return []
    return [t.strip().upper() for t in (d.get("recommended_techniques") or [])[:limit] if str(t).strip()]


@app.post("/hunt/hypothesis")
async def hunt_hypothesis(
    request: Request,
    hypothesis: str = Form(...),
    scope_group: str = Form(None),
    use_profile: str = Form(None),
    use_ai: str = Form(None),
    ai_provider: str = Form(None),
    ai_model: str = Form(None),
    archer_session: Optional[str] = Cookie(None),
):
    """Generate detections from a free-text hunting hypothesis.

    Deterministic by default: the hypothesis is mapped to ATT&CK techniques by what it names
    (T-codes, technique names, a group, commands). With AI it is also refined — the model reads
    intent the matcher can't. Optional scoping narrows to a named group, or broadens to the
    organisation's likely adversaries from the most recent profile.
    """
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    user_id = user.id

    text = (hypothesis or "").strip()
    if len(text) < 8:
        db.close()
        return JSONResponse({"error": "Give a fuller hypothesis — name the techniques, tactics, tools or group you expect."}, status_code=400)

    found = _extract_from_hypothesis(text)
    technique_id_list = set(found["technique_ids"])

    # Refine with AI: the model maps intent the deterministic matcher can't (needs db for keys)
    refined = []
    if use_ai == "true":
        refined = _ai_refine_hypothesis(text, user_id, db)
        technique_id_list |= set(refined)
    db.close()

    # Industry/profile scope: broaden to the most recently profiled org's likely adversaries
    from_profile = []
    if use_profile == "true":
        from_profile = _profile_recommended_techniques()
        technique_id_list |= set(from_profile)

    technique_id_list = sorted(technique_id_list)

    # Optional: scope to a named threat group. With techniques found, keep only that group's
    # (intersection); with none, fall back to the group's techniques for the hypothesis's tactics.
    scope = (scope_group or "").strip()
    if scope:
        try:
            from archer.mitre.procedures import get_group_coverage
            cov = get_group_coverage(scope, GENERATE_DIR) or {}
            group_tids = {t.get("technique_id", "").upper()
                          for key in ("covered", "gaps", "intel_only")
                          for t in cov.get(key, [])}
        except Exception:
            group_tids = set()
        if group_tids:
            if technique_id_list:
                technique_id_list = [t for t in technique_id_list if t in group_tids] or technique_id_list
            else:
                technique_id_list = sorted(group_tids)

    if not technique_id_list:
        return JSONResponse({
            "error": "Nothing concrete to hunt in that hypothesis. Name techniques (T-codes or names like "
                     "\"Kerberoasting\"), tactics, tools or a group — or enable AI to refine it.",
            "extracted": found}, status_code=422)

    technique_id_list = technique_id_list[:60]  # keep a widened run from running away

    genai_mode = _apply_ai_provider_choice(ai_provider, ai_model) if use_ai == "true" else None
    if genai_mode is None:
        genai_mode = "heuristic"
    llm_args = _hunt_llm_args(archer_session, ai_provider, ai_model) if use_ai == "true" else {}
    siem_args = _siem_args(archer_session)

    slug = re.sub(r"[^A-Za-z0-9]+", "_", text)[:40].strip("_") or "run"
    group_name = sanitize_group_name(f"Hypothesis_{slug}")

    def _bg():
        try:
            write_progress(group_name, {"status": "researching_techniques", "phase": "preparing",
                                        "stage": "Hypothesis", "created_yaml": 0, "total_yaml": None})
            tactic_map = {}
            for n, tech_id in enumerate(technique_id_list):
                write_progress(group_name, {"research_total": len(technique_id_list), "research_done": n,
                                            "research_step": "Looking up the technique in ATT&CK", "research_item": tech_id})
                info = _get_technique_info(tech_id)
                tactic = info.get("tactic", "Unknown Tactic") if info else "Unknown Tactic"
                tactic_map.setdefault(tactic, []).extend(_technique_entries(tech_id, info))
            write_progress(group_name, {"research_done": len(technique_id_list), "research_step": "Research complete", "research_item": None})
            manual_data = [{"tactic": t, "techniques": te} for t, te in tactic_map.items()]
            if not manual_data:
                raise ValueError(f"Could not build detection data for: {technique_id_list}")
            modified_process_group_wrapper(
                group_name, hypothesis=text, manual_data=manual_data, genai_mode=genai_mode,
                run_correlation=True, osint_enhancement=True, osint_comparison=False,
                lol_datasets=True, merge_by_tactic=False, merge_by_parent=False,
                **siem_args, **_stack_args(archer_session), **llm_args)
        except Exception as e:
            print(f"Hypothesis hunt error: {e}", flush=True)
            import traceback
            traceback.print_exc()
            try:
                write_progress(group_name, {"status": "failed", "error": str(e)})
            except Exception:
                pass

    try:
        start_progress(group_name, {"status": "started", "stage": "Hypothesis", "created_yaml": 0,
                                    "technique_ids": technique_id_list, "user_id": user_id,
                                    "source_type": "hypothesis", "hypothesis": text})
    except Exception:
        pass
    threading.Thread(target=_bg, daemon=True).start()
    return JSONResponse({"redirect_url": f"/progress?group_name={quote(group_name)}",
                         "extracted": found, "ai_refined": refined, "from_profile": from_profile,
                         "techniques": technique_id_list})


@app.get("/api/techniques/yield")
def api_technique_yield(ids: str = "", ai: bool = False, osint: bool = False):
    """
    Techniques that can't produce a detection: with ids, those of a planned run in the given
    mode; without, the whole list (ATT&CK no-indicator techniques, and AI-empty ones).
    """
    from archer.build import technique_yield as ty

    if ids:
        return {"no_detection": ty.preflight([t for t in ids.split(",") if t.strip()], ai=ai, osint=osint)}
    ledger = {t: v for t, v in ty._read_json(ty.LEDGER_PATH).items() if v.get("empty", 0) >= ty.LLM_EMPTY_LIMIT}
    meta = ty._read_json(ty.STATIC_PATH)
    return {"attack_version": meta.get("attack_version"), "checked": meta.get("checked"),
            "no_indicators": ty.static_list(), "ai_empty": ledger,
            "reasons": {k: ty.describe(k) for k in ty.REASONS}}


# Progress page endpoint
@app.get("/progress", response_class=HTMLResponse)
async def progress(
    request: Request, group_name: str = "", archer_session: Optional[str] = Cookie(None)
):
    # Simple progress page shown while the orchestrator runs. Currently
    # the template only needs the request and the group_name to display.

    # Check if user is logged in (but don't require it)
    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()

    # Detect if this is a CVE hunt to set initial page state
    is_cve_hunt = group_name and (group_name.upper().startswith("CVE-"))

    return templates.TemplateResponse(
        "progress.html",
        {"request": request, "user": user, "group_name": group_name, "is_cve_hunt": is_cve_hunt},
    )


@app.get("/regex", response_class=HTMLResponse)
def regex_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Regex tester (Build): matching and the flavour checks run in the browser; nothing is sent here."""
    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()
    return templates.TemplateResponse("regex.html", {"request": request, "user": user})


@app.get("/manual", response_class=HTMLResponse)
def manual(request: Request, group_name: str = "", archer_session: Optional[str] = Cookie(None)):
    tactics, techniques = get_mitre_lists()
    render_time = datetime.utcnow().isoformat() + "Z"

    # Guests may use this page; resolve a session if present so the header reflects it
    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()

    return templates.TemplateResponse(
        "manual.html",
        {
            "request": request,
            "user": user,
            "group_name": group_name,
            "tactics": tactics,
            "techniques": techniques,
            "render_time": render_time,
        },
    )


@app.get("/health")
def health():
    # "app" lets the desktop app tell an Archer server from anything else answering at a URL
    return {"status": "ok", "app": "archer"}


_DRAFT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")


def _draft_user(request: Request, archer_session: Optional[str], requested_user_id: str = ""):
    """Return (user_id or None, error response or None). A requested user_id must be the session user."""
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return None, JSONResponse({"ok": False, "error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    if requested_user_id and str(requested_user_id) != str(user.id):
        return None, JSONResponse({"ok": False, "error": "user_id mismatch"}, status_code=403)
    return (str(user.id) if requested_user_id else None), None


def _draft_dir(user_id: Optional[str]) -> str:
    return os.path.join(DRAFTS_DIR, "users", user_id) if user_id else DRAFTS_DIR


@app.post("/save_draft")
async def save_draft(request: Request, archer_session: Optional[str] = Cookie(None)):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False}, status_code=400)
    draft_id = str(payload.get("draft_id") or "")
    if not _DRAFT_ID_RE.fullmatch(draft_id):
        return JSONResponse({"ok": False, "error": "invalid draft_id"}, status_code=400)
    user_id, err = _draft_user(request, archer_session, str(payload.get("user_id") or ""))
    if err:
        return err
    drafts_dir = _draft_dir(user_id)
    os.makedirs(drafts_dir, exist_ok=True)
    with open(os.path.join(drafts_dir, f"{draft_id}.json"), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return JSONResponse({"ok": True})


@app.get("/load_draft")
async def load_draft(
    request: Request, draft_id: str = "", user_id: str = "", archer_session: Optional[str] = Cookie(None)
):
    if not _DRAFT_ID_RE.fullmatch(draft_id):
        return JSONResponse({"ok": False}, status_code=400)
    user_id, err = _draft_user(request, archer_session, user_id)
    if err:
        return err
    path = os.path.join(_draft_dir(user_id), f"{draft_id}.json")
    if not os.path.exists(path):
        return JSONResponse({"ok": True, "entries": []})
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return JSONResponse({"ok": True, "entries": data.get("entries", [])})
    except Exception:
        return JSONResponse({"ok": False}, status_code=500)


# Handler for manual submission of appended techniques
@app.post("/manual_submit")
async def manual_submit(
    request: Request,
    group_name: str = Form("manual"),
    group_desc: str = Form(""),
    technique_entries: str = Form(""),
    archer_session: Optional[str] = Cookie(None),
):
    """
    Receive manual technique entries (JSON string), validate them,
    transform the client payload into the `manual_data` structure expected
    by the `process_group` orchestrator, persist a draft for auditing,
    then call the orchestrator and redirect to the progress page.

    Inputs (form fields):
    - group_name: the name supplied on the previous page
    - group_desc: optional description/hypothesis
    - technique_entries: JSON string of appended technique objects

    Returns: RedirectResponse to /progress on success, or re-renders the
    manual form with an error message on validation failure.
    """
    try:
        entries = json.loads(technique_entries) if technique_entries else []
    except Exception:
        entries = []

    # Server-side validation: require at least one entry and each must have technique and procedures
    if not entries:
        # Re-render manual page with an error message
        tactics, techniques = get_mitre_lists()
        render_time = datetime.utcnow().isoformat() + "Z"
        return templates.TemplateResponse(
            "manual.html",
            {
                "request": request,
                "group_name": group_name,
                "tactics": tactics,
                "techniques": techniques,
                "render_time": render_time,
                "error_message": "Please append at least one technique before submitting.",
            },
        )

    invalid = False
    for ent in entries:
        if not ent.get("technique") or not ent.get("procedures"):
            invalid = True
            break
    if invalid:
        tactics, techniques = get_mitre_lists()
        render_time = datetime.utcnow().isoformat() + "Z"
        return templates.TemplateResponse(
            "manual.html",
            {
                "request": request,
                "group_name": group_name,
                "tactics": tactics,
                "techniques": techniques,
                "render_time": render_time,
                "error_message": "Each appended technique must include a technique name and procedures.",
            },
        )

    # Group techniques by tactic to match process_group expected schema
    tactic_map = {}
    for ent in entries:
        tech = ent.get("technique")
        tactics = ent.get("tactics") or []
        procedures = ent.get("procedures", "")
        # If no tactics were selected, put under a generic 'Unknown' tactic
        if not tactics:
            tactics = ["Unknown"]
        for tac in tactics:
            tactic_map.setdefault(tac, []).append(
                {
                    "technique": tech,
                    "op_guidance": procedures,
                    "red_tool": "",
                    "detect_guidance": "",
                }
            )

    manual_data = []
    for tac, techs in tactic_map.items():
        manual_data.append({"tactic": tac, "techniques": techs})

    # Use the provided group_desc as hypothesis if present
    hypothesis = group_desc or "Manual submission"

    # Persist draft to data/drafts/{group_name}.json for auditing/debugging
    try:
        drafts_dir = DRAFTS_DIR
        os.makedirs(drafts_dir, exist_ok=True)
        draft_path = os.path.join(drafts_dir, f"{sanitize_group_name(group_name)}.json")
        with open(draft_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "group_name": group_name,
                    "group_desc": group_desc,
                    "entries": entries,
                },
                fh,
                indent=2,
            )
    except Exception:
        # non-fatal: if we can't write the draft, continue processing
        pass

    # Call the orchestrator to process the manual data in background
    def _bg_manual():
        try:
            # Use the modified wrapper instead of direct process_group
            # Note: manual submissions don't currently pass genai_mode or run_correlation from UI
            modified_process_group_wrapper(
                group_name,
                hypothesis,
                manual_data=manual_data,
                genai_mode=None,
                run_correlation=False,
                **_siem_args(archer_session),
                **_stack_args(archer_session),
            )
        except Exception:
            try:
                write_progress(group_name, {"status": "failed"})
            except Exception:
                pass

    # Fresh record first, so the thread's own updates land after it
    try:
        start_progress(group_name, {"status": "started", "stage": "queued", "created_yaml": 0})
    except Exception:
        pass
    threading.Thread(target=_bg_manual, daemon=True).start()

    # Redirect user to progress page
    return RedirectResponse(url=f"/progress?group_name={quote(group_name)}", status_code=303)


@app.get("/progress_status")
async def progress_status(group_name: str = ""):
    # Return the JSON progress status for the given group_name so the
    # front-end can poll and update progress bars.
    if not group_name:
        return JSONResponse({"ok": False, "error": "group_name required"}, status_code=400)
    data = read_progress(group_name)
    response = {"ok": True, "progress": data}
    return JSONResponse(response)


@app.get("/correlations/{group_name}.json")
async def correlations_json(group_name: str):
    path = os.path.join(CORRELATE_DIR, f"{group_name}.json")
    if not os.path.exists(path):
        return JSONResponse({"ok": False, "error": "not_found"}, status_code=404)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return JSONResponse({"ok": True, "results": data})
    except Exception:
        return JSONResponse({"ok": False}, status_code=500)


@app.get("/api/results/{group_name}")
def results_json(group_name: str, run: str = ""):
    """
    A run's results as JSON (the CLI, the MCP server and the agents read this; the
    results page renders the same files). run=latest limits it to the latest run.
    """
    import yaml as _yaml

    from archer.build.ioc_flow import load_ioc_flow
    from archer.build.run_files import latest_run

    files = group_yaml_files(group_name, GENERATE_DIR) if os.path.exists(GENERATE_DIR) else []
    latest = latest_run(group_name) or {}
    run_only = None
    if run == "latest" and latest.get("files"):
        run_only = set(latest["files"])
        files = [f for f in files if os.path.basename(f) in run_only]

    detections = []
    for path in sorted(files):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = _yaml.safe_load(fh) or {}
        except Exception as e:
            detections.append({"file": os.path.basename(path), "error": str(e)})
            continue
        # Standard files: one query plus requiredDataConnectors; bespoke: a queries list
        connectors = [c.get("connectorId", "") for c in doc.get("requiredDataConnectors") or [] if isinstance(c, dict)]
        platform = ", ".join(doc.get("detection_platforms") or connectors)
        queries = doc.get("queries") or ([{"platform": platform, "query": doc.get("query", "")}] if doc.get("query") else [])
        technique = doc.get("technique_id")
        detections.append({
            "file": os.path.basename(path),
            "name": doc.get("name", ""),
            "techniques": doc.get("techniques") or ([technique] if technique else []),
            "tactics": doc.get("tactics") or [],
            "severity": doc.get("severity", ""),
            "platforms": doc.get("detection_platforms") or sorted({q.get("platform", "") for q in queries} - {""}),
            "queries": [{"platform": q.get("platform", ""), "data_source": q.get("data_source", ""),
                         "query": q.get("query", "")} for q in queries],
            **_assessment(doc),
        })

    correlations = []
    for name in (sanitize_group_name(group_name), group_name):
        corr_path = os.path.join(CORRELATE_DIR, f"{name}.json")
        if os.path.exists(corr_path):
            try:
                with open(corr_path, "r", encoding="utf-8") as fh:
                    correlations = _run_correlations(json.load(fh).get("vendor_correlations", []), run_only)
            except (ValueError, AttributeError):
                pass
            break
    return JSONResponse({
        "ok": True,
        "group_name": group_name,
        "run": "latest" if run == "latest" else "all",
        "latest_run": {"completed_at": latest.get("completed_at"), "files": len(latest.get("files") or [])} if latest else None,
        "detections": detections,
        "correlations": [{"vendor": c.get("vendor", ""), "a": os.path.basename(c.get("a") or ""),
                          "b": [os.path.basename(p) for p in _correlation_paths(c)[1:]] if c.get("chain") else os.path.basename(c.get("b") or ""), "tactics": c.get("tactics") or [],
                          "techniques": c.get("techniques_involved") or [], "relevance": c.get("relevance_score"),
                          "query": c.get("combined_query") or ""}
                         for c in correlations],
        "ioc_flow": load_ioc_flow(group_name) or None,
    })


@app.get("/api/coverage")
def coverage_json(request: Request, group: str = "", techniques: str = "",
                  archer_session: Optional[str] = Cookie(None)):
    """
    Detection coverage: for a group (its techniques, covered or not) or for technique
    IDs (comma-separated). Covered = a file in the detection library names the technique.
    """
    from archer.mitre.procedures import _detected_technique_ids, get_group_coverage

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    auth_result[1].close()
    if group:
        result = get_group_coverage(group, GENERATE_DIR)
        if not result:
            return JSONResponse({"error": f"Group '{group}' not found in ATT&CK data"}, status_code=404)
        return result
    wanted = [t.strip().upper() for t in techniques.split(",") if t.strip()]
    covered = _detected_technique_ids(Path(GENERATE_DIR))
    attack = _attack_techniques()

    def describe(tid):
        obj = attack.get(tid) or {}
        return {"technique_id": tid, "name": obj.get("name"), "covered": tid in covered,
                "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
                **({} if obj else {"note": "not in the Enterprise matrix (mobile/ICS aren't loaded)"})}

    return {"techniques": [describe(t) for t in wanted],
            "covered_count": sum(t in covered for t in wanted), "gap_count": sum(t not in covered for t in wanted)}


@functools.lru_cache(maxsize=1)
def _attack_techniques() -> dict:
    """{technique ID: attack-pattern} from the cached ATT&CK bundle."""
    path = paths.CACHE / "enterprise-attack.json"
    with open(path, encoding="utf-8") as fh:
        bundle = json.load(fh)
    index = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                index[ref["external_id"].upper()] = obj
    return index


@app.get("/api/techniques/{technique_id}")
def technique_json(technique_id: str):
    """An ATT&CK technique: name, tactics, platforms, description."""
    obj = _attack_techniques().get(technique_id.strip().upper())
    if not obj:
        return JSONResponse({"error": f"{technique_id} isn't in the ATT&CK Enterprise matrix "
                                      f"(Archer doesn't load the Mobile or ICS matrices)"}, status_code=404)
    description = re.sub(r"\(Citation:[^)]*\)", "", obj.get("description", "")).strip()
    return {
        "technique_id": technique_id.upper(),
        "name": obj.get("name"),
        "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
        "platforms": obj.get("x_mitre_platforms", []),
        "description": description[:1500],
    }


class _BlockStrDumper(yaml.SafeDumper):
    """Multi-line strings as | block scalars, as the detection files have them."""


_BlockStrDumper.add_representer(
    str, lambda d, v: d.represent_scalar("tag:yaml.org,2002:str", v, style="|" if "\n" in v else None))


@app.post("/api/detections/{filename}/query")
async def save_detection_query(filename: str, request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Replace one query in a detection file (the repair agent's write). The query must pass
    the static checks; the previous query is kept in the file's repair_history.
    Body: {"index": 0, "query": "...", "reason": "..."}
    """
    from archer.validation.static_check import check_query

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    body = await request.json()
    path = os.path.join(GENERATE_DIR, sanitize_filename(filename))
    if not os.path.isfile(path):
        return JSONResponse({"error": "File not found"}, status_code=404)
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    index, query = int(body.get("index") or 0), str(body.get("query") or "").strip("\n") + "\n"
    if doc.get("queries"):
        if not 0 <= index < len(doc["queries"]):
            return JSONResponse({"error": f"No query {index} in {filename}"}, status_code=400)
        target, platform = doc["queries"][index], doc["queries"][index].get("platform")
    else:
        target = doc
        platform = ", ".join(c.get("connectorId", "") for c in doc.get("requiredDataConnectors") or [] if isinstance(c, dict))
    check = check_query(query, platform)
    if check["ok"] is False:
        return JSONResponse({"error": "The query still has errors; not saved", "check": check}, status_code=422)
    entry = {
        "at": datetime.utcnow().isoformat(timespec="seconds") + "Z", "by": user.email, "index": index,
        "reason": str(body.get("reason") or "")[:500], "previous_query": target.get("query", ""),
    }
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    edited = None if doc.get("queries") else _replace_query_block(text, query)
    if edited is not None and (not doc.get("repair_history") or text.rstrip().endswith(
            yaml.dump(doc["repair_history"], Dumper=_BlockStrDumper, sort_keys=False, allow_unicode=True,
                      width=10000).rstrip())):
        # Legacy file: only the query block changes, so comments and layout survive
        history = yaml.dump([entry], Dumper=_BlockStrDumper, sort_keys=False, allow_unicode=True, width=10000)
        edited = edited.rstrip("\n") + "\n" + ("" if doc.get("repair_history") else "repair_history:\n") + history
    else:
        doc.setdefault("repair_history", []).append(entry)
        target["query"] = query
        edited = yaml.dump(doc, Dumper=_BlockStrDumper, sort_keys=False, allow_unicode=True, width=10000)
    if (yaml.safe_load(edited) or {}).get("query", query) != query and not doc.get("queries"):
        return JSONResponse({"error": "Couldn't rewrite the query block safely; not saved"}, status_code=500)
    # Keep the generator stamp: the query no longer matches its hash, so later runs keep
    # this repair instead of rewriting the file (archer.build.yaml.detection_action)
    stamp = text.split("\n", 1)[0]
    if stamp.startswith("# archer-generator:") and not edited.startswith(stamp):
        edited = stamp + "\n" + edited
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(edited)
    return {"success": True, "file": os.path.basename(path), "check": check}


@app.get("/api/attack/techniques")
def attack_techniques():
    """Every current ATT&CK technique with its default tactics, and the tactics in matrix
    order: the choices for changing a detection's mapping."""
    from .visualization.navigator import matrix, technique_index

    bundle = getattr(app.state, "bundle", None)
    index = technique_index(bundle)
    return {
        "tactics": [c["tactic"] for c in matrix(bundle)],
        "techniques": [{"id": tid, **v} for tid, v in sorted(index.items())],
    }


@app.post("/api/detections/mapping")
async def change_detection_mapping(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Change or restore the ATT&CK mapping of one or more detection files (a results card
    can hold several). A comment is required either way and is kept in each file.
    Body: {"files": [...] or "legacy_id": every file on that technique,
           "action": "change"|"restore"|"upgrade", "technique_id", "tactics", "comment",
           "rename_rule": bool (SecOps: rename the rule after the new technique)}
    upgrade moves a detection off a revoked or deprecated technique: the new technique
    becomes its ATT&CK default and the file is renamed after it.
    """
    from .build import attack_mapping
    from .visualization.navigator import legacy, matrix, technique_index

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    body = await request.json()
    files = [sanitize_filename(f) for f in body.get("files") or [] if f]
    if not files and body.get("legacy_id"):
        # Every detection on one revoked/deprecated technique (Coverage: Upgrade all)
        from .visualization.navigator import detection_files_for

        files = detection_files_for(GENERATE_DIR, str(body["legacy_id"]))
    if not files:
        return JSONResponse({"error": "No detection files given"}, status_code=400)
    paths = [os.path.join(GENERATE_DIR, f) for f in files]
    missing = [f for f, p in zip(files, paths) if not os.path.isfile(p)]
    if missing:
        return JSONResponse({"error": f"Not found: {', '.join(missing)}"}, status_code=404)
    bundle = getattr(app.state, "bundle", None)
    index = technique_index(bundle) or None
    order = [c["tactic"] for c in matrix(bundle)] or None
    comment = str(body.get("comment") or "")[:1000]
    results, unchanged = {}, None
    try:
        for f, path in zip(files, paths):
            try:
                if body.get("action") == "restore":
                    results[f] = attack_mapping.restore(path, comment, user.email)
                elif body.get("action") == "upgrade":
                    old = legacy(bundle).get(attack_mapping.read(path)["technique_id"], {})
                    results[f] = attack_mapping.upgrade(
                        path, str(body.get("technique_id") or ""), body.get("tactics") or [], comment,
                        user.email, index or {}, order, rename_rule=bool(body.get("rename_rule")),
                        status=old.get("status", "legacy"))
                else:
                    results[f] = attack_mapping.change(path, str(body.get("technique_id") or ""),
                                                       body.get("tactics") or [], comment, user.email,
                                                       index=index, tactic_order=order,
                                                       rename_rule=bool(body.get("rename_rule")))
            except attack_mapping.Unchanged as err:
                unchanged = err  # another file on the card may still need it
    except attack_mapping.MappingError as err:
        return JSONResponse({"error": str(err), "saved": list(results)}, status_code=422)
    if not results:
        return JSONResponse({"error": str(unchanged)}, status_code=422)
    return {"success": True, "files": results}


def _replace_query_block(text: str, query: str) -> Optional[str]:
    """Swap the body of a top-level `query: |` block; None when the file has no such block."""
    lines = text.split("\n")
    start = next((i for i, line in enumerate(lines) if re.match(r"^query:\s*\|[-+]?\s*$", line)), None)
    if start is None:
        return None
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or lines[end].startswith((" ", "\t"))):
        end += 1
    # Blank lines just before the next key belong to the layout, not the query
    while end - 1 > start and not lines[end - 1].strip():
        end -= 1
    body = ["  " + line if line else "" for line in query.rstrip("\n").split("\n")]
    return "\n".join(lines[:start + 1] + body + lines[end:])


@app.get("/list_drafts")
async def list_drafts(request: Request, user_id: str = "", archer_session: Optional[str] = Cookie(None)):
    user_id, err = _draft_user(request, archer_session, user_id)
    if err:
        return err
    drafts_dir = _draft_dir(user_id)
    results = []
    if not os.path.exists(drafts_dir):
        return JSONResponse({"ok": True, "drafts": []})
    for fname in os.listdir(drafts_dir):
        if fname.endswith(".json"):
            path = os.path.join(drafts_dir, fname)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    j = json.load(fh)
                results.append(
                    {
                        "draft_id": fname[:-5],
                        "group_name": j.get("group_name", ""),
                        "mtime": os.path.getmtime(path),
                    }
                )
            except Exception:
                pass
    return JSONResponse({"ok": True, "drafts": results})


@app.get("/threat_groups")
async def get_threat_groups(query: str = ""):
    """
    Return a list of threat group names and aliases from MITRE ATT&CK
    that match the provided query string.
    """
    bundle = getattr(app.state, "bundle", None)
    if not bundle:
        return JSONResponse({"ok": False, "groups": []})

    groups = []
    query_lower = query.lower()

    for obj in bundle.objects:
        if obj.get("type") == "intrusion-set":
            name = obj.get("name", "")
            aliases = obj.get("aliases", [])

            # Add the primary name if it matches
            if query_lower in name.lower():
                groups.append({"name": name, "is_alias": False})

            # Add matching aliases
            for alias in aliases:
                if alias != name and query_lower in alias.lower():
                    groups.append({"name": alias, "is_alias": True, "primary": name})

    # Remove duplicates and sort
    seen = set()
    unique_groups = []
    for group in groups:
        if group["name"] not in seen:
            seen.add(group["name"])
            unique_groups.append(group)

    # Sort: primary names first, then aliases, alphabetically within each
    unique_groups.sort(key=lambda x: (x.get("is_alias", False), x["name"].lower()))

    # Limit results to 10 for performance
    return JSONResponse({"ok": True, "groups": unique_groups[:10]})


# Modify the orchestrator process to ensure completion
_CONFIGURED_MIN_RELEVANCE = os.environ.get("CORRELATION_MIN_RELEVANCE")


def modified_process_group_wrapper(
    group_name,
    hypothesis,
    manual_data=None,
    genai_mode=None,
    run_correlation=False,
    osint_enhancement=False,
    osint_comparison=False,
    lol_datasets=True,
    merge_by_tactic=False,
    merge_by_parent=False,
    excluded_vendors=None,
    correlation_min_relevance=None,
    use_llm=False,
    llm_config=None,
    tech_stack=None,
):
    """Wrapper for process_group to ensure proper completion and transition to GenAI."""

    # Capture start time for duration tracking
    import time

    start_time = time.time()

    # Set GENAI_MODE environment variable if provided
    if genai_mode:
        os.environ["GENAI_MODE"] = genai_mode

    # Set correlation merging options
    if merge_by_tactic:
        os.environ["CORRELATION_MERGE_BY_TACTIC"] = "true"
    else:
        os.environ.pop("CORRELATION_MERGE_BY_TACTIC", None)

    if merge_by_parent:
        os.environ["CORRELATION_MERGE_BY_PARENT"] = "true"
    else:
        os.environ.pop("CORRELATION_MERGE_BY_PARENT", None)

    # Technique hunts can set the threshold; every other run gets the configured one back
    if correlation_min_relevance is not None:
        os.environ["CORRELATION_MIN_RELEVANCE"] = str(correlation_min_relevance)
    elif _CONFIGURED_MIN_RELEVANCE is None:
        os.environ.pop("CORRELATION_MIN_RELEVANCE", None)
    else:
        os.environ["CORRELATION_MIN_RELEVANCE"] = _CONFIGURED_MIN_RELEVANCE

    try:
        # Call the original process_group with run_correlation parameter
        # IMPORTANT: Use named parameters to avoid positional argument mismatch
        # print(f"DEBUG: About to call process_group with:")
        # print(f"  - group_name: {group_name}")
        # print(f"  - output_dir: None")
        # print(f"  - hypothesis: {hypothesis}")
        # print(f"  - manual_data: {manual_data is not None} (is not None)")
        # print(f"  - run_correlation: {run_correlation}")

        process_group(
            group_name=group_name,
            output_dir=None,
            hypothesis=hypothesis,
            manual_data=manual_data,
            run_correlation=run_correlation,
            osint_enhancement=osint_enhancement,
            osint_comparison=osint_comparison,
            lol_datasets=lol_datasets,
            excluded_vendors=excluded_vendors,
            use_llm=use_llm,
            llm_config=llm_config,
            tech_stack=tech_stack,
        )

        # print(f"DEBUG: process_group completed successfully")

        # Calculate duration
        end_time = time.time()
        duration_seconds = end_time - start_time

        # If correlation was requested, log correlation activity
        if run_correlation:
            progress_data = read_progress(group_name) or {}
            user_id = progress_data.get("user_id")
            if user_id:
                try:
                    # Count detections and correlations
                    detection_count = progress_data.get("created_yaml", 0)

                    # Count correlations from the JSON file
                    correlation_count = 0
                    correlation_file = os.path.join(CORRELATE_DIR, f"{group_name}.json")
                    if os.path.exists(correlation_file):
                        import json

                        with open(correlation_file, "r") as f:
                            correlations = json.load(f)
                            correlation_count = len(correlations.get("correlations", []))

                    source_type = progress_data.get("source_type", "group")

                    # Build title
                    if source_type == "cve":
                        cve_ids = progress_data.get("cve_ids", [])
                        title = f"Built correlations for {', '.join(cve_ids) if cve_ids else 'CVE'}"
                    else:
                        title = f"Built correlations for {group_name}"

                    # Log the activity
                    log_activity(
                        user_id=user_id,
                        activity_type="correlate",
                        title=title,
                        description=f"Generated {detection_count} detections and {correlation_count} correlations",
                        metadata={
                            "detection_count": detection_count,
                            "correlation_count": correlation_count,
                            "group_name": group_name,
                            "source_type": source_type,
                        },
                    )
                except Exception as log_error:
                    print(f"Error logging correlation activity: {log_error}")

            # Mark as complete (IMPORTANT: Set status to "complete" for correlations too)
            progress_data = read_progress(group_name) or {}
            progress_data["status"] = "complete"
            progress_data["phase"] = "complete"
            progress_data["current_technique"] = None
            progress_data["duration"] = duration_seconds
            # print(f"✅ Setting progress status to 'complete' for {group_name} (correlations finished)")
            # print(f"   Progress data: created_yaml={progress_data.get('created_yaml')}, total_yaml={progress_data.get('total_yaml')}, processed={progress_data.get('processed')}, total_pairs={progress_data.get('total_pairs')}")
            write_progress(group_name, progress_data)
            return

        # Otherwise, just mark as complete
        progress_data = read_progress(group_name) or {}
        progress_data["status"] = "complete"
        progress_data["phase"] = "complete"
        progress_data["current_technique"] = None
        progress_data["duration"] = duration_seconds
        write_progress(group_name, progress_data)

        # Log activity to timeline
        user_id = progress_data.get("user_id")
        if user_id:
            try:
                # Count detections generated
                detection_count = progress_data.get("created_yaml", 0)
                source_type = progress_data.get("source_type", "group")

                # Build title based on source type
                if source_type == "cve":
                    cve_ids = progress_data.get("cve_ids", [])
                    title = f"Generated detections for {', '.join(cve_ids) if cve_ids else 'CVE'}"
                else:
                    title = f"Generated detections for {group_name}"

                # Log the activity
                log_activity(
                    user_id=user_id,
                    activity_type="generate",
                    title=title,
                    description=f"Successfully generated {detection_count} detection rules",
                    metadata={
                        "detection_count": detection_count,
                        "group_name": group_name,
                        "source_type": source_type,
                    },
                )
            except Exception as log_error:
                print(f"Error logging activity: {log_error}")

    except Exception as e:
        import traceback

        print(f"Error in process group: {e}")
        print("Full traceback:")
        traceback.print_exc()
        try:
            write_progress(group_name, {"status": "failed", "error": str(e)})
        except:
            pass


@app.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    ai_provider: str = Form(None),
    ai_model: str = Form(None),
    auto_generate: str = Form(None),
    run_correlation: str = Form(None),
    archer_session: Optional[str] = Cookie(None),
):
    """
    Handle file upload for TTP/IOC extraction.

    Accepts threat intelligence files (PDF, TXT, JSON, CSV, YARA) and extracts
    TTPs and IOCs using GenAI, then optionally generates detection queries.
    """
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    user, db = auth_result
    user_id = user.id
    db.close()  # Close DB session

    try:
        # SECURITY: Validate filename to prevent path traversal
        import os
        import re

        if not file.filename:
            return JSONResponse(
                {"success": False, "error": "No filename provided"}, status_code=400
            )

        # Sanitize filename - remove path components and dangerous characters
        safe_filename = os.path.basename(file.filename)
        safe_filename = re.sub(r"[^\w\s\-\.]", "_", safe_filename)

        # Check file extension whitelist
        allowed_extensions = {
            ".pdf",
            ".txt",
            ".md",
            ".json",
            ".csv",
            ".xlsx",
            ".xls",
            ".docx",
            ".doc",
            ".yar",
            ".yara",
        }
        file_ext = os.path.splitext(safe_filename)[1].lower()

        if file_ext not in allowed_extensions:
            return JSONResponse(
                {
                    "success": False,
                    "error": f"File type '{file_ext}' not allowed. Allowed types: {', '.join(allowed_extensions)}",
                },
                status_code=400,
            )

        # SECURITY: Limit file size to 50MB
        file_content = await file.read()
        max_size = 50 * 1024 * 1024  # 50MB

        if len(file_content) > max_size:
            return JSONResponse(
                {
                    "success": False,
                    "error": f"File too large. Maximum size is {max_size // (1024*1024)}MB",
                },
                status_code=413,
            )

        # Import the file intelligence parser
        from archer.parsers.file_intelligence import parse_intelligence_file

        # Parse the file to extract TTPs and IOCs; the AI chosen in the run's prompt (if any)
        # reads it as well as the patterns
        llm_config = _hunt_llm_args(archer_session, ai_provider, ai_model).get("llm_config")
        # Off the event loop: a PDF or an AI read takes long enough to stall every other request
        from starlette.concurrency import run_in_threadpool

        result = await run_in_threadpool(
            parse_intelligence_file,
            file_path=safe_filename,
            file_content=file_content,
            llm_config=llm_config,
        )

        # Extract data
        ttps = result.get("ttps", [])
        iocs = result.get("iocs", {})

        # Create a synthetic group name for tracking
        import hashlib

        file_hash = hashlib.md5(file_content).hexdigest()[:8]
        base_name = os.path.splitext(safe_filename)[0]
        # SECURITY: Sanitize the group name to prevent path traversal
        synthetic_group_name = sanitize_group_name(f"Upload_{base_name}_{file_hash}")

        # Save extraction results to file for later use
        import json

        upload_dir = UPLOADS_DIR
        os.makedirs(upload_dir, exist_ok=True)

        result_file = os.path.join(upload_dir, f"{synthetic_group_name}_extraction.json")
        with open(result_file, "w") as f:
            json.dump(
                {
                    "filename": safe_filename,
                    "ttps": ttps,
                    "iocs": iocs,
                    "ioc_mentions": result.get("ioc_mentions") or {},
                    "synthetic_group_name": synthetic_group_name,
                    "ai_provider": ai_provider or "",
                    "ai_model": ai_model or "",
                    "run_correlation": run_correlation == "true",
                },
                f,
                indent=2,
            )

        # Always return extraction results first for user review
        # The frontend will display these and give user option to proceed
        response_data = {
            "success": True,
            "show_extraction": True,
            "filename": safe_filename,
            "synthetic_group_name": synthetic_group_name,
            "ttps": ttps,
            "iocs": {k: v for k, v in iocs.items() if v},  # Only include non-empty
            "ttps_count": len(ttps),
            "iocs_count": sum(len(v) for v in iocs.values()),
            "auto_generate_requested": auto_generate == "true",
        }

        # Log upload activity
        try:
            log_activity(
                user_id=user_id,
                activity_type="upload",
                title=f"Uploaded threat intelligence: {safe_filename}",
                description=f"Extracted {len(ttps)} TTPs and {sum(len(v) for v in iocs.values())} IOCs",
                metadata={
                    "filename": safe_filename,
                    "ttps_count": len(ttps),
                    "iocs_count": sum(len(v) for v in iocs.values()),
                },
            )
        except Exception as log_error:
            print(f"Error logging upload activity: {log_error}")

        return JSONResponse(response_data)

    except Exception as e:
        import traceback

        traceback.print_exc()
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post("/upload/generate")
async def generate_from_upload(
    request: Request,
    synthetic_group_name: str = Form(...),
    selected_ttps: str = Form(None),
    selected_iocs: str = Form(None),
    osint_enhancement: str = Form(None),
    osint_comparison: str = Form(None),
    lol_datasets: str = Form(None),
    archer_session: Optional[str] = Cookie(None),
):
    """
    Generate detections from previously uploaded and extracted file.
    Called after user reviews extraction results and chooses to proceed.
    Now supports user-selected TTPs and IOCs.
    """
    try:
        import json
        import os

        # SECURITY: Sanitize group name to prevent path traversal
        safe_group_name = sanitize_group_name(synthetic_group_name)

        # Load the extraction results
        upload_dir = UPLOADS_DIR
        result_file = os.path.join(upload_dir, f"{safe_group_name}_extraction.json")

        # SECURITY: Validate the path is within the expected directory
        safe_path = validate_safe_path(upload_dir, result_file)
        if not safe_path:
            return JSONResponse({"success": False, "error": "Invalid file path"}, status_code=400)

        result_file = safe_path

        if not os.path.exists(result_file):
            return JSONResponse(
                {
                    "success": False,
                    "error": "Extraction results not found. Please upload the file again.",
                },
                status_code=404,
            )

        with open(result_file, "r") as f:
            extraction_data = json.load(f)

        # Use selected TTPs/IOCs if provided, otherwise use all extracted data
        if selected_ttps:
            ttps = json.loads(selected_ttps)
        else:
            ttps = extraction_data.get("ttps", [])

        if selected_iocs:
            iocs = json.loads(selected_iocs)
        else:
            iocs = extraction_data.get("iocs", {})
        filename = extraction_data.get("filename", "unknown")
        run_correlation = extraction_data.get("run_correlation", False)
        report_ai = _report_ai_args(archer_session, extraction_data)

        bundle = getattr(request.app.state, "bundle", None)
        report_actor = extraction_data.get("group_name") or synthetic_group_name

        def _bg():
            _run_report_generation(
                synthetic_group_name, ttps, iocs, filename, bundle, report_actor,
                f"Generated from uploaded file: {filename}",
                mentions=extraction_data.get("ioc_mentions"),
                run_correlation=True,  # Always enabled by default
                # The Analyse tab's boxes; a request without them keeps the defaults
                osint_enhancement=(osint_enhancement != "false"),
                osint_comparison=(osint_comparison == "true"),
                lol_datasets=(lol_datasets != "false"),
                **report_ai,
                **_siem_args(archer_session),
                **_stack_args(archer_session),
            )

        # Fresh record first, so the thread's own updates land after it
        try:
            start_progress(
                synthetic_group_name,
                {
                    "status": "processing",
                    "current_step": "Generating detections from uploaded file",
                    "ttps_found": len(ttps),
                    "iocs_found": sum(len(v) for v in iocs.values()),
                },
            )
        except Exception:
            pass
        threading.Thread(target=_bg, daemon=True).start()

        return JSONResponse(
            {
                "success": True,
                "redirect": f"/progress?group_name={synthetic_group_name}",
                "ttps_found": len(ttps),
                "iocs_found": sum(len(v) for v in iocs.values()),
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post("/analyze_blog")
def analyze_blog(
    request: Request,
    url: str = Form(...),
    ai_provider: str = Form(None),
    ai_model: str = Form(None),
    auto_generate: str = Form(None),
    run_correlation: str = Form(None),
    archer_session: Optional[str] = Cookie(None),
):
    """
    Analyze a blog post or threat report URL and extract TTPs, procedures, and IOCs.

    Similar to file upload, can optionally auto-generate detection queries.
    """
    try:
        url = url.strip()

        if not url:
            return JSONResponse({"success": False, "message": "No URL provided"}, status_code=400)

        # Import the blog analyzer
        from archer.parsers.blog_analyzer import analyze_blog_post

        # Analyze the blog post
        print(f"\nAnalyzing blog post: {url}")
        llm_config = _hunt_llm_args(archer_session, ai_provider, ai_model).get("llm_config")
        result = analyze_blog_post(url, include_text=bool(llm_config),
                                   bundle=getattr(request.app.state, "bundle", None))

        if not result.get("success"):
            error_msg = result.get("error", "Failed to analyze blog post")

            # Determine appropriate status code based on error type
            status_code = 500  # Default for server errors
            error_lower = error_msg.lower()

            # Validation errors (400)
            if any(phrase in error_lower for phrase in [
                "invalid url", "no hostname", "unable to resolve"
            ]):
                status_code = 400
            # Security blocks (403)
            elif any(phrase in error_lower for phrase in [
                "not allowed", "private ip", "localhost", "link-local",
                "multicast", "reserved"
            ]):
                status_code = 403
            # Fetch failures (422 - Unprocessable Entity)
            elif "failed to fetch" in error_lower:
                status_code = 422

            return JSONResponse(
                {"success": False, "message": error_msg},
                status_code=status_code,
            )

        # Extract data
        ttps = result.get("techniques", [])
        iocs = result.get("iocs", {})
        group_name = result.get("group_name", "")
        if llm_config and result.get("text"):
            # The AI chosen in the run's prompt reads the post as well as the patterns
            from archer.parsers.file_intelligence import llm_extract_iocs, llm_extract_ttps

            ttps = sorted(set(ttps) | set(llm_extract_ttps(result["text"], llm_config)))
            for kind, found in llm_extract_iocs(result["text"], llm_config).items():
                iocs[kind] = sorted(set(iocs.get(kind) or []) | set(found))
        procedures = result.get("procedures", [])

        # Create a synthetic group name for tracking if not found
        import hashlib
        import json
        import os

        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        # SECURITY: Sanitize group name
        # No group named: the run is called after the article ("Report_Nightmare-Eclipse_Tooling…")
        # Asides like "(Updated October 19)" go, and a long title is cut between words, not inside one ("Upd")
        title = re.sub(r"\s*[(\[][^)\]]*[)\]]", "", result.get("title") or "")
        title_words = re.sub(r"[^\w-]+", "_", title).strip("_")
        if len(title_words) > 60:
            title_words = title_words[:61].rsplit("_", 1)[0] if "_" in title_words[:61] else title_words[:60]
        raw_group_name = group_name or (f"Report_{title_words}" if title_words else f"BlogAnalysis_{url_hash}")
        synthetic_group_name = sanitize_group_name(raw_group_name)

        # Save extraction results to file for later use (like file upload)
        blog_dir = BLOG_DIR
        os.makedirs(blog_dir, exist_ok=True)

        result_file = os.path.join(blog_dir, f"{synthetic_group_name}_extraction.json")
        with open(result_file, "w") as f:
            json.dump(
                {
                    "url": url,
                    "filename": url,  # Use URL as filename for consistency
                    "group_name": group_name,
                    "ttps": ttps,
                    "iocs": iocs,
                    "ioc_mentions": result.get("ioc_mentions") or {},
                    "procedures": procedures,
                    "synthetic_group_name": synthetic_group_name,
                    "ai_provider": ai_provider or "",
                    "ai_model": ai_model or "",
                    "run_correlation": run_correlation == "true",
                },
                f,
                indent=2,
            )

        # Always return extraction results first for user review (same as file upload)
        return JSONResponse(
            {
                "success": True,
                "show_extraction": True,
                "filename": f"Blog: {url[:50]}..." if len(url) > 50 else f"Blog: {url}",
                "synthetic_group_name": synthetic_group_name,
                "ttps": ttps,
                "iocs": {k: v for k, v in iocs.items() if v},  # Only include non-empty
                "ttps_count": len(ttps),
                "iocs_count": sum(len(v) for v in iocs.values()),
                "auto_generate_requested": auto_generate == "true",
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return JSONResponse(
            {"success": False, "message": f"Error analyzing blog: {str(e)}"}, status_code=500
        )


@app.post("/blog/generate")
async def generate_from_blog(
    request: Request,
    synthetic_group_name: str = Form(...),
    selected_ttps: str = Form(None),
    selected_iocs: str = Form(None),
    osint_enhancement: str = Form(None),
    osint_comparison: str = Form(None),
    lol_datasets: str = Form(None),
    archer_session: Optional[str] = Cookie(None),
):
    """
    Generate detections from previously analyzed blog post.
    Called after user reviews extraction results and chooses to proceed.
    Now supports user-selected TTPs and IOCs.
    """
    try:
        import json
        import os

        # SECURITY: Sanitize group name to prevent path traversal
        safe_group_name = sanitize_group_name(synthetic_group_name)

        # Load the extraction results
        blog_dir = BLOG_DIR
        result_file = os.path.join(blog_dir, f"{safe_group_name}_extraction.json")

        # SECURITY: Validate the path is within the expected directory
        safe_path = validate_safe_path(blog_dir, result_file)
        if not safe_path:
            return JSONResponse({"success": False, "error": "Invalid file path"}, status_code=400)

        result_file = safe_path

        if not os.path.exists(result_file):
            return JSONResponse(
                {
                    "success": False,
                    "error": "Extraction results not found. Please analyze the blog post again.",
                },
                status_code=404,
            )

        with open(result_file, "r") as f:
            extraction_data = json.load(f)

        # Use selected TTPs/IOCs if provided, otherwise use all extracted data
        if selected_ttps:
            ttps = json.loads(selected_ttps)
        else:
            ttps = extraction_data.get("ttps", [])

        if selected_iocs:
            iocs = json.loads(selected_iocs)
        else:
            iocs = extraction_data.get("iocs", {})
        url = extraction_data.get("url", "unknown")
        run_correlation = extraction_data.get("run_correlation", False)
        report_ai = _report_ai_args(archer_session, extraction_data)

        bundle = getattr(request.app.state, "bundle", None)
        report_actor = extraction_data.get("group_name") or synthetic_group_name

        def _bg():
            _run_report_generation(
                synthetic_group_name, ttps, iocs, url, bundle, report_actor,
                f"Generated from blog post: {url}",
                mentions=extraction_data.get("ioc_mentions"),
                run_correlation=run_correlation,
                osint_enhancement=(osint_enhancement != "false"),
                osint_comparison=(osint_comparison == "true"),
                lol_datasets=(lol_datasets != "false"),
                **report_ai,
                **_siem_args(archer_session),
                **_stack_args(archer_session),
            )

        # Fresh record first, so the thread's own updates land after it
        try:
            start_progress(
                synthetic_group_name,
                {
                    "status": "processing",
                    "current_step": "Generating detections from blog post",
                    "ttps_found": len(ttps),
                    "iocs_found": sum(len(v) for v in iocs.values()),
                },
            )
        except Exception:
            pass
        threading.Thread(target=_bg, daemon=True).start()

        return JSONResponse(
            {
                "success": True,
                "redirect": f"/progress?group_name={synthetic_group_name}",
                "ttps_found": len(ttps),
                "iocs_found": sum(len(v) for v in iocs.values()),
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return JSONResponse(
            {"success": False, "message": f"Error analyzing blog: {str(e)}"}, status_code=500
        )


@app.post("/emulate")
async def emulate_technique(
    request: Request,
    technique: str = Form(...),
    emulation_mode: str = Form("simulate"),
    remote_execution: str = Form(None),
    remote_hosts: str = Form(None),
):
    """
    Execute adversary emulation using Atomic Red Team.

    Supports both local simulation and live execution modes.
    Can execute on remote hosts if configured.
    """
    if not EMULATION_ENABLED:
        return JSONResponse({"success": False, "message": "Emulation is not enabled. See _archive/REINTEGRATION.md."}, status_code=503)
    try:
        from archer.emulation.atomic import AtomicRedTeam

        # Parse technique or group name
        technique = technique.strip()

        # If it looks like a threat group, we need to map it to techniques
        if not technique.startswith("T"):
            # It's a group name - fetch techniques for the group
            bundle = getattr(app.state, "bundle", None)
            if bundle:
                # Find the group in the bundle
                group_obj = None
                for obj in bundle.get("objects", []):
                    if obj.get("type") == "intrusion-set":
                        if obj.get("name", "").lower() == technique.lower() or any(
                            alias.lower() == technique.lower() for alias in obj.get("aliases", [])
                        ):
                            group_obj = obj
                            break

                if group_obj:
                    # Get techniques used by this group
                    techniques = []
                    group_id = group_obj.get("id")
                    for obj in bundle.get("objects", []):
                        if obj.get("type") == "relationship":
                            if (
                                obj.get("source_ref") == group_id
                                and obj.get("relationship_type") == "uses"
                            ):
                                target_id = obj.get("target_ref")
                                # Find the technique
                                for tech_obj in bundle.get("objects", []):
                                    if tech_obj.get("id") == target_id:
                                        if tech_obj.get("type") == "attack-pattern":
                                            ext_refs = tech_obj.get("external_references", [])
                                            for ref in ext_refs:
                                                if ref.get("source_name") == "mitre-attack":
                                                    techniques.append(ref.get("external_id"))
                                                    break

                    if not techniques:
                        return JSONResponse(
                            {
                                "success": False,
                                "error": f"No techniques found for group '{technique}'",
                            },
                            status_code=400,
                        )

                    # Use the first technique for now
                    technique = techniques[0]
                else:
                    return JSONResponse(
                        {
                            "success": False,
                            "error": f"Threat group '{technique}' not found in MITRE ATT&CK",
                        },
                        status_code=400,
                    )
            else:
                return JSONResponse(
                    {"success": False, "error": "MITRE ATT&CK data not loaded"}, status_code=500
                )

        # Initialize Atomic Red Team
        atomic = AtomicRedTeam()

        # Check if in simulate mode
        is_simulate = emulation_mode == "simulate"

        if is_simulate:
            # Simulate mode - just show what would be executed
            try:
                atomic_data = atomic.get_technique_atomics(technique)
                atomic_tests = atomic_data.get("atomic_tests", [])

                return JSONResponse(
                    {
                        "success": True,
                        "mode": "simulate",
                        "technique": technique,
                        "technique_name": atomic_data.get("display_name", ""),
                        "test_count": len(atomic_tests),
                        "tests": [
                            {
                                "name": test.get("name", ""),
                                "description": test.get("description", ""),
                                "executor": test.get("executor", {}).get("name", ""),
                                "platforms": test.get("supported_platforms", []),
                            }
                            for test in atomic_tests
                        ],
                        "message": "Simulation complete. Enable 'Live Execution' to actually run these tests.",
                    }
                )
            except FileNotFoundError as e:
                return JSONResponse({"success": False, "error": str(e)}, status_code=404)
        else:
            # Live execution mode - actually run the tests
            # THIS IS DANGEROUS - only for controlled environments
            try:
                results = atomic.execute_technique(technique_id=technique, auto_cleanup=True)

                return JSONResponse(
                    {
                        "success": True,
                        "mode": "live",
                        "technique": technique,
                        "results": results,
                        "message": "Emulation executed successfully",
                    }
                )
            except Exception as e:
                import traceback

                traceback.print_exc()
                return JSONResponse(
                    {"success": False, "error": f"Emulation failed: {str(e)}"}, status_code=500
                )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


OSINT_KEY_ENV = {
    "shodan": "SHODAN_API_KEY",
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "github": "GITHUB_TOKEN",
    "hibp": "HIBP_API_KEY",
}


def apply_osint_keys_to_env(db, user_id):
    """
    The OSINT profiler reads its keys from os.environ, but the UI saves them to the APIKey table.
    Bridge the two: push the user's saved OSINT keys into the environment before profiling. A saved
    key wins over a shell-set one; a platform with no saved key is left as the environment has it.
    Single-machine use (the keys are org-wide), so the process environment is the right place.
    """
    for platform, env_name in OSINT_KEY_ENV.items():
        row = db.query(APIKey).filter(APIKey.user_id == user_id, APIKey.platform == platform).first()
        if not row:
            continue
        if row.enabled is False:
            os.environ.pop(env_name, None)  # disabled on the home page: kept in the vault, not applied
            continue
        try:
            value = decrypt_api_key(row.encrypted_key)
        except Exception:
            value = None
        if value:
            os.environ[env_name] = value


@app.post("/profile")
def profile_company(
    request: Request,
    domain: str = Form(...),
    include_industry: str = Form(None),
    include_geography: str = Form(None),
    include_tech_stack: str = Form(None),
    include_supply_chain: str = Form(None),
    use_openai: str = Form(None),
    generate_detections: str = Form(None),
    archer_session: Optional[str] = Cookie(None),
):
    """
    Profile a company based on their domain and generate threat intelligence.

    Analyzes:
    - Industry sector and targeted threat groups
    - Geographic location and nation-state threats
    - Technology stack and CVEs
    - Supply chain dependencies

    Returns profile data and optionally generates detection queries.
    """
    try:
        from archer.intelligence import profile_company as do_profile
        from archer.build.orchestrator import process_group

        # Clean domain input
        domain = domain.strip().lower()
        # Remove http:// or https:// if present
        domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

        # Build options dict
        # Note: Auto-Generate, Industry, Geography, and Tech Stack are always enabled by default
        options = {
            "include_industry": True,  # Always enabled
            "include_geography": True,  # Always enabled
            "include_tech_stack": True,  # Always enabled
            "include_supply_chain": include_supply_chain == "true",
        }

        use_ai = use_openai == "true"
        auto_generate = True  # Always generate detections by default

        # Use domain as group_name for progress tracking
        group_name = domain.replace(".", "_").replace("/", "_")

        # Make the user's saved OSINT keys available to the profiler (it reads os.environ)
        try:
            _kdb = next(get_db())
            try:
                _ku = get_user_from_session_id(archer_session, _kdb) if archer_session else None
                if _ku:
                    apply_osint_keys_to_env(_kdb, _ku.id)
            finally:
                _kdb.close()
        except Exception:
            pass

        # Profiling runs in the background so the browser can follow it on a progress page,
        # the same as a hunt, instead of holding a blocking request open. The profiler emits
        # its own stage updates through write_progress; we seed a fresh record first so a
        # previous profile of this domain doesn't make the page redirect straight away.
        safe_domain = domain.replace(".", "_").replace("/", "_")
        profile_dir = Path("data") / "profiles"
        profile_dir.mkdir(parents=True, exist_ok=True)
        profile_path = profile_dir / f"{safe_domain}_profile.json"

        write_progress(group_name, {"status": "profiling", "stage": 1, "total_stages": 7,
                                    "message": "Starting profile…", "source_type": "profile",
                                    "error": None})

        def _profile_bg():
            try:
                print(f"\nProfiling domain: {domain}")
                profile = do_profile(domain, options, use_openai=use_ai, group_name=group_name)
                with open(profile_path, "w", encoding="utf-8") as f:
                    json.dump(profile, f, indent=2)
                print(f"Profile saved to: {profile_path}")
                write_progress(group_name, {"status": "profile_complete", "stage": 7,
                                            "total_stages": 7, "message": "Profile complete"})
            except Exception as e:
                import traceback
                traceback.print_exc()
                write_progress(group_name, {"status": "failed", "error": str(e)})

        import threading
        threading.Thread(target=_profile_bg, daemon=True).start()

        return JSONResponse({
            "success": True,
            "redirect_url": "/profile-progress?" + urlencode({"domain": domain, "group_name": group_name}),
            "message": "Profiling started",
        })

    except Exception as e:
        import traceback

        traceback.print_exc()
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post("/api/technique_names")
async def get_technique_names(request: Request):
    """
    Get technique names for given technique IDs.

    Request body: {"technique_ids": ["T1059.001", "T1078", ...]}
    Returns: {"T1059.001": "PowerShell", "T1078": "Valid Accounts", ...}
    """
    try:
        import json
        from pathlib import Path

        body = await request.json()
        technique_ids = body.get("technique_ids", [])

        # Load MITRE ATT&CK data
        mitre_path = paths.CACHE / "enterprise-attack.json"
        if not mitre_path.exists():
            return JSONResponse(
                {"success": False, "error": "MITRE ATT&CK data not found"}, status_code=500
            )

        with open(mitre_path) as f:
            data = json.load(f)

        # Build mapping
        technique_names = {}
        for obj in data["objects"]:
            if obj.get("type") == "attack-pattern":
                ext_refs = obj.get("external_references", [])
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id")
                        tech_name = obj.get("name")
                        if tech_id in technique_ids:
                            technique_names[tech_id] = tech_name

        return JSONResponse(technique_names)

    except Exception as e:
        print(f"Error getting technique names: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post("/api/actors/techniques")
async def get_actors_techniques(request: Request):
    """
    Get consolidated ATT&CK techniques for a list of threat actors.

    Request body: {"actors": ["APT29", "Lazarus Group"]}
    Returns a consolidated list of techniques with per-actor attribution,
    following all three MITRE attribution paths (direct, via software, via campaign).
    """
    from archer.mitre.procedures import (
        _build_indexes,
        _resolve_group,
        _walk_path1,
        _walk_path2,
        _walk_path3,
    )

    try:
        body = await request.json()
        actors = body.get("actors", [])

        if not actors:
            return JSONResponse({"ok": False, "error": "No actors provided"}, status_code=400)

        if len(actors) > 20:
            return JSONResponse({"ok": False, "error": "Maximum 20 actors per request"}, status_code=400)

        bundle = getattr(app.state, "bundle", None)
        if not bundle:
            return JSONResponse({"ok": False, "error": "MITRE ATT&CK data not loaded"}, status_code=503)

        # Build indexes once for all actor lookups
        objects = list(bundle.objects)
        groups, techniques, software, campaigns = _build_indexes(objects)

        # technique_map: (technique_id, tactic) -> {technique_id, technique_name, tactic,
        #                                            actors: {actor_name: set(attribution_types)}}
        technique_map = {}
        actors_found = []
        actors_not_found = []
        actor_metadata: dict = {}

        for raw_actor in actors:
            actor_name = raw_actor.strip()
            if not actor_name:
                continue

            stix_id = _resolve_group(groups, actor_name)
            if not stix_id:
                actors_not_found.append(actor_name)
                continue

            actors_found.append(actor_name)
            actor_metadata[actor_name] = _actor_stix_metadata(groups[stix_id])

            # Walk all three attribution paths for this single actor
            rows = []
            seen = set()
            single_group = {stix_id: groups[stix_id]}
            _walk_path1(objects, single_group, techniques, rows, seen)
            _walk_path2(objects, single_group, techniques, software, rows, seen)
            _walk_path3(objects, single_group, techniques, campaigns, rows, seen)

            for row in rows:
                tech_id = row["technique_id"]
                tactic = row["tactic"]
                key = (tech_id, tactic)

                if key not in technique_map:
                    technique_map[key] = {
                        "technique_id": tech_id,
                        "technique_name": row["technique_name"],
                        "tactic": tactic,
                        "actors": {},
                    }

                actor_entry = technique_map[key]["actors"]
                if actor_name not in actor_entry:
                    actor_entry[actor_name] = set()
                actor_entry[actor_name].add(row["attribution_type"])

        # Build output list sorted by technique_id then tactic
        consolidated = []
        for (tech_id, tactic), data in sorted(technique_map.items()):
            actors_list = [
                {
                    "name": actor,
                    "attribution_types": sorted(atypes),
                }
                for actor, atypes in sorted(data["actors"].items())
            ]
            consolidated.append({
                "technique_id": tech_id,
                "technique_name": data["technique_name"],
                "tactic": tactic,
                "actors": actors_list,
                "actor_count": len(actors_list),
            })

        shared_count = sum(1 for t in consolidated if t["actor_count"] > 1)

        return JSONResponse({
            "ok": True,
            "techniques": consolidated,
            "actors_found": actors_found,
            "actors_not_found": actors_not_found,
            "actor_metadata": actor_metadata,
            "total_techniques": len(consolidated),
            "shared_count": shared_count,
        })

    except Exception as e:
        print(f"Error in /api/actors/techniques: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


def _actor_stix_metadata(obj: dict) -> dict:
    """Extract exportable metadata from a STIX intrusion-set object."""
    mitre_id = ""
    mitre_url = ""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            mitre_id = ref.get("external_id", "")
            mitre_url = ref.get("url", "")
            break

    raw_domains = obj.get("x_mitre_domains", [])
    domain_map = {"enterprise-attack": "Enterprise", "mobile-attack": "Mobile", "ics-attack": "ICS"}
    domains = "; ".join(domain_map.get(d, d) for d in raw_domains) or "Enterprise"

    name = obj.get("name", "")
    aliases = [a for a in (obj.get("aliases") or []) if a != name]
    aliases_str = "; ".join(aliases)

    enterprise_layer = f"https://attack.mitre.org/groups/{mitre_id}/enterprise-layer.json" if mitre_id and "Enterprise" in domains else ""
    mobile_layer     = f"https://attack.mitre.org/groups/{mitre_id}/mobile-layer.json"     if mitre_id and "Mobile"     in domains else ""
    ics_layer        = f"https://attack.mitre.org/groups/{mitre_id}/ics-layer.json"        if mitre_id and "ICS"        in domains else ""

    return {
        "mitre_group_id":   mitre_id,
        "domains":          domains,
        "aliases":          aliases_str,
        "mitre_url":        mitre_url,
        "enterprise_layer": enterprise_layer,
        "mobile_layer":     mobile_layer,
        "ics_layer":        ics_layer,
    }


@app.post("/api/research/export-xlsx")
async def export_research_xlsx(request: Request):
    """
    Generate a professionally styled XLSX workbook for the Research tab.

    Request body:
      {"type": "actors"|"techniques", "actors": ["APT29", ...]}

    Returns a .xlsx file as a streaming response.
    - type=actors  → single "Actors" sheet (18 cols, matching reference format)
    - type=techniques → "Raw Mappings" + "Technique Coverage" sheets
    """
    import io
    from datetime import datetime as _dt

    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment
        from openpyxl.utils import get_column_letter
    except ImportError:
        return JSONResponse({"ok": False, "error": "openpyxl not installed"}, status_code=500)

    from fastapi.responses import StreamingResponse
    from archer.mitre.procedures import (
        _build_indexes, _resolve_group,
        _walk_path1, _walk_path2, _walk_path3,
        _attack_id, _clean,
    )

    try:
        body = await request.json()
        export_type = body.get("type", "techniques")
        actor_names = body.get("actors", [])

        if not actor_names:
            return JSONResponse({"ok": False, "error": "No actors provided"}, status_code=400)

        bundle = getattr(app.state, "bundle", None)
        if not bundle:
            return JSONResponse({"ok": False, "error": "MITRE data not loaded"}, status_code=503)

        objects = list(bundle.objects)
        groups_idx, techniques_idx, software_idx, campaigns_idx = _build_indexes(objects)

        # Resolve actors → {stix_id: canonical_name}, preserving input order
        resolved_stix: dict = {}   # stix_id → canonical name
        input_order: list  = []    # canonical names in input order (deduped)
        for raw in actor_names:
            stix_id = _resolve_group(groups_idx, raw.strip())
            if stix_id and stix_id not in resolved_stix:
                canon = groups_idx[stix_id].get("name", raw.strip())
                resolved_stix[stix_id] = canon
                input_order.append(canon)

        if not input_order:
            return JSONResponse({"ok": False, "error": "No actors resolved"}, status_code=404)

        # ── Styling helpers ──────────────────────────────────────────────────
        HDR_FILL  = PatternFill("solid", fgColor="1F4E79")
        HDR_FONT  = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
        HDR_ALIGN = Alignment(horizontal="center", vertical="center", wrap_text=True)
        DATA_FONT = Font(name="Calibri", size=11)
        DATA_ALIGN = Alignment(vertical="top", wrap_text=True)

        def apply_header(ws, headers, widths):
            for c, (h, w) in enumerate(zip(headers, widths), 1):
                cell = ws.cell(1, c, h)
                cell.fill = HDR_FILL
                cell.font = HDR_FONT
                cell.alignment = HDR_ALIGN
                ws.column_dimensions[get_column_letter(c)].width = w
            ws.row_dimensions[1].height = 30
            ws.freeze_panes = "A2"

        def write_row(ws, r, values):
            for c, v in enumerate(values, 1):
                cell = ws.cell(r, c, v if v is not None else "")
                cell.font = DATA_FONT
                cell.alignment = DATA_ALIGN

        def fmt_date(d):
            if not d:
                return ""
            # STIXdatetime (and plain datetime) objects already have .day/.month/.year
            if hasattr(d, "day"):
                return f"{d.day} {d.strftime('%B')} {d.year}"
            # String fallback
            s = str(d)
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    dt = _dt.strptime(s, fmt)
                    return f"{dt.day} {dt.strftime('%B')} {dt.year}"
                except ValueError:
                    pass
            return s[:10] if len(s) >= 10 else s

        # Load enriched group metadata from app.state cache (built at startup)
        group_meta_cache: dict = getattr(app.state, "group_metadata", {})

        wb = openpyxl.Workbook()
        wb.remove(wb.active)

        # ════════════════════════════════════════════════════════════════════
        if export_type == "actors":
            ACTORS_H = [
                'Actor', 'MITRE Group ID', 'Domains', 'Aliases',
                'Nexus', 'Sponsor / Affiliation', 'Activity since',
                'Primary objectives', 'Target regions', 'Target sectors',
                'Notable tools/malware', 'Notable campaigns/ops',
                'Attribution confidence', 'MITRE URL',
                'Enterprise layer', 'Mobile layer', 'ICS layer', 'Additional sources',
            ]
            ACTORS_W = [22,12,14,45,22,34,12,24,24,34,26,22,18,34,38,38,38,44]
            ws = wb.create_sheet("Actors")
            apply_header(ws, ACTORS_H, ACTORS_W)

            r = 2
            for raw in actor_names:
                stix_id = _resolve_group(groups_idx, raw.strip())
                if not stix_id:
                    continue
                grp = groups_idx[stix_id]
                m   = _actor_stix_metadata(grp)
                # Pull enriched fields from cache (keyed by ATT&CK ID or stix_id)
                ec  = group_meta_cache.get(m["mitre_group_id"]) or \
                      group_meta_cache.get(stix_id) or {}
                write_row(ws, r, [
                    grp.get("name", raw),
                    m["mitre_group_id"],
                    m["domains"],
                    m["aliases"],
                    ec.get("nexus", ""),
                    ec.get("sponsor", ""),
                    ec.get("activity_since", ""),
                    ec.get("primary_objectives", ""),
                    ec.get("target_regions", ""),
                    ec.get("target_sectors", ""),
                    ec.get("tools_malware", ""),
                    ec.get("campaigns", ""),
                    ec.get("attribution_confidence", ""),
                    m["mitre_url"],
                    m["enterprise_layer"],
                    m["mobile_layer"],
                    m["ics_layer"],
                    "",  # Additional sources — manual field
                ])
                r += 1

        # ════════════════════════════════════════════════════════════════════
        else:  # type == "techniques"
            resolved_set = set(resolved_stix.keys())

            # ── Raw Mappings: direct path-1 relationships with descriptions ─
            raw_rows = []
            for obj in objects:
                if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
                    continue
                src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
                if src not in resolved_set or tgt not in techniques_idx:
                    continue
                grp  = groups_idx[src]
                tech = techniques_idx[tgt]
                g_att = _attack_id(grp)
                t_att = _attack_id(tech)
                if not g_att or not t_att:
                    continue
                raw_rows.append([
                    g_att,
                    grp.get("name", ""),
                    t_att,
                    tech.get("name", ""),
                    _clean(obj.get("description", "")),
                    fmt_date(obj.get("created", "")),
                    fmt_date(obj.get("modified", "")),
                ])
            raw_rows.sort(key=lambda r: (r[1], r[2]))

            RAW_H = ['source ID', 'Group Name', 'target ID', 'target name',
                     'mapping description', 'created', 'last modified']
            RAW_W = [11, 20, 11, 56, 60, 18, 15]
            ws_raw = wb.create_sheet("Raw Mappings")
            apply_header(ws_raw, RAW_H, RAW_W)
            for i, row in enumerate(raw_rows, 2):
                write_row(ws_raw, i, row)

            # ── Technique Coverage: all 3 paths, pivot, sorted by count desc ─
            all_rows: list = []
            all_seen: set  = set()
            for stix_id, canon in resolved_stix.items():
                sg = {stix_id: groups_idx[stix_id]}
                _walk_path1(objects, sg, techniques_idx, all_rows, all_seen)
                _walk_path2(objects, sg, techniques_idx, software_idx, all_rows, all_seen)
                _walk_path3(objects, sg, techniques_idx, campaigns_idx, all_rows, all_seen)

            tech_pivot: dict = {}   # tid → {canon_name: 1}
            tech_name_map: dict = {}
            for row in all_rows:
                tid   = row["technique_id"]
                actor = row["group_name"]
                tech_pivot.setdefault(tid, {})[actor] = 1
                tech_name_map.setdefault(tid, row["technique_name"])

            actor_order = sorted(input_order)
            COV_H = ['target ID', 'target name'] + actor_order + ['Group_Count']
            COV_W = [11, 47] + [max(12, len(a) + 2) for a in actor_order] + [14]

            cov_data = []
            for tid, amap in tech_pivot.items():
                count = sum(1 for a in actor_order if amap.get(a))
                row = [tid, tech_name_map[tid]]
                for a in actor_order:
                    row.append(1 if amap.get(a) else 0)
                row.append(count)
                cov_data.append(row)
            cov_data.sort(key=lambda r: -r[-1])

            ws_cov = wb.create_sheet("Technique Coverage")
            apply_header(ws_cov, COV_H, COV_W)
            for i, row in enumerate(cov_data, 2):
                write_row(ws_cov, i, row)

        # ── Stream XLSX bytes to client ──────────────────────────────────────
        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)
        fname = "actors.xlsx" if export_type == "actors" else "techniques.xlsx"
        return StreamingResponse(
            buf,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    except Exception as exc:
        import traceback; traceback.print_exc()
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


# Country keywords whose mentions are classified as attribution or targeting
# (archer.intelligence.country_context) rather than matched as plain substrings
_COUNTRY_KEYWORDS: set = {
    "china", "russia", "iran", "north korea", "pakistan",
    "vietnam", "india", "ukraine", "israel", "united states", "turkey", "lebanon",
}

# Industry / country keyword → description search terms
_ACTOR_KEYWORD_VARIANTS: dict = {
    # Industries
    "finance":           ["financial", "finance", "banking", "bank", "insurance", "cryptocurrency", "fintech"],
    "retail":            ["retail", "consumer goods", "e-commerce", "ecommerce", "supermarket"],
    "defence":           ["defense", "defence", "military", "armed forces", "department of defense", "dod", "nato"],
    "healthcare":        ["healthcare", "health care", "hospital", "medical", "pharmaceutical", "pharma", "biotech"],
    "energy":            ["energy", "oil and gas", "oil & gas", "utilities", "power grid", "electric", "nuclear"],
    "technology":        ["technology", "tech sector", "semiconductor", "software company", "it sector", "high-tech"],
    "telecommunications": ["telecommunications", "telecom", "telco", "internet service provider", "isp"],
    "government":        ["government", "public sector", "federal", "ministry", "civil service", "state-owned"],
    "aerospace":         ["aerospace", "aviation", "space industry", "satellite"],
    "education":         ["education", "university", "academic", "research institution"],
    "manufacturing":     ["manufacturing", "industrial", "factory", "production"],
    "media":             ["media", "news", "journalism", "broadcasting", "entertainment"],
    "legal":             ["legal", "law firm", "judiciary"],
    # Countries / regions
    "china":             ["chinese", "china", "prc", "people's republic of china", "beijing"],
    "russia":            ["russian", "russia", "kremlin", "moscow", "gru", "fsb", "svr"],
    "iran":              ["iranian", "iran", "tehran", "irgc"],
    "north korea":       ["north korean", "north korea", "dprk", "pyongyang", "lazarus"],
    "pakistan":          ["pakistan", "pakistani", "islamabad"],
    "vietnam":           ["vietnam", "vietnamese"],
    "india":             ["india", "indian"],
    "ukraine":           ["ukraine", "ukrainian"],
    "israel":            ["israel", "israeli"],
    "united states":     ["united states", "us-based", "american actor"],
    "turkey":            ["turkey", "turkish"],
    "lebanon":           ["lebanon", "lebanese", "hezbollah"],
}


@app.get("/api/actors/by-keyword")
async def get_actors_by_keyword(keyword: str = "", keywords: str = "", mode: str = "AND", scope: str = "attributed"):
    """
    Return actor names whose MITRE descriptions match given keyword(s).

    Single:   ?keyword=Iran
    Multiple: ?keywords=Iran,Finance&mode=AND  (actors matching ALL keywords)
              ?keywords=Iran,Finance&mode=OR   (actors matching ANY keyword)
    Country keywords honour scope: attributed (default) = the actor is from/sponsored
    by the country; targeted = the actor has targeted it. Industry keywords describe
    targeting already and match the same way in both scopes.
    Returns: {"ok": true, "actors": [...], "count": N}
    """
    from archer.intelligence.country_context import country_matches

    scope = scope.lower()
    if scope not in ("attributed", "targeted"):
        return JSONResponse({"ok": False, "error": "scope must be 'attributed' or 'targeted'"}, status_code=400)
    raw = keywords if keywords else keyword
    kw_list = [k.strip() for k in raw.split(",") if k.strip()]
    if not kw_list:
        return JSONResponse({"ok": False, "error": "No keyword provided"}, status_code=400)

    bundle = getattr(app.state, "bundle", None)
    if not bundle:
        return JSONResponse({"ok": False, "error": "MITRE ATT&CK data not loaded"}, status_code=503)

    per_kw_terms = [
        _ACTOR_KEYWORD_VARIANTS.get(kw.lower(), [kw.lower()])
        for kw in kw_list
    ]

    use_and = mode.upper() != "OR"
    matched = []
    for obj in bundle.objects:
        if obj.get("type") == "intrusion-set":
            description = (obj.get("description") or "")

            def kw_hit(kw: str, terms: list) -> bool:
                if kw.lower() in _COUNTRY_KEYWORDS:
                    return country_matches(description, terms, scope)
                return any(t in description.lower() for t in terms)

            if use_and:
                hit = all(kw_hit(kw, terms) for kw, terms in zip(kw_list, per_kw_terms))
            else:
                hit = any(kw_hit(kw, terms) for kw, terms in zip(kw_list, per_kw_terms))
            if hit:
                matched.append(obj.get("name", ""))

    matched = sorted(filter(None, matched))
    return JSONResponse({"ok": True, "actors": matched, "count": len(matched), "keywords": kw_list, "mode": mode.upper(), "scope": scope})


_GROUP_SIZES = {"mtime": None, "counts": {}}


@app.get("/api/group-sizes")
async def group_sizes(groups: str = ""):
    """ATT&CK procedure count per group, for the Profile modal's time estimate."""
    import csv

    path = os.path.join(DATA_DIR, "mitre_procedures.csv")
    try:
        mtime = os.path.getmtime(path)
        if _GROUP_SIZES["mtime"] != mtime:
            counts = {}
            with open(path, newline="", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    name = (row.get("group_name") or row.get("group_sw_name") or "").strip().lower()
                    if name:
                        counts[name] = counts.get(name, 0) + 1
            _GROUP_SIZES.update(mtime=mtime, counts=counts)
    except OSError:
        pass
    wanted = [g.strip() for g in groups.split(",") if g.strip()]
    return {"sizes": {g: _GROUP_SIZES["counts"].get(g.lower()) for g in wanted}}


@app.post("/profile/generate-detections")
async def generate_detections_from_profile(
    request: Request,
    domain: str = Form(...),
    selected_groups: str = Form(...),  # Comma-separated list
    run_correlation: str = Form(None),
):
    """
    Generate detections for user-selected threat groups from a profile.

    This is called after the user reviews the profile and selects which
    threat groups they want to generate detections for.
    """
    try:
        from archer.build.orchestrator import process_group

        # Parse selected groups
        groups = [g.strip() for g in selected_groups.split(",") if g.strip()]

        if not groups:
            return JSONResponse(
                {"success": False, "error": "No threat groups selected"}, status_code=400
            )

        should_correlate = run_correlation == "true"

        print(
            f"\nGenerating detections for {len(groups)} selected threat groups from {domain} profile..."
        )

        # Groups run one after another; the progress page follows each in turn
        def _generate_bg():
            for group in groups:
                print(f"Generating detections for: {group}")
                try:
                    result = process_group(group, run_correlation=should_correlate)
                    print(f"Generated detections for {group}: {result}")
                except Exception as e:
                    import traceback

                    traceback.print_exc()
                    write_progress(group, {"status": "failed", "error": str(e)})

        import threading

        # A fresh record for every group before the thread starts: the page must not read
        # a group's previous run (it would show it complete and move on)
        for position, group in enumerate(groups):
            start_progress(group, {
                "stage": "queued", "created_yaml": 0, "source_type": "profile",
                **({"current_step": f"Queued behind {groups[position - 1]}"} if position else {}),
            })
        threading.Thread(target=_generate_bg, daemon=True).start()

        # Return progress redirect
        group_list = ", ".join(groups[:3])  # Show first 3 groups
        if len(groups) > 3:
            group_list += f" and {len(groups) - 3} more"

        return JSONResponse(
            {
                "success": True,
                "redirect_url": "/progress?" + urlencode({"group_name": groups[0], "queue": ",".join(groups)}),
                "message": f"Generating detections for: {group_list}",
                "groups": groups,
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


def _run_report_generation(group, ttps, iocs, source, bundle, actor, description, mentions=None, **kwargs):
    """
    Background job for an uploaded file or blog post: IOC sweeps, then the techniques.

    The sweep count goes into the progress record, so a run with IOCs but no techniques
    finishes as a success rather than "nothing generated".
    """
    from archer.build.ioc_sweep import write_ioc_sweeps

    try:
        # The report's atomic IOCs aren't tied to a technique: one sweep per SIEM
        sweeps = write_ioc_sweeps(group, iocs, source, GENERATE_DIR, mentions=mentions,
                                  excluded_vendors=kwargs.get("excluded_vendors"))
        if sweeps:
            print(f"IOC sweep detections: {', '.join(os.path.basename(p) for p in sweeps)}")
        write_progress(group, {"ioc_sweeps": len(sweeps)})
        if not ttps:
            write_progress(group, {
                "status": "complete", "phase": "complete", "created_yaml": 0, "total_yaml": 0,
                **({} if sweeps else {"error": "No techniques were selected and none of the IOCs could be swept for."}),
            })
            return
        manual_data = _report_manual_data(ttps, bundle, actor, source)
    except Exception as e:
        print(f"Error preparing report generation: {e}")
        write_progress(group, {"status": "failed", "error": str(e)})
        return
    try:
        modified_process_group_wrapper(group, description, manual_data=manual_data, **kwargs)
    except Exception as e:
        print(f"Error processing report: {e}")
        try:
            write_progress(group, {"status": "failed", "error": str(e)})
        except Exception:
            pass


def _report_manual_data(ttps, bundle, actor: str, source: str) -> list:
    """
    process_group's manual_data for a report's techniques, grouped by tactic.

    When the report's actor is an ATT&CK group (by name or alias, e.g. UNC3944 ->
    Scattered Spider), each technique uses that group's ATT&CK procedures, which carry
    per-technique indicators. Techniques without one fall back to the technique's own
    description, as a technique hunt does.
    """
    from archer.mitre.retrieve import retrieve_group, retrieve_procedures, retrieve_techniques

    group_procs = {}
    group_id = retrieve_group(bundle, actor) if bundle is not None and actor else None
    if group_id:
        for proc in retrieve_procedures(bundle, retrieve_techniques(bundle, group_id)):
            group_procs.setdefault(proc[0], []).append(proc)
        print(f"Blog actor '{actor}' resolved to an ATT&CK group: {len(group_procs)} techniques with procedures")

    by_tactic = {}
    for tid in dict.fromkeys(ttps):
        info = _get_technique_info(tid) or {}
        tactic = info.get("tactic", "Unknown Tactic")
        name = info.get("name", tid)
        procs = group_procs.get(tid)
        if procs:
            for proc in procs:
                by_tactic.setdefault((proc[2] or [tactic])[0], []).append({
                    "technique": tid, "name": proc[1] or name,
                    "activity_desc": proc[3],
                    "op_guidance": proc[4], "red_tool": proc[5],
                    "detect_guidance": (proc[6] or [""])[0],
                    "procedure_platforms": proc[7] if len(proc) > 7 else [],
                    "software_platforms": proc[8] if len(proc) > 8 else {},
                })
        else:
            for entry in _technique_entries(tid, info, bundle):
                entry["activity_desc"] = f"Reported in {source}. {entry['activity_desc']}"
                by_tactic.setdefault(tactic, []).append(entry)
    return [{"tactic": tactic, "techniques": techs} for tactic, techs in by_tactic.items()]


def _technique_entries(tid: str, info: Optional[dict], bundle=None) -> list:
    """
    process_group's entries for a technique with no group behind it: a technique hunt, or a
    report technique its actor has no ATT&CK procedure for.

    A technique's description names no commands, files or registry keys, so without AI or
    OSINT nothing could be built from it. The procedure examples of the ATT&CK groups that
    use the technique do (T1003.001: procdump -ma lsass.exe), so their indicators are used.
    A parent's own examples are often vague (T1003), so its sub-techniques' examples, which
    retrieve_procedures expands, each become an entry too.
    """
    info = info or {}
    description = info.get("description") or f"Detect usage of {tid}"
    entry = {
        "technique": tid, "name": info.get("name", tid),
        "activity_desc": description, "op_guidance": description, "red_tool": {},
        "detect_guidance": description, "procedure_platforms": info.get("platforms", []),
    }
    bundle = bundle if bundle is not None else getattr(app.state, "bundle", None)
    if bundle is None or not info.get("stix_id"):
        return [entry]
    from archer.mitre.retrieve import retrieve_procedures

    try:
        procs = [p for p in retrieve_procedures(bundle, [(description, info["stix_id"])], merge_expanded=False)
                 if p[0] == tid or p[0].startswith(tid + ".")]
    except Exception as e:
        print(f"Could not gather ATT&CK procedure indicators for {tid}: {e}")
        return [entry]
    entries = []
    for proc in procs:
        if not (isinstance(proc[4], dict) and any(k != "description" for k in proc[4])):
            continue
        own = proc[0] == tid
        entries.append({
            **entry,
            "technique": proc[0], "name": entry["name"] if own else (proc[1] or proc[0]),
            "activity_desc": description if own else (proc[3] or description),
            "op_guidance": proc[4], "red_tool": proc[5] or {},
            "procedure_platforms": (proc[7] if len(proc) > 7 and proc[7] else entry["procedure_platforms"]),
            "software_platforms": proc[8] if len(proc) > 8 else {},
        })
        print(f"{proc[0]}: indicators from ATT&CK procedure examples "
              f"({', '.join(k for k in proc[4] if k != 'description')})")
    return entries or [entry]


def _get_technique_info(ttp_id: str) -> dict:
    """Get technique information from MITRE ATT&CK bundle."""
    bundle = getattr(app.state, "bundle", None)
    if not bundle:
        return None

    # Search for technique in bundle
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            # Check external references for technique ID
            for ref in obj.get("external_references", []):
                if ref.get("external_id") == ttp_id:
                    # Extract tactic
                    tactics = []
                    for phase in obj.get("kill_chain_phases", []):
                        tactic_name = phase.get("phase_name", "").replace("-", " ").title()
                        tactics.append(tactic_name)

                    return {
                        "tid": ttp_id,
                        "stix_id": obj.get("id"),
                        "name": obj.get("name", ttp_id),
                        "tactic": tactics[0] if tactics else "Unknown",
                        "description": obj.get("description", ""),
                        "software_used": [],
                        "platforms": obj.get("x_mitre_platforms", ["windows"]),
                    }

    return None


def _get_technique_info_by_name(technique_name: str) -> dict:
    """Get technique information from MITRE ATT&CK bundle by technique name."""
    # Try to get bundle from app state first (already loaded during startup)
    bundle = getattr(app.state, "bundle", None)

    # If not available, load from cache
    if not bundle:
        from archer.mitre.enterprise import get_stix_data

        url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        bundle = get_stix_data(url)
    if not bundle:
        return None

    # Search for technique in bundle by name
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern" and obj.get("name") == technique_name:
            # Extract tactic
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                tactic_name = phase.get("phase_name", "").replace("-", " ").title()
                tactics.append(tactic_name)

            # Get technique ID
            technique_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            return {
                "tid": technique_id,
                "name": obj.get("name", technique_name),
                "tactic": tactics[0] if tactics else "Unknown",
                "tactics": tactics,
                "description": obj.get("description", ""),
                "software_used": [],
                "platforms": obj.get("x_mitre_platforms", ["windows"]),
            }

    return None


# =============================================================================
# Results Page and Download API Routes
# =============================================================================

from fastapi.responses import FileResponse, StreamingResponse
import glob
import zipfile
import io
from datetime import timedelta


def _run_correlations(correlations, run_only):
    """Correlations between files the run produced; all of them when run_only is None."""
    if run_only is None:
        return correlations
    return [c for c in correlations
            if all(os.path.basename(p) in run_only for p in _correlation_paths(c))]


def _correlation_paths(corr):
    """A correlation's detection files: a, then b (a list for a chain)."""
    b = corr.get("b")
    return [p for p in [corr.get("a")] + (b if isinstance(b, list) else [b]) if p]



def _latest_run_record(group_name: str):
    from archer.build.run_files import latest_run

    return latest_run(group_name)


def _is_attack_group(group_name: str) -> bool:
    bundle = getattr(app.state, "bundle", None)
    try:
        return bool(bundle) and check_group_in_mitre(bundle, group_name) == "Y"
    except Exception:
        return False


def _assessment(doc: dict) -> dict:
    """Quality grade and false-positive risk for a detection (archer.validation.quality, #33)."""
    if not doc.get("query"):
        return {}
    try:
        from archer.validation.quality import assess

        return assess(doc)
    except Exception as e:
        print(f"⚠️  Couldn't assess {doc.get('name')}: {e}")
        return {}


@app.get("/results", response_class=HTMLResponse)
def results_page(request: Request, group_name: str, run: str = "", archer_session: Optional[str] = Cookie(None)):
    """
    Render the results dashboard showing generated detections, correlations, and attack flows.

    run=latest limits the detections to the files the group's latest run produced;
    without it, every detection tagged for the group is shown.
    """
    # Check if user is logged in (but don't require it)
    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()

    safe_group = sanitize_group_name(group_name)
    run_view = None
    run_only = None  # basenames of the latest run's files, when showing only that run
    all_yaml_files = []

    # Collect detection files by vendor
    generate_dir = GENERATE_DIR
    detection_files = {}
    vendor_icons = {
        "splunk": "🔍",
        "mde": "🛡️",
        "microsoft": "🛡️",
        "elastic": "🔎",
        "googlesecops": "🔎",
    }

    vendor_display_names = {
        "splunk": "Splunk",
        "mde": "Defender XDR",
        "microsoft": "Defender XDR",
        "elastic": "Elastic",
        "googlesecops": "Google SecOps",
    }

    from .visualization.navigator import legacy as legacy_lookup

    legacy_techniques = legacy_lookup(getattr(request.app.state, "bundle", None))
    if os.path.exists(generate_dir):
        yaml_files = all_yaml_files = group_yaml_files(group_name, generate_dir)

        # Group YAMLs accumulate across runs: offer the latest run on its own
        from archer.build.run_files import latest_run

        latest = latest_run(group_name)
        in_run = set((latest or {}).get("files") or [])
        run_files_now = [f for f in yaml_files if os.path.basename(f) in in_run]
        if run_files_now and len(run_files_now) < len(yaml_files):
            completed = (latest or {}).get("completed_at")
            run_view = {
                "active": run == "latest",
                "run_count": len(run_files_now),
                "all_count": len(yaml_files),
                "completed": datetime.fromtimestamp(completed).strftime("%d %b %Y %H:%M") if completed else "",
            }
            if run == "latest":
                yaml_files = run_files_now
                run_only = {os.path.basename(f) for f in run_files_now}

        for yaml_file in yaml_files:
            filename = os.path.basename(yaml_file)

            # OPTIMIZATION: Read file content and parse YAML only once
            try:
                with open(yaml_file, "r") as f:
                    file_content = f.read()
            except:
                continue  # Skip unreadable files

            yaml_data = load_yaml_file(yaml_file)
            if not yaml_data:
                continue  # Skip invalid YAML files

            # Determine vendor from YAML connectorId field (more reliable than filename)
            vendor = None
            # Sentinel-style files nest it: requiredDataConnectors: [{connectorId: ...}]
            connector_value = yaml_data.get("connectorId", "") or " ".join(
                str(c.get("connectorId", "")) for c in yaml_data.get("requiredDataConnectors") or []
                if isinstance(c, dict)
            )
            if connector_value:
                if "MicrosoftThreatProtection" in connector_value:
                    vendor = "mde"
                elif "Splunk" in connector_value:
                    vendor = "splunk"
                elif "GoogleSecOps" in connector_value:
                    vendor = "googlesecops"
                elif "Elastic" in connector_value:
                    vendor = "elastic"

            # Fallback to filename pattern if connectorId not found
            if not vendor:
                if filename.startswith("Device") or "_Device" in filename:
                    vendor = "mde"
                elif filename.endswith("_prod.yaml"):
                    vendor = "splunk"
                else:
                    # Fallback: check for vendor keywords
                    for v in vendor_icons.keys():
                        if f"_{v}_" in filename.lower() or f"_{v}." in filename.lower():
                            vendor = v
                            break

            if not vendor:
                vendor = "splunk"  # Default to Splunk instead of unknown

            if vendor not in detection_files:
                detection_files[vendor] = []

            # Extract technique and title from filename
            # Format: example_index.yaml or T1234_DeviceEvents.yaml
            parts = filename.replace(".yaml", "").split("_")

            # First part is always the technique (T1234)
            technique = parts[0] if parts else "Unknown"

            # For title, use everything after technique, cleaned up
            if len(parts) > 1:
                # Remove technique from parts
                title_parts = parts[1:]
                # Remove 'prod' if it's the last part
                if title_parts and title_parts[-1].lower() == "prod":
                    title_parts = title_parts[:-1]
                # Join and clean up
                raw_title = " ".join(title_parts).replace("_", " ").lower()

                # Apply mapping using the global constant
                title = DATA_SOURCE_DISPLAY_NAMES.get(raw_title, raw_title.title())
            else:
                title = filename

            # Extract description from YAML data (already parsed)
            description = yaml_data.get("description", "")
            if description:
                # Format description - replace "; " with newlines
                formatted_desc = description.replace("; ", "\n")
                # Limit total length
                if len(formatted_desc) > 300:
                    formatted_desc = formatted_desc[:300] + "..."
                description = formatted_desc
            else:
                description = ""

            # IMPORTANT: Read technique name from YAML file's "name:" field, NOT from filename
            # Filenames are filesystem-safe (no spaces/slashes) but YAML has the correct MITRE ATT&CK name
            yaml_technique_name = yaml_data.get("name", "")

            # Get technique name from ATT&CK if available (only for actual technique IDs like T1234)
            technique_name = ""
            technique_upper = technique.upper()
            if technique_upper.startswith("T") and hasattr(
                request.app.state, "technique_descriptions"
            ):
                try:
                    tech_desc = request.app.state.technique_descriptions.get(technique_upper, {})
                    technique_name = tech_desc.get("name", "")
                except:
                    pass

            # Format technique display as "T1234 - Technique Name" or just the tactic name
            if technique_name:
                technique_display = f"{technique_upper} - {technique_name}"
            elif yaml_technique_name:
                # Use the technique name from YAML file (preserves MITRE ATT&CK formatting)
                technique_display = yaml_technique_name
            else:
                # Check if it's an actual technique ID (T followed by digits) vs a technique name
                import re

                is_technique_id = bool(re.match(r"^T\d{4}", technique_upper))

                if is_technique_id:
                    # It's a technique ID like T1234 without a name - display as-is
                    technique_display = technique_upper
                else:
                    # Format CamelCase technique names with spaces (including all-caps like TRUSTMODIFICATION)
                    technique_display = format_technique_name(technique)

            # Create both HTML and plain text versions of the description
            desc_text = description or f"Detection rule for {technique}"
            desc_html = markdown_links_to_html(desc_text)
            desc_plain = markdown_links_to_plain(desc_text)

            # Extract indicators from YAML indicators section or query (use pre-parsed data)
            indicators = get_indicators_from_yaml(yaml_file, yaml_data=yaml_data)

            # Check for OSINT enrichment (use pre-read content)
            is_osint_enriched, osint_data = check_osint_enriched(
                yaml_file, file_content=file_content
            )

            # Debug: Log what we're passing to template
            if is_osint_enriched or osint_data:
                print(f"   is_osint_enriched: {is_osint_enriched}")
                print(f"   osint_data present: {bool(osint_data)}")

            # Extract the query and tactics from YAML for preview (use already-loaded yaml_data)
            query_text = yaml_data.get("query", "")
            tactics_list = yaml_data.get("tactics") or []
            # Get primary tactic (first in list)
            primary_tactic = tactics_list[0] if tactics_list else "Unknown"

            # Calculate detection likelihood score (0-100)
            detection_likelihood = calculate_detection_likelihood(
                indicators=indicators, query=query_text, technique=technique, yaml_data=yaml_data
            )

            # Check if reference queries were used
            reference_used = yaml_data.get("reference_used", False)
            reference_sources = yaml_data.get("reference_sources", [])

            # Validate query syntax matches vendor and uses valid tables/indexes
            query_validation = validate_query_syntax(query_text, vendor)
            is_query_valid = query_validation.get("is_valid", True)
            query_warnings = query_validation.get("warnings", [])

            # Skip invalid queries (wrong language or invalid tables)
            if not is_query_valid:
                print(f"   Skipping invalid query in {filename}: {', '.join(query_warnings)}")
                continue

            detection_files[vendor].append(
                {
                    "file": filename,
                    "title": title,
                    "technique": technique.upper(),
                    "technique_display": technique_display,
                    "description": desc_text,
                    "description_html": desc_html,
                    "description_plain": desc_plain,
                    "indicators": indicators,
                    "needs_review": bool(osint_data)
                    and not is_osint_enriched,  # True if OSINT comparison found results but didn't integrate them
                    "osint_enriched": is_osint_enriched,  # OSINT enhanced flag (purple badge) - only true if enhancement checkbox was enabled
                    "osint_data": osint_data,  # OSINT comparison data (for Show Details button) - included if OSINT comparison ran
                    "query": query_text,  # Add query for preview
                    "tactic": primary_tactic,  # Primary tactic for color coding
                    "tactics": tactics_list,  # All tactics
                    "detection_likelihood": detection_likelihood,  # Likelihood score (0-100)
                    **_assessment(yaml_data),  # quality grade and false-positive risk (#33)
                    "reference_used": reference_used,  # Reference query flag (green badge)
                    "reference_sources": reference_sources,  # List of reference sources used
                    "technique_id": str(yaml_data.get("technique_id") or ""),
                    "attack_override": yaml_data.get("attack_override"),  # ATT&CK mapping changed by hand
                    "attack_mapping_history": yaml_data.get("attack_mapping_history") or [],
                    "rule_name": attack_rule_name(query_text),  # SecOps rule, renamable with the mapping
                    # Revoked/deprecated in ATT&CK since the detection was built: tagged, upgradable
                    "legacy": legacy_techniques.get(str(yaml_data.get("technique_id") or "")),
                    # Data sources this detection needs — used to flag it if the estate doesn't ingest them (#12)
                    "required_data_connectors": yaml_data.get("requiredDataConnectors") or [],
                }
            )

    # Build vendor list for template with grouping
    # Group detections by technique + description (same technique + same IOCs = group together)
    detections = []
    total_detections = 0

    # Per-tenant availability (#12): load once, flag detections needing an un-ingested data source
    from archer.build.availability import load as _load_avail, missing_sources as _missing_sources
    _avail_cfg = _load_avail()

    for vendor, files in detection_files.items():
        # Group files by technique + description for display
        grouped = {}
        for file_data in files:
            key = (file_data["technique"], file_data["description"])
            if key not in grouped:
                grouped[key] = {
                    "required_data_connectors": [],
                    "technique": file_data["technique"],
                    "technique_display": file_data.get("technique_display", file_data["technique"]),
                    "titles": [],
                    "description": file_data["description"],
                    "description_html": file_data.get("description_html", file_data["description"]),
                    "description_plain": file_data.get(
                        "description_plain", file_data["description"]
                    ),
                    "indicators": file_data.get("indicators", []),
                    "needs_review": file_data.get("needs_review", False),
                    "osint_enriched": file_data.get("osint_enriched", False),
                    "osint_data": file_data.get("osint_data", {}),
                    "tactic": file_data.get("tactic", "Unknown"),
                    "tactics": file_data.get("tactics", []),
                    "detection_likelihood": file_data.get("detection_likelihood", 50),
                    "quality": file_data.get("quality"),
                    "fp_risk": file_data.get("fp_risk"),
                    "cost": file_data.get("cost"),
                    "queries": [],  # Store all queries for this group
                    "files": [],
                    "technique_id": file_data.get("technique_id", ""),
                    "attack_override": None,
                    "attack_mapping_history": [],
                    "rule_name": file_data.get("rule_name"),
                    "legacy": file_data.get("legacy"),
                }
            else:
                # A card is as good as its weakest query: lowest quality, highest false-positive risk
                q, r = file_data.get("quality"), file_data.get("fp_risk")
                if q and (not grouped[key]["quality"] or q["score"] < grouped[key]["quality"]["score"]):
                    grouped[key]["quality"] = q
                if r and (not grouped[key]["fp_risk"] or r["score"] > grouped[key]["fp_risk"]["score"]):
                    grouped[key]["fp_risk"] = r
                c = file_data.get("cost")
                if c and (not grouped[key]["cost"] or c["score"] > grouped[key]["cost"]["score"]):
                    grouped[key]["cost"] = c
                # Merge indicators from multiple detections in the same group
                existing_indicators = set(grouped[key]["indicators"])
                new_indicators = file_data.get("indicators", [])
                for ind in new_indicators:
                    if ind not in existing_indicators:
                        grouped[key]["indicators"].append(ind)
                        existing_indicators.add(ind)
                # Preserve OSINT enrichment if any detection in the group is enriched
                if file_data.get("osint_enriched"):
                    grouped[key]["osint_enriched"] = True
                    # Merge OSINT data
                    if file_data.get("osint_data"):
                        grouped[key]["osint_data"].update(file_data["osint_data"])
            grouped[key]["titles"].append(file_data["title"])
            grouped[key]["files"].append(file_data["file"])
            for _conn in file_data.get("required_data_connectors") or []:
                if _conn not in grouped[key]["required_data_connectors"]:
                    grouped[key]["required_data_connectors"].append(_conn)
            if file_data.get("attack_override") and not grouped[key]["attack_override"]:
                grouped[key]["attack_override"] = file_data["attack_override"]
            if len(file_data.get("attack_mapping_history") or []) > len(grouped[key]["attack_mapping_history"]):
                grouped[key]["attack_mapping_history"] = file_data["attack_mapping_history"]
            # Add query if it exists and isn't already in the list
            query_text = file_data.get("query", "")
            if query_text and query_text not in grouped[key]["queries"]:
                grouped[key]["queries"].append(query_text)
            total_detections += 1  # Count every detection individually

        # Convert grouped data to list format for display
        detection_list = []
        for (technique, description), data in sorted(grouped.items(), key=lambda x: x[0][0]):
            # Sort titles alphabetically and join with commas
            sorted_titles = sorted(data["titles"])
            combined_title = ", ".join(sorted_titles)
            is_osint = data.get("osint_enriched", False)
            osint_data = data.get("osint_data", {})
            has_indicators = len(data.get("indicators", [])) > 0
            detection_list.append(
                {
                    "technique": data["technique_display"],  # Use full display name
                    "title": combined_title,
                    "description": description,
                    "description_html": data.get("description_html", description),
                    "description_plain": data.get("description_plain", description),
                    "indicators": data.get("indicators", []),
                    "needs_review": bool(osint_data)
                    and not is_osint,  # True if OSINT comparison found results but didn't integrate them
                    "osint_enriched": is_osint,  # Purple badge
                    "osint_data": osint_data,
                    "queries": data.get("queries", []),  # Pass queries for preview
                    "tactic": data.get("tactic", "Unknown"),  # Primary tactic
                    "tactics": data.get("tactics", []),  # All tactics
                    "detection_likelihood": data.get(
                        "detection_likelihood", 50
                    ),  # Likelihood score
                    "quality": data.get("quality"),
                    "fp_risk": data.get("fp_risk"),
                    "cost": data.get("cost"),
                    "files": data["files"],
                    "technique_id": data["technique_id"],
                    "attack_override": data["attack_override"],
                    "attack_mapping_history": data["attack_mapping_history"],
                    "rule_name": data["rule_name"],
                    "legacy": data["legacy"],
                    # Data sources the estate doesn't ingest, so this detection can't fire (#12)
                    "unavailable_sources": sorted({
                        m["dataType"] for m in _missing_sources(
                            {"requiredDataConnectors": data.get("required_data_connectors") or []}, _avail_cfg)
                    }) if _avail_cfg else [],
                }
            )

        # Keep ungrouped file list for saving to library (with all fields)
        ungrouped_files = []
        for file_data in files:
            ungrouped_files.append(
                {
                    "technique": file_data.get("technique", ""),
                    "technique_display": file_data.get(
                        "technique_display", file_data.get("technique", "")
                    ),
                    "title": file_data["title"],
                    "description": file_data.get("description", ""),
                    "description_html": file_data.get(
                        "description_html", file_data.get("description", "")
                    ),
                    "description_plain": file_data.get(
                        "description_plain", file_data.get("description", "")
                    ),
                    "indicators": file_data.get("indicators", []),
                    "query": file_data.get("query", ""),
                    "tactic": file_data.get("tactic", "Unknown"),
                    "tactics": file_data.get("tactics", []),
                    "osint_enriched": file_data.get("osint_enriched", False),
                    "osint_data": file_data.get("osint_data", {}),
                    "detection_likelihood": file_data.get("detection_likelihood", 50),
                    "needs_review": file_data.get("needs_review", False),
                    # Not "technique_id": the Library tells a results-page save by its absence
                    "attack_id": file_data.get("technique_id", ""),
                    "attack_override": file_data.get("attack_override"),
                    "attack_mapping_history": file_data.get("attack_mapping_history") or [],
                }
            )

        detections.append(
            {
                "name": vendor,
                "display_name": vendor_display_names.get(vendor, vendor.title()),
                "icon": vendor_icons.get(vendor, "📋"),
                "count": len(files),  # Original count for display
                "detections": detection_list,  # Grouped for display
                "all_files": ungrouped_files,  # Ungrouped for saving
            }
        )

    # Google SecOps and Elastic are now fully supported - no longer "Coming Soon"
    # They will appear automatically when YAML files are generated for them

    # Sort vendors: Google SecOps, MDE, Splunk, Elastic, then others
    vendor_order = {"googlesecops": 0, "mde": 1, "microsoft": 1, "splunk": 2, "elastic": 3}
    detections.sort(key=lambda x: (vendor_order.get(x["name"], 99), x["name"]))

    # Load correlations
    correlations = []
    # Try both sanitized name (with underscores) and original name (with spaces)
    correlation_file = os.path.join(CORRELATE_DIR, f"{safe_group}.json")
    if not os.path.exists(correlation_file):
        # Try with spaces instead of underscores
        correlation_file = os.path.join(CORRELATE_DIR, f"{group_name}.json")

    if os.path.exists(correlation_file):
        try:
            import re

            with open(correlation_file, "r") as f:
                corr_data = json.load(f)
                # The file uses "vendor_correlations" not "correlations"
                vendor_corrs = _run_correlations(corr_data.get("vendor_correlations", []), run_only)

                # Shown as the engine left them: ranked and grouped already, one file each
                # (archer.build.correlation_files). Merging again here showed one SecOps
                # correlation per first technique and dropped the rest, and gave Defender XDR
                # cards a query no file held
                pre_merge_count = post_merge_count = len(vendor_corrs)

                # Update progress with post-merge correlation count
                from archer.build.progress import write_progress

                write_progress(
                    group_name,
                    {
                        "correlation_count_pre_merge": pre_merge_count,
                        "correlation_count_post_merge": post_merge_count,
                    },
                )

                # Extract technique and data source information from filenames
                for idx, corr in enumerate(vendor_corrs):
                    vendor = corr.get("vendor", "unknown")
                    file_a = corr.get("a", "")
                    file_b = corr.get("b", "")
                    relevance_score = corr.get("relevance_score", 0.0)
                    combined_query = corr.get("combined_query", "")
                    # The correlation's own file (archer.build.correlation_files) wins: it may be edited
                    if corr.get("file"):
                        from archer.build.correlation_files import read_query

                        combined_query = read_query(os.path.join(CORRELATE_DIR, corr["file"])) or combined_query
                    is_merged = corr.get("merged", False)

                    # Parse filename format: "example_index.yaml"
                    # Example: "Multi-FactorAuthentication_edr_events.yaml"
                    techniques = []
                    has_needs_review = False
                    severities = []
                    tactics_set = set()
                    time_window = "1h"  # Default

                    total_indicators = 0  # Track total indicators across both detections
                    part_docs = []  # The detections as they are now (archer.build.correlation_osint)

                    # Get techniques_involved for later use in building the techniques list
                    techniques_involved = corr.get("techniques_involved", [])

                    # Handle file_b being either a string or a list (for merged correlations)
                    files_to_process = [file_a]
                    if isinstance(file_b, list):
                        files_to_process.extend(file_b)
                    elif file_b:
                        files_to_process.append(file_b)

                    for file_path in files_to_process:
                        if file_path:
                            # Check if file exists before processing
                            full_path = os.path.join(GENERATE_DIR, os.path.basename(file_path))
                            if not os.path.exists(full_path):
                                print(f"Skipping correlation {idx+1} - file not found: {file_path}")
                                break  # Skip this entire correlation if either file is missing

                            filename = os.path.basename(file_path).replace(".yaml", "")
                            parts = filename.split("_")

                            if len(parts) >= 2:
                                # First part is the technique ID (e.g., T1078)
                                technique_id = parts[0].replace("-", " ")

                                # Check if this file has indicators
                                indicators = get_indicators_from_yaml(full_path)
                                total_indicators += len(indicators)

                                # Extract metadata from YAML file including actual technique name and data source
                                yaml_data = load_yaml_file(full_path)
                                if yaml_data:
                                    part_docs.append(yaml_data)
                                technique_name = technique_id  # Default to ID if name not found
                                data_source = "Unknown"  # Default
                                friendly_source = "Unknown"

                                if yaml_data:
                                    # Get actual technique name from YAML and format it with spaces
                                    raw_name = yaml_data.get("name", technique_id)
                                    technique_name = format_technique_name(raw_name)

                                    # Extract data source from YAML requiredDataConnectors or dataTypes
                                    data_connectors = yaml_data.get("requiredDataConnectors", [])
                                    if data_connectors and len(data_connectors) > 0:
                                        # Get the first data type from first connector
                                        first_connector = data_connectors[0]
                                        data_types = first_connector.get("dataTypes", [])
                                        if data_types and len(data_types) > 0:
                                            data_source = data_types[0]
                                            # Map to friendly name
                                            friendly_source = DATA_SOURCE_DISPLAY_NAMES.get(
                                                data_source.lower(), data_source
                                            )

                                    # Get severity
                                    severity = yaml_data.get("severity", "Medium")
                                    severities.append(severity)

                                    # Get tactics
                                    tactics = yaml_data.get("tactics") or []
                                    primary_tactic = "Unknown"
                                    if isinstance(tactics, list):
                                        tactics_set.update(tactics)
                                        # Use first tactic as primary for coloring
                                        primary_tactic = tactics[0] if tactics else "Unknown"

                                    # Extract time window from combined query if available
                                    # (Splunk transaction maxspan, YARA-L match window)
                                    match = re.search(r"maxspan=(\d+[hmd])|\$\w+ over (\d+[smhd])", combined_query)
                                    if match:
                                        time_window = match.group(1) or match.group(2)

                                techniques.append(
                                    {
                                        "id": technique_id,
                                        "name": technique_name,
                                        "source": friendly_source,
                                        "tactic": primary_tactic,
                                        "query": yaml_data.get("query", "") if yaml_data else "",
                                        "file": full_path,
                                        "attack_id": str((yaml_data or {}).get("technique_id") or ""),
                                        "attack_override": (yaml_data or {}).get("attack_override"),
                                    }
                                )

                    if len(techniques) >= 2:
                        # Skip correlations with 0 total indicators across both detections
                        # This indicates the correlation cannot be effectively used as both detections
                        # require manual review and have no IOCs/patterns to search for
                        if total_indicators == 0:
                            print(
                                f"Skipping correlation {idx+1} - 0 total indicators across both detections"
                            )
                            continue

                        # Needs Review badge should NOT be shown if there are indicators
                        # The correlation is usable as long as there are some indicators to search for
                        # (even if one of the detections has 0 indicators, the other can still be correlated)
                        has_needs_review = False

                        # Determine highest severity
                        highest_severity = "Medium"
                        for sev in severities:
                            if sev in SEVERITY_ORDER:
                                if SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(
                                    highest_severity
                                ):
                                    highest_severity = sev

                        # The vendor field indicates where the query runs (Splunk, MDE, etc.)
                        # This is the query platform, NOT the data sources being queried
                        # Map vendor to display name (splunk -> Splunk, mde -> MDE, etc.)
                        vendor_display = DATA_SOURCE_DISPLAY_NAMES.get(
                            vendor.lower(), vendor.title()
                        )

                        # Extract tables (MDE) or indexes (Splunk) from the combined query
                        tables_indexes = extract_tables_indexes(combined_query, vendor)

                        # Build technique-to-tactic mapping and formatted names for techniques_involved
                        technique_tactic_map = {}
                        techniques_involved_formatted = []
                        techniques_by_tactic = {}  # Group techniques by tactic
                        # techniques_involved already loaded above at line 4361

                        # Map each technique to its primary tactic and get formatted name
                        # Build attack flow from ALL techniques (including merged ones)
                        seen_technique_keys = set()
                        for tech_name in techniques_involved:
                            # Look for YAML file matching this technique name
                            # Normalize technique name to match filename format (remove spaces)
                            filename_pattern = tech_name.replace(" ", "").replace("/", "")
                            pattern = os.path.join(GENERATE_DIR, f"{filename_pattern}_*.yaml")
                            matching_files = glob.glob(pattern)
                            yaml_data = load_yaml_file(matching_files[0]) if matching_files else None

                            if yaml_data:
                                formatted_name = format_technique_name(yaml_data.get("name", tech_name))
                                tech_tactics = yaml_data.get("tactics") or []
                            else:
                                # Fallback: format the filename-based name
                                formatted_name = tech_name.replace("-", " ")
                                tech_tactics = ["Unknown"]

                            # Each technique once: techniques_involved can name one twice
                            # ('Multi-Factor Authentication', 'Multi-FactorAuthentication')
                            key = technique_key(formatted_name)
                            if key in seen_technique_keys:
                                continue
                            seen_technique_keys.add(key)

                            # Use first tactic as primary
                            technique_tactic_map[formatted_name] = tech_tactics[0] if tech_tactics else "Unknown"
                            techniques_involved_formatted.append(formatted_name)
                            # Group by ALL tactics (not just primary) for attack flow visualization
                            for tactic in tech_tactics:
                                techniques_by_tactic.setdefault(tactic, []).append(formatted_name)

                        # Sort techniques_involved_formatted by MITRE ATT&CK tactic order
                        # Sort by PRIMARY tactic to match how techniques are highlighted
                        tactic_order = [
                            "Initial Access",
                            "Execution",
                            "Persistence",
                            "Privilege Escalation",
                            "Defense Evasion",
                            "Credential Access",
                            "Discovery",
                            "Lateral Movement",
                            "Collection",
                            "Command and Control",
                            "Exfiltration",
                            "Impact",
                        ]

                        def get_technique_sort_key(tech_name):
                            # Use the primary tactic from technique_tactic_map
                            tactic = technique_tactic_map.get(tech_name, "Unknown")
                            try:
                                tactic_index = tactic_order.index(tactic)
                            except ValueError:
                                tactic_index = 999  # Unknown tactics go last

                            # Return tuple: (tactic_index, technique_name_alphabetically)
                            # This sorts by tactic first, then alphabetically within same tactic
                            return (tactic_index, tech_name.lower())

                        techniques_involved_formatted.sort(key=get_technique_sort_key)

                        # Identify primary techniques for highlighting
                        # Goal: Highlight 2-3 unique primary tactics
                        # Strategy: Keep adding techniques until we have 3 unique tactics
                        primary_technique_names = []
                        primary_tactics = set()

                        for tech_name in techniques_involved_formatted:
                            primary_technique_names.append(tech_name)
                            if tech_name in technique_tactic_map:
                                primary_tactics.add(technique_tactic_map[tech_name])

                            # Stop after we have 3 unique tactics
                            if len(primary_tactics) >= 3:
                                break

                        # Rebuild techniques_by_tactic to only include primary techniques
                        # This ensures attack flow only shows tactics involved in the primary techniques
                        techniques_by_tactic_filtered = {}
                        for tech_name in primary_technique_names:
                            # Look for YAML file to get ALL tactics (not just primary)
                            filename_pattern = tech_name.replace(" ", "").replace("/", "")
                            pattern = os.path.join(GENERATE_DIR, f"{filename_pattern}_*.yaml")
                            matching_files = glob.glob(pattern)

                            if matching_files:
                                yaml_data = load_yaml_file(matching_files[0])
                                if yaml_data:
                                    tech_tactics = yaml_data.get("tactics", [])
                                    # Add this technique to all its tactics
                                    for tactic in tech_tactics:
                                        if tactic not in techniques_by_tactic_filtered:
                                            techniques_by_tactic_filtered[tactic] = []
                                        if tech_name not in techniques_by_tactic_filtered[tactic]:
                                            techniques_by_tactic_filtered[tactic].append(tech_name)

                        # Replace techniques_by_tactic with filtered version
                        techniques_by_tactic = techniques_by_tactic_filtered

                        # Calculate attack chain length (number of tactics in attack flow order)
                        tactic_order = [
                            "Initial Access",
                            "Execution",
                            "Persistence",
                            "Privilege Escalation",
                            "Defense Evasion",
                            "Credential Access",
                            "Discovery",
                            "Lateral Movement",
                            "Collection",
                            "Command and Control",
                            "Exfiltration",
                            "Impact",
                        ]
                        attack_chain_length = sum(
                            1 for tactic in tactic_order if tactic in techniques_by_tactic
                        )

                        # Rebuild techniques list to match techniques_involved_formatted order and content
                        # This ensures the displayed techniques match what's being used for highlighting
                        techniques_rebuilt = []
                        for formatted_name in techniques_involved_formatted:
                            # Find matching technique in the original techniques list
                            matching_tech = None
                            for tech in techniques:
                                if tech["name"] == formatted_name:
                                    matching_tech = tech
                                    break

                            if matching_tech:
                                # Update the tactic field to use the PRIMARY tactic
                                primary_tactic = technique_tactic_map.get(
                                    formatted_name, matching_tech.get("tactic", "Unknown")
                                )
                                matching_tech_copy = matching_tech.copy()
                                matching_tech_copy["tactic"] = primary_tactic
                                techniques_rebuilt.append(matching_tech_copy)
                            else:
                                # Create a minimal technique entry if not found in original list
                                # This happens when techniques_involved has techniques not in files_to_process
                                primary_tactic = technique_tactic_map.get(formatted_name, "Unknown")
                                techniques_rebuilt.append(
                                    {
                                        "id": formatted_name.replace(" ", "-"),
                                        "name": formatted_name,
                                        "source": vendor_display,
                                        "tactic": primary_tactic,
                                    }
                                )

                        # One technique can span several parts (an MDE detection per table): one badge, every query
                        parts_by_name = {}
                        for tech in techniques:
                            parts_by_name.setdefault(tech["name"], []).append(
                                dict(tech, tactic=technique_tactic_map.get(tech["name"], tech.get("tactic", "Unknown"))))

                        # Use the rebuilt list
                        techniques = techniques_rebuilt

                        individual_queries = [
                            {
                                "technique_name": t["name"],
                                "technique_id": t.get("attack_id") or t["id"],
                                "tactic": t["tactic"],
                                "query": t.get("query", ""),
                                "attack_override": t.get("attack_override"),
                                # Which part, when a technique has several: the table/index in its filename
                                "variant": os.path.basename(t.get("file") or "").rsplit(".", 1)[0].partition("_")[2]
                                if len(parts_by_name[name]) > 1 else "",
                            }
                            for name in techniques_involved_formatted
                            for t in parts_by_name.get(name, [])
                            if t.get("query")
                        ]

                        from archer.build.correlation_osint import inherited, stale_parts

                        osint = inherited(part_docs)
                        correlations.append(
                            {
                                # What the detections' OSINT enrichment brings, and parts rewritten since (#23)
                                "osint_data": {"indicators": {"query_snippets": osint["snippets"]},
                                               "sources": osint["sources"]} if osint["snippets"] or osint["sources"] else None,
                                "osint_enriched": osint["enhanced"],
                                # Its details are fetched when opened (GET /api/osint-details)
                                "osint_files": [os.path.basename(f) for f in files_to_process if f],
                                "known_false_positives": osint["known_false_positives"],
                                "lol_references": osint["lol_references"],
                                "stale_parts": stale_parts(combined_query, part_docs),
                                "techniques": techniques,
                                "flow_file": f"{safe_group}_corr_{idx+1}.html",
                                "vendor": vendor_display,
                                "needs_review": has_needs_review,
                                "relevance_score": int(
                                    relevance_score * 100
                                ),  # Convert to percentage
                                "severity": highest_severity,
                                "time_window": time_window,
                                "tactics": list(tactics_set),
                                "combined_query": combined_query,
                                "query_file": corr.get("file"),
                                "query_edited": bool(corr.get("edited")),
                                "tables_indexes": tables_indexes,  # Add tables/indexes
                                "techniques_involved": techniques_involved_formatted,  # Add formatted technique names
                                "technique_tactic_map": technique_tactic_map,  # Map techniques to their primary tactics
                                "techniques_by_tactic": techniques_by_tactic,  # Group techniques by tactic
                                "attack_chain_length": attack_chain_length,  # Number of tactics in ordered attack flow
                                "is_merged": is_merged,  # Flag indicating if this is a merged correlation
                                # Three techniques on one host, in any order (archer.ai.genai.engine._build_chains)
                                "is_chain": bool(corr.get("chain")),
                                "primary_tactics": list(
                                    primary_tactics
                                ),  # Tactics containing the original correlation pair
                                "individual_queries": individual_queries,  # Per-technique queries for chained display
                            }
                        )
        except Exception as e:
            print(f"Error loading correlations: {e}")
            pass

    # Group correlations by vendor (similar to detections)
    correlations_by_vendor = {}
    for corr in correlations:
        vendor = corr.get("vendor", "Unknown")
        if vendor not in correlations_by_vendor:
            correlations_by_vendor[vendor] = []
        correlations_by_vendor[vendor].append(corr)

    # Convert to list format similar to detections
    grouped_correlations = []
    for vendor, vendor_corrs in correlations_by_vendor.items():
        # Sort correlations within each vendor by:
        # 1. Relevance score (descending)
        # 2. Attack chain length (number of tactics in attack flow progression, descending)
        sorted_corrs = sorted(
            vendor_corrs,
            key=lambda c: (
                -c.get("relevance_score", 0),  # Higher relevance first
                -c.get("attack_chain_length", 0),  # Longer attack chains first (as tiebreaker)
            ),
        )

        grouped_correlations.append(
            {"name": vendor, "count": len(sorted_corrs), "correlations": sorted_corrs}
        )

    # Vendor priority (SecOps first), not volume
    correlation_order = {"Google SecOps": 0, "Defender XDR": 1, "MDE": 1, "Splunk": 2, "Elastic": 3}
    grouped_correlations.sort(key=lambda x: (correlation_order.get(x["name"], 99), -x["count"]))

    # Check if attack flow exists
    attack_flow_file = os.path.join(ATTACK_FLOWS_DIR, f"{safe_group}_complete_flow.html")
    attack_flow_exists = os.path.exists(attack_flow_file)

    # Get unique technique count and tactic count
    technique_set = set()
    tactic_set = set()
    for vendor_data in detections:
        for detection in vendor_data["detections"]:
            technique_set.add(detection["technique"])
            # Add all tactics from this detection
            tactics = detection.get("tactics", [])
            if tactics:
                tactic_set.update(tactics)

    # Kill-chain attack flow: detected techniques, ATT&CK-attributed gaps, correlation edges
    attack_flow = None
    try:
        from archer.visualization.flow_view import attributed_techniques, build_flow_view, current_tactics

        flow_paths = {v: [os.path.join(generate_dir, d["file"]) for d in entries]
                      for v, entries in detection_files.items()}
        raw_correlations = []
        if os.path.exists(correlation_file):
            with open(correlation_file, encoding="utf-8") as fh:
                raw_correlations = _run_correlations(json.load(fh).get("vendor_correlations", []), run_only)
        attributed = attributed_techniques(group_name)
        if run_only is not None:
            # Detected by an earlier run, just not this one: not a gap
            from archer.visualization.flow_view import read_detection

            def _ids(paths):
                return {d["id"] for d in map(read_detection, paths) if d}

            earlier = _ids(all_yaml_files) - _ids(p for ps in flow_paths.values() for p in ps)
            attributed = [t for t in attributed if t["id"] not in earlier]
        bundle = getattr(request.app.state, "bundle", None)
        attack_flow = build_flow_view(
            flow_paths,
            raw_correlations,
            attributed,
            current_tactics(bundle) if bundle is not None else None,
        )
        # Downloadable Attack Flow 2.x bundle; replaces the flat chain the generator writes
        from archer.visualization.flow_view import to_attack_flow_bundle

        attack_flow["stix_file"] = f"{safe_group}_complete_flow.json"
        os.makedirs(ATTACK_FLOWS_DIR, exist_ok=True)
        with open(os.path.join(ATTACK_FLOWS_DIR, attack_flow["stix_file"]), "w", encoding="utf-8") as fh:
            json.dump(to_attack_flow_bundle(attack_flow, group_name), fh, indent=2)
        # The view itself, so an edited flow can be exported (/api/attack-flow/export)
        with open(os.path.join(ATTACK_FLOWS_DIR, f"{safe_group}_flow_view.json"), "w", encoding="utf-8") as fh:
            json.dump({"group_name": group_name, "view": attack_flow}, fh)
    except Exception as e:
        print(f"Attack flow view unavailable: {e}")

    # IOC flow: only when this view includes the run's IOC sweep (no IOCs, no diagram)
    ioc_flow = None
    if any("IOCSweep" in d["file"] for entries in detection_files.values() for d in entries):
        from archer.build.ioc_flow import load_ioc_flow

        ioc_flow = load_ioc_flow(group_name) or None

    # Anatomy workflow: actor, tools, CVEs and services down to its objectives (archer.visualization.anatomy)
    anatomy = None
    try:
        from archer.visualization import anatomy as anatomy_lib
        from archer.visualization.flow_view import read_detection

        view_paths = [os.path.join(generate_dir, d["file"]) for entries in detection_files.values() for d in entries]
        anatomy = anatomy_lib.build(group_name, view_paths, {d["id"] for d in map(read_detection, view_paths) if d})
    except Exception as e:
        print(f"Anatomy workflow unavailable: {e}")

    # Calculate duration (if progress file exists)
    # Progress files are saved with the original group name (with spaces), not sanitized
    duration = 0
    progress_file = os.path.join(PROGRESS_DIR, f"{group_name}.json")
    if os.path.exists(progress_file):
        try:
            with open(progress_file, "r") as f:
                progress_data = json.load(f)
                # Get actual duration in seconds from progress data
                duration = progress_data.get("duration", 0)
        except:
            pass

    # Get MITRE ID if available
    mitre_id = None
    # For CVE groups, skip MITRE check (they won't be in MITRE groups)
    if not safe_group.upper().startswith("CVE-"):
        try:
            from archer.mitre.enterprise import get_stix_data

            bundle = get_stix_data(
                "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
            )
            if check_group_in_mitre(bundle, safe_group):
                # Try to find MITRE ID from STIX data
                mitre_id = safe_group  # Simplified
        except:
            pass

    # Load auto-validation results if they exist
    validation_results = {}
    validation_summary = {"total": 0, "passed": 0, "failed": 0, "avg_f1": 0}
    build_dir = Path("data/build") / safe_group
    validation_file = build_dir / "validation_results.json"
    if validation_file.exists():
        try:
            with open(validation_file, "r") as f:
                validation_results = json.load(f)
            if validation_results:
                validation_summary["total"] = len(validation_results)
                validation_summary["passed"] = sum(1 for v in validation_results.values() if v.get("passed"))
                validation_summary["failed"] = validation_summary["total"] - validation_summary["passed"]
                f1_scores = [v.get("f1_score", 0) for v in validation_results.values()]
                validation_summary["avg_f1"] = sum(f1_scores) / len(f1_scores) if f1_scores else 0
        except Exception as e:
            print(f"Error loading validation results: {e}")

    # Flow edits persist for a logged-in user once the group's results are in their library
    flow_layout = {"logged_in": bool(user), "persist": False, "state": None, "group_name": safe_group}
    if user and attack_flow:
        from archer.visualization.flow_layouts import load_layout, results_in_library

        db = next(get_db())
        try:
            flow_layout["persist"] = results_in_library(db, user.id, safe_group)
            if flow_layout["persist"]:
                flow_layout["state"] = load_layout(db, user.id, safe_group)
        except Exception as e:
            print(f"Flow layout unavailable: {e}")
        finally:
            db.close()

    # Threat briefing, without AI; an AI summary only when someone asks for one
    from archer.build import briefing as briefing_lib

    no_detection = _no_detection(group_name)
    briefing = briefing_lib.build(attack_flow, no_detection)

    # Cross-vendor playbooks (#8): a chain's stages re-expressed across SIEMs, with join keys
    cross_vendor = []
    if os.path.exists(correlation_file):
        try:
            with open(correlation_file, encoding="utf-8") as fh:
                cross_vendor = json.load(fh).get("cross_vendor_correlations", []) or []
        except (OSError, ValueError):
            cross_vendor = []

    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "user": user,
            "group_name": safe_group,
            "flow_layout": flow_layout,
            "mitre_id": mitre_id,
            "total_detections": total_detections,
            "vendor_count": len(detections),
            "correlation_count": len(correlations),
            "technique_count": len(technique_set),
            "tactic_count": len(tactic_set),
            "duration": duration,
            "detections": detections,
            "correlations": grouped_correlations,
            "attack_flow_exists": attack_flow_exists,
            "attack_flow": attack_flow,
            # Vendor keys the user generates for (Profile → SIEM platforms; none chosen means all)
            "profile_vendors": [SIEM_PLATFORMS[s] for s in _user_siems(user)] or list(SIEM_PLATFORMS.values()),
            "ioc_flow": ioc_flow,
            "anatomy": anatomy,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "validation_results": validation_results,
            "validation_summary": validation_summary,
            "run_view": run_view,
            # Detections the last run left alone because their query was edited by hand
            "kept_edited": (_latest_run_record(group_name) or {}).get("kept_edited") or [],
            "stack_warnings": (_latest_run_record(group_name) or {}).get("stack_warnings") or [],
            # Regenerate re-runs a threat group through /generate
            "can_regenerate": _is_attack_group(group_name),
            "no_detection": no_detection,
            "briefing": briefing,
            "briefing_ai": briefing_lib.load_summary(safe_group, briefing),
            "cross_vendor": cross_vendor,
        },
    )


@app.post("/api/briefing/summary")
async def briefing_summary(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Body: {"group_name": ...}. A short AI-written briefing from the run's facts (the same
    briefing the results page shows), with the provider assigned to Ask Archer in the
    profile; saved so the results page shows it until the run changes.
    """
    from archer.build import briefing as briefing_lib
    from archer.chat import _generate, _provider_candidates

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        group = sanitize_group_name(str((await request.json()).get("group_name") or ""))
        try:
            with open(os.path.join(ATTACK_FLOWS_DIR, f"{group}_flow_view.json"), encoding="utf-8") as fh:
                flow = json.load(fh).get("view")
        except (OSError, ValueError):
            return JSONResponse({"error": "Open the run's results first: the briefing comes from its attack flow"},
                                status_code=404)
        facts = briefing_lib.build(flow, _no_detection(group))
        if not facts:
            return JSONResponse({"error": "This run has no techniques to brief on"}, status_code=404)
        endpoints = getattr(request.app.state, "local_llm_endpoints", None) or []
        candidates, assigned = _provider_candidates(user.id, db, endpoints)
        if not candidates:
            return JSONResponse({"error": "No AI provider: add one under Profile → API Keys"}, status_code=503)
        try:
            reply, provider = _generate(candidates, assigned, "Threat briefing summary",
                                        prompt=briefing_lib.prompt(group, facts), temperature=0.3, max_tokens=600)
        except HTTPException as e:
            return JSONResponse({"error": str(e.detail)}, status_code=e.status_code)
        text = (getattr(reply, "content", reply) or "").strip()
        if not text:
            return JSONResponse({"error": f"{provider} returned nothing"}, status_code=502)
        saved = briefing_lib.save_summary(group, facts, text, provider)
        return {"text": saved["text"], "provider": provider}
    finally:
        db.close()


def _no_detection(group_name: str) -> list:
    """The latest run's techniques that produced nothing, each with why (technique_yield.REASONS)."""
    from archer.build.run_files import latest_run
    from archer.build.technique_yield import describe

    return [{**m, "text": describe(m.get("reason", ""), m.get("technique", "")),
             "url": "https://attack.mitre.org/techniques/" + m.get("technique", "").replace(".", "/") + "/"}
            for m in (latest_run(group_name) or {}).get("no_detection") or []]


@app.post("/api/detections/splunk/generate")
async def generate_splunk_detections(request: Request):
    """
    Trigger ATT&CK-aligned Splunk detection query generation.

    Workflow
    --------
    1. Checks whether the Archer-side MITRESaw cache (data/mitre_procedures.csv)
       is older than 7 days.
         - Fresh (≤7 days): runs  MITRESaw.py -d -E -q        (-DEC)
         - Stale (>7 days): runs  MITRESaw.py -d -E -F -q     (-DECF)
    2. Reads unique MITRE ATT&CK techniques from the updated CSV.
    3. For each technique, calls the configured LLM (Claude → GPT → Ollama)
       using bespoke/prompts/ master and template prompts.
       Queries are restricted to the Splunk indexes defined in
       bespoke/mappings/schemas/schemaSplunk.json.
    4. Saves one JSON detection file per technique to data/detections/splunk/.

    Request body (JSON, all optional)
    ----------------------------------
    {
        "force_refresh": false,   // true to force MITRESaw re-run regardless of cache age
        "group": null,            // ATT&CK group name or ID to limit scope (e.g. "APT29")
        "skip_existing": true     // false to regenerate files that already exist
    }

    Response
    --------
    {
        "success": true,
        "cache_refreshed": bool,
        "total_techniques": int,
        "generated": int,
        "skipped": int,
        "failed": int,
        "files": ["data/detections/splunk/T1059-001_command_scripting_interpreter.json", ...]
    }
    """
    from archer.detection.splunk import run_splunk_detection_generation

    try:
        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        force_refresh = bool(body.get("force_refresh", False))
        group_filter = body.get("group") or None
        skip_existing = bool(body.get("skip_existing", True))

        local_llm_state = getattr(request.app.state, "local_llm_detected", {})

        llm = None
        llm_type = "cloud"
        try:
            from archer.chat import _get_llm_provider_anonymous
            llm_obj, provider_name = _get_llm_provider_anonymous(local_llm_state)
            if llm_obj is not None:
                llm = llm_obj
                llm_type = "local" if "ollama" in provider_name.lower() else "cloud"
                logger.info("Splunk detection generation using LLM: %s", provider_name)
        except Exception as exc:
            logger.warning("Could not resolve LLM provider for detection generation: %s", exc)

        result = run_splunk_detection_generation(
            llm=llm,
            llm_type=llm_type,
            force_refresh=force_refresh,
            group_filter=group_filter,
            skip_existing=skip_existing,
        )

        return JSONResponse({"success": True, **result})

    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse({"success": False, "error": str(exc)}, status_code=500)


@app.get("/api/detections/splunk")
def list_splunk_detections():
    """
    List all generated Splunk detection files.

    Returns a list of objects with technique_id, technique_name, filename,
    query_count, and tactic for each saved detection.
    """
    detections_dir = paths.DATA / "detections" / "splunk"
    if not detections_dir.exists():
        return JSONResponse({"detections": [], "total": 0})

    detections = []
    for path in sorted(detections_dir.glob("*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                obj = json.load(f)
            detections.append({
                "filename": path.name,
                "technique_id": obj.get("technique_id", ""),
                "technique_name": obj.get("technique_name", ""),
                "full_technique_name": obj.get("full_technique_name", ""),
                "tactic": obj.get("tactic", ""),
                "query_count": len(obj.get("queries", [])),
                "indexes": [q.get("source_index") for q in obj.get("queries", [])],
            })
        except Exception:
            continue

    return JSONResponse({"detections": detections, "total": len(detections)})


@app.get("/api/detections/splunk/status")
def splunk_detection_status():
    """
    Return whether the procedures CSV matches the ATT&CK bundle, and detection coverage.
    """
    from archer.mitre.procedures import is_cache_stale, built_version, bundle_version, _DEFAULT_CSV

    cache_exists = _DEFAULT_CSV.exists()

    detections_dir = paths.DATA / "detections" / "splunk"
    detection_count = len(list(detections_dir.glob("*.json"))) if detections_dir.exists() else 0

    return JSONResponse({
        "cache_exists": cache_exists,
        "cache_stale": is_cache_stale(),
        "built_from_attack": built_version() or None,
        "attack_bundle": bundle_version() or None,
        "splunk_detections_generated": detection_count,
        "detections_dir": str(detections_dir),
    })


@app.get("/api/detection/{filename}")
def get_detection_content(filename: str):
    """
    Return the content of a detection YAML file.
    """
    safe_filename = sanitize_filename(filename)
    file_path = os.path.join(GENERATE_DIR, safe_filename)

    if not os.path.exists(file_path):
        return {"error": "File not found"}, 404

    try:
        with open(file_path, "r") as f:
            content = f.read()
        return content
    except Exception as e:
        return {"error": str(e)}, 500


@app.get("/api/download/detection/{filename}")
def download_detection(filename: str):
    """
    Download a single detection YAML file.
    """
    safe_filename = sanitize_filename(filename)
    file_path = os.path.join(GENERATE_DIR, safe_filename)

    if not os.path.exists(file_path):
        return {"error": "File not found"}, 404

    return FileResponse(file_path, media_type="application/x-yaml", filename=safe_filename)


@app.get("/api/download/all/{group_name}")
def download_all_detections(group_name: str):
    """
    Download all detections, correlations, and attack flows for a group as a ZIP file.
    """
    return _group_zip(group_name)


@app.post("/api/download/all/{group_name}")
def download_selected_detections(group_name: str, detections: List[str] = Form([]),
                                 correlations: List[str] = Form([])):
    """
    The same ZIP with only the detections and correlations ticked on the results page:
    detection file names and correlation files (as their index records them).
    """
    return _group_zip(group_name, {os.path.basename(d) for d in detections},
                      {os.path.basename(c) for c in correlations})


def _group_zip(group_name: str, detections: Optional[set] = None, correlations: Optional[set] = None):
    """None means every one; a set keeps only those files (and the index's matching entries)."""
    print(f"\n{'='*60}")
    print(f"DOWNLOAD ALL REQUEST RECEIVED")
    print(f"Group name: {group_name}")
    print(f"{'='*60}\n")

    safe_group = sanitize_group_name(group_name)
    formatted_tag = f"{group_name} (Group)"

    # Create in-memory ZIP file
    zip_buffer = io.BytesIO()
    files_added = 0

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        # Add detection YAMLs - find all YAML files containing the group tag
        generate_dir = GENERATE_DIR
        if os.path.exists(generate_dir):
            for yaml_file in glob.glob(os.path.join(generate_dir, "*.yaml")):
                try:
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        content = f.read()
                        # Check if this YAML file contains the group tag
                        if formatted_tag in content:
                            filename = os.path.basename(yaml_file)
                            if detections is not None and filename not in detections:
                                continue
                            zip_file.write(yaml_file, f"detections/{filename}")
                            files_added += 1
                            logger.info(f"Added detection: {filename}")
                except Exception as e:
                    logger.error(f"Error reading YAML file {yaml_file}: {e}")
                    continue

        # Add correlation JSON - use original group name (with spaces)
        corr_file = os.path.join(CORRELATE_DIR, f"{group_name}.json")
        if os.path.exists(corr_file) and correlations is not None:
            with open(corr_file, encoding="utf-8") as fh:
                index = json.load(fh)
            index["vendor_correlations"] = [c for c in index.get("vendor_correlations") or []
                                            if os.path.basename(c.get("file") or "") in correlations]
            zip_file.writestr(f"correlations/{group_name}.json", json.dumps(index, indent=2))
            files_added += 1
        elif os.path.exists(corr_file):
            zip_file.write(corr_file, f"correlations/{group_name}.json")
            files_added += 1
            logger.info(f"Added correlation: {group_name}.json")
        else:
            logger.warning(f"Correlation file not found: {corr_file}")

        # One YAML per correlation (archer.build.correlation_files); the JSON above is their index
        from archer.build.correlation_files import group_dir

        for corr_yaml in sorted(glob.glob(os.path.join(group_dir(group_name), "*.yaml"))):
            if correlations is not None and os.path.basename(corr_yaml) not in correlations:
                continue
            zip_file.write(corr_yaml, f"correlations/{os.path.basename(corr_yaml)}")
            files_added += 1

        # Add attack flows - try both sanitized and original group name patterns
        flow_dir = ATTACK_FLOWS_DIR
        if os.path.exists(flow_dir):
            # Try sanitized version (with underscores)
            for flow_file in glob.glob(os.path.join(flow_dir, f"{safe_group}_*.json")):
                filename = os.path.basename(flow_file)
                zip_file.write(flow_file, f"attack_flows/{filename}")
                files_added += 1
                logger.info(f"Added attack flow JSON: {filename}")

            for flow_file in glob.glob(os.path.join(flow_dir, f"{safe_group}_*.html")):
                filename = os.path.basename(flow_file)
                zip_file.write(flow_file, f"attack_flows/{filename}")
                files_added += 1
                logger.info(f"Added attack flow HTML: {filename}")

            # Also try original group name (with spaces)
            for flow_file in glob.glob(os.path.join(flow_dir, f"{group_name}_*.json")):
                filename = os.path.basename(flow_file)
                if f"attack_flows/{filename}" not in zip_file.namelist():
                    zip_file.write(flow_file, f"attack_flows/{filename}")
                    files_added += 1
                    logger.info(f"Added attack flow JSON: {filename}")

            for flow_file in glob.glob(os.path.join(flow_dir, f"{group_name}_*.html")):
                filename = os.path.basename(flow_file)
                if f"attack_flows/{filename}" not in zip_file.namelist():
                    zip_file.write(flow_file, f"attack_flows/{filename}")
                    files_added += 1
                    logger.info(f"Added attack flow HTML: {filename}")

    logger.info(f"Total files added to ZIP: {files_added}")
    zip_buffer.seek(0)

    # Use quotes around filename to handle spaces properly
    filename = f'"{group_name}.zip"'
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/attack-flow/{filename}")
def view_attack_flow(filename: str):
    """
    Serve an attack flow HTML file for viewing.
    """
    safe_filename = sanitize_filename(filename)
    file_path = os.path.join(ATTACK_FLOWS_DIR, safe_filename)

    if not os.path.exists(file_path):
        return {"error": "Attack flow not found"}, 404

    return FileResponse(file_path, media_type="text/html")


@app.get("/api/download/flow/{filename}")
def download_attack_flow(filename: str):
    """
    Download an attack flow JSON file.
    """
    safe_filename = sanitize_filename(filename)
    file_path = os.path.join(ATTACK_FLOWS_DIR, safe_filename)

    if not os.path.exists(file_path):
        return {"error": "File not found"}, 404

    return FileResponse(file_path, media_type="application/json", filename=safe_filename)


# ============================================================================
# Authentication Helpers
# ============================================================================


def log_activity(
    user_id: int, activity_type: str, title: str, description: str = None, metadata: dict = None
):
    """
    Helper function to log user activity to the timeline.

    Args:
        user_id: User ID to log activity for
        activity_type: Type of activity (generate, correlate, upload, library_save, library_export)
        title: Activity title
        description: Optional activity description
        metadata: Optional metadata dict (will be JSON encoded)
    """
    from archer.database.models import ActivityLog, ActivityType
    from archer.database.db import SessionLocal
    import json

    db = SessionLocal()
    try:
        # Convert string to ActivityType enum
        try:
            activity_enum = ActivityType(activity_type)
        except ValueError:
            logger.error(f"Invalid activity type: {activity_type}")
            return

        # Create activity log entry
        activity = ActivityLog(
            user_id=user_id,
            activity_type=activity_enum,
            title=title,
            description=description,
            metadata=json.dumps(metadata) if metadata else None,
        )

        db.add(activity)
        db.commit()

    except Exception as e:
        db.rollback()
        logger.error(f"Error logging activity: {e}")
    finally:
        db.close()


def require_auth(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Helper function to require authentication.

    Returns the authenticated user or redirects to login page.

    Args:
        request: FastAPI request object
        archer_session: Session cookie value

    Returns:
        Tuple of (user, db) if authenticated, RedirectResponse to login if not
    """
    if not archer_session:
        return RedirectResponse(url="/login", status_code=303)

    db = next(get_db())
    user = get_user_from_session_id(archer_session, db)

    if not user:
        db.close()
        return RedirectResponse(url="/login", status_code=303)

    return user, db


# ============================================================================
# Authentication Routes
# ============================================================================


@app.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    response: Response,
    registered: Optional[str] = None,
    next_url: Optional[str] = None,
):
    """
    Render the login page with CSRF protection.
    """
    from archer.security.csrf import generate_csrf_token
    import secrets

    # Generate a temporary session ID for CSRF (if user not logged in)
    # This will be replaced with the real session ID after login
    temp_session_id = secrets.token_urlsafe(16)
    csrf_token = generate_csrf_token(temp_session_id)

    # Check if user just registered
    success_message = None
    if registered == "true":
        success_message = "Registration successful! Please log in with your credentials."

    # Store temp session ID in a cookie for CSRF validation
    template_response = templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": None,
            "success": success_message,
            "csrf_token": csrf_token,
            "next_url": next_url or "/",
        },
    )

    template_response.set_cookie(
        key="archer_csrf_session",
        value=temp_session_id,
        max_age=3600,  # 1 hour
        httponly=True,
        samesite="lax",
    )

    return template_response


@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request):
    """
    Render the password reset page.
    """
    return templates.TemplateResponse("reset_password.html", {"request": request})


@app.post("/login")
async def login(
    request: Request,
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    remember_me: Optional[str] = Form(None),
    next_url: Optional[str] = Form("/"),
    csrf_token: str = Form(...),
    archer_csrf_session: Optional[str] = Cookie(None),
):
    """
    Authenticate user and create session.

    Security features:
    - CSRF protection
    - Rate limiting (5 attempts per 5 minutes per IP)
    - Account lockout (15 minutes after 5 failed attempts)
    - Audit logging of all login attempts

    Args:
        email: User's email address
        password: User's password
        remember_me: "true" if Remember Me checkbox is checked
        next_url: URL to redirect to after successful login
        csrf_token: CSRF token from form
        archer_csrf_session: CSRF session ID from cookie

    Returns:
        Redirect to home page on success, login page with error on failure
    """
    from archer.security.rate_limit import check_rate_limit, record_attempt, reset_rate_limit
    from archer.database.audit import log_audit_event, EVENT_LOGIN_SUCCESS, EVENT_LOGIN_FAILURE
    from archer.security.csrf import validate_csrf_token, consume_csrf_token, generate_csrf_token
    from datetime import datetime, timezone

    db = next(get_db())
    try:
        # Get client IP and user agent for logging
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        # Validate CSRF token
        if not archer_csrf_session or not validate_csrf_token(csrf_token, archer_csrf_session):
            log_audit_event(
                db=db,
                event_type=EVENT_LOGIN_FAILURE,
                email=email,
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                details="Invalid CSRF token",
            )
            # Rebind to a fresh CSRF session so a resubmit works without a manual reload
            import secrets

            retry_session = secrets.token_urlsafe(16)
            error_response = templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "Security validation failed. Please try again.",
                    "csrf_token": generate_csrf_token(retry_session),
                },
                status_code=403,
            )
            error_response.set_cookie(
                key="archer_csrf_session",
                value=retry_session,
                max_age=3600,
                httponly=True,
                samesite="lax",
            )
            return error_response

        # Consume CSRF token to prevent reuse
        consume_csrf_token(csrf_token)
        # Re-rendered forms need a live token; the submitted one is now spent
        next_csrf = generate_csrf_token(archer_csrf_session)

        # Check rate limit by IP address
        rate_limit_key = f"login:{client_ip}"
        is_allowed, remaining = check_rate_limit(rate_limit_key, max_attempts=5, window_seconds=300)

        if not is_allowed:
            log_audit_event(
                db=db,
                event_type=EVENT_LOGIN_FAILURE,
                email=email,
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                details="Rate limit exceeded",
            )
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "csrf_token": next_csrf,
                    "error": "Too many login attempts. Please try again in 5 minutes.",
                },
                status_code=429,
            )

        # Find user by email
        user = db.query(User).filter(User.email == email).first()

        if not user:
            record_attempt(rate_limit_key)
            log_audit_event(
                db=db,
                event_type=EVENT_LOGIN_FAILURE,
                email=email,
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                details="User not found",
            )
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "csrf_token": next_csrf, "error": "Invalid email or password"},
                status_code=401,
            )

        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.now(timezone.utc).replace(
            tzinfo=None
        ):
            log_audit_event(
                db=db,
                event_type=EVENT_LOGIN_FAILURE,
                user_id=user.id,
                email=email,
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                details=f"Account locked until {user.locked_until}",
            )
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "csrf_token": next_csrf,
                    "error": "Account is temporarily locked due to multiple failed login attempts. Please try again later.",
                },
                status_code=403,
            )

        # Verify password
        if not verify_password(password, user.password_hash):
            # Increment failed login attempts
            user.failed_login_attempts += 1

            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                from datetime import timedelta

                user.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(
                    minutes=15
                )
                db.commit()

                log_audit_event(
                    db=db,
                    event_type=EVENT_LOGIN_FAILURE,
                    user_id=user.id,
                    email=email,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    success=False,
                    details=f"Account locked after {user.failed_login_attempts} failed attempts",
                )

                return templates.TemplateResponse(
                    "login.html",
                    {
                        "request": request,
                        "csrf_token": next_csrf,
                        "error": "Account locked due to multiple failed login attempts. Please try again in 15 minutes.",
                    },
                    status_code=403,
                )

            db.commit()
            record_attempt(rate_limit_key)

            log_audit_event(
                db=db,
                event_type=EVENT_LOGIN_FAILURE,
                user_id=user.id,
                email=email,
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                details=f"Invalid password (attempt {user.failed_login_attempts}/5)",
            )

            return templates.TemplateResponse(
                "login.html",
                {"request": request, "csrf_token": next_csrf, "error": "Invalid email or password"},
                status_code=401,
            )

        # Check if user is active
        if not user.is_active:
            log_audit_event(
                db=db,
                event_type=EVENT_LOGIN_FAILURE,
                user_id=user.id,
                email=email,
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                details="Account disabled",
            )
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "csrf_token": next_csrf,
                    "error": "Account is disabled. Please contact an administrator.",
                },
                status_code=403,
            )

        # Successful login - reset failed attempts and unlock account
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

        # Reset rate limit for this IP
        reset_rate_limit(rate_limit_key)

        # Create session
        remember = remember_me == "true"
        session_id = create_session(user.id, remember_me=remember, db=db)

        # Log successful login
        log_audit_event(
            db=db,
            event_type=EVENT_LOGIN_SUCCESS,
            user_id=user.id,
            email=email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=True,
            details=f"Login successful (Remember Me: {remember})",
        )

        # Validate next_url parameter to prevent open redirect vulnerabilities
        # Only allow relative URLs starting with /
        redirect_url = "/"
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            redirect_url = next_url

        # Set session cookie
        redirect_response = RedirectResponse(url=redirect_url, status_code=303)

        # Set cookie with appropriate max_age
        if remember:
            max_age = 7 * 24 * 60 * 60  # 7 days in seconds
        else:
            max_age = 16 * 60 * 60  # 16 hours in seconds

        redirect_response.set_cookie(
            key="archer_session", value=session_id, max_age=max_age, httponly=True, samesite="lax"
        )

        return redirect_response

    finally:
        db.close()


@app.get("/logout")
async def logout(
    request: Request, response: Response, archer_session: Optional[str] = Cookie(None)
):
    """
    Log out user by deleting their session.
    """
    if archer_session:
        db = next(get_db())
        try:
            delete_session(archer_session, db)
        finally:
            db.close()

    # Redirect to login page and clear cookie
    redirect_response = RedirectResponse(url="/login", status_code=303)
    redirect_response.delete_cookie(key="archer_session")
    return redirect_response


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, response: Response):
    """
    Render the registration page with CSRF protection.
    """
    from archer.security.csrf import generate_csrf_token
    import secrets

    # Generate a temporary session ID for CSRF (if user not logged in)
    temp_session_id = secrets.token_urlsafe(16)
    csrf_token = generate_csrf_token(temp_session_id)

    # Store temp session ID in a cookie for CSRF validation
    template_response = templates.TemplateResponse(
        "register.html", {"request": request, "error": None, "csrf_token": csrf_token}
    )

    template_response.set_cookie(
        key="archer_csrf_session",
        value=temp_session_id,
        max_age=3600,  # 1 hour
        httponly=True,
        samesite="lax",
    )

    return template_response


@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    """
    Render the forgot password page (coming soon).
    """
    return templates.TemplateResponse("forgot_password.html", {"request": request})


@app.post("/register")
async def register(
    request: Request,
    response: Response,
    email: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    csrf_token: str = Form(...),
    archer_csrf_session: Optional[str] = Cookie(None),
):
    """
    Register a new user account.

    Security features:
    - CSRF protection
    - Password strength validation
    - Email validation
    - Rate limiting (5 attempts per 5 minutes per IP)
    - Audit logging of all registration attempts

    Args:
        email: User's email address
        full_name: User's full name
        password: User's password
        password_confirm: Password confirmation
        csrf_token: CSRF token from form
        archer_csrf_session: CSRF session ID from cookie

    Returns:
        Redirect to login page on success, registration page with error on failure
    """
    from archer.security.rate_limit import check_rate_limit, record_attempt
    from archer.database.audit import log_audit_event, EVENT_USER_CREATED
    from archer.security.csrf import validate_csrf_token, consume_csrf_token, generate_csrf_token
    from archer.auth.password import validate_password, hash_password
    import re

    db = next(get_db())
    try:
        # Get client IP and user agent for logging
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        # Validate CSRF token
        if not archer_csrf_session or not validate_csrf_token(csrf_token, archer_csrf_session):
            # Rebind to a fresh CSRF session so a resubmit works without a manual reload
            import secrets

            retry_session = secrets.token_urlsafe(16)
            error_response = templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "Security validation failed. Please try again.",
                    "csrf_token": generate_csrf_token(retry_session),
                },
                status_code=403,
            )
            error_response.set_cookie(
                key="archer_csrf_session",
                value=retry_session,
                max_age=3600,
                httponly=True,
                samesite="lax",
            )
            return error_response

        # Consume CSRF token to prevent reuse
        consume_csrf_token(csrf_token)
        # Re-rendered forms need a live token; the submitted one is now spent
        next_csrf = generate_csrf_token(archer_csrf_session)

        # Check rate limit by IP address
        rate_limit_key = f"register:{client_ip}"
        is_allowed, remaining = check_rate_limit(rate_limit_key, max_attempts=5, window_seconds=300)

        if not is_allowed:
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "Too many registration attempts. Please try again in 5 minutes.",
                    "csrf_token": next_csrf,
                },
                status_code=429,
            )

        # Validate email format
        email = email.strip().lower()
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, email) or len(email) > 64:
            record_attempt(rate_limit_key)
            return templates.TemplateResponse(
                "register.html",
                {"request": request, "error": "Invalid email address", "csrf_token": next_csrf},
                status_code=400,
            )

        # Check if email already exists
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            record_attempt(rate_limit_key)
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "An account with this email address already exists",
                    "csrf_token": next_csrf,
                },
                status_code=400,
            )

        # Validate full name
        full_name = full_name.strip()
        if len(full_name) < 2 or len(full_name) > 64:
            record_attempt(rate_limit_key)
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "Full name must be between 2 and 64 characters",
                    "csrf_token": next_csrf,
                },
                status_code=400,
            )

        # Validate passwords match
        if password != password_confirm:
            record_attempt(rate_limit_key)
            return templates.TemplateResponse(
                "register.html",
                {"request": request, "error": "Passwords do not match", "csrf_token": next_csrf},
                status_code=400,
            )

        # Validate password strength
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            record_attempt(rate_limit_key)
            return templates.TemplateResponse(
                "register.html",
                {"request": request, "error": error_msg, "csrf_token": next_csrf},
                status_code=400,
            )

        # Create new user
        new_user = User(
            email=email,
            full_name=full_name,
            password_hash=hash_password(password),
            role=UserRole.STANDARD,  # Default to standard user
            is_active=True,
            failed_login_attempts=0,
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Log successful registration
        log_audit_event(
            db=db,
            event_type=EVENT_USER_CREATED,
            user_id=new_user.id,
            email=email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=True,
            details=f"User registered: {full_name}",
        )

        # Redirect to login page with success message
        return RedirectResponse(url="/login?registered=true", status_code=303)

    finally:
        db.close()


# ============================================================================
# Profile Management Routes
# ============================================================================


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Render the profile page with user information and settings.

    Requires authentication.
    """
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return auth_result

    user, db = auth_result

    try:
        return templates.TemplateResponse(
            "profile.html", {"request": request, "user": user, "profile_picture_url": None,
                             "countries": __import__("archer.intelligence.cyber_powers", fromlist=["countries"]).countries()}
        )
    finally:
        db.close()


@app.get("/flows", response_class=HTMLResponse)
def flows_page(request: Request, group: str = "", archer_session: Optional[str] = Cookie(None)):
    """Attack flows of everything saved to the library: pick a group, report or CVE to open its flow."""
    from archer.visualization.flow_layouts import library_flows, load_layout

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return auth_result
    user, db = auth_result
    try:
        flows = library_flows(db, user.id, getattr(request.app.state, "bundle", None))
        chosen = next((f for f in flows if f["group"] == group), None) or next((f for f in flows if f["view"]), None)
        state = load_layout(db, user.id, chosen["group"]) if chosen and chosen["view"] else None
    finally:
        db.close()
    kinds = {}
    for f in flows:
        kinds.setdefault(f["kind"], []).append(f)
    return templates.TemplateResponse("flows.html", {
        "request": request, "user": user, "kinds": kinds, "chosen": chosen,
        "group_name": chosen["group"] if chosen else "",
        "attack_flow": chosen["view"] if chosen else None,
        "flow_layout": {"logged_in": True, "persist": True, "state": state,
                        "group_name": chosen["group"]} if chosen else None,
    })


@app.get("/anatomy", response_class=HTMLResponse)
def anatomy_page(request: Request, group: str = "", archer_session: Optional[str] = Cookie(None)):
    """Anatomy workflows of the threat groups and CVEs saved to the library (archer.visualization.anatomy)."""
    from archer.visualization import anatomy as anatomy_lib
    from archer.visualization.flow_layouts import library_flows

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return auth_result
    user, db = auth_result
    try:
        saved = library_flows(db, user.id, getattr(request.app.state, "bundle", None))
    finally:
        db.close()
    # Reports, technique hunts and profiles have no actor or CVE to draw
    entries = [f for f in saved if f["kind"] in ("Threat group", "CVE") and anatomy_lib.has_anatomy(f["group"])]
    chosen = next((f for f in entries if f["group"] == group), None) or (entries[0] if entries else None)
    view = anatomy_lib.for_group(chosen["group"], GENERATE_DIR) if chosen else None
    kinds = {}
    for f in entries:
        kinds.setdefault(f["kind"], []).append(f)
    return templates.TemplateResponse("anatomy.html", {
        "request": request, "user": user, "kinds": kinds, "chosen": chosen,
        "group_name": chosen["group"] if chosen else "", "anatomy": view,
    })


@app.get("/api/osint-details", response_class=HTMLResponse)
def results_osint(request: Request, kind: str = "detection", files: List[str] = Query(default=[])):
    """
    A results card's OSINT details, rendered when first opened: shipping every card's
    query snippets with the page made it tens of megabytes. kind=detection merges the
    files' osint_data, as the results page groups them; kind=correlation inherits from
    its parts (archer.build.correlation_osint).
    """
    paths = [os.path.join(GENERATE_DIR, os.path.basename(f)) for f in files[:50] if f.endswith(".yaml")]
    paths = [p for p in paths if os.path.isfile(p)]
    if kind == "correlation":
        from archer.build.correlation_osint import inherited

        osint = inherited([d for d in map(load_yaml_file, paths) if d])
        data = {"indicators": {"query_snippets": osint["snippets"]}} if osint["snippets"] else {}
    else:
        data = {}
        for p in paths:
            data.update(check_osint_enriched(p)[1] or {})
    if not data:
        return HTMLResponse('<p class="osint-empty">No OSINT details are recorded for this any more.</p>')
    return templates.TemplateResponse("partials/osint_details.html", {"request": request, "osint": data})


@app.get("/flow", response_class=HTMLResponse)
def flow_only_page(request: Request, group_name: str, archer_session: Optional[str] = Cookie(None)):
    """
    One group's attack flow on its own page (the flow's Open in New Tab): the view the
    results page last built (data/attack_flows/<group>_flow_view.json), with the user's edits.
    """
    from archer.visualization.flow_layouts import load_layout, results_in_library

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return auth_result
    user, db = auth_result
    safe_group = sanitize_group_name(group_name)
    view = None
    path = os.path.join(ATTACK_FLOWS_DIR, f"{safe_group}_flow_view.json")
    if safe_group and os.path.dirname(os.path.abspath(path)) == os.path.abspath(ATTACK_FLOWS_DIR):
        try:
            with open(path, encoding="utf-8") as fh:
                view = json.load(fh).get("view")
        except (OSError, ValueError):
            view = None
    layout = {"logged_in": True, "persist": False, "state": None, "group_name": safe_group}
    try:
        if view:
            layout["persist"] = results_in_library(db, user.id, safe_group)
            if layout["persist"]:
                layout["state"] = load_layout(db, user.id, safe_group)
    finally:
        db.close()
    return templates.TemplateResponse("flow_only.html", {
        "request": request, "user": user, "group_name": safe_group,
        "attack_flow": view, "flow_layout": layout, "flow_only": True,
    })


@app.get("/exposure", response_class=HTMLResponse)
def exposure_page(request: Request, domain: str, archer_session: Optional[str] = Cookie(None)):
    """
    The organisation exposure map for a profiled domain (archer.visualization.exposure): what the
    OSINT profiling unearthed and how each piece links back to the domain. Reads the saved profile
    under data/profiles/; build it on the home page first.
    """
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return auth_result
    user, db = auth_result
    db.close()

    safe = (domain or "").strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    safe_file = re.sub(r"[^a-z0-9._-]", "_", safe).replace(".", "_")
    profiles_dir = Path("data") / "profiles"
    path = profiles_dir / f"{safe_file}_profile.json"
    expo = None
    if safe_file and os.path.dirname(os.path.abspath(path)) == os.path.abspath(profiles_dir) and path.is_file():
        try:
            with open(path, encoding="utf-8") as fh:
                profile = json.load(fh)
            from archer.visualization import exposure as exposure_mod
            expo = exposure_mod.build(profile)
        except (OSError, ValueError):
            expo = None
    return templates.TemplateResponse("exposure.html", {"request": request, "user": user,
                                                        "domain": safe, "exposure": expo})


# ---------------------------------------------------------------- STIX / TAXII & MISP (#19)

def _save_stix_extraction(result: dict, source_label: str) -> dict:
    """Save an import's extraction in the blog-analysis shape (so /blog/generate can use it) and
    return the review payload the STIX page shows."""
    import hashlib
    import json as _json

    ttps = result.get("techniques", []) or []
    iocs = {k: v for k, v in (result.get("iocs") or {}).items() if v}
    group_name = result.get("group_name") or ""
    title = re.sub(r"\s*[(\[][^)\]]*[)\]]", "", result.get("title") or "")
    title_words = re.sub(r"[^\w-]+", "_", title).strip("_")[:60].strip("_")
    digest = hashlib.md5(_json.dumps(result, sort_keys=True).encode()).hexdigest()[:8]
    raw = group_name or (f"{source_label}_{title_words}" if title_words else f"{source_label}_{digest}")
    name = sanitize_group_name(raw)
    os.makedirs(BLOG_DIR, exist_ok=True)
    with open(os.path.join(BLOG_DIR, f"{name}_extraction.json"), "w") as fh:
        _json.dump({
            "url": result.get("taxii_collection") or source_label, "filename": source_label,
            "group_name": group_name, "ttps": ttps, "iocs": iocs,
            "ioc_mentions": result.get("ioc_mentions") or {}, "procedures": result.get("procedures", []),
            "synthetic_group_name": name, "ai_provider": "", "ai_model": "", "run_correlation": True,
        }, fh, indent=2)
    return {"success": True, "show_extraction": True, "synthetic_group_name": name,
            "group_name": group_name, "ttps": ttps, "iocs": iocs,
            "ttps_count": len(ttps), "iocs_count": sum(len(v) for v in iocs.values())}


@app.get("/intel/stix", response_class=HTMLResponse)
def stix_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Import STIX/TAXII/MISP intel as a hunt input, or export a run as a STIX bundle."""
    from archer.config import DATA_DIR

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return auth
    user, db = auth
    db.close()
    runs_dir = os.path.join(DATA_DIR, "runs")
    runs = sorted((n[:-5] for n in os.listdir(runs_dir) if n.endswith(".json")), key=str.lower) \
        if os.path.isdir(runs_dir) else []
    return templates.TemplateResponse("stix.html", {"request": request, "user": user, "runs": runs})


@app.post("/api/intel/stix/import")
async def stix_import(request: Request, file: UploadFile = File(None), text: str = Form(None),
                      archer_session: Optional[str] = Cookie(None)):
    """A STIX 2.1 bundle or a MISP event (upload or pasted) → the extraction the generator uses."""
    import json as _json

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in to import intelligence"}, status_code=401)
    _user, db = auth
    db.close()
    try:
        if file is not None:
            raw = (await file.read()).decode("utf-8", "replace")
            label = file.filename or "import.json"
        elif text:
            raw, label = text, "pasted.json"
        else:
            return JSONResponse({"success": False, "error": "Provide a file or paste JSON"}, status_code=400)
        data = _json.loads(raw)
    except ValueError:
        return JSONResponse({"success": False, "error": "Not valid JSON"}, status_code=400)

    from archer.parsers.misp_import import parse_misp_event
    from archer.parsers.stix_import import parse_stix_bundle

    is_misp = isinstance(data, dict) and ("Event" in data or data.get("Attribute") or ("info" in data and "objects" not in data))
    result = parse_misp_event(data) if is_misp else parse_stix_bundle(data)
    if not result.get("success"):
        return JSONResponse({"success": False, "error": result.get("error", "Could not parse")}, status_code=422)
    if not result.get("techniques") and not any(result.get("iocs", {}).values()):
        return JSONResponse({"success": False, "error": "No techniques or IOCs found in the input"}, status_code=422)
    return JSONResponse(_save_stix_extraction(result, "MISP" if is_misp else "STIX"))


@app.post("/api/intel/taxii/import")
def taxii_import(request: Request, url: str = Form(...), username: str = Form(""), password: str = Form(""),
                 archer_session: Optional[str] = Cookie(None)):
    """Poll a TAXII 2.1 collection and import its objects as a hunt input."""
    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in to import intelligence"}, status_code=401)
    _user, db = auth
    db.close()
    try:
        from archer.parsers.taxii_client import import_collection

        result = import_collection(url.strip(), username=username.strip(), password=password)
    except Exception as e:
        return JSONResponse({"success": False, "error": f"TAXII fetch failed: {e}"}, status_code=502)
    if not result.get("success"):
        return JSONResponse({"success": False, "error": result.get("error", "Could not parse the collection")}, status_code=422)
    if not result.get("techniques") and not any(result.get("iocs", {}).values()):
        return JSONResponse({"success": False, "error": "The collection held no techniques or IOCs"}, status_code=422)
    return JSONResponse(_save_stix_extraction(result, "TAXII"))


@app.post("/api/intel/misp/import")
def misp_instance_import(request: Request, url: str = Form(...), api_key: str = Form(...),
                         last: str = Form("30d"), archer_session: Optional[str] = Cookie(None)):
    """Pull recent events from a MISP instance (URL + API key) and import them as a hunt input."""
    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in to import intelligence"}, status_code=401)
    _user, db = auth
    db.close()
    if not api_key.strip():
        return JSONResponse({"success": False, "error": "A MISP API key is required"}, status_code=400)
    try:
        from archer.parsers.misp_client import import_events

        result = import_events(url.strip(), api_key.strip(), last=last.strip() or "30d")
    except Exception as e:
        return JSONResponse({"success": False, "error": f"MISP fetch failed: {e}"}, status_code=502)
    if not result.get("success"):
        return JSONResponse({"success": False, "error": result.get("error", "Could not read the instance")}, status_code=422)
    if not result.get("techniques") and not any(result.get("iocs", {}).values()):
        return JSONResponse({"success": False, "error": "No techniques or IOCs in the returned events"}, status_code=422)
    return JSONResponse(_save_stix_extraction(result, "MISP"))


@app.get("/api/intel/misp/export")
def misp_export_run(request: Request, group: str = Query(...), archer_session: Optional[str] = Cookie(None)):
    """A saved run's techniques and IOCs → a downloadable MISP event (JSON)."""
    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"error": "Log in to export"}, status_code=401)
    _user, db = auth
    db.close()
    safe = sanitize_group_name(group)
    connector_siem = {"GoogleSecOps": "secops", "MicrosoftThreatProtection": "mde", "Splunk": "splunk", "Elastic": "elastic"}
    dets = []
    for name in group_yaml_files(safe, GENERATE_DIR):
        doc = load_yaml_file(os.path.join(GENERATE_DIR, os.path.basename(name)))
        if not doc or not doc.get("technique_id"):
            continue
        connector = ((doc.get("requiredDataConnectors") or [{}])[0] or {}).get("connectorId", "")
        dets.append({"name": doc.get("name"), "technique_id": doc.get("technique_id"),
                     "query": doc.get("query", ""), "siem": connector_siem.get(connector, connector),
                     "indicators": doc.get("indicators") or {}})
    if not dets:
        return JSONResponse({"error": f"No detections found for {group}"}, status_code=404)
    from archer.parsers.misp_export import run_to_misp

    event = run_to_misp(safe, dets)
    return Response(content=event, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{safe}_misp_event.json"'})


@app.get("/api/intel/stix/export")
def stix_export_run(request: Request, group: str = Query(...), archer_session: Optional[str] = Cookie(None)):
    """A saved run's detections → a downloadable STIX 2.1 bundle."""
    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"error": "Log in to export"}, status_code=401)
    _user, db = auth
    db.close()
    safe = sanitize_group_name(group)
    connector_siem = {"GoogleSecOps": "secops", "MicrosoftThreatProtection": "mde", "Splunk": "splunk", "Elastic": "elastic"}
    dets = []
    for name in group_yaml_files(safe, GENERATE_DIR):
        doc = load_yaml_file(os.path.join(GENERATE_DIR, os.path.basename(name)))
        if not doc or not doc.get("technique_id"):
            continue
        connector = ((doc.get("requiredDataConnectors") or [{}])[0] or {}).get("connectorId", "")
        dets.append({"name": doc.get("name"), "technique_id": doc.get("technique_id"),
                     "query": doc.get("query", ""), "siem": connector_siem.get(connector, connector),
                     "indicators": doc.get("indicators") or {}})
    if not dets:
        return JSONResponse({"error": f"No detections found for {group}"}, status_code=404)
    from archer.parsers.stix_export import run_to_stix

    bundle = run_to_stix(safe, dets)
    return Response(content=bundle, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{safe}_stix_bundle.json"'})


def _runs_list():
    """Group names that have a saved run, newest first."""
    runs_dir = os.path.join(DATA_DIR, "runs")
    if not os.path.isdir(runs_dir):
        return []
    entries = [(os.path.getmtime(os.path.join(runs_dir, n)), n[:-5])
               for n in os.listdir(runs_dir) if n.endswith(".json")]
    return [name for _m, name in sorted(entries, reverse=True)]


@app.get("/detections/code", response_class=HTMLResponse)
def detections_code_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Export detections to a git repo (one commit per run) and diff two commits."""
    from archer.export import detections_git, repo_config

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return auth
    user, db = auth
    db.close()
    cfg = repo_config.load()
    repo = cfg["repo_path"]
    commits = detections_git.list_commits(repo, limit=50)
    return templates.TemplateResponse("detections_code.html", {
        "request": request, "user": user, "runs": _runs_list(), "commits": commits,
        "repo_path": repo, "remote_url": cfg["remote_url"], "push_enabled": cfg["push_enabled"],
        "repo_configured": repo_config.is_configured(), "is_admin": user.role.value == "admin"})


@app.post("/api/detections/code/export")
def detections_code_export(request: Request, group: str = Form(...), message: str = Form(""),
                           archer_session: Optional[str] = Cookie(None)):
    """Commit a group's current detections into the git repo; push if a remote is configured."""
    from archer.export import detections_git, repo_config

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in to export"}, status_code=401)
    _user, db = auth
    db.close()
    safe = sanitize_group_name(group)
    if not group_yaml_files(safe, GENERATE_DIR):
        return JSONResponse({"success": False, "error": f"No detections for {group}. Hunt it first."}, status_code=404)
    cfg = repo_config.load()
    try:
        res = detections_git.export_run(safe, GENERATE_DIR, cfg["repo_path"],
                                        group_yaml_files, message=message.strip() or None)
    except Exception as e:
        return JSONResponse({"success": False, "error": f"Export failed: {e}"}, status_code=500)
    res["success"] = True
    if res.get("committed") and cfg.get("push_enabled") and cfg.get("remote_url"):
        res["push"] = repo_config.push(cfg["repo_path"], cfg["remote_url"], res.get("branch", "main"))
    return JSONResponse(res)


@app.post("/api/detections/code/diff")
def detections_code_diff(request: Request, ref_a: str = Form(...), ref_b: str = Form(...),
                         group: str = Form(""), archer_session: Optional[str] = Cookie(None)):
    """Added / removed / changed detections between two commits."""
    from archer.export import detections_git, repo_config

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in to diff"}, status_code=401)
    _user, db = auth
    db.close()
    for ref in (ref_a, ref_b):
        if not re.fullmatch(r"[0-9a-fA-F]{7,40}|HEAD(~\d+)?", ref.strip()):
            return JSONResponse({"success": False, "error": "Pick two commits from the list"}, status_code=400)
    diff = detections_git.diff_runs(repo_config.repo_path(), ref_a.strip(), ref_b.strip(),
                                    group=sanitize_group_name(group) if group else None)
    diff["success"] = True
    return JSONResponse(diff)


@app.post("/api/detections/code/push")
def detections_code_push(request: Request, group: str = Form(...), siem: str = Form(...),
                         archer_session: Optional[str] = Cookie(None)):
    """Dry-run plan for pushing a group's detections to a SIEM rule store (no live push)."""
    from archer.export import siem_push

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in to plan a push"}, status_code=401)
    _user, db = auth
    db.close()
    safe = sanitize_group_name(group)
    connector_siem = {"GoogleSecOps": "secops", "MicrosoftThreatProtection": "mde", "Splunk": "splunk", "Elastic": "elastic"}
    from archer.build.availability import load as _load_avail, missing_sources
    avail = _load_avail()
    dets = []
    excluded = 0
    for name in group_yaml_files(safe, GENERATE_DIR):
        doc = load_yaml_file(os.path.join(GENERATE_DIR, os.path.basename(name)))
        if not doc or not doc.get("technique_id"):
            continue
        # Don't plan a push for a rule that can't fire on this estate (#12)
        if avail and missing_sources(doc, avail):
            excluded += 1
            continue
        connector = ((doc.get("requiredDataConnectors") or [{}])[0] or {}).get("connectorId", "")
        dets.append({"name": doc.get("name"), "technique_id": doc.get("technique_id"),
                     "query": doc.get("query", ""), "severity": doc.get("severity", "medium"),
                     "siem": connector_siem.get(connector, connector)})
    plan = siem_push.plan_push(siem, dets, execute=False)
    if excluded:
        plan["excluded_unavailable"] = excluded
    return JSONResponse(plan, status_code=200 if plan.get("success") else 400)


@app.get("/api/detections/code/config")
def detections_code_config_get(request: Request, archer_session: Optional[str] = Cookie(None)):
    """The detections-as-code repo config (admin only)."""
    from archer.export import repo_config

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"error": "Log in"}, status_code=401)
    user, db = auth
    db.close()
    if user.role != UserRole.ADMIN:
        return JSONResponse({"error": "Admin access required"}, status_code=403)
    return JSONResponse(repo_config.load())


@app.post("/api/detections/code/config")
def detections_code_config_save(request: Request, repo_path: str = Form(...), remote_url: str = Form(""),
                                push_enabled: str = Form(""), archer_session: Optional[str] = Cookie(None)):
    """Save the detections-as-code repo config (admin only)."""
    from archer.export import repo_config

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in"}, status_code=401)
    user, db = auth
    db.close()
    if user.role != UserRole.ADMIN:
        return JSONResponse({"success": False, "error": "Admin access required"}, status_code=403)
    saved = repo_config.save(repo_path, remote_url, push_enabled in ("1", "true", "on", "yes"))
    return JSONResponse({"success": True, **saved})


@app.post("/api/detections/code/config/test")
def detections_code_config_test(request: Request, repo_path: str = Form(...), remote_url: str = Form(""),
                                archer_session: Optional[str] = Cookie(None)):
    """Test the configured path and remote (admin only; remote check is read-only)."""
    from archer.export import repo_config

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"error": "Log in"}, status_code=401)
    user, db = auth
    db.close()
    if user.role != UserRole.ADMIN:
        return JSONResponse({"error": "Admin access required"}, status_code=403)
    return JSONResponse(repo_config.test_connectivity(repo_path, remote_url))


@app.get("/api/siem-mappings/availability")
def siem_availability_get(request: Request, archer_session: Optional[str] = Cookie(None)):
    """What the estate ingests per SIEM, plus the catalogue of gate-able sources (admin only, #12)."""
    from archer.build import availability

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"error": "Log in"}, status_code=401)
    user, db = auth
    db.close()
    if user.role != UserRole.ADMIN:
        return JSONResponse({"error": "Admin access required"}, status_code=403)
    return JSONResponse({"ingested": availability.load(),
                         "catalogue": availability.source_catalogue(GENERATE_DIR)})


@app.post("/api/siem-mappings/availability")
async def siem_availability_save(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Save the per-SIEM ingested-source lists (admin only, #12).

    Body is JSON {"mde": [...tables...], "secops": [...UDM event types...]}. A SIEM omitted here is
    left ungated (all its sources count as ingested)."""
    from archer.build import availability

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in"}, status_code=401)
    user, db = auth
    db.close()
    if user.role != UserRole.ADMIN:
        return JSONResponse({"success": False, "error": "Admin access required"}, status_code=403)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"success": False, "error": "Invalid JSON body"}, status_code=400)
    ingested = {k: v for k, v in (body or {}).items() if isinstance(v, list)}
    saved = availability.save(ingested)
    return JSONResponse({"success": True, "ingested": saved})


def _test_data_admin(request, archer_session):
    """Shared auth for the sample-data toggle. Returns (user, db) or a JSONResponse."""
    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in"}, status_code=401)
    user, db = auth
    db.close()
    if user.role != UserRole.ADMIN:
        return JSONResponse({"success": False, "error": "Admin access required"}, status_code=403)
    return user, db


@app.get("/api/test-data/status")
def test_data_status(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Is the labelled sample scenario currently seeded? (admin only)."""
    from archer.cli import test_data
    res = _test_data_admin(request, archer_session)
    if isinstance(res, JSONResponse):
        return res
    return JSONResponse({"success": True, **test_data.state()})


@app.post("/api/test-data/populate")
def test_data_populate(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Seed the labelled SampleSpider scenario alongside real data (admin only).

    Additive and manifest-tracked: everything it writes is tagged [SAMPLE] and removed exactly by
    depopulate, so it never mixes with real work."""
    import contextlib
    import io
    from archer.cli import test_data

    res = _test_data_admin(request, archer_session)
    if isinstance(res, JSONResponse):
        return res
    user, _ = res
    if test_data.state().get("present"):
        return JSONResponse({"success": True, "already_present": True, **test_data.state()})
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            test_data.populate(force=False, email=user.email or "")
    except Exception as e:  # noqa: BLE001 — surface seeding failures to the admin
        logger.error(f"Sample data populate failed: {e}")
        return JSONResponse({"success": False, "error": str(e), "log": buf.getvalue()}, status_code=500)
    return JSONResponse({"success": True, "log": buf.getvalue(), **test_data.state()})


@app.post("/api/test-data/depopulate")
def test_data_depopulate(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Remove exactly what populate created — real data is untouched (admin only)."""
    import contextlib
    import io
    from archer.cli import test_data

    res = _test_data_admin(request, archer_session)
    if isinstance(res, JSONResponse):
        return res
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            test_data.depopulate()
    except Exception as e:  # noqa: BLE001
        logger.error(f"Sample data depopulate failed: {e}")
        return JSONResponse({"success": False, "error": str(e), "log": buf.getvalue()}, status_code=500)
    return JSONResponse({"success": True, "log": buf.getvalue(), **test_data.state()})


_SCHEMA_SIEMS = ("splunk", "elastic", "mde", "secops")


@app.get("/api/siem-mappings/schema")
def siem_schema_get(request: Request, siem: str = Query(...), archer_session: Optional[str] = Cookie(None)):
    """The active field schema for a SIEM and whether an override is in place (admin only, #12)."""
    from archer.build import schema_overrides

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"error": "Log in"}, status_code=401)
    user, db = auth
    db.close()
    if user.role != UserRole.ADMIN:
        return JSONResponse({"error": "Admin access required"}, status_code=403)
    if siem.lower() not in _SCHEMA_SIEMS:
        return JSONResponse({"error": f"Unknown SIEM '{siem}'"}, status_code=400)
    return JSONResponse(schema_overrides.override_info(siem))


@app.post("/api/siem-mappings/schema")
async def siem_schema_save(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Save a per-tenant field-schema override (admin only, #12).

    Body JSON {"siem": "splunk", "schema": {…}}. The schema replaces the base at generation time."""
    from archer.build import schema_overrides

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in"}, status_code=401)
    user, db = auth
    db.close()
    if user.role != UserRole.ADMIN:
        return JSONResponse({"success": False, "error": "Admin access required"}, status_code=403)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"success": False, "error": "Invalid JSON body"}, status_code=400)
    siem = str((body or {}).get("siem", "")).lower()
    if siem not in _SCHEMA_SIEMS:
        return JSONResponse({"success": False, "error": f"Unknown SIEM '{siem}'"}, status_code=400)
    try:
        saved = schema_overrides.save_override(siem, (body or {}).get("schema"))
    except ValueError as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=422)
    return JSONResponse({"success": True, **saved, "runs": len(_runs_list())})


@app.post("/api/siem-mappings/schema/reset")
def siem_schema_reset(request: Request, siem: str = Form(...), archer_session: Optional[str] = Cookie(None)):
    """Remove a SIEM's override so the base schema applies again (admin only, #12)."""
    from archer.build import schema_overrides

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in"}, status_code=401)
    user, db = auth
    db.close()
    if user.role != UserRole.ADMIN:
        return JSONResponse({"success": False, "error": "Admin access required"}, status_code=403)
    if siem.lower() not in _SCHEMA_SIEMS:
        return JSONResponse({"success": False, "error": f"Unknown SIEM '{siem}'"}, status_code=400)
    removed = schema_overrides.reset_override(siem)
    return JSONResponse({"success": True, "removed": removed, "runs": len(_runs_list())})


# ---------------------------------------------------------------------------
# Threat library and assessments (#24)
# ---------------------------------------------------------------------------

def _profile_groups(domain: str):
    """A saved profile's ranked group names."""
    import json as _json

    path = os.path.join(DATA_DIR, "profiles", f"{sanitize_filename(domain)}_profile.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = _json.load(fh)
    except (OSError, ValueError):
        return []
    return [g for g in (data.get("recommended_groups") or []) if g]


@app.get("/threat-library")
def threat_library_page(request: Request):
    """Folded into the Assessments page's Threat library tab (#24)."""
    return RedirectResponse("/assessments#library", status_code=307)


@app.post("/api/threat-library/build")
def threat_library_build(request: Request, source: str = Form(...),
                         archer_session: Optional[str] = Cookie(None)):
    """Build test cases from a profile (source=profile:<domain>) or a group (source=group:<name>)."""
    import json as _json

    from archer.assessments.library import build_test_cases
    from archer.database.models import ThreatTestCase

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in to build test cases"}, status_code=401)
    user, db = auth
    try:
        kind, _, value = source.partition(":")
        if kind == "profile":
            groups = _profile_groups(value)
            label = f"profile:{value}"
        elif kind == "group":
            groups = [value]
            label = f"group:{value}"
        else:
            return JSONResponse({"success": False, "error": "Pick a profile or name a group"}, status_code=400)
        if not groups:
            return JSONResponse({"success": False, "error": "No ranked groups for that source"}, status_code=404)

        cases = build_test_cases(groups)
        if not cases:
            return JSONResponse({"success": False, "error": "No procedures found (is the MITRESaw CSV built?)"}, status_code=404)
        existing = {s for (s,) in db.query(ThreatTestCase.signature).filter(ThreatTestCase.user_id == user.id)}
        added = 0
        for c in cases:
            if c["signature"] in existing:
                continue
            db.add(ThreatTestCase(
                user_id=user.id, signature=c["signature"], technique_id=c["technique_id"],
                technique_name=c["technique_name"], tactic=c["tactic"], group_name=c["group_name"],
                procedure=c["procedure"], indicators=_json.dumps(c["indicators"]),
                prevalence=c["prevalence"], atomic_guid=c["atomic_guid"], source=label))
            existing.add(c["signature"])
            added += 1
        db.commit()
    finally:
        db.close()
    return JSONResponse({"success": True, "added": added, "candidates": len(cases)})


@app.post("/api/threat-library/delete")
def threat_library_delete(request: Request, case_id: str = Form(""), clear: str = Form(""),
                          archer_session: Optional[str] = Cookie(None)):
    """Remove one test case, or clear the whole library."""
    from archer.database.models import ThreatTestCase

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in"}, status_code=401)
    user, db = auth
    try:
        q = db.query(ThreatTestCase).filter(ThreatTestCase.user_id == user.id)
        if clear:
            n = q.delete()
        elif case_id.isdigit():
            n = q.filter(ThreatTestCase.id == int(case_id)).delete()
        else:
            return JSONResponse({"success": False, "error": "Nothing to delete"}, status_code=400)
        db.commit()
    finally:
        db.close()
    return JSONResponse({"success": True, "deleted": n})


@app.get("/assessments", response_class=HTMLResponse)
def assessments_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Threat library and assessment campaigns on one page, two tabs (#24)."""
    import json as _json

    from archer.database.models import Assessment, AssessmentResult, ThreatTestCase
    from archer.visualization.navigator import detection_files_for

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return auth
    user, db = auth
    try:
        rows = db.query(Assessment).filter(Assessment.user_id == user.id) \
            .order_by(Assessment.created_at.desc()).all()
        items = []
        for a in rows:
            total = db.query(AssessmentResult).filter(AssessmentResult.assessment_id == a.id).count()
            items.append({"id": a.id, "name": a.name, "target": a.target, "operator": a.operator,
                          "run_date": a.run_date, "cases": total})
        case_rows = db.query(ThreatTestCase).filter(ThreatTestCase.user_id == user.id) \
            .order_by(ThreatTestCase.prevalence.desc(), ThreatTestCase.technique_id).all()
        cases = []
        for c in case_rows:
            cases.append({"id": c.id, "technique_id": c.technique_id, "technique_name": c.technique_name,
                          "tactic": c.tactic, "group_name": c.group_name, "prevalence": c.prevalence,
                          "procedure": c.procedure, "atomic_guid": c.atomic_guid,
                          "detections": len(detection_files_for(GENERATE_DIR, c.technique_id))})
        profiles_dir = os.path.join(DATA_DIR, "profiles")
        profiles = sorted(n[:-13] for n in os.listdir(profiles_dir)) if os.path.isdir(profiles_dir) else []
    finally:
        db.close()
    return templates.TemplateResponse("assessments.html", {
        "request": request, "user": user, "assessments": items, "cases": cases, "profiles": profiles})


@app.post("/api/assessments/create")
def assessment_create(request: Request, name: str = Form(...), target: str = Form(""),
                      operator: str = Form(""), run_date: str = Form(""),
                      archer_session: Optional[str] = Cookie(None)):
    from archer.database.models import Assessment

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in"}, status_code=401)
    user, db = auth
    try:
        a = Assessment(user_id=user.id, name=name.strip() or "Untitled assessment",
                       target=target.strip(), operator=operator.strip(), run_date=run_date.strip())
        db.add(a)
        db.commit()
        aid = a.id
    finally:
        db.close()
    return JSONResponse({"success": True, "id": aid})


@app.get("/api/threat-library/macat-export")
def threat_library_macat_export(request: Request, archer_session: Optional[str] = Cookie(None)):
    """The user's threat-library test cases as a MACATable library TOML (MACAT/VECTR interop)."""
    import json as _json

    from archer.assessments.macat import test_cases_to_macatable
    from archer.database.models import ThreatTestCase

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"error": "Log in to export"}, status_code=401)
    user, db = auth
    try:
        rows = db.query(ThreatTestCase).filter(ThreatTestCase.user_id == user.id) \
            .order_by(ThreatTestCase.prevalence.desc(), ThreatTestCase.technique_id).all()
        cases = [{"signature": c.signature, "technique_id": c.technique_id, "technique_name": c.technique_name,
                  "tactic": c.tactic, "procedure": c.procedure, "atomic_guid": c.atomic_guid,
                  "group_name": c.group_name,
                  "indicators": _json.loads(c.indicators) if c.indicators else {}} for c in rows]
    finally:
        db.close()
    if not cases:
        return JSONResponse({"error": "No test cases to export. Build some first."}, status_code=404)
    toml = test_cases_to_macatable(cases)
    return Response(content=toml, media_type="application/toml",
                    headers={"Content-Disposition": 'attachment; filename="archer_threat_library.macatable.toml"'})


def _plan_siems(user) -> list:
    """The user's SIEM keys to validate in; all of them if none chosen."""
    return _user_siems(user) or list(SIEM_PLATFORMS.keys())


@app.post("/api/emulate/plan")
def emulate_plan(request: Request, kind: str = Form(...), value: str = Form(...),
                 archer_session: Optional[str] = Cookie(None)):
    """Build an emulation plan for a group, CVE or technique (#25)."""
    from archer.telemetry.planner import build_plan

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in to plan an emulation"}, status_code=401)
    user, db = auth
    db.close()
    v = value.strip()
    if not v:
        return JSONResponse({"success": False, "error": "Name a group, CVE or technique"}, status_code=400)
    target = sanitize_group_name(v) if kind in ("group", "cve") else v
    plan = build_plan(kind, target, _plan_siems(user), GENERATE_DIR)
    return JSONResponse(plan, status_code=200 if plan.get("success") else 404)


@app.get("/api/emulate/plan/export")
def emulate_plan_export(request: Request, kind: str = Query(...), value: str = Query(...),
                        fmt: str = Query("runsheet"), archer_session: Optional[str] = Cookie(None)):
    """Export an emulation plan as a Markdown run sheet or a MACATable library TOML."""
    from archer.telemetry.planner import build_plan, plan_to_runsheet, plan_to_test_cases

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"error": "Log in to export"}, status_code=401)
    user, db = auth
    db.close()
    target = sanitize_group_name(value.strip()) if kind in ("group", "cve") else value.strip()
    plan = build_plan(kind, target, _plan_siems(user), GENERATE_DIR)
    if not plan.get("success"):
        return JSONResponse({"error": plan.get("error", "No plan")}, status_code=404)
    safe = sanitize_filename(value.strip()) or kind
    if fmt == "macat":
        from archer.assessments.macat import test_cases_to_macatable

        body = test_cases_to_macatable(plan_to_test_cases(plan))
        return Response(content=body, media_type="application/toml",
                        headers={"Content-Disposition": f'attachment; filename="{safe}_emulation.macatable.toml"'})
    return Response(content=plan_to_runsheet(plan), media_type="text/markdown",
                    headers={"Content-Disposition": f'attachment; filename="{safe}_runsheet.md"'})


@app.get("/assessments/{assessment_id}", response_class=HTMLResponse)
def assessment_detail(assessment_id: int, request: Request, archer_session: Optional[str] = Cookie(None)):
    """One campaign: its test cases with red/blue outcomes, the detections and logs for each."""
    from archer.database.models import Assessment, AssessmentResult
    from archer.visualization.navigator import detection_files_for

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return auth
    user, db = auth
    try:
        a = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.user_id == user.id).first()
        if not a:
            db.close()
            return RedirectResponse("/assessments", status_code=303)
        results = db.query(AssessmentResult).filter(AssessmentResult.assessment_id == a.id) \
            .order_by(AssessmentResult.technique_id).all()
        rows = []
        for r in results:
            rows.append({
                "id": r.id, "technique_id": r.technique_id, "technique_name": r.technique_name,
                "tactic": r.tactic, "red_outcome": r.red_outcome, "blue_outcome": r.blue_outcome,
                "detection_file": r.detection_file, "notes": r.notes,
                "detections": len(detection_files_for(GENERATE_DIR, r.technique_id)),
            })
        meta = {"id": a.id, "name": a.name, "target": a.target, "operator": a.operator, "run_date": a.run_date}
    finally:
        db.close()
    return templates.TemplateResponse("assessment_detail.html", {
        "request": request, "user": user, "assessment": meta, "results": rows})


@app.post("/api/assessments/{assessment_id}/add")
def assessment_add_cases(assessment_id: int, request: Request, tactic: str = Form(""),
                         archer_session: Optional[str] = Cookie(None)):
    """Add the library's test cases (optionally one tactic) to an assessment as not-run results."""
    from archer.database.models import Assessment, AssessmentResult, ThreatTestCase

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in"}, status_code=401)
    user, db = auth
    try:
        a = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.user_id == user.id).first()
        if not a:
            return JSONResponse({"success": False, "error": "No such assessment"}, status_code=404)
        q = db.query(ThreatTestCase).filter(ThreatTestCase.user_id == user.id)
        if tactic.strip():
            q = q.filter(ThreatTestCase.tactic.like(f"%{tactic.strip()}%"))
        have = {tid for (tid,) in db.query(AssessmentResult.test_case_id)
                .filter(AssessmentResult.assessment_id == a.id) if tid}
        added = 0
        for c in q.all():
            if c.id in have:
                continue
            db.add(AssessmentResult(assessment_id=a.id, user_id=user.id, test_case_id=c.id,
                                    technique_id=c.technique_id, technique_name=c.technique_name,
                                    tactic=c.tactic))
            added += 1
        db.commit()
    finally:
        db.close()
    return JSONResponse({"success": True, "added": added})


@app.post("/api/assessments/result/{result_id}")
def assessment_update_result(result_id: int, request: Request, red_outcome: str = Form(None),
                             blue_outcome: str = Form(None), detection_file: str = Form(None),
                             notes: str = Form(None), archer_session: Optional[str] = Cookie(None)):
    """Record a test case's red and blue outcome."""
    from archer.database.models import AssessmentResult

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in"}, status_code=401)
    user, db = auth
    try:
        r = db.query(AssessmentResult).filter(AssessmentResult.id == result_id,
                                              AssessmentResult.user_id == user.id).first()
        if not r:
            return JSONResponse({"success": False, "error": "No such result"}, status_code=404)
        reds = {"not_run", "executed", "failed", "blocked"}
        blues = {"not_assessed", "not_logged", "logged", "alerted", "prevented"}
        if red_outcome is not None and red_outcome in reds:
            r.red_outcome = red_outcome
        if blue_outcome is not None and blue_outcome in blues:
            r.blue_outcome = blue_outcome
        if detection_file is not None:
            r.detection_file = detection_file.strip() or None
        if notes is not None:
            r.notes = notes.strip() or None
        db.commit()
    finally:
        db.close()
    return JSONResponse({"success": True})


@app.post("/api/assessments/{assessment_id}/delete")
def assessment_delete(assessment_id: int, request: Request, archer_session: Optional[str] = Cookie(None)):
    """Delete an assessment and its results."""
    from archer.database.models import Assessment, AssessmentResult

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"success": False, "error": "Log in"}, status_code=401)
    user, db = auth
    try:
        a = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.user_id == user.id).first()
        if not a:
            return JSONResponse({"success": False, "error": "No such assessment"}, status_code=404)
        db.query(AssessmentResult).filter(AssessmentResult.assessment_id == a.id).delete()
        db.delete(a)
        db.commit()
    finally:
        db.close()
    return JSONResponse({"success": True})


@app.get("/api/assessments/{assessment_id}/export")
def assessment_export(assessment_id: int, request: Request, fmt: str = Query("csv"),
                      archer_session: Optional[str] = Cookie(None)):
    """Download a campaign's outcomes as CSV or an ATT&CK Navigator layer."""
    from archer.assessments.export import results_to_csv, results_to_navigator
    from archer.database.models import Assessment, AssessmentResult

    auth = require_auth(request, archer_session)
    if isinstance(auth, RedirectResponse):
        return JSONResponse({"error": "Log in"}, status_code=401)
    user, db = auth
    try:
        a = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.user_id == user.id).first()
        if not a:
            return JSONResponse({"error": "No such assessment"}, status_code=404)
        results = [{"technique_id": r.technique_id, "technique_name": r.technique_name, "tactic": r.tactic,
                    "red_outcome": r.red_outcome, "blue_outcome": r.blue_outcome,
                    "detection_file": r.detection_file, "notes": r.notes}
                   for r in db.query(AssessmentResult).filter(AssessmentResult.assessment_id == a.id)
                   .order_by(AssessmentResult.technique_id)]
        name = sanitize_filename(a.name) or f"assessment_{a.id}"
    finally:
        db.close()
    if fmt == "navigator":
        return Response(content=results_to_navigator(a.name, results), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{name}_navigator.json"'})
    return Response(content=results_to_csv(results), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}.csv"'})


@app.get("/catalogue", response_class=HTMLResponse)
def catalogue_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Every organisation profiled so far (data/profiles/*_profile.json), newest first, each linking
    to its exposure map. Like the Library, but for company OSINT rather than detections.
    """
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return auth_result
    user, db = auth_result
    db.close()

    companies = []
    profiles_dir = Path("data") / "profiles"
    if profiles_dir.is_dir():
        for path in profiles_dir.glob("*_profile.json"):
            try:
                with open(path, encoding="utf-8") as fh:
                    prof = json.load(fh)
            except (OSError, ValueError):
                continue
            ci = prof.get("company_info") or {}
            osint = prof.get("osint") or {}
            net = ci.get("networks") or {}
            domain = prof.get("domain") or ci.get("domain")
            if not domain:
                continue
            companies.append({
                "domain": domain,
                "name": ci.get("company_name") or domain,
                "country": ci.get("country"),
                "risk": prof.get("risk_score") or 0,
                "groups": len(prof.get("recommended_groups") or []),
                "timestamp": prof.get("timestamp"),
                "ips": len(ci.get("ip_addresses") or []),
                "subdomains": len(osint.get("subdomains") or []),
                "asns": len(net.get("asns") or []),
                "hosting": net.get("hosting_countries") or [],
                "breaches": (prof.get("breach_surface") or {}).get("count") or 0,
            })
    companies.sort(key=lambda c: c["timestamp"] or "", reverse=True)
    return templates.TemplateResponse("catalogue.html", {"request": request, "user": user, "companies": companies})


@app.get("/profile-progress", response_class=HTMLResponse)
def profile_progress_page(request: Request, domain: str = "", group_name: str = "",
                          archer_session: Optional[str] = Cookie(None)):
    """While a company profile runs in the background, the same style of progress page as a hunt.
    When the profiler finishes it redirects to the Review page for the domain."""
    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()
    return templates.TemplateResponse("profile_progress.html",
                                      {"request": request, "user": user, "domain": domain, "group_name": group_name})


def _load_profile(domain: str):
    """A saved profile for a domain and its sanitised name, or (None, safe) if there isn't one."""
    safe = (domain or "").strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    safe_file = re.sub(r"[^a-z0-9._-]", "_", safe).replace(".", "_")
    profiles_dir = Path("data") / "profiles"
    path = profiles_dir / f"{safe_file}_profile.json"
    if safe_file and os.path.dirname(os.path.abspath(path)) == os.path.abspath(profiles_dir) and path.is_file():
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh), safe
        except (OSError, ValueError):
            pass
    return None, safe


@app.get("/review", response_class=HTMLResponse)
def review_page(request: Request, domain: str, archer_session: Optional[str] = Cookie(None)):
    """
    The Review page for a profiled company: its branding, the profile summary, the exposure map and
    the recommended threat groups (each with a likelihood of targeting the organisation) to generate
    detections for. Replaces the old selection modal. Reads the saved profile under data/profiles/.
    """
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return auth_result
    user, db = auth_result
    db.close()

    profile, safe = _load_profile(domain)
    if not profile:
        # No profile yet: send them back to start one
        return RedirectResponse(url="/", status_code=303)

    from archer.visualization import exposure as exposure_mod
    expo = exposure_mod.build(profile)

    ci = profile.get("company_info") or {}
    tp = profile.get("threat_profile") or {}
    ind = tp.get("industry") or {}
    geo = tp.get("geography") or {}
    details = profile.get("recommended_group_details")
    if not details:  # older profiles have only the flat name list
        details = [{"name": g, "likelihood": None, "band": None, "sources": []}
                   for g in (profile.get("recommended_groups") or [])]
    hosted = ", ".join(x for x in (geo.get("hosting_region"), geo.get("hosting_country")) if x)
    summary = {
        "company": ci.get("company_name") or safe,
        "industry": ind.get("sector"),
        "subsector": ind.get("subsector"),
        "location": ", ".join(x for x in (geo.get("region"), geo.get("country")) if x),
        "hosting": hosted if geo.get("hosting_country") and geo.get("hosting_country") != geo.get("country") else "",
        "source": "; ".join((ci.get("identity") or {}).get("evidence") or []),
        "products": profile.get("detected_stack") or [],
        "risk_score": profile.get("risk_score") or 0,
    }
    return templates.TemplateResponse("review.html", {
        "request": request, "user": user, "domain": safe, "exposure": expo,
        "summary": summary, "groups": details, "group_count": len(details),
    })


LIBRARY_VENDORS = (("googlesecops", "Google SecOps"), ("mde", "Defender XDR"), ("splunk", "Splunk"), ("elastic", "Elastic"))
# Elastic is generated (ES|QL); nothing is Coming Soon
LIBRARY_COMING_SOON = set()


def _library_vendor_key(name: str) -> str:
    key = re.sub(r"[\s_-]+", "", str(name or "")).lower()
    return {"microsoft": "mde", "defenderxdr": "mde", "google": "googlesecops", "secops": "googlesecops"}.get(key, key)


def _library_vendor_slots(items: list, kind: str) -> list:
    """The Library's vendor sections: one per SIEM in Archer's order (Google SecOps, Defender XDR,
    Splunk, Elastic), empty ones included, then anything else by name."""
    by_key = {}
    for v in items:
        key = _library_vendor_key(v["name"])
        if key in by_key:  # e.g. "mde" and "microsoft"
            by_key[key][kind] += v[kind]
            by_key[key]["count"] += v["count"]
        else:
            by_key[key] = {**v, "name": key}
    slots = []
    for key, display in LIBRARY_VENDORS:
        slot = by_key.pop(key, None) or {"name": key, "display_name": display, "count": 0, kind: [],
                                          "empty_state": True}
        slot["display_name"] = display
        if key in LIBRARY_COMING_SOON and not slot["count"]:
            slot.pop("empty_state", None)
            slot["coming_soon"] = True
        slots.append(slot)
    return slots + sorted(by_key.values(), key=lambda v: v["name"])


@app.get("/library", response_class=HTMLResponse)
async def library_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Render the Library page for managing saved detections and correlations.
    """
    from archer.database.models import LibraryDetection, LibraryCorrelation
    import json

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return auth_result

    user, db = auth_result

    try:
        # Vendor display names mapping
        VENDOR_DISPLAY_NAMES = {
            "splunk": "Splunk",
            "mde": "Defender XDR",
            "microsoft": "Defender XDR",
            "elastic": "Elastic",
            "googlesecops": "Google SecOps",
        }

        # Helper function to safely parse JSON fields
        def parse_json_field(field_value, default=None):
            if default is None:
                default = []
            if not field_value:
                return default
            if isinstance(field_value, list):
                return field_value
            if isinstance(field_value, str):
                try:
                    return json.loads(field_value)
                except (json.JSONDecodeError, ValueError):
                    return default
            return default

        from .build import attack_mapping
        from .visualization.navigator import technique_index

        tech_index = technique_index(getattr(app.state, "bundle", None))
        from .visualization.navigator import legacy as legacy_lookup

        legacy_techniques = legacy_lookup(getattr(app.state, "bundle", None))

        # Query all detections and correlations for this user
        detections = db.query(LibraryDetection).filter_by(user_id=user.id).all()
        correlations_db = db.query(LibraryCorrelation).filter_by(user_id=user.id).all()

        # Helper function to fix query indentation (4 spaces -> 2 spaces before pipes)
        def fix_query_indentation(query_text):
            """Fix over-indented pipe operators in KQL queries"""
            if not query_text:
                return query_text
            # Replace "    | " (4 spaces + pipe) with "  | " (2 spaces + pipe)
            return query_text.replace("    | ", "  | ")

        # Group by vendor and collect filter options
        vendors_dict = {}
        correlations_list = []
        all_groups = set()
        all_tactics = set()
        all_techniques = set()

        for det in detections:
            # Parse the content JSON to extract detection details
            try:
                content_data = (
                    library_content(det.content)
                )
            except (json.JSONDecodeError, ValueError):
                content_data = {}

            # Parse JSON fields safely
            tags = parse_json_field(det.tags, [])

            # Extract data from content JSON or YAML-like structure
            # Content can be a query string or a structured object
            if isinstance(content_data, dict):
                # Check if this is a detection object from results page (has 'technique' and 'queries' fields)
                # But NOT an imported YAML (which would have 'mde_tables' or 'splunk_indexes' or 'name' field)
                if (
                    "technique" in content_data
                    and "queries" in content_data
                    and "name" not in content_data
                    and "mde_tables" not in content_data
                    and "splunk_indexes" not in content_data
                ):
                    # This is a detection saved from results page or imported YAML
                    # The "technique" field could be either technique_id (like "T1555.006") or technique_name
                    technique_value = content_data.get("technique") or det.title

                    # Check if technique_value looks like a technique ID (starts with T followed by digits)
                    import re

                    if re.match(r"^T\d{4}(\.\d{3})?$", technique_value):
                        # This is a technique ID, look up the name
                        tech_info = _get_technique_info(technique_value)
                        if tech_info:
                            technique_name = tech_info.get("name", technique_value)
                            technique_id = technique_value
                            tactics = [tech_info.get("tactic", "Unknown")]
                        else:
                            # Lookup failed, use ID as name
                            technique_name = technique_value
                            technique_id = technique_value
                            tactics = []
                    else:
                        # This is a technique name, look up the ID
                        technique_name = technique_value
                        tech_info = _get_technique_info_by_name(technique_name)
                        if tech_info:
                            technique_id = tech_info.get("tid", "")
                            tactics = tech_info.get("tactics", [])
                        else:
                            technique_id = ""
                            tactics = []

                    description = content_data.get("description", "")
                    queries = content_data.get("queries", [])
                    query_content = "\n\n".join(queries) if queries else ""

                    # Extract data source from title (format: "title1, title2, etc")
                    title_parts = content_data.get("title", "").split(", ")
                    data_source = title_parts[0] if title_parts else det.platform or "Unknown"

                    # Extract indicators
                    indicators = parse_json_field(content_data.get("indicators"), [])

                    # Group name not in detection object, will extract from tags
                    group_name = "Unknown"

                    # Check if OSINT enriched
                    osint_enriched = content_data.get("osint_enriched", False)
                    osint_data = None  # Results page detections don't have osint_data

                    # No MDE tables/Splunk indexes for results page detections
                    mde_tables = []
                    splunk_indexes = []

                # Check if this is a YAML-like structure (has 'name' and 'requiredDataConnectors')
                # OR if it's an imported YAML detection (has 'technique', 'queries', and other YAML fields)
                elif (
                    "name" in content_data
                    or "requiredDataConnectors" in content_data
                    or "technique_id" in content_data
                    or (
                        "technique" in content_data
                        and "queries" in content_data
                        and isinstance(content_data.get("queries"), list)
                    )
                ):
                    # This is a YAML detection (either from data/groups or imported via import_yaml_to_library.py)
                    technique_id = content_data.get("technique", "") or content_data.get(
                        "technique_id", ""
                    )

                    # Look up technique name and tactics from MITRE ATT&CK using technique ID
                    tech_info = _get_technique_info(technique_id) if technique_id else None
                    if tech_info:
                        technique_name = tech_info.get("name", technique_id)
                        # We'll extract tactics from content_data below, but tech_info provides fallback
                    else:
                        # Fallback to technique ID if lookup fails (don't use detection title)
                        technique_name = technique_id or content_data.get("name", "Unknown")

                    description = library_description_html(content_data)

                    # Get query from queries array or query field
                    queries = content_data.get("queries", [])
                    if queries:
                        query_content = "\n\n".join(queries)
                    else:
                        query_content = content_data.get("query") or str(content_data)

                    # Use data_source from imported format (platform name like "mde"), not table names
                    data_source = content_data.get("data_source") or det.platform or "Unknown"

                    # Get MDE tables and Splunk indexes separately
                    mde_tables = parse_json_field(content_data.get("mde_tables"), [])
                    splunk_indexes = parse_json_field(content_data.get("splunk_indexes"), [])

                    # Extract indicators from the indicators dict
                    indicators_dict = content_data.get("indicators", {})
                    if isinstance(indicators_dict, dict):
                        # Flatten all indicator values into a single list
                        indicators = []
                        for category, items in indicators_dict.items():
                            if isinstance(items, list):
                                indicators.extend(items)
                            elif items:
                                indicators.append(str(items))
                        # Deduplicate while preserving order
                        indicators = list(dict.fromkeys(indicators))
                    else:
                        indicators = parse_json_field(indicators_dict, [])
                        # Deduplicate while preserving order
                        indicators = list(dict.fromkeys(indicators))

                    # Extract tactics
                    tactics = parse_json_field(content_data.get("tactics"), [])
                    if not tactics:
                        # Try extracting from single tactic field
                        single_tactic = content_data.get("tactic")
                        if single_tactic and single_tactic != "Unknown":
                            tactics = [single_tactic]

                    # Extract group/threat actor
                    group_name = content_data.get("group") or content_data.get(
                        "threat_actor", "Unknown"
                    )

                    # Check if OSINT enriched
                    osint_enriched = content_data.get("osint_enriched") or content_data.get(
                        "osint_enhanced", False
                    )

                    # Extract OSINT data if available
                    osint_data = None
                    if osint_enriched and "osint_indicators" in content_data:
                        osint_data = {
                            "indicators": content_data.get("osint_indicators", {}),
                            "enrichment_date": content_data.get("comparison_date", ""),
                        }

                # Check if this is a correlation object (has 'techniques' and 'combined_query')
                elif "techniques" in content_data and "combined_query" in content_data:
                    # This is a correlation saved from results page - preserve ALL correlation fields
                    techniques = content_data.get("techniques", [])
                    technique_name = " + ".join([t.get("name", "") for t in techniques])
                    technique_id = " + ".join([t.get("id", "") for t in techniques])
                    description = f"Correlation between {len(techniques)} techniques"
                    query_content = content_data.get("combined_query", "")
                    data_source = content_data.get("vendor", det.platform or "Unknown")
                    indicators = []  # Correlations don't have indicators in this structure
                    tactics = parse_json_field(content_data.get("tactics"), [])
                    group_name = "Unknown"
                    osint_enriched = False
                    osint_data = None
                    mde_tables = []
                    splunk_indexes = []

                    # IMPORTANT: Store the original correlation data for rendering attack flows
                    # This will be added to detection_data below as correlation-specific fields

                # Check if this is a detection saved from results page
                # Results page detections have: technique, title, description, and optionally: query, indicators, tactic, etc.
                # But NOT queries (plural) or technique_id
                elif (
                    "technique" in content_data
                    and "title" in content_data
                    and "queries" not in content_data
                    and "technique_id" not in content_data
                ):
                    # This is a detection saved from results page (may have full data or minimal data)
                    technique_name = content_data.get(
                        "technique_display", content_data.get("technique", det.title)
                    )
                    technique_id = (
                        content_data.get("technique", "")
                        if content_data.get("technique", "").startswith("T")
                        else ""
                    )
                    description = library_description_html(content_data)
                    # Results page has "query" (singular), not "queries" (plural)
                    query_content = content_data.get("query", "")
                    # Use platform for vendor, title contains table/index names
                    data_source = det.platform or "Unknown"
                    # Store the table/index names separately
                    title_value = content_data.get("title", "")
                    if det.platform and det.platform.lower() in ["mde", "microsoft"]:
                        mde_tables = [title_value] if title_value else []
                        splunk_indexes = []
                    else:
                        mde_tables = []
                        splunk_indexes = [title_value] if title_value else []
                    indicators = content_data.get("indicators", [])
                    # Results page has "tactic" (singular primary tactic) and "tactics" (array)
                    primary_tactic = content_data.get("tactic", "Unknown")
                    tactics = content_data.get(
                        "tactics", [primary_tactic] if primary_tactic != "Unknown" else []
                    )
                    group_name = "Unknown"  # Will extract from tags
                    osint_enriched = content_data.get("osint_enriched", False)
                    osint_data = content_data.get("osint_data") if osint_enriched else None

                else:
                    # Unknown structure, use defaults
                    technique_name = det.title
                    technique_id = ""
                    description = ""
                    query_content = str(content_data)
                    data_source = det.platform or "Unknown"
                    indicators = []
                    tactics = []
                    group_name = "Unknown"
                    osint_enriched = False
                    osint_data = None
                    mde_tables = []
                    splunk_indexes = []
            else:
                # Content is just a query string
                technique_name = det.title
                technique_id = ""
                description = ""
                query_content = str(content_data)
                data_source = det.platform or ""
                indicators = []
                tactics = []
                group_name = "Unknown"
                osint_enriched = False
                osint_data = None
                mde_tables = []
                splunk_indexes = []

            # Extract group from tags if not found in content
            if group_name == "Unknown":
                for tag in tags:
                    if tag.startswith("Group:"):
                        group_name = tag.replace("Group:", "").strip()
                        break

            # Build detection data object to match results.html structure
            # Format title as comma-separated data sources (matching results page)
            if mde_tables:
                formatted_title = ", ".join(mde_tables)
            elif splunk_indexes:
                formatted_title = ", ".join(splunk_indexes)
            else:
                formatted_title = data_source or det.platform or "Unknown"

            # ATT&CK mapping as the copy holds it (archer.build.attack_mapping); none for correlations
            mapping_state = (attack_mapping.content_state(content_data, tech_index)
                             if isinstance(content_data, dict) and "combined_query" not in content_data else None)
            detection_data = {
                "id": det.id,
                "attack_id": mapping_state["mapping"]["technique_id"] if mapping_state else "",
                "attack_tactics": mapping_state["mapping"]["tactics"] if mapping_state else [],
                "rule_name": mapping_state["mapping"]["rule_name"] if mapping_state else None,
                "attack_mapping_history": mapping_state["history"] if mapping_state else [],
                "legacy": legacy_techniques.get(mapping_state["mapping"]["technique_id"]) if mapping_state else None,
                "technique": technique_name,  # Changed: now the technique name, not ID (matching results page)
                "title": formatted_title,  # Changed: now the data sources, not technique name (matching results page)
                "data_source": data_source or det.platform or "Unknown",
                "description_html": description,
                "queries": [fix_query_indentation(query_content)] if query_content else [],
                "indicators": indicators,
                "mde_tables": mde_tables,
                "splunk_indexes": splunk_indexes,
                "tags": tags,
                "group": group_name,
                "tactic": tactics[0] if tactics else "Unknown",
                "saved_date": det.created_at.strftime("%Y-%m-%d") if det.created_at else "",
                "attack_override": content_data.get("attack_override"),  # ATT&CK mapping changed by hand
                "osint_enriched": osint_enriched,
                "osint_data": osint_data,
                "needs_review": False,  # Generated detections always have indicators
                "detection_likelihood": content_data.get(
                    "detection_likelihood", 75
                ),  # Added to match results page
                **(_assessment(content_data) if isinstance(content_data, dict) and "combined_query" not in content_data
                   else {}),
                # Add correlation-specific fields from content_data (for attack flow visualization)
                "is_merged": content_data.get("is_merged", False),
                "techniques": content_data.get("techniques", []),
                "severity": content_data.get("severity"),
                "attack_chain_length": content_data.get("attack_chain_length"),
                "relevance_score": content_data.get("relevance_score"),
                "time_window": content_data.get("time_window"),
                "primary_tactics": content_data.get("primary_tactics", []),
                "techniques_by_tactic": content_data.get("techniques_by_tactic", {}),
                "technique_tactic_map": content_data.get("technique_tactic_map", {}),
                "tables_indexes": content_data.get("tables_indexes", []),
                "combined_query": content_data.get("combined_query", ""),
                "individual_queries": content_data.get("individual_queries", []),
            }

            # Normalize vendor/platform based on query content and data sources
            # This fixes cases where data_source was set to index names (mcafee, unix, etc.)
            normalized_vendor = data_source or det.platform or "unknown"

            # If query starts with "index=", it's a Splunk detection
            if query_content and query_content.strip().lower().startswith("index="):
                normalized_vendor = "splunk"
            # YARA-L rule, or a SecOps data source under any of its spellings
            elif (query_content and query_content.lstrip().startswith("rule ")) or any(
                k in normalized_vendor.lower().replace(" ", "").replace("_", "") for k in ("secops", "yaral")
            ):
                normalized_vendor = "googlesecops"
            # If MDE tables present, it's an MDE detection
            elif mde_tables and len(mde_tables) > 0:
                normalized_vendor = "mde"
            # If data_source is "MDE" or contains "MDE", it's an MDE detection
            elif normalized_vendor.lower() == "mde" or "mde" in normalized_vendor.lower():
                normalized_vendor = "mde"
            # If data_source is "Microsoft" or "microsoft", it's an MDE detection
            elif normalized_vendor.lower() in ["microsoft", "microsoft defender"]:
                normalized_vendor = "mde"
            # Normalize common Splunk index names to "splunk"
            elif normalized_vendor.lower() in [
                "mcafee",
                "unix",
                "windows",
                "linux",
                "network",
                "firewall",
                "web",
            ]:
                normalized_vendor = "splunk"
            # Otherwise keep the data_source/platform as-is

            vendor = normalized_vendor.lower()
            if vendor not in vendors_dict:
                vendors_dict[vendor] = []

            # Check if this is a correlation (detection_type contains "correlation")
            # Handle both enum value ("sole_correlation") and enum name ("SOLE_CORRELATION")
            detection_type_str = str(det.detection_type).lower() if det.detection_type else ""
            detection_type_name = (
                det.detection_type.name.lower() if hasattr(det.detection_type, "name") else ""
            )
            is_correlation = (
                "correlation" in detection_type_str or "correlation" in detection_type_name
            )

            if is_correlation:
                # Add to correlations list instead of vendors
                correlations_list.append(detection_data)
            else:
                # Add to vendors dict
                vendors_dict[vendor].append(detection_data)

            # Collect filter options
            all_groups.add(group_name)
            if technique_id:
                all_techniques.add(technique_id)
            for tactic in tactics:
                all_tactics.add(tactic)

        # Process correlations from LibraryCorrelation table
        for corr in correlations_db:
            # Parse the content JSON
            try:
                content_data = (
                    library_content(corr.content)
                )
            except (json.JSONDecodeError, ValueError):
                content_data = {}

            # Parse JSON fields safely
            tags = parse_json_field(corr.tags, [])

            # Extract correlation data from content
            if isinstance(content_data, dict):
                technique_name = content_data.get("technique", corr.title)
                technique_id = content_data.get("technique_id", "")
                description = content_data.get("description", "")
                queries = content_data.get("queries", [])
                query_content = "\n\n".join(queries) if queries else ""
                data_source = content_data.get("data_source", corr.platform or "Unknown")
                indicators = parse_json_field(content_data.get("indicators"), [])
                tactics = content_data.get("tactics", [])
                mde_tables = content_data.get("mde_tables", [])
                splunk_indexes = content_data.get("splunk_indexes", [])
                osint_enriched = content_data.get("osint_enriched", False)
                osint_data = content_data.get("osint_data")
                group_name = "Unknown"

                # Extract group from tags
                for tag in tags:
                    if tag.startswith("Group:"):
                        group_name = tag.replace("Group:", "").strip()
                        break

                # Format title as comma-separated data sources
                if mde_tables:
                    formatted_title = ", ".join(mde_tables)
                elif splunk_indexes:
                    formatted_title = ", ".join(splunk_indexes)
                else:
                    formatted_title = data_source

                # Create correlation data object
                correlation_data = {
                    "id": corr.id,
                    "technique": technique_name,
                    "title": formatted_title,
                    "data_source": data_source,
                    "description_html": description,
                    "queries": [fix_query_indentation(query_content)] if query_content else [],
                    "indicators": indicators,
                    "mde_tables": mde_tables,
                    "splunk_indexes": splunk_indexes,
                    "tags": tags,
                    "group": group_name,
                    "tactic": tactics[0] if tactics else "Unknown",
                    "tactics": tactics,
                    "saved_date": corr.created_at.strftime("%Y-%m-%d") if corr.created_at else "",
                    "osint_enriched": osint_enriched,
                    "osint_data": osint_data,
                    "needs_review": False,
                    "detection_likelihood": content_data.get("detection_likelihood", 75),
                    # Correlation-specific fields
                    "vendor": content_data.get(
                        "vendor", "unknown"
                    ),  # Query platform (Splunk, MDE, etc.)
                    "is_merged": content_data.get("is_merged", False),
                    "techniques": content_data.get("techniques", []),
                    "severity": content_data.get("severity"),
                    "attack_chain_length": content_data.get("attack_chain_length"),
                    "relevance_score": content_data.get("relevance_score"),
                    "time_window": content_data.get("time_window"),
                    "primary_tactics": content_data.get("primary_tactics", []),
                    "techniques_by_tactic": content_data.get("techniques_by_tactic", {}),
                    "technique_tactic_map": content_data.get("technique_tactic_map", {}),
                    "tables_indexes": content_data.get("tables_indexes", []),
                    "combined_query": content_data.get("combined_query", ""),
                    "individual_queries": content_data.get("individual_queries", []),
                }

                # Add to correlations list
                correlations_list.append(correlation_data)

                # Collect filter options
                all_groups.add(group_name)
                if technique_id:
                    all_techniques.add(technique_id)
                for tactic in tactics:
                    all_tactics.add(tactic)

        # Format vendors for template
        vendors = []
        for vendor_name, vendor_detections in vendors_dict.items():
            # Group detections by technique and description (like results.html does)
            grouped = {}
            for det in vendor_detections:
                technique = det.get("technique", "")
                description = det.get("description_html", "")
                key = (technique, description)

                if key not in grouped:
                    grouped[key] = {
                        "technique": technique,
                        "description_html": description,
                        "titles": [],
                        "queries": [],
                        "indicators": set(),
                        "mde_tables": set(),
                        "splunk_indexes": set(),
                        "tags": set(),
                        "group": det.get("group", "Unknown"),
                        "tactic": det.get("tactic", "Unknown"),
                        "tactics": set(det.get("tactics", [])),
                        "osint_enriched": det.get("osint_enriched", False),
                        "osint_data": det.get("osint_data"),
                        "detection_likelihood": det.get("detection_likelihood", 75),
                        "data_source": det.get("data_source", "Unknown"),
                        "ids": [],  # Track ALL detection IDs in this group
                        "attack_override": None,
                        "attack_id": det.get("attack_id", ""),
                        "attack_tactics": det.get("attack_tactics", []),
                        "rule_name": det.get("rule_name"),
                        "attack_mapping_history": [],
                        "legacy": det.get("legacy"),
                    }

                # Add this detection's ID to the group
                grouped[key]["ids"].append(det.get("id"))
                if det.get("attack_override") and not grouped[key]["attack_override"]:
                    grouped[key]["attack_override"] = det["attack_override"]
                if len(det.get("attack_mapping_history") or []) > len(grouped[key]["attack_mapping_history"]):
                    grouped[key]["attack_mapping_history"] = det["attack_mapping_history"]

                # Add title (data source)
                title = det.get("title", "")
                if title and title not in grouped[key]["titles"]:
                    grouped[key]["titles"].append(title)

                # Add queries
                for query in det.get("queries", []):
                    if query and query not in grouped[key]["queries"]:
                        grouped[key]["queries"].append(query)

                # Combine indicators
                for indicator in det.get("indicators", []):
                    grouped[key]["indicators"].add(indicator)

                # Combine MDE tables
                for table in det.get("mde_tables", []):
                    grouped[key]["mde_tables"].add(table)

                # Combine Splunk indexes
                for index in det.get("splunk_indexes", []):
                    grouped[key]["splunk_indexes"].add(index)

                # Combine tags
                for tag in det.get("tags", []):
                    grouped[key]["tags"].add(tag)

                # Combine tactics
                for tactic in det.get("tactics", []):
                    grouped[key]["tactics"].add(tactic)

            # Convert grouped data to list format
            detection_list = []
            for (technique, description), data in sorted(
                grouped.items(), key=lambda x: x[0][0].lower()
            ):
                # Sort titles and join with " | "
                sorted_titles = sorted(data["titles"])
                combined_title = " | ".join(sorted_titles)

                detection_list.append(
                    {
                        "ids": data["ids"],  # All IDs in this group
                        "id": (
                            data["ids"][0] if data["ids"] else None
                        ),  # First ID for backwards compatibility
                        "technique": technique,
                        "title": combined_title,
                        "data_source": data["data_source"],
                        "description_html": description,
                        "queries": data["queries"],
                        "indicators": sorted(list(data["indicators"])),
                        "mde_tables": sorted(list(data["mde_tables"])),
                        "splunk_indexes": sorted(list(data["splunk_indexes"])),
                        "tags": sorted(list(data["tags"])),
                        "group": data["group"],
                        "tactic": data["tactic"],
                        "tactics": sorted(list(data["tactics"])),
                        "osint_enriched": data["osint_enriched"],
                        "osint_data": data["osint_data"],
                        "detection_likelihood": data["detection_likelihood"],
                        "attack_override": data["attack_override"],
                        "ids": data["ids"],
                        "attack_id": data["attack_id"],
                        "attack_tactics": data["attack_tactics"],
                        "rule_name": data["rule_name"],
                        "attack_mapping_history": data["attack_mapping_history"],
                        "legacy": data["legacy"],
                    }
                )

            # Count total individual detections (sum of IDs across all groups)
            total_individual_detections = sum(len(det.get("ids", [])) for det in detection_list)

            vendors.append(
                {
                    "name": vendor_name,
                    "display_name": VENDOR_DISPLAY_NAMES.get(vendor_name, vendor_name.title()),
                    "count": total_individual_detections,  # Total individual detections (matching results.html)
                    "detections": detection_list,
                }
            )

        # Every SIEM, in Archer's order (Google SecOps first), whether or not it has items
        vendors = _library_vendor_slots(vendors, "detections")

        # Calculate summary statistics
        # Count detections that are NOT correlations (exclude correlation detection_types from LibraryDetection)
        total_detections = sum(
            1
            for d in detections
            if not d.detection_type
            or not (
                "correlation" in str(d.detection_type).lower()
                or (
                    hasattr(d.detection_type, "name")
                    and "correlation" in d.detection_type.name.lower()
                )
            )
        )

        # Count correlations from both tables (LibraryDetection with correlation type + LibraryCorrelation)
        total_correlations_from_detections = sum(
            1
            for d in detections
            if d.detection_type
            and (
                "correlation" in str(d.detection_type).lower()
                or (
                    hasattr(d.detection_type, "name")
                    and "correlation" in d.detection_type.name.lower()
                )
            )
        )
        total_correlations = total_correlations_from_detections + len(correlations_db)

        # Count unique techniques
        technique_count = len(all_techniques)

        # Calculate time saved statistics (matching results page calculation)
        # Manual approach: 2 hours per detection
        # Archer approach: 0.1 hours per detection (6 minutes average)
        manual_hours = round(total_detections * 2, 1)
        archer_hours = round(total_detections * 0.1, 2)
        hours_saved = round(manual_hours - archer_hours, 1)

        # Group correlations by vendor (matching results.html structure)
        correlations_by_vendor = {}
        for corr in correlations_list:
            # Use the vendor field from the correlation content
            # This vendor indicates the query platform (Splunk, MDE, etc.), not the data source
            # The vendor was already determined during correlation generation
            vendor = corr.get("vendor", "unknown").lower()

            if vendor not in correlations_by_vendor:
                correlations_by_vendor[vendor] = []
            correlations_by_vendor[vendor].append(corr)

        # Convert to list format similar to results.html
        grouped_correlations = []
        for vendor, vendor_corrs in correlations_by_vendor.items():
            # Normalize vendor name to lowercase for lookup
            vendor_lower = vendor.lower()
            grouped_correlations.append(
                {
                    "name": vendor_lower,
                    "display_name": VENDOR_DISPLAY_NAMES.get(vendor_lower, vendor),
                    "count": len(vendor_corrs),
                    "correlations": vendor_corrs,
                }
            )

        grouped_correlations = _library_vendor_slots(grouped_correlations, "correlations")

        from archer.visualization.flow_layouts import library_flows

        flows = library_flows(db, user.id, getattr(request.app.state, "bundle", None))
        # The threat groups and CVEs with an anatomy (Detections → Anatomy); the same pick as that page
        from archer.visualization.anatomy import has_anatomy

        anatomies = [f for f in flows if f["kind"] in ("Threat group", "CVE") and has_anatomy(f["group"])]
        # Denominators from the loaded ATT&CK: Library technique IDs include sub-techniques
        live = [o for o in (getattr(request.app.state, "bundle", None) or {}).get("objects", [])
                if not o.get("revoked") and not o.get("x_mitre_deprecated")]
        attack_techniques = sum(1 for o in live if o.get("type") == "attack-pattern")
        attack_tactics = sum(1 for o in live if o.get("type") == "x-mitre-tactic")

        template_response = templates.TemplateResponse(
            "library.html",
            {
                "request": request,
                "user": user,
                "detections": vendors,
                "correlations": grouped_correlations,
                "total_detections": total_detections,
                "total_correlations": total_correlations,
                "technique_count": technique_count,
                "all_groups": sorted(all_groups),
                "all_tactics": sorted(all_tactics),
                "all_techniques": sorted(filter(None, all_techniques)),
                "hours_saved": hours_saved,
                "manual_hours": manual_hours,
                "archer_hours": archer_hours,
                "flows": flows,
                "anatomies": anatomies,
                "attack_techniques": attack_techniques,
                "attack_tactics": attack_tactics,
            },
        )
        return template_response
    finally:
        db.close()


@app.get("/api/library/detections")
async def get_library_detections(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Get all library detections accessible to the user.
    Returns user's private detections + all shared detections.
    """
    from archer.database.models import LibraryDetection, VisibilityType

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        # Get user's private detections + all shared detections
        detections = (
            db.query(LibraryDetection)
            .filter(
                (LibraryDetection.user_id == user.id)
                | (LibraryDetection.visibility == VisibilityType.SHARED)
            )
            .order_by(LibraryDetection.created_at.desc())
            .all()
        )

        # Format response
        result = []
        for detection in detections:
            creator = db.query(User).filter(User.id == detection.user_id).first()

            # Extract OSINT sources from content if available
            osint_sources = []
            try:
                content_data = (
                    json.loads(detection.content)
                    if isinstance(detection.content, str)
                    else detection.content
                )
                if isinstance(content_data, dict) and "osint_sources" in content_data:
                    osint_sources = content_data["osint_sources"]
            except:
                pass

            result.append(
                {
                    "id": detection.id,
                    "title": detection.title,
                    "detection_type": detection.detection_type.value,
                    "visibility": detection.visibility.value,
                    "creator": creator.full_name if creator else "Unknown",
                    "creator_email": creator.email if creator else "",
                    "platform": detection.platform,
                    "tags": detection.tags,
                    "created_at": detection.created_at.isoformat(),
                    "is_owner": detection.user_id == user.id,
                    "osint_sources": osint_sources,
                }
            )

        return {"success": True, "detections": result}

    except Exception as e:
        logger.error(f"Error fetching library detections: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch detections")
    finally:
        db.close()


@app.post("/api/library/search")
async def search_library(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Search library detections with filters.
    """
    from archer.database.models import LibraryDetection, VisibilityType, DetectionType

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        body = await request.json()
        query_text = body.get("query", "").strip()
        type_filter = body.get("type_filter", "all")
        visibility_filter = body.get("visibility_filter", "all")
        creator_filter = body.get("creator_filter", "all")

        # Build base query
        query = db.query(LibraryDetection).filter(
            (LibraryDetection.user_id == user.id)
            | (LibraryDetection.visibility == VisibilityType.SHARED)
        )

        # Apply search filter (search in title, content, AND tags)
        if query_text:
            query = query.filter(
                (LibraryDetection.title.contains(query_text))
                | (LibraryDetection.content.contains(query_text))
                | (LibraryDetection.tags.contains(query_text))
            )

        # Apply type filter
        if type_filter != "all":
            query = query.filter(LibraryDetection.detection_type == DetectionType(type_filter))

        # Apply visibility filter
        if visibility_filter != "all":
            query = query.filter(LibraryDetection.visibility == VisibilityType(visibility_filter))

        detections = query.order_by(LibraryDetection.created_at.desc()).all()

        # Format response and apply creator filter
        result = []
        for detection in detections:
            creator = db.query(User).filter(User.id == detection.user_id).first()
            creator_name = creator.username if creator else "Unknown"

            # Apply creator filter
            if creator_filter != "all" and creator_name != creator_filter:
                continue
            result.append(
                {
                    "id": detection.id,
                    "title": detection.title,
                    "detection_type": detection.detection_type.value,
                    "visibility": detection.visibility.value,
                    "creator": creator.full_name if creator else "Unknown",
                    "creator_email": creator.email if creator else "",
                    "platform": detection.platform,
                    "tags": detection.tags,
                    "created_at": detection.created_at.isoformat(),
                    "is_owner": detection.user_id == user.id,
                }
            )

        return {"success": True, "detections": result}

    except Exception as e:
        logger.error(f"Error searching library: {e}")
        raise HTTPException(status_code=500, detail="Failed to search library")
    finally:
        db.close()


@app.post("/api/library/export")
async def export_library(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Export selected detections in specified format (json, csv, xml).
    """
    from archer.database.models import LibraryDetection, VisibilityType
    import json
    import csv
    import io
    from fastapi.responses import StreamingResponse

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        body = await request.json()
        detection_ids = body.get("ids", [])
        correlation_ids = body.get("correlation_ids", [])
        export_format = body.get("format", "json")  # json, csv, xml, docx, pdf
        direct_export_data = body.get("export_data", None)  # Direct export data from results page
        group_name = body.get("group_name", "Report")  # Group name for report title
        report_metadata = body.get("metadata", {})  # Additional metadata from results page

        # If direct export data provided (from results page), use it directly
        if direct_export_data:
            export_data = [dict(item, content=with_osint(item.get("content"))) for item in direct_export_data]
        else:
            # Original flow: Get data from library using IDs
            if not detection_ids and not correlation_ids:
                raise HTTPException(
                    status_code=400, detail="No detections or correlations selected"
                )

            # Get detections
            detections = []
            if detection_ids:
                detections = (
                    db.query(LibraryDetection)
                    .filter(
                        LibraryDetection.id.in_(detection_ids),
                        (LibraryDetection.user_id == user.id)
                        | (LibraryDetection.visibility == VisibilityType.SHARED),
                    )
                    .all()
                )

            # Get correlations
            correlations = []
            if correlation_ids:
                from archer.database.models import LibraryCorrelation

                correlations = (
                    db.query(LibraryCorrelation)
                    .filter(
                        LibraryCorrelation.id.in_(correlation_ids),
                        (LibraryCorrelation.user_id == user.id)
                        | (LibraryCorrelation.visibility == VisibilityType.SHARED),
                    )
                    .all()
                )

            if not detections and not correlations:
                raise HTTPException(status_code=404, detail="No detections or correlations found")

            # Prepare data from library
            export_data = []
            for detection in detections:
                creator = db.query(User).filter(User.id == detection.user_id).first()
                export_data.append(
                    {
                        "id": detection.id,
                        "title": detection.title,
                        "type": detection.detection_type.value,
                        "visibility": detection.visibility.value,
                        "creator": creator.full_name if creator else "Unknown",
                        "platform": detection.platform,
                        "content": library_content(detection.content) if detection.content else {},
                        "created_at": detection.created_at.isoformat(),
                    }
                )

        # Export based on format
        if export_format == "json":
            content = json.dumps(export_data, indent=2)
            media_type = "application/json"
            filename = "library_export.json"

        elif export_format == "csv":
            output = io.StringIO()
            writer = csv.DictWriter(
                output,
                fieldnames=[
                    "id",
                    "title",
                    "type",
                    "visibility",
                    "creator",
                    "platform",
                    "created_at",
                ],
            )
            writer.writeheader()
            for item in export_data:
                writer.writerow(
                    {
                        "id": item["id"],
                        "title": item["title"],
                        "type": item["type"],
                        "visibility": item["visibility"],
                        "creator": item["creator"],
                        "platform": item["platform"],
                        "created_at": item["created_at"],
                    }
                )
            content = output.getvalue()
            media_type = "text/csv"
            filename = "library_export.csv"

        elif export_format == "xml":
            xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<library>"]
            for item in export_data:
                xml_lines.append("  <detection>")
                xml_lines.append(f'    <id>{item["id"]}</id>')
                xml_lines.append(f'    <title><![CDATA[{item["title"]}]]></title>')
                xml_lines.append(f'    <type>{item["type"]}</type>')
                xml_lines.append(f'    <visibility>{item["visibility"]}</visibility>')
                xml_lines.append(f'    <creator><![CDATA[{item["creator"]}]]></creator>')
                xml_lines.append(f'    <platform>{item["platform"]}</platform>')
                xml_lines.append(f'    <created_at>{item["created_at"]}</created_at>')
                xml_lines.append("  </detection>")
            xml_lines.append("</library>")
            content = "\n".join(xml_lines)
            media_type = "application/xml"
            filename = "library_export.xml"

        elif export_format == "docx":
            # Generate Word document report
            from archer.reports.generator import WordReportGenerator

            # Prepare detection data for report
            report_detections = []
            for item in export_data:
                # Skip correlations in this loop
                if item.get("type") == "correlation":
                    continue

                content_data = item.get("content", {})
                detection_dict = {
                    "technique": content_data.get("technique", item["title"]),
                    "technique_id": content_data.get("technique", ""),
                    "tactic": content_data.get("tactic", "Unknown"),
                    "data_source": item["platform"],
                    "queries": content_data.get("queries", []),
                    "description_html": content_data.get("description", ""),
                    "indicators": content_data.get("indicators", []),
                    "vendor": item["platform"],
                    "severity": content_data.get("severity", "Medium"),
                    "detection_likelihood": content_data.get("detection_likelihood", 75),
                }
                report_detections.append(detection_dict)

            # Prepare correlation data for report
            report_correlations = []
            if direct_export_data:
                # When using direct export data, extract correlations from export_data
                for item in export_data:
                    if item.get("type") == "correlation":
                        content_data = item.get("content", {})
                        correlation_dict = {
                            "name": item.get("title", "Untitled Correlation"),
                            "techniques": content_data.get("techniques", []),
                            "severity": content_data.get("severity", "High"),
                            "time_window": content_data.get("time_window", "N/A"),
                            "vendor": item.get("platform", "Multi-platform"),
                            "combined_query": content_data.get("combined_query", ""),
                        }
                        report_correlations.append(correlation_dict)
            else:
                # Original flow: Get correlations from database query result
                for corr in correlations:
                    corr_content = (
                        library_content(corr.content)
                    )
                    correlation_dict = {
                        "name": corr.title,
                        "techniques": corr_content.get("techniques", []),
                        "severity": corr_content.get("severity", "High"),
                        "time_window": corr_content.get("time_window", "N/A"),
                        "vendor": corr.platform or "Multi-platform",
                        "combined_query": corr_content.get("combined_query", ""),
                    }
                    report_correlations.append(correlation_dict)

            # Extract group name - use provided group_name first, then from content
            report_group_name = group_name  # Use provided group_name from request
            if not report_group_name or report_group_name == "Report":
                # Fall back to extracting from content
                report_group_name = "Detection Library"
                if report_detections and len(report_detections) > 0:
                    first_content = export_data[0].get("content", {})
                    report_group_name = first_content.get("group", "Detection Library")
                elif report_correlations and len(report_correlations) > 0:
                    report_group_name = "Correlation Rules"

            generator = WordReportGenerator()
            # Merge user info with additional metadata from request
            full_metadata = {
                "user": user.full_name if hasattr(user, "full_name") else "Archer User",
                **report_metadata,  # Include metrics, stats, etc. from results page
            }
            content_bytes = generator.generate(
                group_name=report_group_name,
                detections=report_detections,
                correlations=report_correlations if report_correlations else None,
                metadata=full_metadata,
            )

            media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            filename = f"{report_group_name.replace(' ', '_')}_report.docx"

            return StreamingResponse(
                io.BytesIO(content_bytes),
                media_type=media_type,
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

        elif export_format == "pdf":
            # Generate PDF report
            from archer.reports.generator import PDFReportGenerator

            # Prepare detection data for report
            report_detections = []
            for item in export_data:
                # Skip correlations in this loop
                if item.get("type") == "correlation":
                    continue

                content_data = item.get("content", {})
                detection_dict = {
                    "technique": content_data.get("technique", item["title"]),
                    "technique_id": content_data.get("technique", ""),
                    "tactic": content_data.get("tactic", "Unknown"),
                    "data_source": item["platform"],
                    "queries": content_data.get("queries", []),
                    "description_html": content_data.get("description", ""),
                    "indicators": content_data.get("indicators", []),
                    "vendor": item["platform"],
                    "severity": content_data.get("severity", "Medium"),
                    "detection_likelihood": content_data.get("detection_likelihood", 75),
                }
                report_detections.append(detection_dict)

            # Prepare correlation data for report
            report_correlations = []
            if direct_export_data:
                # When using direct export data, extract correlations from export_data
                for item in export_data:
                    if item.get("type") == "correlation":
                        content_data = item.get("content", {})
                        correlation_dict = {
                            "name": item.get("title", "Untitled Correlation"),
                            "techniques": content_data.get("techniques", []),
                            "severity": content_data.get("severity", "High"),
                            "time_window": content_data.get("time_window", "N/A"),
                            "vendor": item.get("platform", "Multi-platform"),
                            "combined_query": content_data.get("combined_query", ""),
                        }
                        report_correlations.append(correlation_dict)
            else:
                # Original flow: Get correlations from database query result
                for corr in correlations:
                    corr_content = (
                        library_content(corr.content)
                    )
                    correlation_dict = {
                        "name": corr.title,
                        "techniques": corr_content.get("techniques", []),
                        "severity": corr_content.get("severity", "High"),
                        "time_window": corr_content.get("time_window", "N/A"),
                        "vendor": corr.platform or "Multi-platform",
                        "combined_query": corr_content.get("combined_query", ""),
                    }
                    report_correlations.append(correlation_dict)

            # Extract group name - use provided group_name first, then from content
            report_group_name = group_name  # Use provided group_name from request
            if not report_group_name or report_group_name == "Report":
                # Fall back to extracting from content
                report_group_name = "Detection Library"
                if report_detections and len(report_detections) > 0:
                    first_content = export_data[0].get("content", {})
                    report_group_name = first_content.get("group", "Detection Library")
                elif report_correlations and len(report_correlations) > 0:
                    report_group_name = "Correlation Rules"

            generator = PDFReportGenerator()
            # Merge user info with additional metadata from request
            full_metadata = {
                "user": user.full_name if hasattr(user, "full_name") else "Archer User",
                **report_metadata,  # Include metrics, stats, etc. from results page
            }
            content_bytes = generator.generate(
                group_name=report_group_name,
                detections=report_detections,
                correlations=report_correlations if report_correlations else None,
                metadata=full_metadata,
            )

            media_type = "application/pdf"
            filename = f"{report_group_name.replace(' ', '_')}_report.pdf"

            return StreamingResponse(
                io.BytesIO(content_bytes),
                media_type=media_type,
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

        else:
            raise HTTPException(status_code=400, detail="Invalid export format")

        # Log library export activity
        try:
            log_activity(
                user_id=user.id,
                activity_type="library_export",
                title=f"Exported {len(detections)} detections from library",
                description=f"Exported detections in {export_format.upper()} format",
                metadata={"count": len(detections), "format": export_format},
            )
        except Exception as log_error:
            print(f"Error logging library export activity: {log_error}")

        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting library: {e}")
        raise HTTPException(status_code=500, detail="Failed to export library")
    finally:
        db.close()


def _looks_like_query(content) -> bool:
    """A saved detection's query: a string of a real query's length with more than one token."""
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except ValueError:
            return False
    query = content.get("query") if isinstance(content, dict) else None
    if isinstance(query, dict):
        query = query.get("query")
    return isinstance(query, str) and len(query.strip()) >= 20 and len(query.split()) > 1


@app.post("/api/library/save")
async def save_to_library(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Save a new detection or correlation to the library.
    """
    from archer.database.models import (
        LibraryDetection,
        LibraryCorrelation,
        DetectionType,
        VisibilityType,
    )
    import json

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        body = await request.json()
        title = body.get("title")
        detection_type = body.get("detection_type")
        visibility = body.get("visibility", "private")
        content = body.get("content")
        platform = body.get("platform")
        tags = body.get("tags", [])  # Accept tags from frontend

        # Extract group and cve from body for auto-tagging
        group = body.get("group")
        cve = body.get("cve")

        if not title or not detection_type or not content:
            raise HTTPException(status_code=400, detail="Missing required fields")
        content = with_osint(content)
        # A detection must carry a query: a placeholder ({"query": "x"}, saved by a test
        # run) showed in the Library as an Unknown rule with no ATT&CK mapping
        if "correlation" not in detection_type.lower() and not _looks_like_query(content):
            raise HTTPException(status_code=400, detail="The detection has no query to save")

        # Auto-tag with Group and CVE if provided
        auto_tags = []
        if group:
            auto_tags.append(f"Group:{group}")
        if cve:
            auto_tags.append(f"CVE:{cve}")

        # Combine provided tags with auto-tags
        all_tags = list(set(tags + auto_tags))  # Remove duplicates
        tags_json = json.dumps(all_tags) if all_tags else None

        # Check if this is a correlation (detection_type contains "correlation")
        detection_type_lower = detection_type.lower()
        is_correlation = "correlation" in detection_type_lower

        if is_correlation:
            # Save as correlation
            existing_item = (
                db.query(LibraryCorrelation)
                .filter(LibraryCorrelation.user_id == user.id, LibraryCorrelation.title == title)
                .first()
            )

            is_update = False
            if existing_item:
                # Update existing correlation
                is_update = True
                existing_item.visibility = VisibilityType(visibility)
                existing_item.content = (
                    json.dumps(content) if isinstance(content, dict) else content
                )
                existing_item.platform = platform
                existing_item.tags = tags_json
                item_to_return = existing_item
            else:
                # Create new library correlation
                new_correlation = LibraryCorrelation(
                    user_id=user.id,
                    title=title,
                    visibility=VisibilityType(visibility),
                    content=json.dumps(content) if isinstance(content, dict) else content,
                    platform=platform,
                    tags=tags_json,
                )
                db.add(new_correlation)
                item_to_return = new_correlation

            db.commit()

            # Log library save activity
            try:
                log_activity(
                    user_id=user.id,
                    activity_type="library_save" if not is_update else "library_update",
                    title=f"{'Updated' if is_update else 'Saved'} correlation to library: {title}",
                    description=f"{'Updated' if is_update else 'Added'} {detection_type} correlation with {visibility} visibility",
                    metadata={
                        "correlation_id": item_to_return.id,
                        "detection_type": detection_type,
                        "platform": platform,
                        "visibility": visibility,
                        "is_update": is_update,
                    },
                )
            except Exception as log_error:
                print(f"Error logging library save activity: {log_error}")

            return {
                "success": True,
                "message": f"Correlation {'updated in' if is_update else 'saved to'} library",
                "id": item_to_return.id,
                "is_correlation": True,
            }
        else:
            # Save as detection
            existing_detection = (
                db.query(LibraryDetection)
                .filter(LibraryDetection.user_id == user.id, LibraryDetection.title == title)
                .first()
            )

            is_update = False
            if existing_detection:
                # Update existing detection
                is_update = True
                existing_detection.detection_type = DetectionType(detection_type)
                existing_detection.visibility = VisibilityType(visibility)
                existing_detection.content = (
                    json.dumps(content) if isinstance(content, dict) else content
                )
                existing_detection.platform = platform
                existing_detection.tags = tags_json
                detection_to_return = existing_detection
            else:
                # Create new library detection
                new_detection = LibraryDetection(
                    user_id=user.id,
                    title=title,
                    detection_type=DetectionType(detection_type),
                    visibility=VisibilityType(visibility),
                    content=json.dumps(content) if isinstance(content, dict) else content,
                    platform=platform,
                    tags=tags_json,
                )
                db.add(new_detection)
                detection_to_return = new_detection

            db.commit()

            # Log library save activity
            try:
                log_activity(
                    user_id=user.id,
                    activity_type="library_save" if not is_update else "library_update",
                    title=f"{'Updated' if is_update else 'Saved'} detection to library: {title}",
                    description=f"{'Updated' if is_update else 'Added'} {detection_type} detection with {visibility} visibility",
                    metadata={
                        "detection_id": detection_to_return.id,
                        "detection_type": detection_type,
                        "platform": platform,
                        "visibility": visibility,
                        "is_update": is_update,
                    },
                )
            except Exception as log_error:
                print(f"Error logging library save activity: {log_error}")

            return {
                "success": True,
                "message": f"Detection {'updated in' if is_update else 'saved to'} library",
                "id": detection_to_return.id,
                "tags": all_tags,
                "is_update": is_update,
            }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error saving to library: {e}")
        import traceback

        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to save to library: {str(e)}")
    finally:
        db.close()


@app.post("/api/library/tags")
async def update_library_tags(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Update tags for multiple detections in the library.
    """
    from archer.database.models import LibraryDetection
    import json

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        body = await request.json()
        detection_ids = body.get("ids", [])
        tags = body.get("tags", [])

        if not detection_ids:
            raise HTTPException(status_code=400, detail="No detection IDs provided")

        # Validate that all detections belong to the current user
        detections = (
            db.query(LibraryDetection)
            .filter(LibraryDetection.id.in_(detection_ids), LibraryDetection.user_id == user.id)
            .all()
        )

        if len(detections) != len(detection_ids):
            raise HTTPException(status_code=403, detail="Some detections not found or unauthorized")

        # Update tags for all selected detections
        tags_json = json.dumps(tags) if tags else None
        old_tags = [d.tags for d in detections]
        for detection in detections:
            detection.tags = tags_json

        # A group whose last library item lost its Group/CVE tag loses its saved flow layout
        from archer.visualization.flow_layouts import prune_layouts

        db.flush()
        prune_layouts(db, user.id, old_tags)
        db.commit()

        return {
            "success": True,
            "message": f"Tags updated for {len(detections)} detection(s)",
            "count": len(detections),
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating tags: {e}")
        raise HTTPException(status_code=500, detail="Failed to update tags")
    finally:
        db.close()


@app.post("/api/library/mapping")
async def change_library_mapping(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Change or restore the ATT&CK mapping of the caller's own Library copies, with the
    same rules as detection files (archer.build.attack_mapping). A comment is required.
    Body: {"ids": [...], "action": "change"|"restore", "technique_id", "tactics", "comment",
           "rename_rule"}
    """
    from archer.database.models import LibraryDetection
    from .build import attack_mapping
    from .visualization.navigator import legacy, matrix, technique_index

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        body = await request.json()
        ids = [int(i) for i in body.get("ids") or [] if str(i).isdigit()]
        if not ids:
            return JSONResponse({"error": "No Library detections given"}, status_code=400)
        rows = (db.query(LibraryDetection)
                .filter(LibraryDetection.id.in_(ids), LibraryDetection.user_id == user.id).all())
        if len(rows) != len(set(ids)):
            return JSONResponse({"error": "Only your own Library detections can be changed"}, status_code=403)
        bundle = getattr(app.state, "bundle", None)
        index = technique_index(bundle) or None
        order = [c["tactic"] for c in matrix(bundle)] or None
        comment = str(body.get("comment") or "")[:1000]
        changed, unchanged = 0, None
        for row in rows:
            try:
                content = library_content(row.content)
            except (TypeError, ValueError):
                return JSONResponse({"error": f"Library item {row.id} isn't a detection"}, status_code=422)
            if not isinstance(content, dict):
                return JSONResponse({"error": f"Library item {row.id} isn't a detection"}, status_code=422)
            state = attack_mapping.content_state(content, index)
            try:
                if body.get("action") == "restore":
                    plan = attack_mapping.plan_restore(state, comment, user.email)
                elif body.get("action") == "upgrade":
                    old = legacy(bundle).get(state["mapping"]["technique_id"], {})
                    plan = attack_mapping.plan_upgrade(
                        state, str(body.get("technique_id") or ""), body.get("tactics") or [], comment,
                        user.email, index or {}, order, rename_rule=bool(body.get("rename_rule")),
                        status=old.get("status", "legacy"))
                else:
                    plan = attack_mapping.plan_change(
                        state, str(body.get("technique_id") or ""), body.get("tactics") or [], comment,
                        user.email, index, order, rename_rule=bool(body.get("rename_rule")))
            except attack_mapping.Unchanged as err:
                unchanged = err
                continue
            row.content = json.dumps(attack_mapping.apply_content(content, *plan, index=index))
            changed += 1
        if not changed:
            return JSONResponse({"error": str(unchanged)}, status_code=422)
        db.commit()
        return {"success": True, "count": changed}
    except attack_mapping.MappingError as err:
        db.rollback()
        return JSONResponse({"error": str(err)}, status_code=422)
    finally:
        db.close()


@app.post("/api/library/visibility")
async def update_library_visibility(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Update visibility for multiple detections in the library.
    """
    from archer.database.models import LibraryDetection, VisibilityType

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        body = await request.json()
        detection_ids = body.get("ids", [])
        visibility = body.get("visibility", "private")

        if not detection_ids:
            raise HTTPException(status_code=400, detail="No detection IDs provided")

        # Validate that all detections belong to the current user
        detections = (
            db.query(LibraryDetection)
            .filter(LibraryDetection.id.in_(detection_ids), LibraryDetection.user_id == user.id)
            .all()
        )

        if len(detections) != len(detection_ids):
            raise HTTPException(status_code=403, detail="Some detections not found or unauthorized")

        # Update visibility for all selected detections
        visibility_type = VisibilityType(visibility)
        for detection in detections:
            detection.visibility = visibility_type

        db.commit()

        return {
            "success": True,
            "message": f"Visibility updated for {len(detections)} detection(s)",
            "count": len(detections),
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating visibility: {e}")
        raise HTTPException(status_code=500, detail="Failed to update visibility")
    finally:
        db.close()


@app.post("/api/library/delete")
async def delete_library_detections(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Delete multiple detections and/or correlations from the library.
    """
    from archer.database.models import LibraryDetection, LibraryCorrelation

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        body = await request.json()
        detection_ids = body.get("ids", [])
        correlation_ids = body.get("correlation_ids", [])

        if not detection_ids and not correlation_ids:
            raise HTTPException(status_code=400, detail="No detection or correlation IDs provided")

        deleted_count = 0
        deleted_tags = []

        # Delete detections
        if detection_ids:
            detections = (
                db.query(LibraryDetection)
                .filter(LibraryDetection.id.in_(detection_ids), LibraryDetection.user_id == user.id)
                .all()
            )

            if len(detections) != len(detection_ids):
                raise HTTPException(
                    status_code=403, detail="Some detections not found or unauthorized"
                )

            for detection in detections:
                deleted_tags.append(detection.tags)
                db.delete(detection)
            deleted_count += len(detections)

        # Delete correlations
        if correlation_ids:
            # Convert string IDs to integers
            try:
                correlation_ids = [int(id) for id in correlation_ids]
            except (ValueError, TypeError) as e:
                raise HTTPException(status_code=400, detail=f"Invalid correlation ID format: {e}")

            # Try to delete from LibraryCorrelation table first
            correlations_from_corr_table = (
                db.query(LibraryCorrelation)
                .filter(
                    LibraryCorrelation.id.in_(correlation_ids),
                    LibraryCorrelation.user_id == user.id,
                )
                .all()
            )

            corr_table_ids = [c.id for c in correlations_from_corr_table]

            # For IDs not found in LibraryCorrelation, try LibraryDetection (backward compatibility)
            remaining_ids = [id for id in correlation_ids if id not in corr_table_ids]
            correlations_from_det_table = []
            if remaining_ids:
                correlations_from_det_table = (
                    db.query(LibraryDetection)
                    .filter(
                        LibraryDetection.id.in_(remaining_ids), LibraryDetection.user_id == user.id
                    )
                    .all()
                )

            total_found = len(correlations_from_corr_table) + len(correlations_from_det_table)
            if total_found != len(correlation_ids):
                print(f"[DELETE] Expected {len(correlation_ids)} correlations, found {total_found}")
                print(f"[DELETE] Requested IDs: {correlation_ids}")
                print(f"[DELETE] Found in LibraryCorrelation: {corr_table_ids}")
                print(
                    f"[DELETE] Found in LibraryDetection: {[d.id for d in correlations_from_det_table]}"
                )
                raise HTTPException(
                    status_code=403, detail="Some correlations not found or unauthorized"
                )

            # Delete from both tables
            for correlation in correlations_from_corr_table:
                deleted_tags.append(correlation.tags)
                db.delete(correlation)
            for correlation in correlations_from_det_table:
                deleted_tags.append(correlation.tags)
                db.delete(correlation)
            deleted_count += total_found

        # A group with nothing left in the library loses its saved flow layout
        from archer.visualization.flow_layouts import prune_layouts

        db.flush()
        prune_layouts(db, user.id, deleted_tags)
        db.commit()

        return {
            "success": True,
            "message": f"Deleted {deleted_count} item(s)",
            "deleted_count": deleted_count,
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting items: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete items")
    finally:
        db.close()


@app.post("/api/profile")
async def update_profile(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Update user profile information.

    Requires authentication. Updates full_name and team in the database.
    """
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return {"success": False, "error": "Not authenticated"}

    user, db = auth_result

    try:
        data = await request.json()
        full_name = data.get("full_name", "").strip()
        team = data.get("team", "").strip()
        country = (data.get("country") or "").strip()

        if not full_name:
            return {"success": False, "error": "Full name is required"}
        from archer.intelligence.cyber_powers import is_country
        if country and not is_country(country):
            return {"success": False, "error": "Unknown country"}

        # Update user's full name and team
        user.full_name = full_name
        user.team = team if team else None
        if "country" in data:
            user.country = country or None
        db.commit()
        db.refresh(user)

        return {"success": True, "message": "Profile updated successfully"}

    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}

    finally:
        db.close()


def _user_industries(user) -> list:
    from archer.intelligence.feed import as_industries

    try:
        return as_industries(json.loads(user.industries)) if user and user.industries else []
    except (ValueError, TypeError):
        return []


@app.get("/api/profile/siems")
def get_profile_siems(request: Request, archer_session: Optional[str] = Cookie(None)):
    """The SIEMs this user's hunts generate detections for (none chosen: all of them)."""
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    return {"siems": _user_siems(user),
            "choices": [{"id": k, "label": label} for k, label in SIEM_LABELS.items()]
                       + [{"id": k, "label": label, "soon": True} for k, label in SIEM_COMING_SOON.items()]}


@app.post("/api/profile/siems")
async def set_profile_siems(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Body: {"siems": ["secops"]} (ids from GET; an empty list means all)."""
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        wanted = (await request.json()).get("siems") or []
        if not isinstance(wanted, list) or any(s not in SIEM_PLATFORMS for s in wanted):
            return JSONResponse({"error": "Unknown SIEM"}, status_code=400)
        user.siem_platforms = json.dumps([s for s in SIEM_PLATFORMS if s in wanted])
        db.commit()
        return {"success": True, "siems": _user_siems(user)}
    finally:
        db.close()


@app.get("/api/profile/industries")
def get_profile_industries(request: Request, archer_session: Optional[str] = Cookie(None)):
    """The industries the threat feed follows for this user, and the ones to choose from."""
    from archer.intelligence.feed import INDUSTRIES

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    return {"industries": _user_industries(user),
            "choices": [{"id": i, "label": i} for i in INDUSTRIES]}


@app.post("/api/profile/industries")
async def set_profile_industries(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Body: {"industries": ["Finance", ...]} (ids from GET)."""
    from archer.intelligence.feed import INDUSTRIES

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        wanted = (await request.json()).get("industries") or []
        if not isinstance(wanted, list) or any(i not in INDUSTRIES for i in wanted):
            return JSONResponse({"error": "Unknown industry"}, status_code=400)
        user.industries = json.dumps(sorted(set(wanted), key=INDUSTRIES.index))
        db.commit()
        return {"success": True, "industries": json.loads(user.industries)}
    finally:
        db.close()


@app.get("/api/profile/stack")
def get_profile_stack(request: Request, archer_session: Optional[str] = Cookie(None)):
    """The products this user's organisation runs, and the catalogue to choose from."""
    from archer.intelligence.tech_stack import catalogue

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    cat = catalogue()
    return {"stack": _user_stack(user), "categories": cat["categories"],
            "choices": [{"id": pid, "label": p["label"], "category": p["category"], "platforms": p["platforms"]}
                        for pid, p in cat["products"].items()]}


@app.post("/api/profile/stack")
async def set_profile_stack(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Body: {"stack": ["windows", "m365", ...]} (ids from GET; an empty list means everything applies)."""
    from archer.intelligence.tech_stack import as_stack, catalogue

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        wanted = (await request.json()).get("stack") or []
        if not isinstance(wanted, list) or any(p not in catalogue()["products"] for p in wanted):
            return JSONResponse({"error": "Unknown product"}, status_code=400)
        user.tech_stack = json.dumps(as_stack(wanted))
        db.commit()
        return {"success": True, "stack": _user_stack(user)}
    finally:
        db.close()


@app.get("/feed", response_class=HTMLResponse)
def feed_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    """The last week's research that matters to the user's industries, plus opportunistic activity."""
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return auth_result
    user, db = auth_result
    db.close()
    return templates.TemplateResponse("feed.html", {"request": request, "user": user})


@app.get("/api/feed")
def api_feed(request: Request, archer_session: Optional[str] = Cookie(None)):
    """The user's threat feed (cached; a stale cache starts a refresh in the background)."""
    from archer.intelligence import feed

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    feed.refresh_in_background(getattr(request.app.state, "bundle", None),
                               getattr(request.app.state, "group_metadata", {}) or {})
    from archer.intelligence.watchlists import watched

    return {**feed.view(_user_industries(user), stack=_user_stack(user)), "watched": watched(user.id),
            "can_edit_sources": at_least(user, UserRole.OPERATOR)}


@app.get("/api/cves/recent")
def api_recent_cves(request: Request, q: str = "", kev: bool = False, stack: bool = False, min_score: float = 0,
                    offset: int = 0, limit: int = 50, archer_session: Optional[str] = Cookie(None)):
    """The Hunt page's recent-CVE picker: the last 30 days, newest first, filtered (archer.intelligence.cve_feed.recent)."""
    from archer.intelligence import cve_feed

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    chosen = _user_stack(user)
    found = cve_feed.recent(chosen, q=q[:200], kev_only=kev, stack_only=stack, min_score=min_score,
                            offset=max(0, offset), limit=min(max(1, limit), 200))
    return {**found, "status": cve_feed.status(), "window_days": cve_feed.WINDOW_DAYS, "has_stack": bool(chosen)}


@app.get("/api/feed/search")
def api_feed_search(request: Request, q: str = "", web: bool = True, archer_session: Optional[str] = Cookie(None)):
    """Research by keyword: Archer's source archive, ATT&CK, and (web=true) Google News and Bing News."""
    from archer.intelligence import research_search

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    _, db = auth_result
    db.close()
    result = research_search.search(q, getattr(request.app.state, "bundle", None), web=web)
    return JSONResponse(result, status_code=400 if result.get("error") else 200)


def _watch_user(request: Request, archer_session: Optional[str]):
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    return user


@app.get("/api/feed/watchlists")
def api_watchlists(request: Request, archer_session: Optional[str] = Cookie(None)):
    """The user's Threat Feed watchlists with their new matches (archer.intelligence.watchlists)."""
    from archer.intelligence import watchlists

    user = _watch_user(request, archer_session)
    if isinstance(user, JSONResponse):
        return user
    lists = watchlists.list_for(user.id)
    return {"watchlists": lists, "new_count": sum(w["new_count"] for w in lists),
            "email_available": watchlists.email_available()}


@app.get("/api/feed/watchlists/count")
def api_watchlists_count(request: Request, archer_session: Optional[str] = Cookie(None)):
    """New watchlist matches, for the menu bar's badge."""
    from archer.intelligence import watchlists

    user = _watch_user(request, archer_session)
    if isinstance(user, JSONResponse):
        return {"new": 0}
    return {"new": watchlists.new_count(user.id)}


@app.post("/api/feed/watchlists")
def api_watchlists_add(request: Request, body: dict = Body(...), archer_session: Optional[str] = Cookie(None)):
    """Body: {"query": "RedSun", "web": false, "email": false}. What matches already is the baseline."""
    from archer.intelligence import watchlists

    user = _watch_user(request, archer_session)
    if isinstance(user, JSONResponse):
        return user
    try:
        w = watchlists.add(user.id, user.email, body.get("query", ""), web=bool(body.get("web")),
                           want_email=bool(body.get("email")), bundle=getattr(request.app.state, "bundle", None))
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return {"watchlist": w}


@app.patch("/api/feed/watchlists/{watch_id}")
def api_watchlists_update(watch_id: str, request: Request, body: dict = Body(...),
                          archer_session: Optional[str] = Cookie(None)):
    from archer.intelligence import watchlists

    user = _watch_user(request, archer_session)
    if isinstance(user, JSONResponse):
        return user
    w = watchlists.update(user.id, watch_id, web=body.get("web"), email=body.get("email"))
    return {"watchlist": w} if w else JSONResponse({"error": "No such watchlist"}, status_code=404)


@app.delete("/api/feed/watchlists/{watch_id}")
def api_watchlists_remove(watch_id: str, request: Request, archer_session: Optional[str] = Cookie(None)):
    from archer.intelligence import watchlists

    user = _watch_user(request, archer_session)
    if isinstance(user, JSONResponse):
        return user
    return {"removed": True} if watchlists.remove(user.id, watch_id) else JSONResponse(
        {"error": "No such watchlist"}, status_code=404)


@app.post("/api/feed/watchlists/seen")
def api_watchlists_seen(request: Request, body: dict = Body(default={}), archer_session: Optional[str] = Cookie(None)):
    """Body: {"id": "<watchlist>"} marks that one's new matches seen; no id marks them all."""
    from archer.intelligence import watchlists

    user = _watch_user(request, archer_session)
    if isinstance(user, JSONResponse):
        return user
    return {"marked": watchlists.mark_seen(user.id, (body or {}).get("id"))}


@app.post("/api/feed/refresh")
def api_feed_refresh(request: Request, archer_session: Optional[str] = Cookie(None)):
    from archer.intelligence import feed

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    _, db = auth_result
    db.close()
    started = feed.refresh_in_background(getattr(request.app.state, "bundle", None),
                                         getattr(request.app.state, "group_metadata", {}) or {}, force=True)
    return {"started": started}


def _feed_admin(request: Request, archer_session: Optional[str]):
    """The admin user, or the JSONResponse refusing: sources are fetched by the server for everyone."""
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    db.close()
    if not at_least(user, UserRole.OPERATOR):
        return JSONResponse({"error": "Changing the feed's sources needs the Operational analyst role"},
                            status_code=403)
    return user


@app.post("/api/feed/sources")
async def api_feed_add_source(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Add a custom feed source (admin): it must read as RSS or Atom from a public address."""
    from archer.intelligence import feed

    admin = _feed_admin(request, archer_session)
    if isinstance(admin, JSONResponse):
        return admin
    body = await request.json()
    from starlette.concurrency import run_in_threadpool
    result = await run_in_threadpool(feed.add_source, body.get("name"), body.get("url"))
    return JSONResponse(result, status_code=200 if result["ok"] else 400)


@app.delete("/api/feed/sources")
async def api_feed_remove_source(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Remove a custom feed source (admin); the built-in ones stay."""
    from archer.intelligence import feed

    admin = _feed_admin(request, archer_session)
    if isinstance(admin, JSONResponse):
        return admin
    body = await request.json()
    return {"ok": feed.remove_source(body.get("url") or "")}


@app.post("/api/profile/picture")
async def upload_profile_picture(profile_picture: UploadFile = File(...)):
    """
    Upload and save user profile picture.
    """
    # TODO: Add authentication check

    # Validate file type
    if not profile_picture.content_type.startswith("image/"):
        return {"success": False, "error": "File must be an image"}

    # Create profile pictures directory if it doesn't exist
    pics_dir = PROFILE_PICS_DIR
    os.makedirs(pics_dir, exist_ok=True)

    # Generate unique filename
    file_ext = os.path.splitext(profile_picture.filename)[1]
    filename = f"user_profile{file_ext}"  # TODO: Use user ID
    file_path = os.path.join(pics_dir, filename)

    # Save file
    with open(file_path, "wb") as f:
        content = await profile_picture.read()
        f.write(content)

    return {"success": True, "url": f"/static/profile_pictures/{filename}"}


@app.get("/api/profile/timeline")
async def get_timeline(request: Request):
    """
    Get user's historical activity timeline.
    """
    # TODO: Add authentication check
    # TODO: Query database for user's activity

    # For now, return empty timeline
    return {"timeline": []}


@app.get("/api/profile/tokens")
def list_api_tokens(request: Request, archer_session: Optional[str] = Cookie(None)):
    from archer.auth.tokens import list_tokens

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        return {"tokens": list_tokens(db, user.id)}
    finally:
        db.close()


@app.post("/api/profile/tokens")
async def create_api_token(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Body: {"name": "..."}. The token is in this response only; only its hash is kept."""
    from archer.auth.tokens import create_token

    if _bearer_token(request):
        return JSONResponse({"error": "Create API tokens from the profile page, not with a token"}, status_code=403)
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        body = await request.json()
        name = str(body.get("name") or "").strip()
        if not name:
            return JSONResponse({"error": "Give the token a name (what will use it)"}, status_code=400)
        token, info = create_token(db, user.id, name)
        log_activity(user.id, "api_token_created", f"API token created: {info['name']} ({info['prefix']}…)")
        return {"token": token, **info}
    finally:
        db.close()


@app.delete("/api/profile/tokens/{token_id}")
def revoke_api_token(token_id: int, request: Request, archer_session: Optional[str] = Cookie(None)):
    from archer.auth.tokens import revoke_token

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        if not revoke_token(db, user.id, token_id):
            return JSONResponse({"error": "No such token"}, status_code=404)
        log_activity(user.id, "api_token_revoked", f"API token {token_id} revoked")
        return {"ok": True}
    finally:
        db.close()


KEY_MASK = "••••••••"


def mask_api_key(value: str) -> str:
    return KEY_MASK + (value[-4:] if len(value) > 8 else "") if value else ""


@app.get("/api/profile/apikeys")
async def get_api_keys(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    The user's saved keys, masked: only the last 4 characters reach the browser. A
    masked value posted back unchanged leaves the stored key as it is.
    """
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return {"error": "Not authenticated"}

    user, db = auth_result

    try:
        # Query all API keys for this user
        api_keys = db.query(APIKey).filter(APIKey.user_id == user.id).all()

        # Decrypt and return API keys
        result = {}
        for key in api_keys:
            try:
                result[key.platform] = mask_api_key(decrypt_api_key(key.encrypted_key))
            except Exception as e:
                logger.error(f"Failed to decrypt API key {key.platform}: {e}")
                result[key.platform] = ""

        return result

    except Exception as e:
        logger.error(f"Error loading API keys: {e}")
        return {"error": str(e)}

    finally:
        db.close()


@app.post("/api/profile/apikeys")
async def save_api_keys(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Save user's API keys securely.

    Requires authentication. Encrypts and stores API keys for the logged-in user.
    """
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return {"success": False, "error": "Not authenticated"}

    user, db = auth_result

    try:
        data = await request.json()

        # Every key the profile page has a field for. The model's column is "platform";
        # these routes used "key_name", so no key was ever saved (each save raised and
        # the page still said "saved"). Shodan/SecurityTrails/GitHub had fields but
        # weren't in the list; "local" is the optional key of a local model endpoint.
        platforms = ("secops", "splunk", "mde", "elastic", "shodan", "securitytrails", "hibp", "github",
                     "openai", "anthropic", "google", "deepseek", "qwen", "grok", "local")
        # A cleared field removes its key, but only when the page had loaded the saved
        # keys first: a page that failed to load must not wipe them
        clear_empty = bool(data.get("_loaded"))

        for db_name in platforms:
            if db_name not in data:
                continue
            key_value = str(data.get(db_name) or "").strip()

            # Check if key already exists for this user
            existing_key = (
                db.query(APIKey)
                .filter(APIKey.user_id == user.id, APIKey.platform == db_name)
                .first()
            )

            if key_value.startswith(KEY_MASK):
                continue  # the masked value the page was given: unchanged
            if not key_value:
                if existing_key and clear_empty:
                    db.delete(existing_key)
                continue

            # Encrypt the API key
            encrypted_value = encrypt_api_key(key_value)

            if existing_key:
                # Update existing key
                existing_key.encrypted_key = encrypted_value
                existing_key.updated_at = datetime.utcnow()
            else:
                # Create new key
                new_key = APIKey(user_id=user.id, platform=db_name, encrypted_key=encrypted_value)
                db.add(new_key)

        db.commit()
        # Assignments whose provider's key was just removed are dropped. Best effort:
        # the keys are saved, and resolve() ignores an assignment to an unconfigured
        # provider anyway
        try:
            from archer.ai.assignment import apply_update, configured_providers, load_settings, save_settings

            settings = load_settings(db, user.id)
            save_settings(db, user.id, apply_update(settings, {}, configured_providers(db, user.id, settings)))
        except Exception as e:
            db.rollback()
            logger.warning(f"API keys saved; tidying AI assignments failed: {e}")
        return {"success": True, "message": "API keys saved successfully"}

    except Exception as e:
        db.rollback()
        logger.error(f"Error saving API keys: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)

    finally:
        db.close()


@app.post("/api/osint-key")
async def osint_key(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Home-page OSINT key control, so a key can be added or switched off without the Profile page.
    Body: {"platform": "shodan", "key": "..."} saves/replaces a key (and enables it); or
    {"platform": "shodan", "enabled": false} keeps the stored key but stops it being applied.
    Scoped to the OSINT platforms only. Returns the key's set/enabled state for the button to redraw.
    """
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"success": False, "error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        data = await request.json()
        platform = str(data.get("platform") or "").strip().lower()
        if platform not in OSINT_KEY_ENV:
            return JSONResponse({"success": False, "error": "Unknown OSINT platform"}, status_code=400)

        row = db.query(APIKey).filter(APIKey.user_id == user.id, APIKey.platform == platform).first()

        if "key" in data:
            key_value = str(data.get("key") or "").strip()
            if not key_value:
                return JSONResponse({"success": False, "error": "Empty key"}, status_code=400)
            encrypted = encrypt_api_key(key_value)
            if row:
                row.encrypted_key, row.enabled, row.updated_at = encrypted, True, datetime.utcnow()
            else:
                db.add(APIKey(user_id=user.id, platform=platform, encrypted_key=encrypted, enabled=True))
        elif "enabled" in data:
            if not row:
                return JSONResponse({"success": False, "error": "No key to toggle"}, status_code=404)
            row.enabled = bool(data.get("enabled"))
            row.updated_at = datetime.utcnow()
        else:
            return JSONResponse({"success": False, "error": "Nothing to do"}, status_code=400)

        db.commit()
        # Reflect the change in the live environment straight away
        apply_osint_keys_to_env(db, user.id)
        row = db.query(APIKey).filter(APIKey.user_id == user.id, APIKey.platform == platform).first()
        return {"success": True, "platform": platform, "set": bool(row),
                "enabled": (row.enabled is not False) if row else False}
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating OSINT key: {e}")
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        db.close()


@app.get("/api/profile/ai-settings")
async def get_ai_settings(request: Request, archer_session: Optional[str] = Cookie(None)):
    """The user's AI providers, models and job assignments (no keys)."""
    from archer.ai.assignment import CLOUD_PROVIDERS, configured_providers, load_settings

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        settings = load_settings(db, user.id)
        return {
            "settings": settings,
            "providers": configured_providers(db, user.id, settings),
            "catalogue": [{"id": k, "label": v[0], "default_model": v[1]} for k, v in CLOUD_PROVIDERS.items()],
        }
    finally:
        db.close()


@app.post("/api/profile/ai-settings")
async def save_ai_settings(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Update models, the local endpoint, assignments, the call cap or the remembered choice."""
    from archer.ai.assignment import apply_update, configured_providers, load_settings, save_settings

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        update = await request.json()
        settings = load_settings(db, user.id)
        try:
            settings = apply_update(settings, update, configured_providers(db, user.id, settings))
        except (ValueError, TypeError) as e:
            return JSONResponse({"success": False, "error": str(e)}, status_code=400)
        save_settings(db, user.id, settings)
        return {"success": True, "settings": settings, "providers": configured_providers(db, user.id, settings)}
    finally:
        db.close()


@app.post("/api/profile/ai-settings/probe-local")
async def probe_local_model(request: Request, archer_session: Optional[str] = Cookie(None)):
    """Is the local endpoint reachable, and which models does it serve?"""
    import asyncio

    from archer.ai.assignment import probe_local, stored_keys

    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    user, db = auth_result
    try:
        body = await request.json()
        key = body.get("api_key") or ""
        if not key or key.startswith(KEY_MASK):
            key = stored_keys(db, user.id).get("local", "")
    finally:
        db.close()
    return await asyncio.get_event_loop().run_in_executor(None, probe_local, body.get("endpoint", ""), key)


# ==========================================
# SECURITY ENDPOINTS (Password, MFA, Backup Codes)
# ==========================================


@app.post("/api/change-password")
async def change_password(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Change user's password.

    Requires current password for verification.
    """
    from archer.auth.password import verify_password, hash_password
    from archer.database.audit import log_audit_event, EVENT_PASSWORD_CHANGE

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        # Parse request body
        body = await request.json()
        current_password = body.get("current_password")
        new_password = body.get("new_password")

        if not current_password or not new_password:
            raise HTTPException(
                status_code=400, detail="Both current and new password are required"
            )

        # Verify current password
        if not verify_password(current_password, user.password_hash):
            log_audit_event(
                db=db,
                event_type=EVENT_PASSWORD_CHANGE,
                user_id=user.id,
                email=user.email,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                success=False,
                details="Incorrect current password",
            )
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        # Validate new password (same rules as registration)
        if len(new_password) < 16 or len(new_password) > 40:
            raise HTTPException(status_code=400, detail="Password must be 16-40 characters")

        # Update password
        user.password_hash = hash_password(new_password)
        user.updated_at = datetime.utcnow()
        db.commit()

        # Log successful password change
        log_audit_event(
            db=db,
            event_type=EVENT_PASSWORD_CHANGE,
            user_id=user.id,
            email=user.email,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=True,
        )

        return {"success": True, "message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error changing password: {e}")
        raise HTTPException(status_code=500, detail="Failed to change password")
    finally:
        db.close()


@app.get("/api/mfa/status")
async def get_mfa_status(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Get MFA status for current user.
    """
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        return {
            "success": True,
            "enabled": user.mfa_enabled if hasattr(user, "mfa_enabled") else False,
        }
    finally:
        db.close()


@app.post("/api/mfa/setup")
async def setup_mfa(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Generate MFA secret and QR code for setup.

    Does not enable MFA yet - user must verify first.
    """
    from archer.auth.mfa import generate_totp_secret, generate_qr_code

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        # Generate new secret
        secret = generate_totp_secret()

        # Store secret temporarily (not enabled yet)
        user.mfa_secret = secret
        user.mfa_enabled = False
        db.commit()

        # Generate QR code
        qr_code = generate_qr_code(user.email, secret)

        return {"success": True, "secret": secret, "qr_code": qr_code}

    except Exception as e:
        db.rollback()
        logger.error(f"Error setting up MFA: {e}")
        raise HTTPException(status_code=500, detail="Failed to setup MFA")
    finally:
        db.close()


@app.post("/api/mfa/verify")
async def verify_mfa(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Verify TOTP code and enable MFA.
    """
    from archer.auth.mfa import verify_totp_code

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        # Parse request body
        body = await request.json()
        code = body.get("code")

        if not code:
            raise HTTPException(status_code=400, detail="Verification code is required")

        # Check if user has a secret
        if not user.mfa_secret:
            raise HTTPException(status_code=400, detail="MFA setup not started")

        # Verify code
        if not verify_totp_code(user.mfa_secret, code):
            raise HTTPException(status_code=400, detail="Invalid verification code")

        # Enable MFA
        user.mfa_enabled = True
        db.commit()

        return {"success": True, "message": "MFA enabled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error verifying MFA: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify MFA")
    finally:
        db.close()


@app.post("/api/mfa/disable")
async def disable_mfa(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Disable MFA for current user.
    """
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        # Disable MFA
        user.mfa_enabled = False
        user.mfa_secret = None
        user.backup_codes = None
        db.commit()

        return {"success": True, "message": "MFA disabled successfully"}

    except Exception as e:
        db.rollback()
        logger.error(f"Error disabling MFA: {e}")
        raise HTTPException(status_code=500, detail="Failed to disable MFA")
    finally:
        db.close()


@app.post("/api/backup-codes/generate")
async def generate_backup_codes(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Generate new backup recovery codes.

    Invalidates any existing codes.
    """
    from archer.auth.mfa import generate_backup_codes

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        # Generate backup codes
        plain_codes, hashed_codes_json = generate_backup_codes(count=10)

        # Store hashed codes
        user.backup_codes = hashed_codes_json
        db.commit()

        return {"success": True, "codes": plain_codes}

    except Exception as e:
        db.rollback()
        logger.error(f"Error generating backup codes: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate backup codes")
    finally:
        db.close()


@app.get("/api/users")
async def get_users(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Get list of all users (admin only).

    Returns list of users with their email, full name, and account type.
    """
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return {"success": False, "error": "Not authenticated"}

    user, db = auth_result

    # Check if user is admin
    if not user or user.role.value != "admin":
        return {"success": False, "error": "Admin access required"}

    try:
        # Get all users
        all_users = db.query(User).order_by(User.created_at.desc()).all()

        users_list = []
        for u in all_users:
            users_list.append(
                {
                    "id": u.id,
                    "email": u.email,
                    "full_name": u.full_name,
                    "team": u.team,
                    "role": u.role.value,
                    "is_active": u.is_active,
                    "created_at": u.created_at.isoformat() if u.created_at else None,
                    "is_current_user": u.id == user.id,
                }
            )

        return {"success": True, "users": users_list}

    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return {"success": False, "error": str(e)}

    finally:
        db.close()


# =============================================================================
# Password Reset Endpoints
# =============================================================================


@app.post("/api/auth/request-reset")
async def request_password_reset(request: Request):
    """
    Request a password reset. Generates a reset token and sends email (or logs in dev mode).
    """
    try:
        data = await request.json()
        email = data.get("email", "").strip().lower()

        if not email:
            return {"success": False, "error": "Email is required"}

        db = next(get_db())
        try:
            # Get user to get their full name for personalization
            user = db.query(User).filter(User.email == email, User.is_active == True).first()

            # Create reset request
            token = create_password_reset_request(email, db)

            # Same response whether or not the account exists (no enumeration)
            response = {
                "success": True,
                "message": "If an account exists with this email, a password reset link has been sent.",
            }
            if not token:
                return response

            from archer.auth.email import send_password_reset_email, EMAIL_ENABLED

            if EMAIL_ENABLED:
                # SMTP is blocking; keep it off the event loop
                await run_in_threadpool(
                    send_password_reset_email, email=email, token=token, full_name=user.full_name if user else None
                )
            else:
                # Never return the token to the requester: anyone could reset any account.
                # With email disabled the link goes to the server log for the operator.
                logger.warning("EMAIL_ENABLED=false; password reset link for %s: /reset-password?token=%s", email, token)

            return response

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error requesting password reset: {e}")
        return {"success": False, "error": "An error occurred"}


@app.post("/api/auth/reset-password")
async def reset_password(request: Request):
    """
    Reset password using a valid reset token.
    """
    from archer.database.audit import log_audit_event, EVENT_PASSWORD_RESET_COMPLETED
    from archer.auth.password_reset import validate_reset_token

    try:
        data = await request.json()
        token = data.get("token", "").strip()
        new_password = data.get("new_password", "")

        # Get client IP and user agent for logging
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        if not token:
            return {"success": False, "error": "Reset token is required"}

        if not new_password:
            return {"success": False, "error": "New password is required"}

        # Validate password
        is_valid, error_message = validate_password(new_password)
        if not is_valid:
            return {"success": False, "error": error_message}

        db = next(get_db())
        try:
            # Validate token and get user first
            user = validate_reset_token(token, db)

            if not user:
                log_audit_event(
                    db=db,
                    event_type=EVENT_PASSWORD_RESET_COMPLETED,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    success=False,
                    details="Invalid or expired reset token",
                )
                return {"success": False, "error": "Invalid or expired reset token"}

            # Reset password
            success = reset_password_with_token(token, new_password, db)

            if not success:
                log_audit_event(
                    db=db,
                    event_type=EVENT_PASSWORD_RESET_COMPLETED,
                    user_id=user.id,
                    email=user.email,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    success=False,
                    details="Failed to reset password",
                )
                return {"success": False, "error": "Invalid or expired reset token"}

            # Log successful password reset
            log_audit_event(
                db=db,
                event_type=EVENT_PASSWORD_RESET_COMPLETED,
                user_id=user.id,
                email=user.email,
                ip_address=client_ip,
                user_agent=user_agent,
                success=True,
                details="Password reset completed successfully",
            )

            return {
                "success": True,
                "message": "Password has been reset successfully. You can now log in with your new password.",
            }

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        return {"success": False, "error": "An error occurred"}


@app.post("/api/admin/reset-password")
async def admin_reset_user_password(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Admin-only endpoint to reset another user's password.
    """
    # Check authentication and admin role
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return {"success": False, "error": "Not authenticated"}

    admin_user, db = auth_result

    try:
        # Verify admin role
        if admin_user.role != UserRole.ADMIN:
            return {"success": False, "error": "Unauthorized - Admin access required"}

        data = await request.json()
        user_id = data.get("user_id")
        new_password = data.get("new_password", "")

        if not user_id:
            return {"success": False, "error": "User ID is required"}

        if not new_password:
            return {"success": False, "error": "New password is required"}

        # Validate password
        is_valid, error_message = validate_password(new_password)
        if not is_valid:
            return {"success": False, "error": error_message}

        # Reset password
        success = admin_reset_password(user_id, new_password, db)

        if not success:
            return {"success": False, "error": "User not found"}

        return {"success": True, "message": "Password has been reset successfully"}

    except Exception as e:
        logger.error(f"Error in admin password reset: {e}")
        return {"success": False, "error": "An error occurred"}

    finally:
        db.close()


# =============================================================================
# Admin User Management Endpoints
# =============================================================================


@app.get("/api/admin/users")
async def get_all_users(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Get list of all users (Admin only).

    Returns user information excluding sensitive data like passwords.
    """
    # Check authentication and admin role
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return {"success": False, "error": "Not authenticated"}

    admin_user, db = auth_result

    try:
        # Verify admin role
        if admin_user.role != UserRole.ADMIN:
            return {"success": False, "error": "Unauthorized - Admin access required"}

        # Get all users
        users = db.query(User).all()

        # Format user data (exclude sensitive information)
        users_data = []
        for user in users:
            users_data.append(
                {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "team": user.team,
                    "role": user.role.value,
                    "is_active": user.is_active,
                    "created_at": user.created_at.isoformat() if user.created_at else None,
                    "updated_at": user.updated_at.isoformat() if user.updated_at else None,
                }
            )

        return {"success": True, "users": users_data}

    except Exception as e:
        logger.error(f"Error getting users: {e}")
        return {"success": False, "error": "An error occurred"}

    finally:
        db.close()


@app.post("/api/admin/users")
async def create_user(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Create a new user (Admin only).
    """
    # Check authentication and admin role
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return {"success": False, "error": "Not authenticated"}

    admin_user, db = auth_result

    try:
        # Verify admin role
        if admin_user.role != UserRole.ADMIN:
            return {"success": False, "error": "Unauthorized - Admin access required"}

        data = await request.json()
        email = data.get("email", "").strip().lower()
        full_name = data.get("full_name", "").strip()
        password = data.get("password", "")
        role = data.get("role", "standard").lower()

        # Validate email
        from archer.security import validate_email, sanitize_full_name

        email_valid, email_result = validate_email(email)
        if not email_valid:
            return {"success": False, "error": email_result}
        email = email_result

        # Validate full name
        name_valid, name_result = sanitize_full_name(full_name)
        if not name_valid:
            return {"success": False, "error": name_result}
        full_name = name_result

        # Validate password
        is_valid, error_message = validate_password(password)
        if not is_valid:
            return {"success": False, "error": error_message}

        # Validate role (admin, operator or standard)
        valid_roles = {r.value for r in UserRole}
        if role not in valid_roles:
            return {"success": False, "error": f"Invalid role. Must be one of: {', '.join(sorted(valid_roles))}"}

        # Check if user already exists
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            return {"success": False, "error": "User with this email already exists"}

        # Create new user
        user_role = UserRole(role)
        hashed_password = hash_password(password)

        new_user = User(
            email=email,
            full_name=full_name,
            password_hash=hashed_password,
            role=user_role,
            is_active=True,
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return {
            "success": True,
            "message": "User created successfully",
            "user": {
                "id": new_user.id,
                "email": new_user.email,
                "full_name": new_user.full_name,
                "role": new_user.role.value,
            },
        }

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating user: {e}")
        return {"success": False, "error": "An error occurred"}

    finally:
        db.close()


@app.put("/api/admin/users/{user_id}")
async def update_user(request: Request, user_id: int, archer_session: Optional[str] = Cookie(None)):
    """
    Update user details (Admin only).

    Can update: email, full_name, role, is_active
    Cannot update: password (use reset password endpoint)
    """
    # Check authentication and admin role
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return {"success": False, "error": "Not authenticated"}

    admin_user, db = auth_result

    try:
        # Verify admin role
        if admin_user.role != UserRole.ADMIN:
            return {"success": False, "error": "Unauthorized - Admin access required"}

        # Get user to update
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"success": False, "error": "User not found"}

        data = await request.json()

        # Update email if provided
        if "email" in data:
            from archer.security import validate_email

            email = data["email"].strip().lower()
            email_valid, email_result = validate_email(email)
            if not email_valid:
                return {"success": False, "error": email_result}

            # Check if email is already taken by another user
            existing = db.query(User).filter(User.email == email_result, User.id != user_id).first()
            if existing:
                return {"success": False, "error": "Email already in use"}

            user.email = email_result

        # Update full name if provided
        if "full_name" in data:
            from archer.security import sanitize_full_name

            name_valid, name_result = sanitize_full_name(data["full_name"])
            if not name_valid:
                return {"success": False, "error": name_result}
            user.full_name = name_result

        # Update role if provided
        if "role" in data:
            role = data["role"].lower()
            if role not in {r.value for r in UserRole}:
                return {"success": False, "error": "Invalid role"}
            user.role = UserRole(role)

        # Update active status if provided
        if "is_active" in data:
            user.is_active = bool(data["is_active"])

        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)

        return {
            "success": True,
            "message": "User updated successfully",
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role.value,
                "is_active": user.is_active,
            },
        }

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating user: {e}")
        return {"success": False, "error": "An error occurred"}

    finally:
        db.close()


@app.delete("/api/admin/users/{user_id}")
async def deactivate_user(
    request: Request, user_id: int, archer_session: Optional[str] = Cookie(None)
):
    """
    Deactivate a user (Admin only).

    Soft delete - sets is_active to False instead of deleting the record.
    """
    # Check authentication and admin role
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return {"success": False, "error": "Not authenticated"}

    admin_user, db = auth_result

    try:
        # Verify admin role
        if admin_user.role != UserRole.ADMIN:
            return {"success": False, "error": "Unauthorized - Admin access required"}

        # Prevent admin from deactivating themselves
        if admin_user.id == user_id:
            return {"success": False, "error": "Cannot deactivate your own account"}

        # Get user to deactivate
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"success": False, "error": "User not found"}

        # Deactivate user
        user.is_active = False
        user.updated_at = datetime.utcnow()

        # Invalidate all active sessions for this user
        from archer.database.models import Session

        db.query(Session).filter(Session.user_id == user_id, Session.is_active == True).update(
            {"is_active": False}
        )

        db.commit()

        return {"success": True, "message": f"User {user.email} has been deactivated"}

    except Exception as e:
        db.rollback()
        logger.error(f"Error deactivating user: {e}")
        return {"success": False, "error": "An error occurred"}

    finally:
        db.close()


@app.get("/api/activities")
async def get_activities(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Get user's activity timeline.
    """
    from archer.database.models import ActivityLog, ActivityType

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        # Get all activities for the current user, ordered by most recent
        activities = (
            db.query(ActivityLog)
            .filter(ActivityLog.user_id == user.id)
            .order_by(ActivityLog.created_at.desc())
            .limit(100)
            .all()
        )

        # Format activities for frontend
        result = []
        for activity in activities:
            # Parse metadata if it exists
            metadata_dict = {}
            if activity.activity_metadata:
                try:
                    import json

                    metadata_dict = json.loads(activity.activity_metadata)
                except:
                    pass

            result.append(
                {
                    "id": activity.id,
                    "type": activity.activity_type.value,
                    "title": activity.title,
                    "description": activity.description,
                    "metadata": metadata_dict,
                    "created_at": activity.created_at.isoformat(),
                }
            )

        return {"success": True, "activities": result}

    except Exception as e:
        logger.error(f"Error fetching activities: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch activities")

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Browser cache / localStorage reset endpoint
# ---------------------------------------------------------------------------

@app.get("/clear-browser-cache", response_class=HTMLResponse)
async def clear_browser_cache():
    """Serve a page that clears browser localStorage then redirects home."""
    html = """<!DOCTYPE html>
<html><head><title>Clearing cache…</title></head>
<body>
<p>Clearing browser preferences…</p>
<script>
try { localStorage.clear(); } catch(e) {}
window.location.replace('/');
</script>
</body></html>"""
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    """
    Archer CLI entry point.

    Usage:
      archer-cli serve              Start the Archer server (default: port 8000)
      archer-cli serve --port 8001  Start on a custom port
      archer-cli serve --host 0.0.0.0  Bind to all interfaces
      archer-cli serve --reload     Enable auto-reload (development)
      archer-cli clear-cache        Clear server-side caches and reset browser preferences
    """
    import sys
    import argparse
    import shutil

    # Peek at first positional arg for subcommands
    subcommand = None
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        subcommand = sys.argv[1]

    if subcommand == "clear-cache":
        _cli_clear_cache()
        return

    parser = argparse.ArgumentParser(
        prog="archer-cli serve",
        description="Archer – Threat Detection Engineering Platform",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (dev mode)")
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    args = parser.parse_args()

    import uvicorn
    print(f"Starting Archer on http://{args.host}:{args.port}")
    uvicorn.run(
        "archer.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers if not args.reload else 1,
        # Longer than any poll interval: at uvicorn's 5s default a client polling every 5s
        # reuses a connection the server is just closing, and the poll fails
        timeout_keep_alive=75,
    )


def _cli_clear_cache():
    """Clear server-side caches and print browser reset instructions."""
    import shutil
    from archer.config import DATA_DIR

    cleared = []

    # Clear MITRESaw CSV/XLSX cache
    csv_path = Path(DATA_DIR) / "mitre_procedures.csv"
    xlsx_path = Path(DATA_DIR) / "mitre_procedures.xlsx"
    for p in (csv_path, xlsx_path):
        if p.exists():
            p.unlink()
            cleared.append(str(p))

    # Clear generated detections cache
    detections_dir = Path(DATA_DIR) / "detections"
    if detections_dir.exists():
        shutil.rmtree(detections_dir)
        cleared.append(str(detections_dir))

    if cleared:
        print("Cleared server-side caches:")
        for c in cleared:
            print(f"  ✓ {c}")
    else:
        print("No server-side caches found to clear.")

    print()
    print("To reset browser preferences (LLM choice, etc.), visit:")
    print("  http://localhost:8000/clear-browser-cache")
    print()
    print("Or paste this in your browser console:")
    print("  localStorage.clear(); location.reload();")


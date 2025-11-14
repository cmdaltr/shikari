from fastapi import FastAPI, Form, Request, UploadFile, File, Cookie, Response, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from archer.security import sanitize_filename, validate_safe_path, sanitize_group_name
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from typing import Optional

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

# from archer.build import define_vectr_values
from archer.mitre import (
    get_stix_data,
    obtain_all_techniques,
    obtain_technique_descriptions,
)
from archer.mitre.enterprise import check_group_in_mitre
from archer.build.orchestrator import process_group
from archer.genai import process_genai
from datetime import datetime
import os
import json
import logging
import threading
import re
import yaml
from archer.build.progress import read_progress, write_progress
from archer.config import (
    GENERATE_DIR,
    CORRELATE_DIR,
    DRAFTS_DIR,
    UPLOADS_DIR,
    BLOG_DIR,
    ATTACK_FLOWS_DIR,
    PROGRESS_DIR,
    PROFILE_PICS_DIR,
    SEVERITY_ORDER,
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
from archer.database.models import User, UserRole, APIKey


templates = Jinja2Templates(directory="templates")

# Data source display name mapping (used for detection titles and correlation displays)
DATA_SOURCE_DISPLAY_NAMES = {
    "aws cloudtrail": "AWS CloudTrail",
    "aws guardduty": "AWS GuardDuty",
    "aws_waf": "AWS WAF",
    "azure activedirectory": "Entra ID",
    "azure activitylog": "Azure",
    "checkpoint_ips": "CheckPoint IPS",
    "cisco_umbrella": "Cisco Umbrella",
    "citrix_netscaler": "Citrix NetScaler",
    "cloudflare_waf": "Cloudflare WAF",
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
    "imperva_waf": "Imperva WAF",
    "incapsula_waf": "Incapsula WAF",
    "mcafee epo": "McAfee ePO",
    "mcafee_ips": "MacAfee IPS",
    "mcafee_proxy": "McAfee Proxy",
    "microsoft defender": "MDE",
    "microsoft_defender": "MDE",
    "edr_events": "MDE",
    "mde": "MDE",
    "microsoft windows": "Windows Event Logs",
    "microsoft_cloudappsecurity": "MCAS",
    "microsoft_o365": "M365",
    "splunk": "Splunk",
    "unix": "Unix",
}


def load_yaml_file(file_path: str) -> Optional[dict]:
    """
    Load and parse a YAML file safely.

    Args:
        file_path: Path to the YAML file

    Returns:
        Parsed YAML data as dictionary, or None if loading fails
    """
    try:
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
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


def calculate_detection_likelihood(indicators: list, query: str, technique: str, yaml_data: dict) -> int:
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
            if any(x in indicator_lower for x in ['sha256', 'sha1', 'md5', '.exe', 'mimikatz', 'powershell.exe', 'cmd.exe',
                                                    'psexec', 'cobalt', 'beacon', 'meterpreter', 'empire']):
                strong_indicators += 1
            # Medium indicators: file paths, registry keys, specific patterns
            elif any(x in indicator_lower for x in [':\\\\', 'hkey', 'software\\\\', 'system32', 'appdata',
                                                      'temp\\\\', '.dll', '.bat', '.ps1', '.vbs']):
                medium_indicators += 1
            # Weak indicators: generic terms, config files
            elif any(x in indicator_lower for x in ['hosts', 'config', 'settings', 'user', 'admin']):
                weak_indicators += 1
            else:
                medium_indicators += 1

        # Add points based on indicator strength
        score += min(strong_indicators * 8, 30)  # Cap at +30
        score += min(medium_indicators * 5, 20)  # Cap at +20
        score += min(weak_indicators * 2, 10)   # Cap at +10

    else:
        # No indicators extracted - behavioral detection
        score -= 20

    # Data source reliability analysis
    required_connectors = yaml_data.get('requiredDataConnectors', []) if yaml_data else []
    if required_connectors:
        for connector in required_connectors:
            connector_id = connector.get('connectorId', '').lower() if isinstance(connector, dict) else str(connector).lower()

            # Reliable, commonly available data sources
            if any(x in connector_id for x in ['threatprotection', 'defender', 'sysmon', 'windows']):
                score += 10
            # Cloud/specialized data sources (may not be configured)
            elif any(x in connector_id for x in ['azureactivedirectory', 'office365', 'aws', 'gcp']):
                score -= 5

    # Query specificity analysis
    if query:
        query_lower = query.lower()

        # Specific, high-fidelity queries
        if any(x in query_lower for x in ['sha256', 'sha1', 'md5', '==', 'has_all']):
            score += 10
        # Generic "contains" queries (higher false positive risk)
        elif query_lower.count('contains') > 3:
            score -= 5

        # Network-based detections (generally reliable if you have network monitoring)
        if any(x in query_lower for x in ['remoteip', 'destinationip', 'destinationport', 'url', 'domain']):
            score += 10

        # File/Process-based detections (very reliable)
        if any(x in query_lower for x in ['processcommandline', 'filename', 'filepath', 'deviceprocessevents']):
            score += 10

    # Check for weak indicator patterns that reduce likelihood
    if indicators:
        for indicator in indicators:
            # MFA/hosts file example - very weak indicator
            if 'hosts' in indicator.lower() and 'etc' in indicator.lower():
                score -= 25  # Major penalty for weak indicators

            # Generic admin/system paths
            if indicator.lower() in ['admin', 'administrator', 'system', 'user']:
                score -= 10

    # OSINT enrichment adds confidence
    if yaml_data and yaml_data.get('osint_enriched'):
        score += 15

    # Ensure score is within 0-100 range
    final_score = max(0, min(100, score))

    # Debug output
    print(f"[LIKELIHOOD] Technique: {technique}, Indicators: {len(indicators)}, Score: {final_score}", flush=True)

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

    if vendor.lower() == 'mde':
        # Extract MDE table names - pattern: TableName | where ...
        # Common tables: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, etc.
        # Exclude column names like DeviceId, DeviceName
        pattern = r'\b(Device\w+Events|Device\w+Info|Identity\w+Events|Identity\w+Info|Email\w+Events|CloudApp\w+|Alert\w+)\b'
        matches = re.findall(pattern, query)

        # Filter out common column names that aren't tables
        column_names = {'DeviceId', 'DeviceName', 'DeviceType', 'IdentityName', 'EmailSender', 'EmailRecipient'}
        tables_indexes = sorted([m for m in set(matches) if m not in column_names])

    elif vendor.lower() == 'splunk':
        # Extract Splunk index names - pattern: index=indexname or index="indexname"
        pattern = r'index\s*=\s*["\']?([a-zA-Z0-9_\-]+)["\']?'
        matches = re.findall(pattern, query, re.IGNORECASE)
        tables_indexes = sorted(set(matches))

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
    if name.isupper() and len(name) <= 5 and ' ' not in name:
        return name

    # Handle longer all-caps names (like "TRUSTMODIFICATION")
    # Strategy: Use a simple English word list to detect boundaries
    if name.isupper() and len(name) > 5:  # Process longer all-caps strings
        # Common English words that might appear in technique names
        common_words = [
            'TRUST', 'MODIFICATION', 'DATA', 'ENCRYPTED', 'FOR', 'IMPACT',
            'ACCESS', 'ACCOUNT', 'ADMIN', 'APPLICATION', 'AUTH', 'AUTHENTICATION',
            'BACKUP', 'BOOT', 'BROWSER', 'CACHE', 'CERTIFICATE', 'CLOUD',
            'CODE', 'COMMAND', 'COMMUNICATION', 'COMPROMISE', 'CONFIG', 'CONFIGURATION',
            'CONTROL', 'CREDENTIAL', 'DEFENSE', 'DISCOVERY', 'DOMAIN',
            'ELEVATION', 'ESCALATION', 'EVASION', 'EVENT', 'EXECUTION', 'EXPLOIT',
            'FILE', 'FILTER', 'FIREWALL', 'GROUP', 'HIJACK', 'HOOK',
            'INJECTION', 'LATERAL', 'LOG', 'LOGIN', 'MALWARE', 'MANAGEMENT',
            'MEMORY', 'MOVEMENT', 'NETWORK', 'OBJECT', 'PASSWORD', 'PATH',
            'PERMISSION', 'POLICY', 'PORT', 'PRIVILEGE', 'PROCESS', 'PROTOCOL',
            'PROXY', 'REGISTRY', 'REMOTE', 'RESOURCE', 'ROOT', 'SCRIPT',
            'SECURITY', 'SERVER', 'SERVICE', 'SESSION', 'SHELL', 'SOFTWARE',
            'STORAGE', 'SYSTEM', 'TASK', 'TOKEN', 'USER', 'WEB', 'WINDOWS'
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
                    remaining = remaining[len(word):]
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
            name = ' '.join(words_found).title()
        else:
            # Couldn't split - just title case it
            name = name.title()

    # If already has spaces, clean up extra spaces and fix known issues
    if ' ' in name:
        # Fix "Multi- Factor" -> "Multi-Factor"
        result = re.sub(r'(\w+)-\s+(\w+)', r'\1-\2', name)
        # Fix "Data Encryptedfor" -> "Data Encrypted for"
        result = re.sub(r'([a-z])for\b', r'\1 for', result)
        result = re.sub(r'([a-z])to\b', r'\1 to', result)
        result = re.sub(r'([a-z])from\b', r'\1 from', result)
        # Fix "N T D S" -> "NTDS"
        result = re.sub(r'\b([A-Z])\s+([A-Z])\s+([A-Z])\s+([A-Z])\b', r'\1\2\3\4', result)
        result = re.sub(r'\b([A-Z])\s+([A-Z])\s+([A-Z])\b', r'\1\2\3', result)
        return result

    # Special case: PowerShell should stay as one word (not "Power Shell")
    if name == 'PowerShell':
        return 'PowerShell'

    # Special case: Windows Management Instrumentation (WMI) variations
    if name in ['WindowsManagementInstrumentation', 'WMI']:
        return 'Windows Management Instrumentation'

    # Insert space before uppercase letters (except at start)
    result = re.sub(r'(?<!^)(?=[A-Z])', ' ', name)

    # Special case: handle specific known lowercase words in the middle
    # "Datafrom Cloud Storage" -> "Data from Cloud Storage"
    # "Exfiltrationto Cloud Storage" -> "Exfiltration to Cloud Storage"
    result = re.sub(r'([a-z])(from)(?=[A-Z\s]|$)', r'\1 \2', result)
    result = re.sub(r'([a-z])(to)(?=[A-Z\s]|$)', r'\1 \2', result)
    result = re.sub(r'([a-z])(for)(?=[A-Z\s]|$)', r'\1 \2', result)

    # Fix hyphenated words: "Multi Factor" -> "Multi-Factor"
    result = re.sub(r'\bMulti\s+Factor\b', 'Multi-Factor', result)
    result = re.sub(r'\bTwo\s+Factor\b', 'Two-Factor', result)

    return result


def merge_correlations(vendor_corrs: list) -> list:
    """
    Merge correlations that share the same first technique (file 'a') and have
    multiple second techniques (file 'b') from the same tactic into a single correlation.

    Example:
        Before:
        - MFA → Create Process with Token (Defense Evasion)
        - MFA → SID-History Injection (Defense Evasion)
        - MFA → Access Token Manipulation (Defense Evasion)

        After:
        - MFA → Create Process with Token/SID-History Injection/Access Token Manipulation

    Args:
        vendor_corrs: List of correlation dictionaries from JSON

    Returns:
        List of correlations with merged entries where applicable
    """
    import os
    import glob

    # Group correlations by (vendor, file_a)
    groups = {}
    for corr in vendor_corrs:
        vendor = corr.get('vendor', 'unknown')
        file_a = corr.get('a', '')
        key = (vendor, file_a)

        if key not in groups:
            groups[key] = []
        groups[key].append(corr)

    # Process each group and merge where appropriate
    merged_correlations = []

    for key, group in groups.items():
        if len(group) == 1:
            # No merging needed - only one correlation for this first technique
            merged_correlations.append(group[0])
            continue

        # Group by PRIMARY tactic of second technique (most specific tactic)
        # Only merge if techniques share a rare/specific tactic (not common ones like Persistence/Defense Evasion)
        by_tactic = {}

        # Common tactics that should NOT trigger merging (too broad)
        common_tactics = {'Persistence', 'Defense Evasion', 'Privilege Escalation'}

        for corr in group:
            file_b = corr.get('b', '')
            if not file_b:
                continue

            # Extract tactics from file_b YAML
            full_path = os.path.join(GENERATE_DIR, os.path.basename(file_b))
            if os.path.exists(full_path):
                yaml_data = load_yaml_file(full_path)
                if yaml_data:
                    tactics = yaml_data.get('tactics', [])

                    # Find the first tactic as primary (prefer non-common tactics)
                    primary_tactic = "Unknown"
                    # First try to find a non-common tactic
                    for tactic in tactics:
                        if tactic not in common_tactics:
                            primary_tactic = tactic
                            break

                    # If no non-common tactic found, use the first tactic (even if common)
                    if primary_tactic == "Unknown" and tactics:
                        primary_tactic = tactics[0]

                    if primary_tactic not in by_tactic:
                        by_tactic[primary_tactic] = []
                    by_tactic[primary_tactic].append(corr)
            else:
                # If file doesn't exist, add to "Unknown" tactic with unique key
                basename_b = os.path.basename(file_b).replace('.yaml', '').split('_')[0]
                unique_key = f"_unique_{basename_b}"
                if unique_key not in by_tactic:
                    by_tactic[unique_key] = []
                by_tactic[unique_key].append(corr)

        # Merge groups with 2+ techniques in same SPECIFIC tactic
        for tactic, tactic_corrs in by_tactic.items():
            if len(tactic_corrs) >= 2 and not tactic.startswith('_unique_'):
                # Merge these correlations (they share a specific tactic)
                merged = _merge_correlation_group(tactic_corrs)
                merged_correlations.append(merged)
            else:
                # Add as-is (unique techniques or single correlation)
                merged_correlations.extend(tactic_corrs)

    return merged_correlations


def find_yaml_for_technique(technique_name: str, yaml_dir: str) -> str:
    """
    Find the YAML file for a given technique name by searching the directory.

    Args:
        technique_name: The technique name to search for (e.g., "Clear Windows Event Logs")
        yaml_dir: Directory containing YAML files

    Returns:
        Filename of matching YAML file, or None if not found
    """
    import glob

    # Normalize technique name for filename matching (remove spaces, special chars)
    normalized = technique_name.replace(' ', '').replace('-', '').lower()

    # Search for YAML files
    yaml_files = glob.glob(os.path.join(yaml_dir, '*.yaml'))

    for yaml_file in yaml_files:
        yaml_data = load_yaml_file(yaml_file)
        if yaml_data:
            # Check if the 'name' field matches
            yaml_name = yaml_data.get('name', '')
            if yaml_name == technique_name:
                return os.path.basename(yaml_file)

    # Fallback: try filename matching
    for yaml_file in yaml_files:
        basename = os.path.basename(yaml_file).replace('.yaml', '')
        # Remove data source suffix (e.g., "_DeviceProcessEvents")
        basename_clean = basename.split('_')[0].lower()
        if basename_clean == normalized:
            return os.path.basename(yaml_file)

    return None


def _merge_correlation_group(correlations: list) -> dict:
    """
    Merge multiple correlations into a single correlation with combined queries.

    Args:
        correlations: List of correlations to merge (all share same first technique and tactic)

    Returns:
        Single merged correlation dictionary
    """
    if not correlations:
        return {}

    # Use first correlation as base
    base = correlations[0].copy()

    # Collect all file_b paths and technique names with their tactics
    files_b = []
    techniques_with_tactics = []

    # Get first technique
    first_tech = base.get('techniques_involved', [])[0] if base.get('techniques_involved') else None
    if first_tech:
        # Get primary tactic of first technique
        file_a = base.get('a', '')
        full_path_a = os.path.join(GENERATE_DIR, os.path.basename(file_a))
        if os.path.exists(full_path_a):
            yaml_data = load_yaml_file(full_path_a)
            if yaml_data:
                tactics_a = yaml_data.get('tactics', [])
                primary_tactic_a = tactics_a[0] if tactics_a else "Unknown"
                techniques_with_tactics.append((first_tech, primary_tactic_a))

    # Extract ALL technique names from file paths (a and b) for each correlation
    # This ensures we capture all techniques that appear in the merged queries
    for corr in correlations:
        # Process file_a (first technique) - skip if already added
        file_a = corr.get('a', '')
        if file_a:
            basename_a = os.path.basename(file_a).replace('.yaml', '').replace('.yml', '')
            full_path_a = os.path.join(GENERATE_DIR, basename_a + '.yaml')
            if os.path.exists(full_path_a):
                yaml_data_a = load_yaml_file(full_path_a)
                if yaml_data_a:
                    tech_name_a = yaml_data_a.get('name', '')
                    if tech_name_a and not any(t[0] == tech_name_a for t in techniques_with_tactics):
                        tactics_a = yaml_data_a.get('tactics', [])
                        primary_tactic_a = tactics_a[0] if tactics_a else "Unknown"
                        techniques_with_tactics.append((tech_name_a, primary_tactic_a))

        # Process file_b (second technique)
        file_b = corr.get('b', '')
        if file_b:
            files_b.append(file_b)

            basename_b = os.path.basename(file_b).replace('.yaml', '').replace('.yml', '')
            full_path_b = os.path.join(GENERATE_DIR, basename_b + '.yaml')
            if os.path.exists(full_path_b):
                yaml_data_b = load_yaml_file(full_path_b)
                if yaml_data_b:
                    tech_name_b = yaml_data_b.get('name', '')
                    if tech_name_b and not any(t[0] == tech_name_b for t in techniques_with_tactics):
                        tactics_b = yaml_data_b.get('tactics', [])
                        primary_tactic_b = tactics_b[0] if tactics_b else "Unknown"
                        techniques_with_tactics.append((tech_name_b, primary_tactic_b))

    # Sort techniques by MITRE ATT&CK tactic order
    tactic_order = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                   'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
                   'Collection', 'Command and Control', 'Exfiltration', 'Impact']

    def get_tactic_index(tech_tuple):
        tactic = tech_tuple[1]
        try:
            return tactic_order.index(tactic)
        except ValueError:
            return 999  # Unknown tactics go last

    techniques_with_tactics.sort(key=get_tactic_index)
    techniques_involved = [tech[0] for tech in techniques_with_tactics]

    # Debug: Log what techniques were collected
    if len(techniques_involved) > 2:
        print(f"DEBUG _merge_correlation_group: Collected {len(techniques_involved)} techniques: {techniques_involved}")

    # Merge queries using OR logic
    merged_query = _build_merged_query(correlations)

    # Update base correlation with merged data
    base['b'] = files_b  # Now an array
    base['merged'] = True
    base['techniques_involved'] = techniques_involved
    base['combined_query'] = merged_query

    # Combine all tactics
    all_tactics = set()
    for corr in correlations:
        all_tactics.update(corr.get('tactics', []))
    base['tactics'] = sorted(list(all_tactics))

    # Use highest relevance score
    base['relevance_score'] = max(c.get('relevance_score', 0.0) for c in correlations)

    return base


def _build_merged_query(correlations: list) -> str:
    """
    Build a merged query that combines multiple second techniques with OR conditions.
    Supports both KQL (MDE) and Splunk query languages.

    Args:
        correlations: List of correlations to merge

    Returns:
        Combined query string
    """
    if not correlations:
        return ""

    # Extract first technique query (same for all correlations)
    first_corr = correlations[0]
    combined_query = first_corr.get('combined_query', '')
    vendor = first_corr.get('vendor', '').lower()

    # Parse out the first technique section
    import re

    # Detect if this is a Splunk query
    is_splunk = (vendor == 'splunk' or
                 (isinstance(combined_query, str) and
                  ('index=' in combined_query or 'earliest=' in combined_query)))

    # For Splunk queries, we can't easily merge the transaction-based correlation syntax
    # Return the first correlation's combined query as-is
    # TODO: Implement proper Splunk correlation merging if needed
    if is_splunk:
        # For now, just return the original combined query
        # Splunk correlations use transaction-based syntax which is complex to merge
        return combined_query

    # KQL/MDE query merging logic below
    # Extract the first "let" statement (first technique)
    first_let_match = re.search(r'(let\s+\w+\s*=.*?\|\s*project[^;]+;)', combined_query, re.DOTALL)
    if not first_let_match:
        return combined_query  # Can't parse, return original

    first_let = first_let_match.group(1)

    # Build combined second technique conditions
    second_conditions = []
    second_let_statements = []
    table_counter = {}

    for idx, corr in enumerate(correlations):
        query = corr.get('combined_query', '')
        techniques = corr.get('techniques_involved', [])

        # Extract second let statement
        # Find all let statements after the first one
        let_matches = list(re.finditer(r'let\s+(\w+)\s*=\s*(\w+)\s*\n\|\s*where\s+Timestamp[^;]+\|\s*where\s+([^\n]+(?:\n(?!\|)[^\n]+)*)', query, re.DOTALL))

        if len(let_matches) > 1:
            # Get the second let statement
            table_name = let_matches[1].group(2)  # e.g., "DeviceEvents"
            where_condition = let_matches[1].group(3).strip()

            # Track unique table names
            if table_name not in table_counter:
                table_counter[table_name] = 0
            table_counter[table_name] += 1

            # Extract the technique name from the existing comment in the WHERE condition
            # Look for // TechniqueName pattern
            comment_match = re.search(r'//\s*([^\n]+)', where_condition)
            if comment_match:
                technique_name = comment_match.group(1).strip()
            else:
                # Fallback: use second technique from list, or all techniques after the first
                technique_name = ' / '.join(techniques[1:]) if len(techniques) > 1 else f"Technique{idx+1}"

            # Strip any existing comment lines from the where_condition to avoid duplication
            # Remove lines that start with // (with optional leading whitespace)
            condition_lines = where_condition.split('\n')
            cleaned_lines = [line for line in condition_lines if not line.lstrip().startswith('//')]
            cleaned_condition = '\n'.join(cleaned_lines).strip()

            # Format the condition with technique comment
            second_conditions.append(f"  // {technique_name}\n  ({cleaned_condition})")

    # Build the merged query
    if not second_conditions:
        return combined_query  # Can't merge, return original

    # Create the second technique query with OR conditions
    # Determine which table is most common
    most_common_table = max(table_counter.keys(), key=lambda k: table_counter[k]) if table_counter else "DeviceEvents"

    # Parse the original query to extract join template
    join_match = re.search(r'(//\s*Chain events.*?\|\s*project\s+\*)', combined_query, re.DOTALL)
    join_template = join_match.group(1) if join_match else ""

    # Build new combined query
    merged = f"""{first_let}

let {most_common_table}_Combined = {most_common_table}
| where Timestamp > ago(1h)
| where
{" or\n".join(second_conditions)}
| project Timestamp, DeviceName, AccountName=AccountName, *;

{join_template}"""

    # Fix the join to use the new combined table
    merged = re.sub(r'\|\s*join\s+kind=inner\s*\(\s*\w+', f'| join kind=inner (\n    {most_common_table}_Combined', merged)

    return merged


def get_platform_from_data_source(data_source: str) -> str:
    """
    Map a data source to its platform/vendor.

    Examples:
        "microsoft_defender" -> "MDE"
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
        return "MDE"
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
        return DATA_SOURCE_DISPLAY_NAMES.get(data_source_lower, data_source.replace("_", " ").title())


def markdown_links_to_html(text):
    """
    Convert markdown links to HTML anchor tags.
    Example: [C0027](https://attack.mitre.org/campaigns/C0027) -> <a href="https://attack.mitre.org/campaigns/C0027" target="_blank">C0027</a>
    """
    pattern = r"\[([^\]]+)\]\(([^)]+)\)"
    return re.sub(pattern, r'<a href="\2" target="_blank">\1</a>', text)


def markdown_links_to_plain(text):
    """
    Remove markdown link syntax, keeping only the link text.
    Example: [C0027](https://attack.mitre.org/campaigns/C0027) -> C0027
    """
    pattern = r"\[([^\]]+)\]\([^)]+\)"
    return re.sub(pattern, r"\1", text)


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
            with open(yaml_file, "r") as f:
                content = f.read()
        else:
            content = file_content

            # Check for OSINT comparison (default behavior - always enabled)
            has_osint_comparison = "osint_compared: true" in content

            # Check for OSINT enhancement (optional - checkbox feature)
            has_osint_enhancement = "osint_enhanced: true" in content

            if has_osint_comparison:
                osint_data = {}

                # Extract comparison date
                date_match = re.search(r"comparison_date:\s*(.+)", content)
                if date_match:
                    osint_data["comparison_date"] = date_match.group(1).strip()

                # Extract sources
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

                # Extract osint_indicators using proper YAML parsing
                import yaml as yaml_lib
                try:
                    yaml_data = yaml_lib.safe_load(content)
                    if yaml_data and "osint_indicators" in yaml_data:
                        indicators = yaml_data["osint_indicators"]
                        if indicators:
                            osint_data["indicators"] = indicators
                except yaml_lib.YAMLError as e:
                    # YAML parsing error - skip with warning
                    filename = os.path.basename(yaml_file)
                    logger.debug(f"Skipping OSINT indicators for {filename}: {str(e).split(chr(10))[0]}")
                    osint_data["indicators"] = {}
                except Exception as e:
                    logger.warning(f"Error extracting OSINT indicators from {os.path.basename(yaml_file)}: {e}")
                    # Fallback to empty indicators
                    osint_data["indicators"] = {}

                # Return enhancement flag and OSINT data
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
                        cleaned = val.strip().strip('*').strip()
                        if cleaned:
                            indicators.append(cleaned)

            # KQL has_any() - alternate approach to catch all values in the parentheses
            has_any_full_pattern = r'has_any\s*\(([^)]+)\)'
            has_any_full_matches = re.findall(has_any_full_pattern, query_text, re.IGNORECASE)
            for match_group in has_any_full_matches:
                # Split by comma and extract quoted values
                values = re.findall(r'"([^"]+)"', match_group)
                for val in values:
                    if val and len(val.strip()) >= 3:
                        cleaned = val.strip().strip('*').strip()
                        if cleaned and cleaned not in indicators:
                            indicators.append(cleaned)

            # Splunk IN () syntax - extract values from IN ("val1", "val2", ...)
            # Example: | search process IN ("wevtutil", "evtx")
            in_pattern = r'\bIN\s*\(([^)]+)\)'
            in_matches = re.findall(in_pattern, query_text, re.IGNORECASE)
            for match_group in in_matches:
                # Extract quoted values
                values = re.findall(r'"([^"]+)"', match_group)
                for val in values:
                    if val and len(val.strip()) >= 3:
                        cleaned = val.strip().strip('*').strip()
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
                if any(common in path for common in ['/var/', '/tmp/', '/etc/', '/home/', '/usr/', '/opt/', '/bin/', '/sbin/', '/dev/', '/proc/', '/sys/']):
                    indicators.append(path)

            # File extensions and patterns (e.g., .pid, .lock, .log)
            extension_pattern = r'["\']?(\.[a-z]{2,5})["\']?'
            extensions = re.findall(extension_pattern, query_text, re.IGNORECASE)
            # Only include meaningful extensions
            meaningful_exts = ['.pid', '.lock', '.log', '.tmp', '.conf', '.cfg', '.ini', '.dat']
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
                cleaned_val = val.strip().strip('*').strip()
                if len(cleaned_val) >= 3 and not cleaned_val.isdigit() and cleaned_val.lower() not in ['and', 'or', 'not', 'null', 'none', 'true', 'false']:
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
                'condition', 'conditions', 'value', 'values', 'data', 'file',
                'process', 'command', 'user', 'system', 'event', 'log', 'entry',
                'action', 'type', 'name', 'path', 'string', 'text', 'info'
            }

            for item in indicators:
                # Strip whitespace AND asterisks for consistent deduplication
                item_str = str(item).strip().strip('*').strip()
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
                            cleaned = str(val).strip().strip('*').strip()

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
                            common_words = {'and', 'or', 'to', 'the', 'a', 'an', 'in', 'on', 'at', 'for', 'with', 'from'}
                            if cleaned.lower() in common_words:
                                continue

                            # Skip if it contains citation markers or ends with period (likely description)
                            if 'Citation:' in cleaned or cleaned.endswith('.'):
                                continue

                            # Skip if it looks like a sentence (contains "may", "can", "to the", etc.)
                            sentence_patterns = [
                                r'\bmay\b', r'\bcan\b', r'\bwill\b', r'\bshould\b',
                                r'to the\b', r'to ensure\b', r'to modify\b',
                                r'Adversaries', r'Users may', r'file to\b',
                                r'\. And$',  # Ends with ". And"
                                r'memory is mapped',  # Descriptive phrase
                                r'virtual address space'  # Descriptive phrase
                            ]
                            if any(re.search(pattern, cleaned, re.IGNORECASE) for pattern in sentence_patterns):
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
app.mount("/static", StaticFiles(directory="static"), name="static")


# Favicon route - ensure favicon is served from root with no-cache headers
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    favicon_path = Path("static/favicon-32.png")
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
    Validate that all required mapping files exist in archer/mappings/.

    Exits the application with a clear error message if any required files are missing.
    """
    required_files = [
        "dataSources.json",
        "entityMappings.json",
        "indicatorMapping.json",
        "logSourceCategories.json",
        "platforms.json",
        "schemaSplunk.json",
        "schemaMDE.json",
        "schemaElastic.json",
        "schemaGoogleSecOps.json",
        "techniquePlatformIndicators.json",
    ]

    mappings_dir = Path("archer/mappings")
    missing_files = []

    for filename in required_files:
        file_path = mappings_dir / filename
        if not file_path.exists():
            missing_files.append(filename)

    if missing_files:
        error_message = "\n" + "="*80 + "\n"
        error_message += "ERROR: Required mapping files are missing!\n"
        error_message += "="*80 + "\n"
        error_message += f"\nThe following required files are missing from {mappings_dir}:\n\n"
        for filename in missing_files:
            error_message += f"  ✗ {filename}\n"
        error_message += "\nPlease ensure all required mapping files are present before starting the application.\n"
        error_message += "="*80 + "\n"

        print(error_message, flush=True)
        import sys
        sys.exit(1)


def get_mitre_lists():
    """
    Helper to return (tactics, techniques) used by templates.

    - tactics: ordered list of ATT&CK tactic names (filtered to an opinionated
      ordering defined by mitre_order).
    - techniques: cached list of technique display names stored in app.state
    """
    mitre_order = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command And Control",
        "Exfiltration",
        "Impact",
    ]
    bundle = getattr(app.state, "bundle", None)
    if bundle:
        tactics = [
            phase["phase_name"].title().replace("-", " ")
            for obj in getattr(bundle, "objects", [])
            if obj.get("type") == "attack-pattern" and "kill_chain_phases" in obj
            for phase in obj["kill_chain_phases"]
        ]
        tactics = list(dict.fromkeys(tactics))
        tactics = [t for t in mitre_order if t in tactics]
    else:
        tactics = []
    techniques = getattr(app.state, "techniques_to_choose", [])
    return tactics, techniques


# Load MITRE data on startup and cache in app.state
@app.on_event("startup")
def load_mitre_data():
    # Download the MITRE ATT&CK STIX bundle and cache useful indexes in
    # app.state so template handlers can access them without repeated network
    # calls. These calls are synchronous during startup to ensure the data
    # is available for user requests.
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    bundle = get_stix_data(url)
    app.state.bundle = bundle
    app.state.techniques_to_choose = obtain_all_techniques(bundle)
    app.state.technique_descriptions = obtain_technique_descriptions(bundle)


@app.on_event("startup")
async def initialize_osint_repos():
    """
    Initialize OSINT detection repositories on startup.

    Clones or updates Sigma and Elastic detection rule repositories locally
    for fast, offline searching without API rate limits. Repos are updated
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
    app.state.osint_user_accepted_failures = False

    async def init_repos():
        try:
            app.state.osint_status = "Cloning detection repositories (this may take 15-20 minutes on first run)..."

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()

            # Clone each repo and track results
            failed_repos = []
            successful_repos = []

            for repo_name in REPOS.keys():
                app.state.osint_status = f"Cloning {repo_name}..."
                app.state.osint_repos[repo_name] = {"status": "cloning", "error": None}

                try:
                    success = await loop.run_in_executor(None, clone_or_update_repo, repo_name, False)

                    if success:
                        app.state.osint_repos[repo_name] = {"status": "ready", "error": None}
                        successful_repos.append(repo_name)
                    else:
                        # Check if it's a timeout by looking at the printed output
                        # The clone_or_update_repo function returns False for timeouts
                        app.state.osint_repos[repo_name] = {"status": "failed", "error": "Clone failed (possibly timeout)"}
                        failed_repos.append(repo_name)
                except Exception as e:
                    error_msg = str(e)
                    if "Timeout" in error_msg or "timed out" in error_msg.lower():
                        error_msg = "Timeout while cloning (repo too large or slow connection)"
                    app.state.osint_repos[repo_name] = {"status": "failed", "error": error_msg}
                    failed_repos.append(repo_name)

            app.state.osint_failed_repos = failed_repos

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

    llm_endpoints = [
        ("Ollama", "http://localhost:11434/api/tags"),
        ("LM Studio", "http://localhost:1234/v1/models"),
        ("Llama.cpp", "http://localhost:8080/health"),
    ]

    async def check_endpoint(name, url):
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: requests.get(url, timeout=2)
            )
            if response.ok:
                return {"name": name, "url": url, "available": True}
        except:
            pass
        return None

    # Check all endpoints concurrently
    tasks = [check_endpoint(name, url) for name, url in llm_endpoints]
    results = await asyncio.gather(*tasks)

    # Find first available LLM
    for result in results:
        if result:
            app.state.local_llm_detected = result
            print(f"✓ Local LLM detected: {result['name']} at {result['url']}")
            return

    app.state.local_llm_detected = {"available": False}
    print("ℹ️  No local LLM detected")


@app.get("/api/llm/detect")
async def get_local_llm_status():
    """Get local LLM detection status."""
    return getattr(app.state, "local_llm_detected", {"available": False})


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


@app.post("/api/mappings/save")
async def save_mapping_config(
    request: Request,
    platform: str = Form(...),
    cmd: str = Form(""),
    file: str = Form(""),
    reg: str = Form(""),
    network: str = Form(""),
    archer_session: Optional[str] = Cookie(None),
):
    """Save custom mapping configuration for a platform."""
    import json

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    user, db = auth_result
    db.close()

    try:
        # Build mapping configuration
        mappings = {}
        if cmd:
            for idx in cmd.split(','):
                idx = idx.strip()
                if idx:
                    mappings[idx] = "| summarize by relevant_fields"

        # Save to custom mapping file
        mapping_file = Path(f"archer/mappings/schema{platform.capitalize()}_custom.json")

        # Read existing template if available
        template_file = Path(f"archer/mappings/schema{platform.capitalize()}.json")
        if template_file.exists():
            with open(template_file, 'r') as f:
                template = json.load(f)
        else:
            template = {}

        # Create simplified mapping structure
        custom_mappings = {
            "cmd": cmd.split(',') if cmd else [],
            "file": file.split(',') if file else [],
            "reg": reg.split(',') if reg else [],
            "network": network.split(',') if network else []
        }

        # Write custom mappings
        with open(mapping_file, 'w') as f:
            json.dump(custom_mappings, f, indent=2)

        return {
            "success": True,
            "message": f"Mapping configuration saved for {platform}",
            "file": str(mapping_file)
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/api/mappings/load")
async def load_mapping_config(
    request: Request,
    platform: str,
    archer_session: Optional[str] = Cookie(None),
):
    """Load current mapping configuration for a platform."""
    import json

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    user, db = auth_result
    db.close()

    try:
        # Try to load custom mapping file first
        mapping_file = Path(f"archer/mappings/schema{platform.capitalize()}_custom.json")

        if mapping_file.exists():
            with open(mapping_file, 'r') as f:
                custom_mappings = json.load(f)

            # Convert arrays back to comma-separated strings
            return {
                "success": True,
                "mappings": {
                    "cmd": ", ".join(custom_mappings.get("cmd", [])),
                    "file": ", ".join(custom_mappings.get("file", [])),
                    "reg": ", ".join(custom_mappings.get("reg", [])),
                    "network": ", ".join(custom_mappings.get("network", []))
                }
            }
        else:
            return {
                "success": False,
                "message": "No custom configuration found"
            }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.post("/api/mappings/test")
async def test_mapping_config(
    request: Request,
    platform: str = Form(...),
    cmd: str = Form(""),
    file: str = Form(""),
    reg: str = Form(""),
    network: str = Form(""),
    archer_session: Optional[str] = Cookie(None),
):
    """Test/validate mapping configuration."""
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    user, db = auth_result
    db.close()

    try:
        # Basic validation: check that index names don't contain invalid characters
        import re
        valid_pattern = re.compile(r'^[a-zA-Z0-9_\-,\s]+$')

        all_values = [cmd, file, reg, network]
        for value in all_values:
            if value and not valid_pattern.match(value):
                return {
                    "success": False,
                    "error": "Index names can only contain letters, numbers, underscores, hyphens, commas, and spaces"
                }

        return {
            "success": True,
            "message": "Configuration is valid"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/api/status/osint")
async def get_osint_status():
    """Get OSINT repository initialization status."""
    return {
        "ready": getattr(app.state, "osint_ready", False),
        "status": getattr(app.state, "osint_status", "Unknown"),
        "repos": getattr(app.state, "osint_repos", {}),
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
    return {
        "accepted": True,
        "message": "Continuing without failed repositories"
    }


@app.get("/api/correlation/params")
async def get_correlation_params():
    """Get current correlation parameters from config files."""
    import re
    try:
        # Read config.py for threshold
        config_path = os.path.join(os.path.dirname(__file__), 'config.py')
        with open(config_path, 'r') as f:
            config_content = f.read()

        # Extract threshold
        threshold_match = re.search(r'correlation_min_relevance = float\(os\.getenv\("CORRELATION_MIN_RELEVANCE", "([0-9.]+)"\)\)', config_content)
        threshold = float(threshold_match.group(1)) if threshold_match else 0.40

        # Read engine.py for per_vendor and tech_freq
        engine_path = os.path.join(os.path.dirname(__file__), 'genai', 'engine.py')
        with open(engine_path, 'r') as f:
            engine_content = f.read()

        # Extract max_per_vendor
        per_vendor_match = re.search(r'max_per_vendor: int = (\d+)', engine_content)
        per_vendor = int(per_vendor_match.group(1)) if per_vendor_match else 25

        # Extract tech frequency limit
        tech_freq_match = re.search(r'if max_occurrences < (\d+):\s*#.*simple correlations', engine_content)
        tech_freq = int(tech_freq_match.group(1)) if tech_freq_match else 20

        return {
            "success": True,
            "threshold": threshold,
            "per_vendor": per_vendor,
            "tech_freq": tech_freq
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "threshold": 0.40,
            "per_vendor": 25,
            "tech_freq": 20
        }


@app.post("/api/correlation/params")
async def save_correlation_params(request: Request):
    """Save correlation parameters to config files."""
    import re
    try:
        data = await request.json()
        threshold = float(data.get('threshold', 0.40))
        per_vendor = int(data.get('per_vendor', 25))
        tech_freq = int(data.get('tech_freq', 20))

        # Validate inputs
        if not (0.0 <= threshold <= 1.0):
            return {"success": False, "message": "Threshold must be between 0.0 and 1.0"}

        if per_vendor < 1:
            return {"success": False, "message": "Per-vendor limit must be at least 1"}

        if tech_freq < 1:
            return {"success": False, "message": "Tech frequency limit must be at least 1"}

        # Update config.py
        config_path = os.path.join(os.path.dirname(__file__), 'config.py')
        with open(config_path, 'r') as f:
            lines = f.readlines()

        for i, line in enumerate(lines):
            if 'correlation_min_relevance = float(os.getenv("CORRELATION_MIN_RELEVANCE"' in line:
                lines[i] = f'    correlation_min_relevance = float(os.getenv("CORRELATION_MIN_RELEVANCE", "{threshold}"))\n'

        with open(config_path, 'w') as f:
            f.writelines(lines)

        # Update engine.py
        engine_path = os.path.join(os.path.dirname(__file__), 'genai', 'engine.py')
        with open(engine_path, 'r') as f:
            content = f.read()

        # Update max_per_vendor parameter default
        content = re.sub(
            r'max_per_vendor: int = \d+',
            f'max_per_vendor: int = {per_vendor}',
            content
        )

        # Update tech frequency limit
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if 'if max_occurrences <' in line and 'simple correlations' in line:
                lines[i] = f'            if max_occurrences < {tech_freq}:  # Allow each technique in up to {tech_freq} simple correlations'
                break

        with open(engine_path, 'w') as f:
            f.write('\n'.join(lines))

        return {
            "success": True,
            "message": "Correlation parameters updated successfully",
            "threshold": threshold,
            "per_vendor": per_vendor,
            "tech_freq": tech_freq
        }

    except Exception as e:
        return {
            "success": False,
            "message": f"Error saving parameters: {str(e)}"
        }


@app.post("/api/status/osint/retry-failed")
async def retry_failed_osint_repos():
    """Retry cloning only the failed OSINT repositories."""
    import asyncio
    from archer.build.osint_repos import clone_or_update_repo

    failed_repos = getattr(app.state, "osint_failed_repos", [])

    if not failed_repos:
        return {
            "success": True,
            "message": "No failed repositories to retry",
            "retried": []
        }

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
        "retried": failed_repos
    }


@app.get("/", response_class=HTMLResponse)
def read_form(request: Request, archer_session: Optional[str] = Cookie(None)):
    # Render the index page where the user can enter a group name. The
    # template expects a `request` object and optionally lists of
    # techniques; other placeholders are provided for future features.

    # Check if user is logged in (but don't require it)
    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
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
    run_correlation: str = Form(None),
    cross_vendor_correlation: str = Form(None),
    run_emulation: str = Form(None),
    emulation_mode: str = Form("simulate"),
    vectr_export: str = Form(None),
    vectr_campaign_name: str = Form(None),
    osint_enhancement: str = Form(None),
    osint_comparison: str = Form(None),
    merge_by_tactic: str = Form(None),
    merge_by_parent: str = Form(None),
    exclude_splunk: str = Form(None),
    exclude_mde: str = Form(None),
    exclude_chronicle: str = Form(None),
    exclude_elastic: str = Form(None),
):
    # Called when the user clicks Generate on the index page. We first
    # check whether the provided group name maps to a known MITRE actor.

    # Determine GENAI_MODE based on checkboxes (priority order)
    # Default to semantic mode for best results (includes advanced parsing + behavioral grouping)
    genai_mode = "semantic"
    if local_llm == "true":
        genai_mode = "local_llm"
    elif ai_generators == "true":
        genai_mode = "ai_generators"

    actor_found = check_group_in_mitre(app.state.bundle, group_name)
    if actor_found == "Y":
        # Known actor: kick off processing in a background thread and immediately return a JSON
        # payload containing a redirect URL so the front-end can navigate to the progress page.
        hypothesis = "Generated from form"

        def _bg():
            try:
                # Build list of excluded vendors
                excluded = []
                if exclude_splunk == "true":
                    excluded.append("splunk")
                if exclude_mde == "true":
                    excluded.append("mde")
                if exclude_chronicle == "true":
                    excluded.append("googlesecops")
                if exclude_elastic == "true":
                    excluded.append("elastic")

                # Use the modified wrapper instead of direct process_group
                modified_process_group_wrapper(
                    group_name,
                    hypothesis,
                    manual_data=None,
                    genai_mode=genai_mode,
                    run_correlation=True,  # Always enabled by default
                    osint_enhancement=True,  # Always enabled by default
                    osint_comparison=(osint_comparison == "true"),
                    merge_by_tactic=(merge_by_tactic == "true"),
                    merge_by_parent=(merge_by_parent == "true"),
                    excluded_vendors=excluded if excluded else None,
                )

                # Run emulation if requested
                if run_emulation == "true":
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

                # Export to VECTR if requested
                if vectr_export == "true":
                    try:
                        from archer.config import VECTRConfig
                        from archer.vectr import export_to_vectr

                        if VECTRConfig.is_configured():
                            campaign_name = vectr_campaign_name if vectr_campaign_name else None
                            export_to_vectr(threat_group=group_name, campaign_name=campaign_name)
                    except Exception as e:
                        print(f"VECTR export error: {e}")

            except Exception:
                try:
                    write_progress(group_name, {"status": "failed"})
                except Exception:
                    pass

        threading.Thread(target=_bg, daemon=True).start()
        # Initialize a progress file so the front-end has something to poll
        try:
            write_progress(
                group_name,
                {
                    "status": "started",
                    "stage": "queued",
                    "created_yaml": 0,
                    "cross_vendor_enabled": (cross_vendor_correlation == "true"),
                },
            )
        except Exception:
            pass
        return JSONResponse({"redirect_url": f"/progress?group_name={group_name}"})
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
                        "redirect_url": f"/manual?group_name={group_name}&blog_found=true&source={blog_result.get('source', '')}"
                    }
                )
        except Exception as e:
            print(f"Blog search failed: {e}")

        # Fallback to manual entry
        return JSONResponse({"redirect_url": f"/manual?group_name={group_name}"})


@app.post("/generate/cve")
async def generate_cve(
    request: Request,
    cve_id: str = Form(...),
    run_correlation: str = Form(None),
    semantic: str = Form(None),
    advanced_parsing: str = Form(None),
    ai_generators: str = Form(None),
    local_llm: str = Form(None),
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

    # Use CVE ID directly as group name (no CVE_ prefix since it already starts with CVE-)
    if len(cve_ids) == 1:
        group_name = cve_ids[0]  # e.g., "CVE-2021-44228"
    else:
        group_name = f"{cve_ids[0]}_plus_{len(cve_ids)-1}"  # e.g., "CVE-2021-44228_plus_2"

    # Determine GENAI_MODE
    # Default to semantic mode for best results (includes advanced parsing + behavioral grouping)
    genai_mode = "semantic"
    if local_llm == "true":
        genai_mode = "local_llm"
    elif ai_generators == "true":
        genai_mode = "ai_generators"

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
                    "stage": "CVE Research",
                    "created_yaml": 0,
                    "total_yaml": len(cve_ids),
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

            for cve in cve_ids:
                # print(f"Researching {cve}...")
                research = research_and_hunt(cve)

                # Collect techniques
                all_techniques.extend(research.get("techniques", []))

                # Collect IOCs
                for ioc_type in all_iocs:
                    all_iocs[ioc_type].extend(research.get("iocs", {}).get(ioc_type, []))

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
                osint_enhancement=True,  # Always enabled by default
                osint_comparison=False,  # Default to false for CVE hunting
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

    threading.Thread(target=_bg, daemon=True).start()

    # Initialize progress
    try:
        write_progress(
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

    return JSONResponse({"redirect_url": f"/progress?group_name={group_name}"})


@app.post("/hunt/technique")
async def hunt_technique(
    request: Request,
    technique_ids: str = Form(...),
    merge_by_tactic: str = Form(None),
    merge_by_parent: str = Form(None),
    osint_enhancement: str = Form(None),
    osint_comparison: str = Form(None),
    ai_generators: str = Form(None),
    local_llm: str = Form(None),
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

    # Determine GENAI_MODE
    genai_mode = "heuristic"
    if local_llm == "true":
        genai_mode = "local_llm"
    elif ai_generators == "true":
        genai_mode = "ai_generators"

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
                    "stage": "Technique Research",
                    "created_yaml": 0,
                    "total_yaml": len(technique_id_list),
                },
            )

            # Build manual_data by looking up each technique
            tactic_map = {}

            for tech_id in technique_id_list:
                tech_info = _get_technique_info(tech_id)

                if not tech_info:
                    print(f"Warning: Could not find information for technique {tech_id}")
                    # Add to "Unknown Tactic" as fallback
                    tactic = "Unknown Tactic"
                else:
                    tactic = tech_info.get("tactic", "Unknown Tactic")

                if tactic not in tactic_map:
                    tactic_map[tactic] = []

                # Build technique entry
                technique_entry = {
                    "technique": tech_id,
                    "op_guidance": tech_info.get("description", f"Hunt for {tech_id}") if tech_info else f"Hunt for {tech_id}",
                    "red_tool": {},
                    "detect_guidance": tech_info.get("description", f"Detect usage of {tech_id}") if tech_info else f"Detect usage of {tech_id}",
                }

                # Add platforms if available
                if tech_info and "platforms" in tech_info:
                    technique_entry["procedure_platforms"] = tech_info["platforms"]

                tactic_map[tactic].append(technique_entry)

            # Convert tactic_map to manual_data format
            manual_data = []
            for tactic, techniques in tactic_map.items():
                manual_data.append({"tactic": tactic, "techniques": techniques})

            if not manual_data:
                raise ValueError(f"Could not build detection data for techniques: {technique_id_list}")

            # Process using existing pipeline
            modified_process_group_wrapper(
                group_name,
                hypothesis=f"Technique Hunt: {', '.join(technique_id_list)}",
                manual_data=manual_data,
                genai_mode=genai_mode,
                run_correlation=True,
                osint_enhancement=osint_enh,
                osint_comparison=osint_comp,
                merge_by_tactic=merge_tactic,
                merge_by_parent=merge_parent,
                correlation_min_relevance=correlation_threshold,
            )

        except Exception as e:
            print(f"Technique hunt error: {e}", flush=True)
            import traceback
            traceback.print_exc()
            try:
                write_progress(group_name, {"status": "failed", "error": str(e)})
            except Exception:
                pass

    threading.Thread(target=_bg, daemon=True).start()

    # Initialize progress
    try:
        write_progress(
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

    return JSONResponse({"redirect_url": f"/progress?group_name={group_name}"})


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


@app.get("/manual", response_class=HTMLResponse)
def manual(request: Request, group_name: str = ""):
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
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/save_draft")
async def save_draft(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False}, status_code=400)
    # Expect payload to include a `draft_id` and optional `user_id`.
    # The payload is stored to disk for later retrieval by /load_draft.
    draft_id = payload.get("draft_id")
    user_id = payload.get("user_id")
    if not draft_id:
        return JSONResponse({"ok": False}, status_code=400)
    # If user_id present in payload, require X-USER-ID header to match.
    if user_id:
        header_uid = request.headers.get("X-USER-ID")
        if not header_uid or header_uid != str(user_id):
            return JSONResponse({"ok": False, "error": "user_id header mismatch"}, status_code=403)
    drafts_dir = DRAFTS_DIR
    if user_id:
        user_dir = os.path.join(drafts_dir, "users", user_id)
        os.makedirs(user_dir, exist_ok=True)
        path = os.path.join(user_dir, f"{draft_id}.json")
    else:
        os.makedirs(drafts_dir, exist_ok=True)
        path = os.path.join(drafts_dir, f"{draft_id}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return JSONResponse({"ok": True})


@app.get("/load_draft")
async def load_draft(draft_id: str = "", user_id: str = ""):
    if not draft_id:
        return JSONResponse({"ok": False}, status_code=400)

    # If user_id provided, only look under that user's drafts
    if user_id:
        user_path = os.path.join(DRAFTS_DIR, "users", user_id, f"{draft_id}.json")
        if not os.path.exists(user_path):
            # not found or access denied
            return JSONResponse({"ok": False, "entries": []}, status_code=403)
        try:
            with open(user_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return JSONResponse({"ok": True, "entries": data.get("entries", [])})
        except Exception:
            return JSONResponse({"ok": False}, status_code=500)

    # No user_id: only allow top-level drafts
    path = os.path.join(DRAFTS_DIR, f"{draft_id}.json")
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
        draft_path = os.path.join(drafts_dir, f"{group_name}.json")
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
            )
        except Exception:
            try:
                write_progress(group_name, {"status": "failed"})
            except Exception:
                pass

    threading.Thread(target=_bg_manual, daemon=True).start()
    try:
        write_progress(group_name, {"status": "started", "stage": "queued", "created_yaml": 0})
    except Exception:
        pass

    # Redirect user to progress page
    return RedirectResponse(url=f"/progress?group_name={group_name}", status_code=303)


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


@app.get("/list_drafts")
async def list_drafts(user_id: str = ""):
    drafts_dir = DRAFTS_DIR
    results = []
    if user_id:
        user_dir = os.path.join(drafts_dir, "users", user_id)
        if not os.path.exists(user_dir):
            return JSONResponse({"ok": True, "drafts": []})
        for fname in os.listdir(user_dir):
            if fname.endswith(".json"):
                path = os.path.join(user_dir, fname)
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

    # list top-level drafts
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


# Add this function to explicitly start the GenAI processing after YAML generation
def start_genai_processing(group_name):
    """
    Helper function to start GenAI processing explicitly after YAML generation completes.
    This ensures proper transition between phases.
    """
    # Update progress to mark YAML generation as complete
    progress_data = read_progress(group_name) or {}

    # Make sure created_yaml equals total_yaml to show 100% completion
    if "total_yaml" in progress_data and progress_data.get("total_yaml", 0) > 0:
        progress_data["created_yaml"] = progress_data["total_yaml"]
    else:
        # If total_yaml is not set, set both to ensure 100% progress
        progress_data["created_yaml"] = progress_data.get("created_yaml", 10)
        progress_data["total_yaml"] = progress_data.get("created_yaml", 10)

    # Mark status as transitioning to GenAI
    progress_data["status"] = "genai_starting"
    write_progress(group_name, progress_data)

    # Start the actual GenAI processing
    try:
        import importlib.util

        spec = importlib.util.find_spec("archer.build.genai")
        if spec:
            genai_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(genai_module)

            # Start GenAI processing in a new thread
            def _bg_genai():
                try:
                    # Call the appropriate GenAI processing function
                    if hasattr(genai_module, "process_genai"):
                        # This is where GenAI correlation starts (dynamically loaded)
                        genai_module.process_genai(group_name)
                    elif hasattr(genai_module, "process"):
                        # Alternative entry point for GenAI processing
                        genai_module.process(group_name)
                    else:
                        print(f"Warning: GenAI module loaded but no process function found")
                        # Update progress to show GenAI is complete (fallback)
                        progress_data = read_progress(group_name) or {}
                        progress_data["status"] = "genai_complete"
                        write_progress(group_name, progress_data)
                except Exception as e:
                    print(f"Error in GenAI processing: {e}")
                    # Mark as failed
                    try:
                        progress_data = read_progress(group_name) or {}
                        progress_data["status"] = "failed"
                        write_progress(group_name, progress_data)
                    except:
                        pass

            threading.Thread(target=_bg_genai, daemon=True).start()
    except Exception as e:
        print(f"Error starting GenAI: {e}")


# Modify the orchestrator process to ensure completion
def modified_process_group_wrapper(
    group_name, hypothesis, manual_data=None, genai_mode=None, run_correlation=False, osint_enhancement=False, osint_comparison=False, merge_by_tactic=False, merge_by_parent=False, excluded_vendors=None
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
            excluded_vendors=excluded_vendors,
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
                        description=f"Generated {detection_count} detections and {correlation_count} cross-vendor correlations",
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
            if "total_yaml" in progress_data:
                progress_data["created_yaml"] = progress_data["total_yaml"]
            else:
                progress_data["created_yaml"] = progress_data.get("created_yaml", 10)
                progress_data["total_yaml"] = progress_data.get("created_yaml", 10)

            progress_data["status"] = "complete"
            progress_data["duration"] = duration_seconds
            # print(f"✅ Setting progress status to 'complete' for {group_name} (correlations finished)")
            # print(f"   Progress data: created_yaml={progress_data.get('created_yaml')}, total_yaml={progress_data.get('total_yaml')}, processed={progress_data.get('processed')}, total_pairs={progress_data.get('total_pairs')}")
            write_progress(group_name, progress_data)
            return

        # Otherwise, just mark as complete
        progress_data = read_progress(group_name) or {}
        if "total_yaml" in progress_data:
            progress_data["created_yaml"] = progress_data["total_yaml"]
        else:
            progress_data["created_yaml"] = progress_data.get("created_yaml", 10)
            progress_data["total_yaml"] = progress_data.get("created_yaml", 10)

        progress_data["status"] = "complete"
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
            write_progress(group_name, {"status": "failed"})
        except:
            pass


# Add a new endpoint to handle completion signals from the frontend
@app.post("/complete_yaml")
async def complete_yaml(request: Request, group_name: str = ""):
    """Handle explicit completion signal from frontend when YAML progress reaches 100%."""
    if not group_name:
        return JSONResponse({"ok": False, "error": "group_name required"}, status_code=400)

    # Fetch current progress
    progress_data = read_progress(group_name) or {}

    # Only proceed if we're not already in GenAI phase
    if progress_data.get("status") not in [
        "genai_started",
        "genai_starting",
        "genai_processing",
        "genai_complete",
    ]:
        # Ensure YAML progress shows as complete
        if "total_yaml" in progress_data:
            progress_data["created_yaml"] = progress_data["total_yaml"]
        else:
            progress_data["created_yaml"] = progress_data.get("created_yaml", 10)
            progress_data["total_yaml"] = progress_data.get("created_yaml", 10)

        # Mark as ready for GenAI (but preserve any existing GenAI progress fields)
        progress_data["status"] = "genai_starting"
        write_progress(group_name, progress_data)

        # Start GenAI processing in a background thread
        try:

            def _bg_genai():
                try:
                    print(f"Starting GenAI correlation for {group_name} in background thread")
                    process_genai(group_name)
                    print(f"GenAI correlation for {group_name} completed")
                except Exception as e:
                    print(f"Error in GenAI processing: {e}")
                    try:
                        progress_data = read_progress(group_name) or {}
                        progress_data["status"] = "failed"
                        write_progress(group_name, progress_data)
                    except:
                        pass

            thread = threading.Thread(target=_bg_genai, daemon=True)
            thread.start()
            print(f"Started background thread for GenAI processing: {thread.name}")
        except Exception as e:
            print(f"Error starting GenAI: {e}")

    return JSONResponse({"ok": True})


@app.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    use_openai: str = Form(None),
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

        # Parse the file to extract TTPs and IOCs
        use_ai = use_openai == "true"
        result = parse_intelligence_file(
            file_path=safe_filename,
            file_content=file_content,
            use_openai=use_ai,
            use_local_llm=False,
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
                    "synthetic_group_name": synthetic_group_name,
                    "use_openai": use_ai,
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
        use_ai = extraction_data.get("use_openai", False)
        run_correlation = extraction_data.get("run_correlation", False)

        # Build manual data structure for process_group
        manual_data = {
            "techniques": [],
            "identifiers": iocs,  # Use extracted IOCs
            "metadata": {"source": "file_upload", "filename": filename, "ttps_found": ttps},
        }

        # Add technique data for each TTP
        for ttp_id in ttps:
            # Try to get technique info from MITRE
            try:
                technique_info = _get_technique_info(ttp_id)
                if technique_info:
                    manual_data["techniques"].append(technique_info)
            except Exception:
                # If we can't find the technique, add minimal data
                manual_data["techniques"].append(
                    {
                        "tid": ttp_id,
                        "name": f"Technique {ttp_id}",
                        "tactic": "Unknown",
                        "description": f"Extracted from {filename}",
                        "software_used": [],
                        "platforms": ["windows", "linux", "macos"],
                    }
                )

        # Process in background thread
        def _bg():
            try:
                modified_process_group_wrapper(
                    synthetic_group_name,
                    f"Generated from uploaded file: {filename}",
                    manual_data=manual_data,
                    genai_mode="semantic" if not use_ai else "ai_generators",
                    run_correlation=True,  # Always enabled by default
                    osint_enhancement=(osint_enhancement == "true"),  # Default to False for uploads
                    osint_comparison=False,  # Default to false for uploads
                )
            except Exception as e:
                print(f"Error processing upload: {e}")
                try:
                    write_progress(synthetic_group_name, {"status": "failed", "error": str(e)})
                except Exception:
                    pass

        threading.Thread(target=_bg, daemon=True).start()

        # Initialize progress
        try:
            write_progress(
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
async def analyze_blog(
    request: Request,
    url: str = Form(...),
    use_openai: str = Form(None),
    auto_generate: str = Form(None),
    run_correlation: str = Form(None),
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
        result = analyze_blog_post(url)

        if not result.get("success"):
            return JSONResponse(
                {"success": False, "message": result.get("error", "Failed to analyze blog post")},
                status_code=500,
            )

        # Extract data
        ttps = result.get("techniques", [])
        iocs = result.get("iocs", {})
        group_name = result.get("group_name", "")
        procedures = result.get("procedures", [])

        # Create a synthetic group name for tracking if not found
        import hashlib
        import json
        import os

        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        # SECURITY: Sanitize group name
        raw_group_name = group_name or f"BlogAnalysis_{url_hash}"
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
                    "procedures": procedures,
                    "synthetic_group_name": synthetic_group_name,
                    "use_openai": use_openai == "true",
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
        procedures = extraction_data.get("procedures", [])
        use_ai = extraction_data.get("use_openai", False)
        run_correlation = extraction_data.get("run_correlation", False)

        # Build manual data structure for process_group
        manual_data = {
            "techniques": [],
            "identifiers": iocs,  # Use extracted IOCs
            "metadata": {
                "source": "blog_analysis",
                "url": url,
                "ttps_found": ttps,
                "procedures": procedures,
            },
        }

        # Add technique data for each TTP
        for ttp_id in ttps:
            # Try to get technique info from MITRE
            try:
                technique_info = _get_technique_info(ttp_id)
                if technique_info:
                    manual_data["techniques"].append(technique_info)
            except Exception:
                # If we can't find the technique, add minimal data
                manual_data["techniques"].append(
                    {
                        "tid": ttp_id,
                        "name": f"Technique {ttp_id}",
                        "tactic": "Unknown",
                        "description": f"Extracted from {url}",
                        "software_used": [],
                        "platforms": ["windows", "linux", "macos"],
                    }
                )

        # Process in background thread
        def _bg():
            try:
                modified_process_group_wrapper(
                    synthetic_group_name,
                    f"Generated from blog post: {url}",
                    manual_data=manual_data,
                    genai_mode="semantic" if not use_ai else "ai_generators",
                    run_correlation=run_correlation,
                )
            except Exception as e:
                print(f"Error processing blog analysis: {e}")
                try:
                    write_progress(synthetic_group_name, {"status": "failed", "error": str(e)})
                except Exception:
                    pass

        threading.Thread(target=_bg, daemon=True).start()

        # Initialize progress
        try:
            write_progress(
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


@app.post("/profile")
async def profile_company(
    request: Request,
    domain: str = Form(...),
    include_industry: str = Form(None),
    include_geography: str = Form(None),
    include_tech_stack: str = Form(None),
    include_supply_chain: str = Form(None),
    use_openai: str = Form(None),
    generate_detections: str = Form(None),
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

        # Profile the company
        print(f"\nProfiling domain: {domain}")
        profile = do_profile(domain, options, use_openai=use_ai, group_name=group_name)

        # Save profile to data/profiles/
        profile_dir = Path("data") / "profiles"
        profile_dir.mkdir(parents=True, exist_ok=True)

        # Use domain as filename (sanitized)
        safe_domain = domain.replace(".", "_").replace("/", "_")
        profile_path = profile_dir / f"{safe_domain}_profile.json"

        with open(profile_path, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)

        print(f"Profile saved to: {profile_path}")

        # Always return profile for user review first
        # User can then select which threat groups to generate detections for
        return JSONResponse(
            {
                "success": True,
                "profile": profile,
                "message": "Company profile complete",
                "profile_path": str(profile_path),
                "recommended_groups": profile.get("recommended_groups", []),
                "show_selection": auto_generate,  # Show selection UI if auto-generate was checked
            }
        )

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
        mitre_path = Path(__file__).parent / "data" / "cache" / "enterprise-attack.json"
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

        # Use the first group as primary (for progress tracking)
        primary_group = groups[0]

        # Start background generation for all selected groups
        def _generate_bg():
            try:
                for group in groups:
                    print(f"Generating detections for: {group}")
                    result = process_group(group, run_correlation=should_correlate)
                    print(f"Generated detections for {group}: {result}")
            except Exception as e:
                print(f"Error generating detections: {e}")
                import traceback

                traceback.print_exc()

        import threading

        threading.Thread(target=_generate_bg, daemon=True).start()

        # Return progress redirect
        group_list = ", ".join(groups[:3])  # Show first 3 groups
        if len(groups) > 3:
            group_list += f" and {len(groups) - 3} more"

        return JSONResponse(
            {
                "success": True,
                "redirect_url": f"/progress?group_name={primary_group}",
                "message": f"Generating detections for: {group_list}",
                "groups": groups,
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


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


@app.get("/results", response_class=HTMLResponse)
def results_page(request: Request, group_name: str, archer_session: Optional[str] = Cookie(None)):
    """
    Render the results dashboard showing generated detections, correlations, and attack flows.
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

    # Collect detection files by vendor
    generate_dir = GENERATE_DIR
    detection_files = {}
    vendor_icons = {
        "splunk": "🔍",
        "mde": "🛡️",
        "microsoft": "🛡️",
        "elastic": "🔎",
        "googlesecops": "🔎",
        "qradar": "🎯",
        "sumo": "☁️",
        "chronicle": "📊",
    }

    vendor_display_names = {
        "splunk": "Splunk",
        "mde": "MDE",
        "microsoft": "MDE",
        "elastic": "Elastic",
        "googlesecops": "Google SecOps",
        "qradar": "IBM QRadar",
        "sumo": "Sumo Logic",
        "chronicle": "Google Chronicle",
    }

    # Find all YAML files for this group
    # For CVE groups, files are named by technique (T1059, T1190) not group name
    # For threat actor groups, files are named by tactic but tagged with group name
    if os.path.exists(generate_dir):
        # Try both group name pattern and wildcard pattern for CVEs
        pattern1 = os.path.join(generate_dir, f"{safe_group}_*.yaml")
        pattern2 = (
            os.path.join(generate_dir, "T*_*.yaml")
            if safe_group.upper().startswith("CVE")
            else os.path.join(generate_dir, "*.yaml")
        )

        yaml_files = glob.glob(pattern1)
        if not yaml_files and pattern2 != pattern1:
            yaml_files = glob.glob(pattern2)
            # Filter by checking tags inside YAML for threat actor groups
            filtered_files = []
            for yaml_file in yaml_files:
                try:
                    with open(yaml_file, "r") as f:
                        content = f.read()
                        # Check if group name is in tags (e.g., "Scattered Spider (Group)")
                        if f"{group_name} (Group)" in content or f"{safe_group} (Group)" in content:
                            filtered_files.append(yaml_file)
                except:
                    pass
            yaml_files = filtered_files if filtered_files else yaml_files

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
            connector_value = yaml_data.get("connectorId", "")
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
                is_technique_id = bool(re.match(r'^T\d{4}', technique_upper))

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
            is_osint_enriched, osint_data = check_osint_enriched(yaml_file, file_content=file_content)

            # Debug: Log what we're passing to template
            if is_osint_enriched or osint_data:
                print(f"   is_osint_enriched: {is_osint_enriched}")
                print(f"   osint_data present: {bool(osint_data)}")

            # Extract the query and tactics from YAML for preview (use already-loaded yaml_data)
            query_text = yaml_data.get("query", "")
            tactics_list = yaml_data.get("tactics", [])
            # Get primary tactic (first in list)
            primary_tactic = tactics_list[0] if tactics_list else "Unknown"

            # Calculate detection likelihood score (0-100)
            detection_likelihood = calculate_detection_likelihood(
                indicators=indicators,
                query=query_text,
                technique=technique,
                yaml_data=yaml_data
            )

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
                    "needs_review": bool(osint_data) and not is_osint_enriched,  # True if OSINT comparison found results but didn't integrate them
                    "osint_enriched": is_osint_enriched,  # OSINT enhanced flag (purple badge) - only true if enhancement checkbox was enabled
                    "osint_data": osint_data,  # OSINT comparison data (for Show Details button) - included if OSINT comparison ran
                    "query": query_text,  # Add query for preview
                    "tactic": primary_tactic,  # Primary tactic for color coding
                    "tactics": tactics_list,  # All tactics
                    "detection_likelihood": detection_likelihood,  # Likelihood score (0-100)
                }
            )

    # Build vendor list for template with grouping
    # Group detections by technique + description (same technique + same IOCs = group together)
    detections = []
    total_detections = 0

    for vendor, files in detection_files.items():
        # Group files by technique + description for display
        grouped = {}
        for file_data in files:
            key = (file_data["technique"], file_data["description"])
            if key not in grouped:
                grouped[key] = {
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
                    "queries": [],  # Store all queries for this group
                }
            else:
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
                    "needs_review": bool(osint_data) and not is_osint,  # True if OSINT comparison found results but didn't integrate them
                    "osint_enriched": is_osint,  # Purple badge
                    "osint_data": osint_data,
                    "queries": data.get("queries", []),  # Pass queries for preview
                    "tactic": data.get("tactic", "Unknown"),  # Primary tactic
                    "tactics": data.get("tactics", []),  # All tactics
                    "detection_likelihood": data.get("detection_likelihood", 50),  # Likelihood score
                }
            )

        # Keep ungrouped file list for saving to library (with all fields)
        ungrouped_files = []
        for file_data in files:
            ungrouped_files.append(
                {
                    "technique": file_data.get("technique", ""),
                    "technique_display": file_data.get("technique_display", file_data.get("technique", "")),
                    "title": file_data["title"],
                    "description": file_data.get("description", ""),
                    "description_html": file_data.get("description_html", file_data.get("description", "")),
                    "description_plain": file_data.get("description_plain", file_data.get("description", "")),
                    "indicators": file_data.get("indicators", []),
                    "query": file_data.get("query", ""),
                    "tactic": file_data.get("tactic", "Unknown"),
                    "tactics": file_data.get("tactics", []),
                    "osint_enriched": file_data.get("osint_enriched", False),
                    "osint_data": file_data.get("osint_data", {}),
                    "detection_likelihood": file_data.get("detection_likelihood", 50),
                    "needs_review": file_data.get("needs_review", False),
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

    # Chronicle and Elastic are now fully supported - no longer "Coming Soon"
    # They will appear automatically when YAML files are generated for them

    # Sort vendors: Splunk, MDE, Google SecOps, Elastic, then others
    vendor_order = {"splunk": 0, "mde": 1, "microsoft": 1, "googlesecops": 2, "elastic": 3}
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
                vendor_corrs = corr_data.get("vendor_correlations", [])

                # Merge correlations with same first technique and related second techniques
                print(f"[MERGE] Before merging: {len(vendor_corrs)} correlations", flush=True)
                pre_merge_count = len(vendor_corrs)
                vendor_corrs = merge_correlations(vendor_corrs)
                post_merge_count = len(vendor_corrs)
                print(f"[MERGE] After merging: {post_merge_count} correlations", flush=True)

                # Update progress with post-merge correlation count
                from archer.build.progress import write_progress
                write_progress(
                    group_name,
                    {
                        "correlation_count_pre_merge": pre_merge_count,
                        "correlation_count_post_merge": post_merge_count,
                    }
                )

                # Extract technique and data source information from filenames
                for idx, corr in enumerate(vendor_corrs):
                    vendor = corr.get("vendor", "unknown")
                    file_a = corr.get("a", "")
                    file_b = corr.get("b", "")
                    relevance_score = corr.get("relevance_score", 0.0)
                    combined_query = corr.get("combined_query", "")
                    is_merged = corr.get("merged", False)

                    # Parse filename format: "example_index.yaml"
                    # Example: "Multi-FactorAuthentication_edr_events.yaml"
                    techniques = []
                    has_needs_review = False
                    severities = []
                    tactics_set = set()
                    time_window = "1h"  # Default

                    total_indicators = 0  # Track total indicators across both detections

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
                                technique_name = technique_id  # Default to ID if name not found
                                data_source = "Unknown"  # Default
                                friendly_source = "Unknown"

                                if yaml_data:
                                    # Get actual technique name from YAML and format it with spaces
                                    raw_name = yaml_data.get('name', technique_id)
                                    technique_name = format_technique_name(raw_name)

                                    # Extract data source from YAML requiredDataConnectors or dataTypes
                                    data_connectors = yaml_data.get('requiredDataConnectors', [])
                                    if data_connectors and len(data_connectors) > 0:
                                        # Get the first data type from first connector
                                        first_connector = data_connectors[0]
                                        data_types = first_connector.get('dataTypes', [])
                                        if data_types and len(data_types) > 0:
                                            data_source = data_types[0]
                                            # Map to friendly name
                                            friendly_source = DATA_SOURCE_DISPLAY_NAMES.get(
                                                data_source.lower(), data_source
                                            )

                                    # Get severity
                                    severity = yaml_data.get('severity', 'Medium')
                                    severities.append(severity)

                                    # Get tactics
                                    tactics = yaml_data.get('tactics', [])
                                    primary_tactic = "Unknown"
                                    if isinstance(tactics, list):
                                        tactics_set.update(tactics)
                                        # Use first tactic as primary for coloring
                                        primary_tactic = tactics[0] if tactics else "Unknown"

                                    # Extract time window from combined query if available
                                    if 'maxspan' in combined_query:
                                        match = re.search(r'maxspan=(\d+[hmd])', combined_query)
                                        if match:
                                            time_window = match.group(1)

                                techniques.append(
                                    {
                                        "id": technique_id,
                                        "name": technique_name,
                                        "source": friendly_source,
                                        "tactic": primary_tactic,
                                    }
                                )

                    if len(techniques) >= 2:
                        # Skip correlations with 0 total indicators across both detections
                        # This indicates the correlation cannot be effectively used as both detections
                        # require manual review and have no IOCs/patterns to search for
                        if total_indicators == 0:
                            print(f"Skipping correlation {idx+1} - 0 total indicators across both detections")
                            continue

                        # Needs Review badge should NOT be shown if there are indicators
                        # The correlation is usable as long as there are some indicators to search for
                        # (even if one of the detections has 0 indicators, the other can still be correlated)
                        has_needs_review = False

                        # Determine highest severity
                        highest_severity = "Medium"
                        for sev in severities:
                            if sev in SEVERITY_ORDER:
                                if SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(highest_severity):
                                    highest_severity = sev

                        # The vendor field indicates where the query runs (Splunk, MDE, etc.)
                        # This is the query platform, NOT the data sources being queried
                        # Map vendor to display name (splunk -> Splunk, mde -> MDE, etc.)
                        vendor_display = DATA_SOURCE_DISPLAY_NAMES.get(vendor.lower(), vendor.title())

                        # Extract tables (MDE) or indexes (Splunk) from the combined query
                        tables_indexes = extract_tables_indexes(combined_query, vendor)

                        # Build technique-to-tactic mapping and formatted names for techniques_involved
                        technique_tactic_map = {}
                        techniques_involved_formatted = []
                        techniques_by_tactic = {}  # Group techniques by tactic
                        # techniques_involved already loaded above at line 4361

                        # Map each technique to its primary tactic and get formatted name
                        # Build attack flow from ALL techniques (including merged ones)
                        for tech_name in techniques_involved:
                            # Look for YAML file matching this technique name
                            # Normalize technique name to match filename format (remove spaces)
                            filename_pattern = tech_name.replace(" ", "").replace("/", "")
                            pattern = os.path.join(GENERATE_DIR, f"{filename_pattern}_*.yaml")
                            matching_files = glob.glob(pattern)

                            if matching_files:
                                # Use first matching file
                                yaml_data = load_yaml_file(matching_files[0])
                                if yaml_data:
                                    # Get formatted name from YAML
                                    raw_name = yaml_data.get('name', tech_name)
                                    formatted_name = format_technique_name(raw_name)

                                    tech_tactics = yaml_data.get('tactics', [])
                                    # Use first tactic as primary
                                    primary_tactic = tech_tactics[0] if tech_tactics else "Unknown"
                                    technique_tactic_map[formatted_name] = primary_tactic
                                    techniques_involved_formatted.append(formatted_name)

                                    # Group by ALL tactics (not just primary) for attack flow visualization
                                    for tactic in tech_tactics:
                                        if tactic not in techniques_by_tactic:
                                            techniques_by_tactic[tactic] = []
                                        if formatted_name not in techniques_by_tactic[tactic]:
                                            techniques_by_tactic[tactic].append(formatted_name)
                                else:
                                    # Fallback: format the filename-based name
                                    formatted_name = tech_name.replace("-", " ")
                                    technique_tactic_map[formatted_name] = "Unknown"
                                    techniques_involved_formatted.append(formatted_name)
                                    if "Unknown" not in techniques_by_tactic:
                                        techniques_by_tactic["Unknown"] = []
                                    techniques_by_tactic["Unknown"].append(formatted_name)
                            else:
                                # Fallback: format the filename-based name
                                formatted_name = tech_name.replace("-", " ")
                                technique_tactic_map[formatted_name] = "Unknown"
                                techniques_involved_formatted.append(formatted_name)
                                if "Unknown" not in techniques_by_tactic:
                                    techniques_by_tactic["Unknown"] = []
                                techniques_by_tactic["Unknown"].append(formatted_name)

                        # Sort techniques_involved_formatted by MITRE ATT&CK tactic order
                        # Sort by PRIMARY tactic to match how techniques are highlighted
                        tactic_order = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                                       'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
                                       'Collection', 'Command and Control', 'Exfiltration', 'Impact']

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
                                    tech_tactics = yaml_data.get('tactics', [])
                                    # Add this technique to all its tactics
                                    for tactic in tech_tactics:
                                        if tactic not in techniques_by_tactic_filtered:
                                            techniques_by_tactic_filtered[tactic] = []
                                        if tech_name not in techniques_by_tactic_filtered[tactic]:
                                            techniques_by_tactic_filtered[tactic].append(tech_name)

                        # Replace techniques_by_tactic with filtered version
                        techniques_by_tactic = techniques_by_tactic_filtered

                        # Calculate attack chain length (number of tactics in attack flow order)
                        tactic_order = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                                       'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
                                       'Collection', 'Command and Control', 'Exfiltration', 'Impact']
                        attack_chain_length = sum(1 for tactic in tactic_order if tactic in techniques_by_tactic)

                        # Rebuild techniques list to match techniques_involved_formatted order and content
                        # This ensures the displayed techniques match what's being used for highlighting
                        techniques_rebuilt = []
                        for formatted_name in techniques_involved_formatted:
                            # Find matching technique in the original techniques list
                            matching_tech = None
                            for tech in techniques:
                                if tech['name'] == formatted_name:
                                    matching_tech = tech
                                    break

                            if matching_tech:
                                # Update the tactic field to use the PRIMARY tactic
                                primary_tactic = technique_tactic_map.get(formatted_name, matching_tech.get('tactic', 'Unknown'))
                                matching_tech_copy = matching_tech.copy()
                                matching_tech_copy['tactic'] = primary_tactic
                                techniques_rebuilt.append(matching_tech_copy)
                            else:
                                # Create a minimal technique entry if not found in original list
                                # This happens when techniques_involved has techniques not in files_to_process
                                primary_tactic = technique_tactic_map.get(formatted_name, "Unknown")
                                techniques_rebuilt.append({
                                    "id": formatted_name.replace(" ", "-"),
                                    "name": formatted_name,
                                    "source": vendor_display,
                                    "tactic": primary_tactic,
                                })

                        # Use the rebuilt list
                        techniques = techniques_rebuilt

                        correlations.append(
                            {
                                "techniques": techniques,
                                "flow_file": f"{safe_group}_corr_{idx+1}.html",
                                "vendor": vendor_display,
                                "needs_review": has_needs_review,
                                "relevance_score": int(relevance_score * 100),  # Convert to percentage
                                "severity": highest_severity,
                                "time_window": time_window,
                                "tactics": list(tactics_set),
                                "combined_query": combined_query,
                                "tables_indexes": tables_indexes,  # Add tables/indexes
                                "techniques_involved": techniques_involved_formatted,  # Add formatted technique names
                                "technique_tactic_map": technique_tactic_map,  # Map techniques to their primary tactics
                                "techniques_by_tactic": techniques_by_tactic,  # Group techniques by tactic
                                "attack_chain_length": attack_chain_length,  # Number of tactics in ordered attack flow
                                "is_merged": is_merged,  # Flag indicating if this is a merged correlation
                                "primary_tactics": list(primary_tactics),  # Tactics containing the original correlation pair
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
                -c.get("attack_chain_length", 0)  # Longer attack chains first (as tiebreaker)
            )
        )

        grouped_correlations.append({
            "name": vendor,
            "count": len(sorted_corrs),
            "correlations": sorted_corrs
        })

    # Sort by count descending
    grouped_correlations.sort(key=lambda x: -x["count"])

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

    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "user": user,
            "group_name": safe_group,
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
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    )


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
                    with open(yaml_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Check if this YAML file contains the group tag
                        if formatted_tag in content:
                            filename = os.path.basename(yaml_file)
                            zip_file.write(yaml_file, f"detections/{filename}")
                            files_added += 1
                            logger.info(f"Added detection: {filename}")
                except Exception as e:
                    logger.error(f"Error reading YAML file {yaml_file}: {e}")
                    continue

        # Add correlation JSON - use original group name (with spaces)
        corr_file = os.path.join(CORRELATE_DIR, f"{group_name}.json")
        if os.path.exists(corr_file):
            zip_file.write(corr_file, f"correlations/{group_name}.json")
            files_added += 1
            logger.info(f"Added correlation: {group_name}.json")
        else:
            logger.warning(f"Correlation file not found: {corr_file}")

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
async def login_page(request: Request, response: Response, registered: Optional[str] = None, next_url: Optional[str] = None):
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
        {"request": request, "error": None, "success": success_message, "csrf_token": csrf_token, "next_url": next_url or "/"},
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
    from archer.security.csrf import validate_csrf_token, consume_csrf_token
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
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "Security validation failed. Please refresh the page and try again.",
                    "csrf_token": "",  # Force page reload
                },
                status_code=403,
            )

        # Consume CSRF token to prevent reuse
        consume_csrf_token(csrf_token)

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
                {"request": request, "error": "Invalid email or password"},
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
                {"request": request, "error": "Invalid email or password"},
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
    return templates.TemplateResponse(
        "forgot_password.html", {"request": request}
    )


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
    from archer.security.csrf import validate_csrf_token, consume_csrf_token
    from archer.auth.password import validate_password, hash_password
    import re

    db = next(get_db())
    try:
        # Get client IP and user agent for logging
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        # Validate CSRF token
        if not archer_csrf_session or not validate_csrf_token(csrf_token, archer_csrf_session):
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "Security validation failed. Please refresh the page and try again.",
                    "csrf_token": "",  # Force page reload
                },
                status_code=403,
            )

        # Consume CSRF token to prevent reuse
        consume_csrf_token(csrf_token)

        # Check rate limit by IP address
        rate_limit_key = f"register:{client_ip}"
        is_allowed, remaining = check_rate_limit(rate_limit_key, max_attempts=5, window_seconds=300)

        if not is_allowed:
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "Too many registration attempts. Please try again in 5 minutes.",
                    "csrf_token": csrf_token,
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
                {"request": request, "error": "Invalid email address", "csrf_token": csrf_token},
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
                    "csrf_token": csrf_token,
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
                    "csrf_token": csrf_token,
                },
                status_code=400,
            )

        # Validate passwords match
        if password != password_confirm:
            record_attempt(rate_limit_key)
            return templates.TemplateResponse(
                "register.html",
                {"request": request, "error": "Passwords do not match", "csrf_token": csrf_token},
                status_code=400,
            )

        # Validate password strength
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            record_attempt(rate_limit_key)
            return templates.TemplateResponse(
                "register.html",
                {"request": request, "error": error_msg, "csrf_token": csrf_token},
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
            "profile.html", {"request": request, "user": user, "profile_picture_url": None}
        )
    finally:
        db.close()


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
            "mde": "MDE",
            "microsoft": "MDE",
            "elastic": "Elastic",
            "google_secops": "Google SecOps",
            "sentinel": "Azure Sentinel"
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
                content_data = json.loads(det.content) if isinstance(det.content, str) else det.content
            except (json.JSONDecodeError, ValueError):
                content_data = {}

            # Parse JSON fields safely
            tags = parse_json_field(det.tags, [])

            # Extract data from content JSON or YAML-like structure
            # Content can be a query string or a structured object
            if isinstance(content_data, dict):
                # Check if this is a detection object from results page (has 'technique' and 'queries' fields)
                # But NOT an imported YAML (which would have 'mde_tables' or 'splunk_indexes' or 'name' field)
                if "technique" in content_data and "queries" in content_data and "name" not in content_data and "mde_tables" not in content_data and "splunk_indexes" not in content_data:
                    # This is a detection saved from results page or imported YAML
                    # The "technique" field could be either technique_id (like "T1555.006") or technique_name
                    technique_value = content_data.get("technique") or det.title

                    # Check if technique_value looks like a technique ID (starts with T followed by digits)
                    import re
                    if re.match(r'^T\d{4}(\.\d{3})?$', technique_value):
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
                elif "name" in content_data or "requiredDataConnectors" in content_data or "technique_id" in content_data or ("technique" in content_data and "queries" in content_data and isinstance(content_data.get("queries"), list)):
                    # This is a YAML detection (either from data/generate or imported via import_yaml_to_library.py)
                    technique_id = content_data.get("technique", "") or content_data.get("technique_id", "")

                    # Look up technique name and tactics from MITRE ATT&CK using technique ID
                    tech_info = _get_technique_info(technique_id) if technique_id else None
                    if tech_info:
                        technique_name = tech_info.get("name", technique_id)
                        # We'll extract tactics from content_data below, but tech_info provides fallback
                    else:
                        # Fallback to technique ID if lookup fails (don't use detection title)
                        technique_name = technique_id or content_data.get("name", "Unknown")

                    description = content_data.get("description_html") or content_data.get("description", "")
                    # Convert markdown links to HTML anchor tags
                    description = markdown_links_to_html(description)

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
                    group_name = content_data.get("group") or content_data.get("threat_actor", "Unknown")

                    # Check if OSINT enriched
                    osint_enriched = content_data.get("osint_enriched") or content_data.get("osint_enhanced", False)

                    # Extract OSINT data if available
                    osint_data = None
                    if osint_enriched and "osint_indicators" in content_data:
                        osint_data = {
                            "indicators": content_data.get("osint_indicators", {}),
                            "enrichment_date": content_data.get("comparison_date", "")
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
                elif "technique" in content_data and "title" in content_data and "queries" not in content_data and "technique_id" not in content_data:
                    # This is a detection saved from results page (may have full data or minimal data)
                    technique_name = content_data.get("technique_display", content_data.get("technique", det.title))
                    technique_id = content_data.get("technique", "") if content_data.get("technique", "").startswith("T") else ""
                    description = content_data.get("description_html", content_data.get("description", ""))
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
                    tactics = content_data.get("tactics", [primary_tactic] if primary_tactic != "Unknown" else [])
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

            detection_data = {
                "id": det.id,
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
                "saved_date": det.created_at.strftime('%Y-%m-%d') if det.created_at else "",
                "osint_enriched": osint_enriched,
                "osint_data": osint_data,
                "needs_review": False,  # Generated detections always have indicators
                "detection_likelihood": content_data.get("detection_likelihood", 75),  # Added to match results page
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
                "combined_query": content_data.get("combined_query", "")
            }

            # Normalize vendor/platform based on query content and data sources
            # This fixes cases where data_source was set to index names (mcafee, unix, etc.)
            normalized_vendor = data_source or det.platform or "unknown"

            # If query starts with "index=", it's a Splunk detection
            if query_content and query_content.strip().lower().startswith("index="):
                normalized_vendor = "splunk"
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
            elif normalized_vendor.lower() in ['mcafee', 'unix', 'windows', 'linux', 'network', 'firewall', 'web']:
                normalized_vendor = "splunk"
            # Otherwise keep the data_source/platform as-is

            vendor = normalized_vendor.lower()
            if vendor not in vendors_dict:
                vendors_dict[vendor] = []

            # Check if this is a correlation (detection_type contains "correlation")
            # Handle both enum value ("sole_correlation") and enum name ("SOLE_CORRELATION")
            detection_type_str = str(det.detection_type).lower() if det.detection_type else ""
            detection_type_name = det.detection_type.name.lower() if hasattr(det.detection_type, 'name') else ""
            is_correlation = "correlation" in detection_type_str or "correlation" in detection_type_name

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
                content_data = json.loads(corr.content) if isinstance(corr.content, str) else corr.content
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
                    "saved_date": corr.created_at.strftime('%Y-%m-%d') if corr.created_at else "",
                    "osint_enriched": osint_enriched,
                    "osint_data": osint_data,
                    "needs_review": False,
                    "detection_likelihood": content_data.get("detection_likelihood", 75),
                    # Correlation-specific fields
                    "vendor": content_data.get("vendor", "unknown"),  # Query platform (Splunk, MDE, etc.)
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
                    "combined_query": content_data.get("combined_query", "")
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
                        "ids": []  # Track ALL detection IDs in this group
                    }

                # Add this detection's ID to the group
                grouped[key]["ids"].append(det.get("id"))

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
            for (technique, description), data in sorted(grouped.items(), key=lambda x: x[0][0].lower()):
                # Sort titles and join with " | "
                sorted_titles = sorted(data["titles"])
                combined_title = " | ".join(sorted_titles)

                detection_list.append({
                    "ids": data["ids"],  # All IDs in this group
                    "id": data["ids"][0] if data["ids"] else None,  # First ID for backwards compatibility
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
                    "detection_likelihood": data["detection_likelihood"]
                })

            # Count total individual detections (sum of IDs across all groups)
            total_individual_detections = sum(len(det.get("ids", [])) for det in detection_list)

            vendors.append({
                "name": vendor_name,
                "display_name": VENDOR_DISPLAY_NAMES.get(vendor_name, vendor_name.title()),
                "count": total_individual_detections,  # Total individual detections (matching results.html)
                "detections": detection_list
            })

        # Add Splunk as empty placeholder (if not already present)
        if not any(v["name"] == "splunk" for v in vendors):
            vendors.append({
                "name": "splunk",
                "display_name": "Splunk",
                "count": 0,
                "detections": [],
                "empty_state": True
            })

        # Add MDE as empty placeholder (if not already present)
        if not any(v["name"] in ["mde", "microsoft"] for v in vendors):
            vendors.append({
                "name": "mde",
                "display_name": "MDE",
                "count": 0,
                "detections": [],
                "empty_state": True
            })

        # Sort vendors: Splunk, MDE, Google SecOps, Elastic, then others
        vendor_order = {"splunk": 0, "mde": 1, "microsoft": 1, "googlesecops": 2, "elastic": 3}
        vendors.sort(key=lambda v: (vendor_order.get(v["name"], 99), v["name"]))

        # Calculate summary statistics
        # Count detections that are NOT correlations (exclude correlation detection_types from LibraryDetection)
        total_detections = sum(
            1 for d in detections
            if not d.detection_type or not (
                "correlation" in str(d.detection_type).lower() or
                (hasattr(d.detection_type, 'name') and "correlation" in d.detection_type.name.lower())
            )
        )

        # Count correlations from both tables (LibraryDetection with correlation type + LibraryCorrelation)
        total_correlations_from_detections = sum(
            1 for d in detections
            if d.detection_type and (
                "correlation" in str(d.detection_type).lower() or
                (hasattr(d.detection_type, 'name') and "correlation" in d.detection_type.name.lower())
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
            grouped_correlations.append({
                "name": vendor_lower,
                "display_name": VENDOR_DISPLAY_NAMES.get(vendor_lower, vendor),
                "count": len(vendor_corrs),
                "correlations": vendor_corrs
            })

        # Add Splunk as empty placeholder (if not already present)
        if not any(v["name"] in ["Splunk", "splunk"] for v in grouped_correlations):
            grouped_correlations.append({
                "name": "splunk",
                "display_name": "Splunk",
                "count": 0,
                "correlations": [],
                "empty_state": True
            })

        # Add MDE as empty placeholder (if not already present)
        if not any(v["name"] in ["MDE", "mde", "microsoft", "Microsoft"] for v in grouped_correlations):
            grouped_correlations.append({
                "name": "mde",
                "display_name": "MDE",
                "count": 0,
                "correlations": [],
                "empty_state": True
            })

        # Add Google SecOps as "Coming Soon" placeholder (if not already present)
        if not any(v["name"] in ["google_secops", "Google SecOps"] for v in grouped_correlations):
            grouped_correlations.append({
                "name": "google_secops",
                "display_name": "Google SecOps",
                "count": 0,
                "correlations": [],
                "coming_soon": True
            })

        # Add Elastic as "Coming Soon" placeholder (if not already present)
        if not any(v["name"] in ["elastic", "Elastic"] for v in grouped_correlations):
            grouped_correlations.append({
                "name": "elastic",
                "display_name": "Elastic",
                "count": 0,
                "correlations": [],
                "coming_soon": True
            })

        # Sort correlations: Splunk, MDE, Google SecOps, Elastic, then others
        # Priority: empty_state and coming_soon go after actual data
        def sort_correlations(v):
            vendor_order = {"Splunk": 0, "splunk": 0, "MDE": 1, "mde": 1, "googlesecops": 2, "Google SecOps": 2, "elastic": 3, "Elastic": 3}
            is_placeholder = v.get("coming_soon", False) or v.get("empty_state", False)
            has_data = v["count"] > 0
            return (not has_data, is_placeholder, vendor_order.get(v["name"], 99), v["name"])

        grouped_correlations.sort(key=sort_correlations)

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
                "archer_hours": archer_hours
            }
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
                content_data = json.loads(detection.content) if isinstance(detection.content, str) else detection.content
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
            export_data = direct_export_data
        else:
            # Original flow: Get data from library using IDs
            if not detection_ids and not correlation_ids:
                raise HTTPException(status_code=400, detail="No detections or correlations selected")

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
                    "content": json.loads(detection.content) if detection.content else {},
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
                    "detection_likelihood": content_data.get("detection_likelihood", 75)
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
                            "combined_query": content_data.get("combined_query", "")
                        }
                        report_correlations.append(correlation_dict)
            else:
                # Original flow: Get correlations from database query result
                for corr in correlations:
                    corr_content = json.loads(corr.content) if isinstance(corr.content, str) else corr.content
                    correlation_dict = {
                        "name": corr.title,
                        "techniques": corr_content.get("techniques", []),
                        "severity": corr_content.get("severity", "High"),
                        "time_window": corr_content.get("time_window", "N/A"),
                        "vendor": corr.platform or "Multi-platform",
                        "combined_query": corr_content.get("combined_query", "")
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
                "user": user.full_name if hasattr(user, 'full_name') else "Archer User",
                **report_metadata  # Include metrics, stats, etc. from results page
            }
            content_bytes = generator.generate(
                group_name=report_group_name,
                detections=report_detections,
                correlations=report_correlations if report_correlations else None,
                metadata=full_metadata
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
                    "detection_likelihood": content_data.get("detection_likelihood", 75)
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
                            "combined_query": content_data.get("combined_query", "")
                        }
                        report_correlations.append(correlation_dict)
            else:
                # Original flow: Get correlations from database query result
                for corr in correlations:
                    corr_content = json.loads(corr.content) if isinstance(corr.content, str) else corr.content
                    correlation_dict = {
                        "name": corr.title,
                        "techniques": corr_content.get("techniques", []),
                        "severity": corr_content.get("severity", "High"),
                        "time_window": corr_content.get("time_window", "N/A"),
                        "vendor": corr.platform or "Multi-platform",
                        "combined_query": corr_content.get("combined_query", "")
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
                "user": user.full_name if hasattr(user, 'full_name') else "Archer User",
                **report_metadata  # Include metrics, stats, etc. from results page
            }
            content_bytes = generator.generate(
                group_name=report_group_name,
                detections=report_detections,
                correlations=report_correlations if report_correlations else None,
                metadata=full_metadata
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


@app.post("/api/library/save")
async def save_to_library(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Save a new detection or correlation to the library.
    """
    from archer.database.models import LibraryDetection, LibraryCorrelation, DetectionType, VisibilityType
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
                existing_item.content = json.dumps(content) if isinstance(content, dict) else content
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
                existing_detection.content = json.dumps(content) if isinstance(content, dict) else content
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
        for detection in detections:
            detection.tags = tags_json

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

        # Delete detections
        if detection_ids:
            detections = (
                db.query(LibraryDetection)
                .filter(LibraryDetection.id.in_(detection_ids), LibraryDetection.user_id == user.id)
                .all()
            )

            if len(detections) != len(detection_ids):
                raise HTTPException(status_code=403, detail="Some detections not found or unauthorized")

            for detection in detections:
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
                .filter(LibraryCorrelation.id.in_(correlation_ids), LibraryCorrelation.user_id == user.id)
                .all()
            )

            corr_table_ids = [c.id for c in correlations_from_corr_table]

            # For IDs not found in LibraryCorrelation, try LibraryDetection (backward compatibility)
            remaining_ids = [id for id in correlation_ids if id not in corr_table_ids]
            correlations_from_det_table = []
            if remaining_ids:
                correlations_from_det_table = (
                    db.query(LibraryDetection)
                    .filter(LibraryDetection.id.in_(remaining_ids), LibraryDetection.user_id == user.id)
                    .all()
                )

            total_found = len(correlations_from_corr_table) + len(correlations_from_det_table)
            if total_found != len(correlation_ids):
                print(f"[DELETE] Expected {len(correlation_ids)} correlations, found {total_found}")
                print(f"[DELETE] Requested IDs: {correlation_ids}")
                print(f"[DELETE] Found in LibraryCorrelation: {corr_table_ids}")
                print(f"[DELETE] Found in LibraryDetection: {[d.id for d in correlations_from_det_table]}")
                raise HTTPException(status_code=403, detail="Some correlations not found or unauthorized")

            # Delete from both tables
            for correlation in correlations_from_corr_table:
                db.delete(correlation)
            for correlation in correlations_from_det_table:
                db.delete(correlation)
            deleted_count += total_found

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

        if not full_name:
            return {"success": False, "error": "Full name is required"}

        # Update user's full name and team
        user.full_name = full_name
        user.team = team if team else None
        db.commit()
        db.refresh(user)

        return {"success": True, "message": "Profile updated successfully"}

    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}

    finally:
        db.close()


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


@app.get("/api/profile/apikeys")
async def get_api_keys(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Get user's API keys (decrypted for display).

    Requires authentication. Returns decrypted API keys for the logged-in user.
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
                decrypted_value = decrypt_api_key(key.encrypted_key)
                result[key.key_name] = decrypted_value
            except Exception as e:
                logger.error(f"Failed to decrypt API key {key.key_name}: {e}")
                result[key.key_name] = ""

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

        # Map of frontend field names to database key names
        key_mapping = {
            "splunk": "splunk",
            "mde": "mde",
            "elastic": "elastic",
            "openai": "openai",
            "anthropic": "anthropic",
        }

        # Process each API key
        for frontend_name, db_name in key_mapping.items():
            key_value = data.get(frontend_name, "").strip()

            # Skip empty keys
            if not key_value:
                continue

            # Check if key already exists for this user
            existing_key = (
                db.query(APIKey)
                .filter(APIKey.user_id == user.id, APIKey.key_name == db_name)
                .first()
            )

            # Encrypt the API key
            encrypted_value = encrypt_api_key(key_value)

            if existing_key:
                # Update existing key
                existing_key.encrypted_key = encrypted_value
                existing_key.updated_at = datetime.utcnow()
            else:
                # Create new key
                new_key = APIKey(user_id=user.id, key_name=db_name, encrypted_key=encrypted_value)
                db.add(new_key)

        db.commit()
        return {"success": True, "message": "API keys saved successfully"}

    except Exception as e:
        db.rollback()
        logger.error(f"Error saving API keys: {e}")
        return {"success": False, "error": str(e)}

    finally:
        db.close()


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

            if not token:
                # For security, don't reveal if email exists or not
                return {
                    "success": True,
                    "message": "If an account exists with this email, a password reset link has been sent.",
                }

            # Send password reset email
            from archer.auth.email import send_password_reset_email, EMAIL_ENABLED

            email_sent = send_password_reset_email(
                email=email, token=token, full_name=user.full_name if user else None
            )

            # In development mode (EMAIL_ENABLED=false), also return the token for testing
            response = {
                "success": True,
                "message": "Password reset link has been sent to your email.",
            }

            if not EMAIL_ENABLED:
                # Development mode - include token in response for testing
                reset_url = f"http://localhost:8000/reset-password?token={token}"
                response["reset_url"] = reset_url
                response["token"] = token
                response["dev_mode"] = True

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

        # Validate role
        if role not in ["admin", "standard"]:
            return {"success": False, "error": "Invalid role. Must be 'admin' or 'standard'"}

        # Check if user already exists
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            return {"success": False, "error": "User with this email already exists"}

        # Create new user
        user_role = UserRole.ADMIN if role == "admin" else UserRole.STANDARD
        hashed_password = hash_password(password)

        new_user = User(
            email=email,
            full_name=full_name,
            hashed_password=hashed_password,
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
            if role not in ["admin", "standard"]:
                return {"success": False, "error": "Invalid role"}
            user.role = UserRole.ADMIN if role == "admin" else UserRole.STANDARD

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
 

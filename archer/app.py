from fastapi import FastAPI, Form, Request, UploadFile, File, Cookie, Response
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
    except Exception as e:
        logger.error(f"Failed to load YAML file {file_path}: {e}")
        return None


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


def check_osint_enriched(yaml_file):
    """
    Check if a YAML file has OSINT enrichment metadata.
    Returns tuple: (is_enriched: bool, osint_data: dict)
    """
    try:
        with open(yaml_file, "r") as f:
            content = f.read()
            # Check for osint_enriched flag
            if "osint_enriched: true" in content:
                osint_data = {}
                # Extract enrichment date
                date_match = re.search(r"enrichment_date:\s*(.+)", content)
                if date_match:
                    osint_data["enrichment_date"] = date_match.group(1).strip()
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
                return True, osint_data
    except Exception as e:
        logger.error(f"Error checking OSINT enrichment in {yaml_file}: {e}")
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
                item_str = str(item).strip()
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

                # Skip if already seen
                if item_lower in seen:
                    continue

                # Add to unique list (max 10)
                if len(unique_indicators) < 10:
                    seen.add(item_lower)
                    unique_indicators.append(item_str)

            return unique_indicators
    except:
        return []


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
):
    # Called when the user clicks Generate on the index page. We first
    # check whether the provided group name maps to a known MITRE actor.

    # Determine GENAI_MODE based on checkboxes (priority order)
    genai_mode = None
    if local_llm == "true":
        genai_mode = "local_llm"
    elif ai_generators == "true":
        genai_mode = "ai_generators"
    elif semantic == "true":
        genai_mode = "semantic"
    elif advanced_parsing == "true":
        genai_mode = "advanced_parsing"
    # If none selected, genai_mode remains None (uses default/heuristic)

    actor_found = check_group_in_mitre(app.state.bundle, group_name)
    if actor_found == "Y":
        # Known actor: kick off processing in a background thread and immediately return a JSON
        # payload containing a redirect URL so the front-end can navigate to the progress page.
        hypothesis = "Generated from form"

        def _bg():
            try:
                # Use the modified wrapper instead of direct process_group
                modified_process_group_wrapper(
                    group_name,
                    hypothesis,
                    manual_data=None,
                    genai_mode=genai_mode,
                    run_correlation=(run_correlation == "true"),
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
    genai_mode = None
    if local_llm == "true":
        genai_mode = "local_llm"
    elif ai_generators == "true":
        genai_mode = "ai_generators"
    elif semantic == "true":
        genai_mode = "semantic"
    elif advanced_parsing == "true":
        genai_mode = "advanced_parsing"

    def _bg():
        try:
            print(f"========================================", flush=True)
            print(f"CVE BACKGROUND THREAD STARTED", flush=True)
            print(f"Group name: {group_name}", flush=True)
            print(f"CVE IDs: {cve_ids}", flush=True)
            print(f"========================================", flush=True)

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
                print(f"Researching {cve}...")
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

            print(f"Found {len(all_techniques)} unique techniques from {len(cve_ids)} CVE(s)")
            print(f"DEBUG: Techniques list: {all_techniques}")
            print(f"DEBUG: IOCs collected: {sum(len(v) for v in all_iocs.values())} total")

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
                        print(f"DEBUG: Getting ATT&CK info for {tech_id}")
                        tech_info = _get_technique_info(tech_id)
                        if tech_info:
                            tactic = tech_info.get("tactic", "CVE Exploitation")
                            print(f"DEBUG: {tech_id} → {tactic}")
                        else:
                            tactic = "CVE Exploitation"
                            print(f"DEBUG: {tech_id} → CVE Exploitation (no ATT&CK mapping)")
                    else:
                        # Synthetic CVE-based technique
                        tactic = "CVE Exploitation"
                        print(f"DEBUG: {tech_id} → CVE Exploitation (synthetic)")

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
                    print(f"DEBUG [app.py]: Built ioc_dict for {tech_id}:")
                    print(f"  - ioc_dict keys: {list(ioc_dict.keys())}")
                    for key, vals in ioc_dict.items():
                        print(
                            f"  - {key}: type={type(vals)}, count={len(vals) if isinstance(vals, list) else 'N/A'}"
                        )

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

            print(f"DEBUG: Built manual_data with {len(manual_data)} tactics")
            for entry in manual_data:
                print(f"  - Tactic: {entry['tactic']}, Techniques: {len(entry['techniques'])}")

            if not manual_data:
                print(f"ERROR: Failed to build manual_data even with fallbacks!")
                print(f"  - CVE IDs: {cve_ids}")
                print(f"  - Techniques: {all_techniques}")
                print(f"  - IOCs: {all_iocs}")
                raise ValueError(f"CVE research failed to build detection data")

            # Process using existing pipeline
            modified_process_group_wrapper(
                group_name,
                hypothesis=f"CVE Hunting: {', '.join(cve_ids)}",
                manual_data=manual_data,
                genai_mode=genai_mode,
                run_correlation=(run_correlation == "true"),
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
    group_name, hypothesis, manual_data=None, genai_mode=None, run_correlation=False
):
    """Wrapper for process_group to ensure proper completion and transition to GenAI."""

    # Set GENAI_MODE environment variable if provided
    if genai_mode:
        os.environ["GENAI_MODE"] = genai_mode

    try:
        # Call the original process_group with run_correlation parameter
        # IMPORTANT: Use named parameters to avoid positional argument mismatch
        print(f"DEBUG: About to call process_group with:")
        print(f"  - group_name: {group_name}")
        print(f"  - output_dir: None")
        print(f"  - hypothesis: {hypothesis}")
        print(f"  - manual_data: {manual_data is not None} (is not None)")
        print(f"  - run_correlation: {run_correlation}")

        process_group(
            group_name=group_name,
            output_dir=None,
            hypothesis=hypothesis,
            manual_data=manual_data,
            run_correlation=run_correlation,
        )

        print(f"DEBUG: process_group completed successfully")

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
            print(f"✅ Setting progress status to 'complete' for {group_name} (correlations finished)")
            print(f"   Progress data: created_yaml={progress_data.get('created_yaml')}, total_yaml={progress_data.get('total_yaml')}, processed={progress_data.get('processed')}, total_pairs={progress_data.get('total_pairs')}")
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
        print(f"Error in process group: {e}")
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

        print(f"\n[DEBUG] Returning extraction results:")
        print(f"  - show_extraction: {response_data['show_extraction']}")
        print(f"  - filename: {response_data['filename']}")
        print(f"  - ttps_count: {response_data['ttps_count']}")
        print(f"  - iocs_count: {response_data['iocs_count']}")
        print(f"  - auto_generate_requested: {response_data['auto_generate_requested']}")

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
                    run_correlation=run_correlation,
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
        options = {
            "include_industry": include_industry == "true",
            "include_geography": include_geography == "true",
            "include_tech_stack": include_tech_stack == "true",
            "include_supply_chain": include_supply_chain == "true",
        }

        use_ai = use_openai == "true"
        auto_generate = generate_detections == "true"

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
        "qradar": "🎯",
        "sumo": "☁️",
        "chronicle": "📊",
    }

    vendor_display_names = {
        "splunk": "Splunk",
        "mde": "Microsoft Defender",
        "microsoft": "Microsoft Defender",
        "elastic": "Elastic",
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

            # Determine vendor from filename
            # MDE files: DeviceEvents, DeviceProcessEvents, etc.
            # Splunk files: *.yaml (e.g., edr_events, linux_syslog, aws_cloudtrail)
            vendor = None

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

            # Read description from YAML (handling multiline descriptions)
            description = ""
            try:
                with open(yaml_file, "r") as f:
                    lines = f.readlines()
                    in_description = False
                    desc_lines = []

                    for i, line in enumerate(lines):
                        # Found description field
                        if line.strip().startswith("description:"):
                            content = line.split(":", 1)[1].strip()
                            # If it's a multiline indicator (| or >)
                            if content in ("|", ">"):
                                in_description = True
                                continue
                            # If content is on the same line
                            elif content:
                                description = content.strip("\"'")
                                break
                        # Collect multiline description content
                        elif in_description:
                            # Stop if we hit a non-indented line or another field
                            if line.strip() and not line.startswith(" "):
                                break
                            # Add the line (strip leading spaces)
                            if line.strip():
                                desc_lines.append(line.strip())

                    # Join collected lines and format with newlines between indicator types
                    if desc_lines:
                        raw_desc = " ".join(desc_lines)
                        # Replace "; " with newlines to separate indicator types
                        formatted_desc = raw_desc.replace("; ", "\n")
                        # Limit total length
                        if len(formatted_desc) > 300:
                            formatted_desc = formatted_desc[:300] + "..."
                        description = formatted_desc
            except:
                pass

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

            # Extract indicators from the query
            indicators = extract_indicators_from_query(yaml_file)

            # Check for OSINT enrichment
            is_osint_enriched, osint_data = check_osint_enriched(yaml_file)

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
                    "needs_review": len(indicators) == 0 and not is_osint_enriched,  # Normal needs review (yellow)
                    "osint_enriched": is_osint_enriched,  # OSINT enriched flag (orange badge)
                    "osint_data": osint_data if is_osint_enriched else {},
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
            total_detections += 1  # Count every detection individually

        # Convert grouped data to list format for display
        detection_list = []
        for (technique, description), data in sorted(grouped.items(), key=lambda x: x[0][0]):
            # Sort titles alphabetically and join with commas
            sorted_titles = sorted(data["titles"])
            combined_title = ", ".join(sorted_titles)
            is_osint = data.get("osint_enriched", False)
            has_indicators = len(data.get("indicators", [])) > 0
            detection_list.append(
                {
                    "technique": data["technique_display"],  # Use full display name
                    "title": combined_title,
                    "description": description,
                    "description_html": data.get("description_html", description),
                    "description_plain": data.get("description_plain", description),
                    "indicators": data.get("indicators", []),
                    "needs_review": not has_indicators and not is_osint,  # Yellow badge
                    "osint_enriched": is_osint,  # Orange badge
                    "osint_data": data.get("osint_data", {}),
                }
            )

        # Keep ungrouped file list for saving to library
        ungrouped_files = []
        for file_data in files:
            ungrouped_files.append(
                {
                    "technique": file_data.get("technique_display", file_data["technique"]),
                    "title": file_data["title"],
                    "description": file_data["description"],
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

    # Add Elastic as "Coming Soon" placeholder
    detections.append(
        {
            "name": "elastic",
            "display_name": "Elastic",
            "icon": "🔎",
            "count": 0,
            "detections": [],
            "coming_soon": True,
        }
    )

    detections.sort(key=lambda x: x["count"], reverse=True)

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

                # Extract technique and data source information from filenames
                for idx, corr in enumerate(vendor_corrs):
                    vendor = corr.get("vendor", "unknown")
                    file_a = corr.get("a", "")
                    file_b = corr.get("b", "")
                    relevance_score = corr.get("relevance_score", 0.0)
                    combined_query = corr.get("combined_query", "")

                    # Parse filename format: "example_index.yaml"
                    # Example: "Multi-FactorAuthentication_edr_events.yaml"
                    techniques = []
                    has_needs_review = False
                    severities = []
                    tactics_set = set()
                    time_window = "1h"  # Default

                    total_indicators = 0  # Track total indicators across both detections

                    for file_path in [file_a, file_b]:
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
                                indicators = extract_indicators_from_query(full_path)
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
                                    if isinstance(tactics, list):
                                        tactics_set.update(tactics)

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
                            }
                        )
        except Exception as e:
            print(f"Error loading correlations: {e}")
            pass

    # Check if attack flow exists
    attack_flow_file = os.path.join(ATTACK_FLOWS_DIR, f"{safe_group}_complete_flow.html")
    attack_flow_exists = os.path.exists(attack_flow_file)

    # Get unique technique count
    technique_set = set()
    for vendor_data in detections:
        for detection in vendor_data["detections"]:
            technique_set.add(detection["technique"])

    # Calculate duration (if progress file exists)
    duration = "N/A"
    progress_file = os.path.join(PROGRESS_DIR, f"{safe_group}.json")
    if os.path.exists(progress_file):
        try:
            with open(progress_file, "r") as f:
                progress_data = json.load(f)
                # Estimate based on timestamps if available
                duration = "~3min"  # Placeholder
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
            "duration": duration,
            "detections": detections,
            "correlations": correlations,
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
    safe_group = sanitize_group_name(group_name)

    # Create in-memory ZIP file
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        # Add detection YAMLs
        generate_dir = GENERATE_DIR
        if os.path.exists(generate_dir):
            for yaml_file in glob.glob(os.path.join(generate_dir, f"{safe_group}_*.yaml")):
                filename = os.path.basename(yaml_file)
                zip_file.write(yaml_file, f"detections/{filename}")

        # Add correlation JSON
        corr_file = os.path.join(CORRELATE_DIR, f"{safe_group}.json")
        if os.path.exists(corr_file):
            zip_file.write(corr_file, f"correlations/{safe_group}.json")

        # Add attack flows
        flow_dir = ATTACK_FLOWS_DIR
        if os.path.exists(flow_dir):
            for flow_file in glob.glob(os.path.join(flow_dir, f"{safe_group}_*.json")):
                filename = os.path.basename(flow_file)
                zip_file.write(flow_file, f"attack_flows/{filename}")

            for flow_file in glob.glob(os.path.join(flow_dir, f"{safe_group}_*.html")):
                filename = os.path.basename(flow_file)
                zip_file.write(flow_file, f"attack_flows/{filename}")

    zip_buffer.seek(0)

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={safe_group}_results.zip"},
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
async def login_page(request: Request, response: Response, registered: Optional[str] = None):
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
        {"request": request, "error": None, "success": success_message, "csrf_token": csrf_token},
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

        # Set session cookie
        redirect_response = RedirectResponse(url="/", status_code=303)

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
    Render the Library page for managing saved detections.
    """
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return auth_result

    user, db = auth_result

    try:
        template_response = templates.TemplateResponse(
            "library.html", {"request": request, "user": user}
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
        export_format = body.get("format", "json")  # json, csv, xml

        if not detection_ids:
            raise HTTPException(status_code=400, detail="No detections selected")

        # Get detections
        detections = (
            db.query(LibraryDetection)
            .filter(
                LibraryDetection.id.in_(detection_ids),
                (LibraryDetection.user_id == user.id)
                | (LibraryDetection.visibility == VisibilityType.SHARED),
            )
            .all()
        )

        if not detections:
            raise HTTPException(status_code=404, detail="No detections found")

        # Prepare data
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
    Save a new detection to the library.
    """
    from archer.database.models import LibraryDetection, DetectionType, VisibilityType
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
        db.commit()

        # Log library save activity
        try:
            log_activity(
                user_id=user.id,
                activity_type="library_save",
                title=f"Saved detection to library: {title}",
                description=f"Added {detection_type} detection with {visibility} visibility",
                metadata={
                    "detection_id": new_detection.id,
                    "detection_type": detection_type,
                    "platform": platform,
                    "visibility": visibility,
                },
            )
        except Exception as log_error:
            print(f"Error logging library save activity: {log_error}")

        return {
            "success": True,
            "message": "Detection saved to library",
            "id": new_detection.id,
            "tags": all_tags,
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error saving to library: {e}")
        raise HTTPException(status_code=500, detail="Failed to save to library")
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
    Delete multiple detections from the library.
    """
    from archer.database.models import LibraryDetection

    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user, db = auth_result

    try:
        body = await request.json()
        detection_ids = body.get("ids", [])

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

        # Delete all selected detections
        for detection in detections:
            db.delete(detection)

        db.commit()

        return {
            "success": True,
            "message": f"Deleted {len(detections)} detection(s)",
            "deleted_count": len(detections),
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting detections: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete detections")
    finally:
        db.close()


@app.post("/api/profile")
async def update_profile(request: Request, archer_session: Optional[str] = Cookie(None)):
    """
    Update user profile information.

    Requires authentication. Updates full_name in the database.
    """
    # Check authentication
    auth_result = require_auth(request, archer_session)
    if isinstance(auth_result, RedirectResponse):
        return {"success": False, "error": "Not authenticated"}

    user, db = auth_result

    try:
        data = await request.json()
        full_name = data.get("full_name", "").strip()

        if not full_name:
            return {"success": False, "error": "Full name is required"}

        # Update user's full name
        user.full_name = full_name
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

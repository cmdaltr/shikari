"""
Bespoke Configuration Loader

Loads organization-specific configuration from bespoke/ directory:
- exclusions.yaml: Global exclusions applied to all queries
- config.yaml: Organization-specific settings
- sample_searches/: Custom detection examples
"""

import os
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from functools import lru_cache
from shikari import paths

# Bespoke directory path
BESPOKE_DIR = paths.BESPOKE


@lru_cache(maxsize=1)
def get_exclusions() -> Dict[str, List[str]]:
    """
    Load global exclusions from bespoke/exclusions.yaml.

    Returns dict with keys:
    - process_exclusions: List of process paths to exclude
    - user_exclusions: List of usernames to exclude
    - host_exclusions: List of hostnames to exclude
    - ip_exclusions: List of IP ranges to exclude
    - custom_exclusions: Dict of field_name -> [values to exclude]
    """
    exclusions_file = BESPOKE_DIR / "exclusions.yaml"

    default_exclusions = {
        "process_exclusions": [],
        "user_exclusions": [],
        "host_exclusions": [],
        "ip_exclusions": [],
        "custom_exclusions": {}
    }

    if not exclusions_file.exists():
        return default_exclusions

    try:
        with open(exclusions_file, 'r') as f:
            data = yaml.safe_load(f) or {}

        return {
            "process_exclusions": data.get("process_exclusions", []),
            "user_exclusions": data.get("user_exclusions", []),
            "host_exclusions": data.get("host_exclusions", []),
            "ip_exclusions": data.get("ip_exclusions", []),
            "custom_exclusions": data.get("custom_exclusions", {})
        }
    except Exception as e:
        print(f"Warning: Failed to load exclusions.yaml: {e}")
        return default_exclusions


@lru_cache(maxsize=1)
def get_config() -> Dict[str, Any]:
    """
    Load organization configuration from bespoke/config.yaml.

    Returns dict with keys:
    - organization: Dict with name, default_index, default_sourcetype
    - field_overrides: Dict mapping standard fields to custom field names
    - query_settings: Dict with max_results, default_timespan, etc.
    """
    config_file = BESPOKE_DIR / "config.yaml"

    default_config = {
        "organization": {
            "name": "",
            "default_index": "",
            "default_sourcetype": ""
        },
        "field_overrides": {},
        "query_settings": {
            "apply_exclusions": True,
            "max_results": 1000,
            "default_timespan": "1h"
        }
    }

    if not config_file.exists():
        return default_config

    try:
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f) or {}

        # Merge with defaults
        config = default_config.copy()
        if "organization" in data:
            config["organization"].update(data["organization"])
        if "field_overrides" in data:
            config["field_overrides"] = data["field_overrides"]
        if "query_settings" in data:
            config["query_settings"].update(data["query_settings"])
        if "caldera" in data:
            config["caldera"] = data["caldera"] or {}

        return config
    except Exception as e:
        print(f"Warning: Failed to load config.yaml: {e}")
        return default_config


def get_sample_searches(technique_id: Optional[str] = None, platform: Optional[str] = None) -> List[Dict]:
    """
    Load custom sample searches from bespoke/output_suggestions/.

    Args:
        technique_id: Filter by MITRE technique ID (e.g., "T1003.001")
        platform: Filter by platform (e.g., "Splunk", "MDE", "Elastic")

    Returns list of dicts with keys:
    - technique_id, platform, description, query, notes
    """
    sample_dir = BESPOKE_DIR / "output_suggestions"

    if not sample_dir.exists():
        return []

    searches = []

    for yaml_file in sample_dir.glob("*.yaml"):
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)

            if not data:
                continue

            # Handle single search or list of searches in one file
            if isinstance(data, list):
                searches.extend(data)
            else:
                searches.append(data)
        except Exception as e:
            print(f"Warning: Failed to load {yaml_file}: {e}")

    # Apply filters
    if technique_id:
        searches = [s for s in searches if s.get("technique_id") == technique_id]
    if platform:
        searches = [s for s in searches if s.get("platform", "").lower() == platform.lower()]

    return searches


def apply_exclusions_to_kql(query: str) -> str:
    """
    Apply bespoke exclusions to a KQL query.

    Adds exclusion clauses for processes, users, hosts, and IPs.
    """
    exclusions = get_exclusions()
    config = get_config()

    # Check if exclusions should be applied
    if not config.get("query_settings", {}).get("apply_exclusions", True):
        return query

    exclusion_clauses = []

    # Process exclusions
    for proc in exclusions.get("process_exclusions", []):
        # Escape backslashes for KQL
        escaped = proc.replace("\\", "\\\\")
        if "*" in escaped:
            # Wildcard - use !startswith or !endswith
            if escaped.endswith("*"):
                exclusion_clauses.append(f'not(InitiatingProcessFolderPath startswith "{escaped[:-1]}")')
            elif escaped.startswith("*"):
                exclusion_clauses.append(f'not(InitiatingProcessFolderPath endswith "{escaped[1:]}")')
            else:
                exclusion_clauses.append(f'not(InitiatingProcessFolderPath matches regex "{escaped.replace("*", ".*")}")')
        else:
            exclusion_clauses.append(f'InitiatingProcessFolderPath != "{escaped}"')

    # User exclusions
    for user in exclusions.get("user_exclusions", []):
        exclusion_clauses.append(f'AccountName != "{user}"')
        exclusion_clauses.append(f'InitiatingProcessAccountName != "{user}"')

    # Host exclusions
    for host in exclusions.get("host_exclusions", []):
        exclusion_clauses.append(f'DeviceName != "{host}"')

    # IP exclusions (for network queries)
    for ip in exclusions.get("ip_exclusions", []):
        if "/" in ip:
            # CIDR notation - use ipv4_is_in_range
            exclusion_clauses.append(f'not(ipv4_is_in_range(RemoteIP, "{ip}"))')
        else:
            exclusion_clauses.append(f'RemoteIP != "{ip}"')

    # Custom field exclusions
    for field, values in exclusions.get("custom_exclusions", {}).items():
        for val in values:
            exclusion_clauses.append(f'{field} != "{val}"')

    if not exclusion_clauses:
        return query

    # Find appropriate place to insert exclusions (after the first where clause)
    # Look for | where pattern
    import re
    where_match = re.search(r'(\|\s*where\s+)', query, re.IGNORECASE)

    if where_match:
        # Insert after existing where clause
        insert_pos = where_match.end()
        exclusion_str = " and ".join(exclusion_clauses) + " and "
        return query[:insert_pos] + exclusion_str + query[insert_pos:]
    else:
        # No where clause - add one
        # Find table name and add where clause after it
        lines = query.split('\n')
        for i, line in enumerate(lines):
            if line.strip() and not line.strip().startswith('//') and not line.strip().startswith('let'):
                # This is likely the table reference line
                exclusion_str = "\n| where " + " and ".join(exclusion_clauses)
                lines[i] = line + exclusion_str
                return '\n'.join(lines)

    return query


def apply_exclusions_to_spl(query: str) -> str:
    """
    Apply bespoke exclusions to a Splunk SPL query.

    Adds NOT clauses for processes, users, hosts, and IPs.
    """
    exclusions = get_exclusions()
    config = get_config()

    # Check if exclusions should be applied
    if not config.get("query_settings", {}).get("apply_exclusions", True):
        return query

    exclusion_clauses = []

    # Process exclusions
    for proc in exclusions.get("process_exclusions", []):
        exclusion_clauses.append(f'NOT process_path="{proc}"')
        exclusion_clauses.append(f'NOT parent_process_path="{proc}"')

    # User exclusions
    for user in exclusions.get("user_exclusions", []):
        exclusion_clauses.append(f'NOT user="{user}"')
        exclusion_clauses.append(f'NOT src_user="{user}"')

    # Host exclusions
    for host in exclusions.get("host_exclusions", []):
        exclusion_clauses.append(f'NOT host="{host}"')
        exclusion_clauses.append(f'NOT dest="{host}"')

    # IP exclusions
    for ip in exclusions.get("ip_exclusions", []):
        if "/" in ip:
            # CIDR - use cidrmatch
            exclusion_clauses.append(f'NOT cidrmatch("{ip}", src_ip)')
            exclusion_clauses.append(f'NOT cidrmatch("{ip}", dest_ip)')
        else:
            exclusion_clauses.append(f'NOT src_ip="{ip}"')
            exclusion_clauses.append(f'NOT dest_ip="{ip}"')

    # Custom field exclusions
    for field, values in exclusions.get("custom_exclusions", {}).items():
        for val in values:
            exclusion_clauses.append(f'NOT {field}="{val}"')

    if not exclusion_clauses:
        return query

    # Add exclusions after the initial search command
    # Find the end of the index/sourcetype specification
    import re

    # Look for common patterns: index=..., sourcetype=..., or just after the opening
    search_match = re.search(r'(index\s*=\s*\S+(?:\s+sourcetype\s*=\s*\S+)?)', query, re.IGNORECASE)

    if search_match:
        insert_pos = search_match.end()
        exclusion_str = " " + " ".join(exclusion_clauses)
        return query[:insert_pos] + exclusion_str + query[insert_pos:]
    else:
        # Prepend to query
        exclusion_str = " ".join(exclusion_clauses) + " "
        return exclusion_str + query


def _str_literal(value: str) -> str:
    """Escape a value for a double-quoted ES|QL or YARA-L string literal."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def apply_exclusions_to_esql(query: str) -> str:
    """
    Apply bespoke exclusions to an Elastic ES|QL query.

    ES|QL is piped like SPL/KQL, so exclusions append as a trailing `| WHERE`
    over ECS fields. Appended, not inserted, because the per-detection queries
    this runs on end on a WHERE, not a STATS — a trailing filter after an
    aggregation would reference dropped columns.
    """
    exclusions = get_exclusions()
    config = get_config()

    if not config.get("query_settings", {}).get("apply_exclusions", True):
        return query

    clauses = []

    # Process exclusions (full executable path)
    for proc in exclusions.get("process_exclusions", []):
        if "*" in proc:
            # ES|QL RLIKE is regex: escape, then turn the wildcard back into .*
            pattern = re.escape(proc).replace("\\*", ".*")
            clauses.append(f'NOT process.executable RLIKE "{_str_literal(pattern)}"')
        else:
            clauses.append(f'process.executable != "{_str_literal(proc)}"')

    # User exclusions
    for user in exclusions.get("user_exclusions", []):
        clauses.append(f'user.name != "{_str_literal(user)}"')

    # Host exclusions
    for host in exclusions.get("host_exclusions", []):
        clauses.append(f'host.name != "{_str_literal(host)}"')

    # IP exclusions (source and destination)
    for ip in exclusions.get("ip_exclusions", []):
        if "/" in ip:
            clauses.append(f'NOT CIDR_MATCH(source.ip, "{ip}")')
            clauses.append(f'NOT CIDR_MATCH(destination.ip, "{ip}")')
        else:
            clauses.append(f'source.ip != "{_str_literal(ip)}"')
            clauses.append(f'destination.ip != "{_str_literal(ip)}"')

    # Custom field exclusions
    for field, values in exclusions.get("custom_exclusions", {}).items():
        for val in values:
            clauses.append(f'{field} != "{_str_literal(val)}"')

    if not clauses:
        return query

    return query.rstrip() + "\n| WHERE " + " AND ".join(clauses)


def _yaral_clauses(exclusions: Dict[str, Any], event_var: str) -> List[str]:
    """
    Negated YARA-L predicates for one event variable (e.g. "$setup").

    Written as `not <field> = "value"`, not `<field> != "value"`: UDM fields
    like principal.ip are repeated, and on a repeated field `= "x"` matches if
    any element equals x, so only `not (= "x")` means "no element equals x".
    CIDR and wildcard paths use net.ip_in_range_cidr() and re.regex().
    """
    e = event_var
    clauses = []

    # Process path — the process itself (target) and its parent (principal)
    for proc in exclusions.get("process_exclusions", []):
        for field in (f"{e}.target.process.file.full_path",
                      f"{e}.principal.process.file.full_path"):
            if "*" in proc:
                pattern = re.escape(proc).replace("\\*", ".*")
                clauses.append(f"not re.regex({field}, `{pattern}`) nocase")
            else:
                clauses.append(f'not {field} = "{_str_literal(proc)}"')

    # User exclusions
    for user in exclusions.get("user_exclusions", []):
        for field in (f"{e}.principal.user.userid", f"{e}.target.user.userid"):
            clauses.append(f'not {field} = "{_str_literal(user)}"')

    # Host exclusions
    for host in exclusions.get("host_exclusions", []):
        for field in (f"{e}.principal.hostname", f"{e}.target.hostname"):
            clauses.append(f'not {field} = "{_str_literal(host)}"')

    # IP exclusions
    for ip in exclusions.get("ip_exclusions", []):
        for field in (f"{e}.principal.ip", f"{e}.target.ip"):
            if "/" in ip:
                clauses.append(f'not net.ip_in_range_cidr({field}, "{ip}")')
            else:
                clauses.append(f'not {field} = "{_str_literal(ip)}"')

    # Custom field exclusions
    for field, values in exclusions.get("custom_exclusions", {}).items():
        for val in values:
            clauses.append(f'not {e}.{field} = "{_str_literal(val)}"')

    return clauses


def apply_exclusions_to_yaral(query: str) -> str:
    """
    Apply bespoke exclusions to a Google SecOps YARA-L rule.

    YARA-L has no trailing filter: exclusions become negated predicates inside
    the `events:` section, repeated for every event variable the rule already
    binds (so each variable stays bound and an excluded host/user drops the whole
    match, not just one stage).
    """
    exclusions = get_exclusions()
    config = get_config()

    if not config.get("query_settings", {}).get("apply_exclusions", True):
        return query

    lines = query.split("\n")

    # Find the events: section and its indentation
    ev_idx = ev_indent = None
    for i, line in enumerate(lines):
        m = re.match(r"(\s*)events:\s*$", line)
        if m:
            ev_idx, ev_indent = i, len(m.group(1))
            break
    if ev_idx is None:
        return query  # not a YARA-L rule we recognise

    # The section ends at the next sibling block (match/outcome/condition)
    end_idx = len(lines)
    for i in range(ev_idx + 1, len(lines)):
        m = re.match(r"(\s*)(match|outcome|condition):\s*$", lines[i])
        if m and len(m.group(1)) <= ev_indent:
            end_idx = i
            break

    body_lines = lines[ev_idx + 1:end_idx]

    # Event variables are the $name tokens that carry a field path ($setup.x);
    # bare match vars like $device have no dot and are skipped.
    event_vars = []
    for v in re.findall(r"\$(\w+)\.", "\n".join(body_lines)):
        if v not in event_vars:
            event_vars.append(v)
    if not event_vars:
        return query

    # Indent new predicates like the existing ones
    pred_indent = " " * (ev_indent + 2)
    for ln in body_lines:
        if ln.strip():
            pred_indent = ln[:len(ln) - len(ln.lstrip())]
            break

    clauses = []
    for var in event_vars:
        clauses.extend(_yaral_clauses(exclusions, f"${var}"))
    if not clauses:
        return query

    block = [pred_indent + "// bespoke exclusions"] + [pred_indent + c for c in clauses]
    return "\n".join(lines[:end_idx] + block + lines[end_idx:])


def apply_exclusions(query: str, platform: str) -> str:
    """
    Apply bespoke exclusions to a query based on platform.

    Args:
        query: The detection query
        platform: "MDE", "Splunk", "Elastic", "GoogleSecOps"

    Returns:
        Query with exclusions applied
    """
    platform_lower = platform.lower()

    if platform_lower in ["mde", "microsoftthreatprotection", "microsoft defender", "kql"]:
        return apply_exclusions_to_kql(query)
    elif platform_lower in ["splunk", "spl"]:
        return apply_exclusions_to_spl(query)
    elif platform_lower in ["elastic", "esql", "es|ql"]:
        return apply_exclusions_to_esql(query)
    elif platform_lower in ["googlesecops", "google secops", "secops", "udm", "yaral", "yara-l"]:
        return apply_exclusions_to_yaral(query)

    return query


def is_bespoke_enabled() -> bool:
    """Check if bespoke customization is configured."""
    exclusions_file = BESPOKE_DIR / "exclusions.yaml"
    config_file = BESPOKE_DIR / "config.yaml"
    searches_dir = BESPOKE_DIR / "searches"

    return (
        exclusions_file.exists() or
        config_file.exists() or
        (searches_dir.exists() and any(searches_dir.glob("*.yaml")))
    )


def clear_cache():
    """Clear cached exclusions and config (useful for testing or after file changes)."""
    get_exclusions.cache_clear()
    get_config.cache_clear()


def get_bespoke_status() -> Dict[str, Any]:
    """Get status of bespoke configuration for diagnostics."""
    exclusions = get_exclusions()
    config = get_config()
    samples = get_sample_searches()

    return {
        "enabled": is_bespoke_enabled(),
        "bespoke_dir": str(BESPOKE_DIR),
        "exclusions_file_exists": (BESPOKE_DIR / "exclusions.yaml").exists(),
        "config_file_exists": (BESPOKE_DIR / "config.yaml").exists(),
        "sample_searches_count": len(samples),
        "process_exclusions_count": len(exclusions.get("process_exclusions", [])),
        "user_exclusions_count": len(exclusions.get("user_exclusions", [])),
        "host_exclusions_count": len(exclusions.get("host_exclusions", [])),
        "ip_exclusions_count": len(exclusions.get("ip_exclusions", [])),
        "organization_name": config.get("organization", {}).get("name", ""),
        "apply_exclusions": config.get("query_settings", {}).get("apply_exclusions", True)
    }


# ── Bespoke Component Validation ────────────────────────────────────────────

# Component definitions: (path_relative_to_bespoke, display_name, required, fallback_description)
_BESPOKE_COMPONENTS = [
    # Critical mappings — generation fails without these
    ("mappings/indicatorMapping.json",       "Indicator Mapping",           True,  "indicator→field mappings for query generation"),
    ("mappings/schemas/schemaSplunk.json",           "Splunk Pipeline Schema",      True,  "per-index SPL transformation pipelines"),
    ("mappings/schemas/schemaMDE.json",              "MDE Schema",                  True,  "MDE table/field definitions"),
    ("mappings/schemas/schemaElastic.json",          "Elastic Schema",              True,  "Elastic field definitions"),
    ("mappings/schemas/schemaGoogleSecOps.json",     "Google SecOps Schema",        True,  "Google SecOps UDM field definitions"),
    ("mappings/sources/platforms.json",              "Platform Mappings",           True,  "platform→index compatibility matrix"),
    ("mappings/sources/dataSources.json",            "Data Sources",                True,  "log source definitions"),
    ("mappings/sources/entityMappings.json",         "Entity Mappings",             True,  "KQL entity extraction patterns"),
    ("mappings/sources/logSourceCategories.json",    "Log Source Categories",       True,  "log source→category mapping"),
    ("mappings/indicatorMapping.json",               "Indicator Mapping",           True,  "indicator→field mappings for query generation"),
    ("mappings/techniquePlatformIndicators.json",    "Technique-Platform Indicators", True, "platform indicator type routing"),
    # LLM prompts — needed for AI generation modes
    ("prompts/DetectionGeneration_Templates.md", "Detection Generation Templates", False, "per-telemetry query templates for LLM generation"),
    ("prompts/CloudLLM_Master.md",           "Cloud LLM Master Prompt",    False, "master prompt for cloud LLM generation"),
    ("prompts/LocalLLM_Master.md",           "Local LLM Master Prompt",    False, "master prompt for local LLM generation"),
    # Query templates
    ("query_templates/DetectionGeneration_Templates.md", "Query Templates", False, "bespoke query templates directory"),
    # Reference queries — few-shot LLM examples
    ("llm_references/Splunk",               "Splunk LLM References",       False, "production Splunk queries used as LLM examples"),
    ("llm_references/MDE",                 "MDE LLM References",          False, "production MDE queries used as LLM examples"),
    # Environment-specific searches
    ("output_suggestions",          "Output Search Suggestions",   False, "org-specific tuned detection queries surfaced to analysts"),
    # Optional config
    ("exclusions.yaml",                     "Exclusions Config",           False, "global query exclusions (e.g. Tanium, sb-sim)"),
    ("config.yaml",                         "Organisation Config",         False, "org name, field overrides, query settings"),
]


def validate_bespoke_components(verbose: bool = False) -> Dict[str, Any]:
    """
    Validate all bespoke components and return a status report.

    For each component:
    - ``present``: file/dir exists
    - ``missing_critical``: required file is absent (generation will degrade)
    - ``missing_optional``: optional file is absent (feature disabled, using defaults)

    Args:
        verbose: If True, print a formatted status table to stdout.

    Returns:
        Dict with keys:
        - ``all_critical_present``: bool
        - ``missing_critical``: list of component names
        - ``missing_optional``: list of component names
        - ``components``: list of per-component dicts
    """
    results = []
    missing_critical: List[str] = []
    missing_optional: List[str] = []

    for rel_path, display_name, required, fallback_desc in _BESPOKE_COMPONENTS:
        full_path = BESPOKE_DIR / rel_path
        exists = full_path.exists()
        status = "present" if exists else ("missing_critical" if required else "missing_optional")

        if not exists:
            if required:
                missing_critical.append(display_name)
            else:
                missing_optional.append(display_name)

        results.append({
            "name": display_name,
            "path": str(full_path),
            "required": required,
            "exists": exists,
            "status": status,
            "fallback": fallback_desc if not exists else None,
        })

    all_critical_present = len(missing_critical) == 0

    if verbose:
        _print_validation_report(results, all_critical_present, missing_critical, missing_optional)

    return {
        "all_critical_present": all_critical_present,
        "missing_critical": missing_critical,
        "missing_optional": missing_optional,
        "components": results,
    }


def _print_validation_report(
    results: list,
    all_critical_present: bool,
    missing_critical: List[str],
    missing_optional: List[str],
) -> None:
    """Print a startup validation summary table."""
    print("\n" + "─" * 70)
    print("  Bespoke Component Validation")
    print("─" * 70)
    for c in results:
        icon = "✓" if c["exists"] else ("✗" if c["required"] else "○")
        tag = "" if c["exists"] else (" [REQUIRED]" if c["required"] else " [optional — using default]")
        print(f"  {icon}  {c['name']}{tag}")
    print("─" * 70)
    if all_critical_present:
        if missing_optional:
            print(f"  All critical components present. {len(missing_optional)} optional component(s) absent.")
        else:
            print("  All bespoke components present.")
    else:
        print(f"  WARNING: {len(missing_critical)} required component(s) missing:")
        for name in missing_critical:
            print(f"    ✗  {name}")
        print("  Generation may produce degraded or incomplete results.")
    print("─" * 70 + "\n")

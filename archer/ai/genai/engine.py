"""
Lightweight GenAI stub for generating correlation suggestions.

This module intentionally avoids external AI providers and instead provides
heuristic-based synthesis from generated YAMLs. It is pluggable and can be
replaced with a true GenAI integration later (e.g., OpenAI, local LLM, n8n).
"""

import os
import json
import math
import importlib.util
import time
import re
import threading
from typing import List, Dict, Tuple, Optional
from archer.build.progress import write_progress
from archer.config import GENERATE_DIR, CORRELATE_DIR

# Global generation mode; set in generate_correlations
_GEN_MODE: str = "heuristic"

# Lock to prevent duplicate correlation generation for the same group
_CORRELATION_LOCKS: Dict[str, threading.Lock] = {}
_LOCKS_LOCK = threading.Lock()  # Lock for the locks dictionary itself

# Import our parser modules - use dynamic imports to handle potential missing modules
_HAS_ADVANCED_PARSING = False
_HAS_SEMANTIC_ANALYSIS = False
_HAS_QUERY_VALIDATION = False
_HAS_AI_GENERATORS = False

# Try to import the parser modules (from archer/parsers/ - one level up from genai/)
try:
    from ..parsers.splunk import (
        parse_splunk_query,
        validate_splunk_query,
        combine_splunk_queries,
        SplunkQuery,
    )
    from ..parsers.mde import (
        parse_kql_query,
        validate_kql_query,
        combine_kql_queries,
        KQLQuery,
    )

    _HAS_ADVANCED_PARSING = True
except ImportError as e:
    print(f"Advanced query parsing modules not available - will use basic methods ({e})")

# Import query validator
try:
    from ..parsers.validator import (
        QueryValidator,
        test_combined_query,
    )

    _HAS_QUERY_VALIDATION = True
except ImportError as e:
    print(f"Query validation module not available - will skip validation ({e})")

# Import semantic analyzer
try:
    from ..parsers.semantics import (
        QuerySemanticAnalyzer,
    )

    _HAS_SEMANTIC_ANALYSIS = True
except ImportError as e:
    print(f"Semantic analysis module not available - will skip semantic analysis ({e})")

# Optional local-LLM support. We attempt to import known local backends but
# degrade gracefully to the heuristic generator if none are available.
_HAS_LLAMA = False
_HAS_TRANSFORMERS = False

# Use importlib to check for package availability before attempting import
if importlib.util.find_spec("llama_cpp"):
    try:
        import llama_cpp  # type: ignore

        _HAS_LLAMA = True
    except Exception:
        _HAS_LLAMA = False

if importlib.util.find_spec("transformers"):
    try:
        import transformers  # type: ignore

        _HAS_TRANSFORMERS = True
    except Exception:
        _HAS_TRANSFORMERS = False


def _list_yaml_files(group_name: str, yaml_dir: str) -> List[str]:
    # Only the group's own detections: pairing against every group's files let
    # other groups' rules crowd the group's correlations out of the cap
    from archer.build.group_files import group_yaml_files

    return group_yaml_files(group_name, yaml_dir)


def _parse_yaml_for_vendor(path: str) -> Dict:
    """
    Parse a YAML file to extract vendor information, search query content, tactics, and name.

    Returns a dictionary with:
    - path: the file path
    - vendor: detected vendor (or None)
    - query: the search query if found (or None)
    - tactics: list of MITRE ATT&CK tactics (or [])
    - name: the technique name from the YAML file (or None)
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except Exception:
        return {"path": path, "vendor": None, "query": None, "tactics": [], "name": None}

    vendor = None
    query = None
    tactics = []
    name = None
    connector_id = None

    # Look for the connectorId field to determine vendor
    for line in text.splitlines():
        line_lower = line.lower().strip()
        if line_lower.startswith("connectorid:"):
            connector_id = line.split(":", 1)[1].strip()
            break

    # Extract the name field from the YAML
    for line in text.splitlines():
        line_stripped = line.strip()
        if line_stripped.startswith("name:"):
            name = line_stripped.split(":", 1)[1].strip()
            break

    # Set vendor based on connectorId
    if connector_id:
        if connector_id == "Splunk":
            vendor = "splunk"
        elif connector_id == "MicrosoftThreatProtection":
            vendor = "mde"
        elif connector_id == "GoogleSecOps":
            vendor = "googlesecops"
        elif connector_id == "Elastic":
            vendor = "elastic"

    # If connectorId wasn't found, try other methods to find vendor/platform
    if not vendor:
        for line in text.splitlines():
            if line.lower().startswith("vendor:"):
                vendor = line.split(":", 1)[1].strip()
                break
            if line.lower().startswith("platform:"):
                vendor = line.split(":", 1)[1].strip()
                break

    # Try to extract search query
    query_marker = False
    query_lines = []

    for line in text.splitlines():
        line_lower = line.lower().strip()

        # Look for common search query markers
        if not query_marker:
            if (
                line_lower.startswith("search:")
                or line_lower.startswith("query:")
                or line_lower.startswith("kql:")
                or line_lower.startswith("spl:")
            ):
                query_marker = True
                # Extract just the query part after the colon
                if ":" in line:
                    query_part = line.split(":", 1)[1].strip()
                    if query_part:  # If there's content after the colon on this line
                        query_lines.append(query_part)
                continue

        # If we're in the query section, collect lines until we hit another section
        elif query_marker:
            if (
                line.strip()
                and not line.startswith(" ")
                and not line.startswith("\t")
                and ":" in line
            ):
                # This appears to be a new section
                query_marker = False
            else:
                query_lines.append(line)

    if query_lines:
        query = "\n".join(query_lines).strip()
        # Clean up the query - remove leading "|\n  " if present
        if query.startswith("|\n"):
            query = query[2:].lstrip()

        # Always override vendor detection based on query content
        if query.lstrip().startswith("index="):
            vendor = "splunk"
        elif query.lstrip().startswith("Device"):
            vendor = "mde"
        elif "rule " in query.lower() and "events:" in query.lower():
            # YARA-L rules start with "rule " and contain "events:" sections
            vendor = "googlesecops"
        elif query.lstrip().startswith("{") and "query" in query.lower() and "bool" in query.lower():
            # Elastic Query DSL starts with { and typically contains "query" and "bool"
            vendor = "elastic"

    # fallback: try filename hints if vendor not found
    if not vendor:
        name = os.path.basename(path).lower()
        if "splunk" in name:
            vendor = "splunk"
        elif "kql" in name or "mde" in name or "microsoft" in name or "sentinel" in name:
            vendor = "mde"
        elif "googlesecops" in name or "yaral" in name or "google" in name:
            vendor = "googlesecops"
        elif "elastic" in name:
            vendor = "elastic"

    # Normalize vendor names to ensure consistency
    if vendor and vendor.lower() in ["splunk"]:
        vendor = "splunk"
    elif vendor and vendor.lower() in [
        "mde",
        "microsoft",
        "sentinel",
        "kql",
        "microsoftthreatprotection",
    ]:
        vendor = "mde"
    elif vendor and vendor.lower() in [
        "googlesecops",
        "google",
        "yaral",
    ]:
        vendor = "googlesecops"
    elif vendor and vendor.lower() in ["elastic", "elasticsearch"]:
        vendor = "elastic"

    # Extract tactics from the YAML
    tactics_marker = False
    for line in text.splitlines():
        line_stripped = line.strip()

        if line_stripped.startswith("tactics:"):
            tactics_marker = True
            continue

        if tactics_marker:
            # Check if this is a list item (starts with -)
            if line_stripped.startswith("- "):
                tactic = line_stripped[2:].strip()
                if tactic:
                    tactics.append(tactic)
            elif (
                line_stripped
                and not line.startswith(" ")
                and not line.startswith("\t")
                and ":" in line
            ):
                # New section started
                break

    return {"path": path, "vendor": vendor, "query": query, "tactics": tactics, "name": name}


# Vendors that get correlations, in priority order. SecOps is the primary platform:
# processed first and allowed more correlations through scoring.
CORRELATION_VENDORS = ["googlesecops", "mde", "splunk"]
CORRELATION_CAP = {"googlesecops": 100}


def _vendor_priority(vendor: str) -> int:
    v = (vendor or "").lower()
    return CORRELATION_VENDORS.index(v) if v in CORRELATION_VENDORS else len(CORRELATION_VENDORS)


def _is_yaral(query: str) -> bool:
    return isinstance(query, str) and query.lstrip().startswith("rule ")


def _source_label(path: Optional[str]) -> str:
    """Technique name from a detection filename: AccessTokenManipulation_GoogleSecOps.yaml -> Access Token Manipulation."""
    if not path or not isinstance(path, str):
        return ""
    stem = os.path.basename(path).rsplit(".", 1)[0]
    stem = re.sub(r"_(GoogleSecOps|microsoft_defender.*|Device\w+|\w+_prod)$", "", stem)
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", stem).replace("_", " ").strip()


def _combine_queries(vendor: str, query_a: str, query_b: str, a: str = None, b: str = None) -> str:
    """
    Combine two queries based on the vendor's query language using all available methods.

    Args:
        vendor: The vendor name (e.g., 'splunk', 'mde')
        query_a: The first query
        query_b: The second query
        a: Path to the first query file (optional, for better naming)
        b: Path to the second query file (optional, for better naming)

    Returns:
        A combined query string
    """
    # Defensive: ensure strings
    query_a = query_a or ""
    query_b = query_b or ""

    if not isinstance(query_a, str) or not isinstance(query_b, str):
        return "// Could not combine queries - inputs not strings"

    if not query_a.strip() or not query_b.strip():
        return "// Could not combine queries - one or both queries were empty"

    # Detect query type based on content
    is_splunk_a = query_a.lstrip().startswith("index=")
    is_splunk_b = query_b.lstrip().startswith("index=")
    is_mde_a = query_a.lstrip().startswith("Device")
    is_mde_b = query_b.lstrip().startswith("Device")

    # Override vendor detection based on query content
    detected_vendor = vendor.lower()
    if _is_yaral(query_a) and _is_yaral(query_b):
        detected_vendor = "googlesecops"
    elif is_splunk_a or is_splunk_b:
        detected_vendor = "splunk"
    elif is_mde_a and is_mde_b:
        detected_vendor = "mde"

    # YARA-L has a native multi-event form; no AI/parser path to choose between
    if detected_vendor == "googlesecops":
        return _basic_combine_queries(detected_vendor, query_a, query_b, _source_label(a), _source_label(b))

    # Heuristic mode: skip AI and advanced parsers entirely
    if _GEN_MODE == "heuristic":
        # Safely extract source names
        source_a = (
            os.path.basename(a).replace("_microsoft_defender.yaml", "").replace(".yaml", "")
            if a and isinstance(a, str)
            else "Query A"
        )
        source_b = (
            os.path.basename(b).replace("_microsoft_defender.yaml", "").replace(".yaml", "")
            if b and isinstance(b, str)
            else "Query B"
        )

        final_query = _basic_combine_queries(
            detected_vendor,
            query_a,
            query_b,
            source_a,
            source_b,
        )
        if detected_vendor == "splunk":
            out = f"""``` Combined Splunk Query ({source_a} followed by {source_b}) ```
{final_query}"""
            return _collapse_double_newlines(out)
        elif detected_vendor in ["mde", "microsoft", "sentinel", "kql"]:
            # Heuristic semantic overlap percentage for KQL
            overlap_pct = _estimate_semantic_overlap_kql(query_a, query_b)
            header = f"// {source_a} followed by {source_b}" + (
                f"; {overlap_pct}% semantic overlap" if overlap_pct else ""
            )
            out = f"""{header}
{final_query}"""
            return _collapse_double_newlines(out)
        else:
            return _collapse_double_newlines(final_query)

    # Non-heuristic modes: may use AI/advanced/semantic if available
    ai_combined = None
    advanced_combined = None
    semantic_strategy = None

    # Lazy-import AI generators only when explicitly requested and available
    if _GEN_MODE in ("ai_generators", "local_llm"):
        try:
            from .models import get_generator, QueryGeneratorBase  # type: ignore

            _local_ai_available = True
        except Exception:
            _local_ai_available = False
        if _local_ai_available:
            try:
                ai_method = os.environ.get("GENAI_MODEL", "local").lower()
                generator = get_generator(ai_method)
                ai_result = generator.combine_queries(query_a, query_b, detected_vendor)
                if isinstance(ai_result, dict) and "combined_query" in ai_result:
                    ai_combined = ai_result.get("combined_query")
            except Exception as e:
                print(f"AI-based query generation failed: {e}")

    # Only attempt advanced parsers if in advanced mode and inputs are non-empty strings
    if _HAS_ADVANCED_PARSING and _GEN_MODE in ("advanced_parsing", "semantic"):
        try:
            if detected_vendor == "splunk":
                advanced_combined = combine_splunk_queries(query_a, query_b)
            elif detected_vendor in ["mde", "microsoft", "sentinel", "kql"]:
                advanced_combined = combine_kql_queries(query_a, query_b)
        except Exception as e:
            print(f"Advanced parser-based query generation failed: {e}")

    if _HAS_SEMANTIC_ANALYSIS and _GEN_MODE == "semantic":
        try:
            analyzer = QuerySemanticAnalyzer()
            semantic_strategy = analyzer.suggest_combination_strategy(
                query_a, query_b, detected_vendor
            )
        except Exception as e:
            print(f"Semantic analysis failed: {e}")

    # Validate advanced/AI outputs if validators available
    def _valid(vendor_name: str, q: Optional[str]) -> bool:
        if not q or not isinstance(q, str):
            return False
        if vendor_name == "splunk":
            try:
                ok, _ = validate_splunk_query(q)
                return ok
            except Exception:
                return False
        elif vendor_name in ["mde", "microsoft", "sentinel", "kql"]:
            try:
                ok, _ = validate_kql_query(q)
                return ok
            except Exception:
                return False
        return True

    final_query = None
    generation_method = ""

    if ai_combined and _valid(detected_vendor, ai_combined):
        final_query = ai_combined
        generation_method = "AI-assisted"
    elif advanced_combined and _valid(detected_vendor, advanced_combined):
        final_query = advanced_combined
        generation_method = "Parser-based"
    else:
        final_query = _basic_combine_queries(detected_vendor, query_a, query_b)
        generation_method = "Basic"

    # Format output - safely extract source names
    source_a = (
        os.path.basename(a).replace("_microsoft_defender.yaml", "").replace(".yaml", "")
        if a and isinstance(a, str)
        else "Query A"
    )
    source_b = (
        os.path.basename(b).replace("_microsoft_defender.yaml", "").replace(".yaml", "")
        if b and isinstance(b, str)
        else "Query B"
    )

    if detected_vendor == "splunk":
        insights = ""
        if semantic_strategy:
            s = semantic_strategy.get("strategy", "unknown")
            ov = int(semantic_strategy.get("overlap", {}).get("overlap_score", 0) * 100)
            insights = f"\n``` Semantic: {ov}% overlap via {s} ```"
        out = f"""``` Combined Splunk Query ({source_a} followed by {source_b}) ```
{final_query}{insights}"""
        return _collapse_double_newlines(out)
    elif detected_vendor in ["mde", "microsoft", "sentinel", "kql"]:
        # Normalize spacing for KQL before returning
        final_query = _normalize_kql_spacing(final_query)
        # Prefer semantic analyzer if available, else fallback to heuristic estimate
        try:
            overlap_pct = (
                int(semantic_strategy.get("overlap", {}).get("overlap_score", 0) * 100)
                if semantic_strategy
                else _estimate_semantic_overlap_kql(query_a, query_b)
            )
        except Exception:
            overlap_pct = _estimate_semantic_overlap_kql(query_a, query_b)
        insights = ""
        if semantic_strategy:
            try:
                s = semantic_strategy.get("strategy", "unknown")
                insights = f"\n// Semantic: {overlap_pct}% overlap via {s}"
            except Exception:
                insights = f"\n// Semantic: {overlap_pct}% overlap"
        header_line = f"// {source_a} followed by {source_b}" + (
            f"; {overlap_pct}% semantic overlap" if overlap_pct else ""
        )
        out = f"""{header_line}
// {generation_method} combination
{final_query}{insights}"""
        return _collapse_double_newlines(out)
    else:
        return _collapse_double_newlines(final_query)


# ==============================================================================
# Correlation Scoring and Filtering
# ==============================================================================

# High-impact MITRE techniques that indicate sophisticated attacks
_HIGH_IMPACT_TECHNIQUES = {
    # Persistence
    "T1053",
    "T1136",
    "T1543",
    "T1547",
    "T1037",
    "T1098",
    # Privilege Escalation
    "T1068",
    "T1134",
    "T1078",
    "T1055",
    "T1548",
    # Defense Evasion
    "T1070",
    "T1027",
    "T1562",
    "T1218",
    "T1140",
    # Credential Access
    "T1003",
    "T1110",
    "T1555",
    "T1556",
    "T1558",
    # Lateral Movement
    "T1021",
    "T1091",
    "T1080",
    "T1550",
    # Collection
    "T1005",
    "T1039",
    "T1056",
    "T1074",
    "T1114",
    # Exfiltration
    "T1020",
    "T1041",
    "T1048",
    "T1567",
    # Impact
    "T1485",
    "T1486",
    "T1490",
    "T1491",
    "T1496",
}

# Logical attack progressions (tactic pairs that naturally follow each other)
_ATTACK_PROGRESSIONS = [
    # Classic kill chain progressions
    ("initial-access", "execution"),
    ("initial-access", "persistence"),
    ("initial-access", "defense-evasion"),
    ("execution", "privilege-escalation"),
    ("execution", "defense-evasion"),
    ("execution", "persistence"),
    ("execution", "credential-access"),
    ("execution", "discovery"),
    ("privilege-escalation", "defense-evasion"),
    ("privilege-escalation", "credential-access"),
    ("privilege-escalation", "persistence"),
    ("credential-access", "lateral-movement"),
    ("credential-access", "collection"),
    ("credential-access", "discovery"),
    ("lateral-movement", "collection"),
    ("lateral-movement", "execution"),
    ("lateral-movement", "credential-access"),
    ("collection", "exfiltration"),
    ("defense-evasion", "persistence"),
    ("defense-evasion", "credential-access"),
    ("defense-evasion", "lateral-movement"),
    ("discovery", "lateral-movement"),
    ("discovery", "collection"),
    ("discovery", "credential-access"),
    ("persistence", "defense-evasion"),
    ("persistence", "execution"),
    ("persistence", "privilege-escalation"),
    # Common tactics that often appear together
    ("execution", "command-and-control"),
    ("persistence", "command-and-control"),
    ("command-and-control", "exfiltration"),
    ("command-and-control", "collection"),
    ("command-and-control", "lateral-movement"),
    ("impact", "exfiltration"),
    ("resource-development", "initial-access"),
    ("reconnaissance", "initial-access"),
]

# Tactic priority weights (higher = more critical to detect)
_TACTIC_PRIORITY = {
    # Critical tactics (highest priority)
    "credential-access": 10,
    "lateral-movement": 10,
    "exfiltration": 10,
    "impact": 10,
    # High priority tactics
    "privilege-escalation": 8,
    "persistence": 8,
    "command-and-control": 8,
    # Medium priority tactics
    "defense-evasion": 6,
    "collection": 6,
    "initial-access": 6,
    # Lower priority tactics (still important but more common/noisy)
    "execution": 4,
    "discovery": 4,
    "resource-development": 3,
    "reconnaissance": 3,
}


def _extract_technique_ids(file_path: str) -> List[str]:
    """Extract MITRE technique IDs from YAML file path or content."""
    technique_ids = []

    # Extract from filename (e.g., T1003.001_splunk.yaml)
    basename = os.path.basename(file_path)
    matches = re.findall(r"T\d{4}(?:\.\d{3})?", basename)
    technique_ids.extend(matches)

    # Always try to extract from file content (more reliable than filename)
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read(1000)  # Read first 1000 chars
                # Look for technique_id field in YAML
                yaml_matches = re.findall(r"technique_id:\s*['\"]?(T\d{4}(?:\.\d{3})?)", content)
                if yaml_matches:
                    technique_ids.extend(yaml_matches)
                else:
                    # Fallback: any T-number patterns
                    matches = re.findall(r"T\d{4}(?:\.\d{3})?", content)
                    technique_ids.extend(matches)
        except:
            pass

    return list(set(technique_ids))


def _extract_tactics(file_path: str) -> List[str]:
    """Extract MITRE tactics from YAML file content."""
    tactics = []

    if not os.path.exists(file_path):
        return tactics

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read(1000)  # Read first 1000 chars

            # Look for tactic field in YAML
            tactic_match = re.search(r'tactic:\s*["\']?([^"\'\n]+)["\']?', content, re.IGNORECASE)
            if tactic_match:
                tactics.append(tactic_match.group(1).lower().strip())

            # Look for tactics array
            tactics_match = re.search(
                r"tactics:\s*\n((?:\s*-\s*[^\n]+\n)+)", content, re.IGNORECASE
            )
            if tactics_match:
                tactic_lines = tactics_match.group(1)
                for line in tactic_lines.split("\n"):
                    line = line.strip().lstrip("- ").strip("\"'")
                    if line:
                        tactics.append(line.lower())
    except:
        pass

    return [t.lower().replace(" ", "-") for t in tactics if t]


def _has_only_generic_terms(query: str) -> bool:
    """
    Check if a query contains only generic terms that are too broad for effective detection.
    Returns True if the query should be filtered out from correlation selection.
    Handles both KQL (MDE) and Splunk query syntax.
    """
    if not query or not isinstance(query, str):
        return True  # Empty query is low quality

    # Define generic terms that are too broad to be useful as sole indicators
    generic_terms = {
        "condition",
        "access",
        "policy",
        "policies",
        "data",
        "file",
        "process",
        "user",
        "system",
        "service",
        "event",
        "log",
        "network",
        "security",
        "admin",
        "administrator",
        "account",
        "information",
        "management",
        "configuration",
        "settings",
        "application",
        "program",
        "software",
        "windows",
        "linux",
    }

    # Extract search terms from both KQL and Splunk queries
    search_terms = []

    # KQL patterns: has_any("term1", "term2"), has "term", contains "term"

    # Extract from has_any(...)
    has_any_pattern = r"has_any\s*\(\s*([^)]+)\s*\)"
    for match in re.finditer(has_any_pattern, query, re.IGNORECASE):
        values = re.findall(r'"([^"]+)"', match.group(1))
        search_terms.extend(values)

    # Extract from has "..."
    has_pattern = r'\bhas\s+"([^"]+)"'
    for match in re.finditer(has_pattern, query, re.IGNORECASE):
        search_terms.append(match.group(1))

    # Extract from contains "..."
    contains_pattern = r'\bcontains\s+"([^"]+)"'
    for match in re.finditer(contains_pattern, query, re.IGNORECASE):
        search_terms.append(match.group(1))

    # Splunk patterns: field=value, field="value", field IN ("value1", "value2")

    # Extract from field="value" or field=value
    splunk_equals_pattern = r'\b(\w+)\s*=\s*"?([^"\s|]+)"?'
    for match in re.finditer(splunk_equals_pattern, query):
        field = match.group(1).lower()
        value = match.group(2).strip('"')
        # Only consider search/filter fields, not metadata like index or sourcetype
        if field not in ["index", "sourcetype", "source", "host", "earliest", "latest"]:
            search_terms.append(value)

    # Extract from IN ("value1", "value2")
    splunk_in_pattern = r"\bIN\s*\(\s*([^)]+)\s*\)"
    for match in re.finditer(splunk_in_pattern, query, re.IGNORECASE):
        values = re.findall(r'"([^"]+)"', match.group(1))
        search_terms.extend(values)

    # Extract from search command with quoted strings
    splunk_search_pattern = r'\bsearch\s+"([^"]+)"'
    for match in re.finditer(splunk_search_pattern, query, re.IGNORECASE):
        search_terms.append(match.group(1))

    # If no search terms found, consider it low quality
    if not search_terms:
        return True

    # Check if ALL search terms are generic
    non_generic_count = 0
    for term in search_terms:
        term_lower = term.lower().strip()
        if term_lower not in generic_terms:
            non_generic_count += 1

    # If there's at least one non-generic term, keep the query
    return non_generic_count == 0


def _calculate_query_specificity(query: str) -> float:
    """
    Calculate query specificity score (0-1).
    Higher score = more specific query (less likely to have false positives).
    """
    if not query or not isinstance(query, str):
        return 0.0

    score = 0.5  # Base score

    # Specific indicators increase score
    specific_patterns = [
        r"\bsha256\s*[=:~]",  # File hashes
        r"\bmd5\s*[=:~]",
        r"\bsha1\s*[=:~]",
        r'\bip\s*[=:]\s*"\d+\.\d+\.\d+\.\d+"',  # Specific IPs
        r"\bdomain\s*[=:]",  # Domain names
        r"\burl\s*[=:]",  # URLs
        r"\bregistry\s+key",  # Registry keys
        r"\bprocess\s+name\s*[=:]",  # Process names
        r'\bcommand\s*line.*[=:~].*"[^"]{20,}"',  # Long command lines
    ]

    for pattern in specific_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            score += 0.1

    # Generic wildcards decrease score
    wildcard_count = query.count("*") + query.count("%")
    score -= min(0.3, wildcard_count * 0.05)

    # Multiple conditions increase score
    condition_keywords = ["where", "and", "or", "join", "|"]
    condition_count = sum(1 for kw in condition_keywords if kw in query.lower())
    score += min(0.2, condition_count * 0.05)

    return max(0.0, min(1.0, score))


def _estimate_false_positive_rate(query: str, vendor: str) -> float:
    """
    Estimate false positive rate (0-1).
    Lower score = less noisy (better).
    """
    if not query or not isinstance(query, str):
        return 1.0

    query_lower = query.lower()

    # High false positive indicators (common operations)
    noisy_patterns = [
        r'\bprocess\s+name\s*[=:]\s*"svchost\.exe"',  # Very common
        r'\bprocess\s+name\s*[=:]\s*"powershell\.exe"',  # Common but can be malicious
        r'\bprocess\s+name\s*[=:]\s*"cmd\.exe"',
        r"\bevent\s+id\s*[=:]\s*4624",  # Successful logon (very common)
        r"\bevent\s+id\s*[=:]\s*4688",  # Process creation (very common)
        r"\bwhere\s+.*[=~]\s*[*%]",  # Overly broad wildcards
    ]

    fp_score = 0.3  # Base false positive rate

    for pattern in noisy_patterns:
        if re.search(pattern, query_lower):
            fp_score += 0.15

    # Specific filters reduce false positives
    specific_filters = [
        r"\bwhere\s+.*rare",  # Explicit rarity filter
        r"\bwhere\s+.*suspicious",
        r"\bwhere\s+.*malicious",
        r"\bcount\s*\([^)]+\)\s*[><]\s*\d+",  # Threshold counting
        r"\bsummarize\s+.*count",
    ]

    for pattern in specific_filters:
        if re.search(pattern, query_lower):
            fp_score -= 0.1

    return max(0.0, min(1.0, fp_score))


def _extract_primary_tables(query: str, vendor: str) -> set:
    """
    Extract primary data tables/indexes from a query.

    Args:
        query: The query string
        vendor: Vendor type (mde, splunk, etc.)

    Returns:
        Set of table/index names
    """
    tables = set()

    if vendor.lower() == "splunk":
        # Extract Splunk indexes
        index_matches = re.findall(r"index\s*=\s*(\w+)", query, re.IGNORECASE)
        tables.update(index_matches)
    else:
        # Extract MDE/KQL tables (DeviceProcessEvents, DeviceFileEvents, etc.)
        table_matches = re.findall(r"\b(Device\w+Events?|Email\w+|Identity\w+)\b", query)
        tables.update(table_matches)

    return tables


def _check_attack_progression(path_a: str, path_b: str) -> bool:
    """
    Check if two detections form a logical attack progression or share tactics.

    Args:
        path_a: Path to first YAML file
        path_b: Path to second YAML file

    Returns:
        True if tactics form a logical progression or share tactics, False otherwise
    """
    tactics_a = _extract_tactics(path_a)
    tactics_b = _extract_tactics(path_b)

    # Allow correlations within the same tactic (e.g., multiple credential-access techniques)
    if set(tactics_a) & set(tactics_b):  # If any tactics overlap
        return True

    # Check if any tactic pair matches attack progressions
    for tactic_a in tactics_a:
        for tactic_b in tactics_b:
            if (tactic_a, tactic_b) in _ATTACK_PROGRESSIONS:
                return True
            elif (tactic_b, tactic_a) in _ATTACK_PROGRESSIONS:
                return True

    return False


def _score_correlation(corr: Dict, file_info: Dict) -> float:
    """
    Score a correlation based on multiple factors.
    Returns score from 0-140 (higher is better).
    """
    path_a = corr.get("a", "")
    path_b = corr.get("b", "")
    query_a = corr.get("query_a", "")
    query_b = corr.get("query_b", "")

    # Extract metadata
    techniques_a = _extract_technique_ids(path_a)
    techniques_b = _extract_technique_ids(path_b)
    tactics_a = _extract_tactics(path_a)
    tactics_b = _extract_tactics(path_b)

    score = 0.0

    # 1. Technique Criticality (0-30 points)
    high_impact_count = 0
    for tech in techniques_a + techniques_b:
        # Check both full ID and base ID (e.g., T1003.001 and T1003)
        base_tech = tech.split(".")[0] if "." in tech else tech
        if tech in _HIGH_IMPACT_TECHNIQUES or base_tech in _HIGH_IMPACT_TECHNIQUES:
            high_impact_count += 1

    score += min(30, high_impact_count * 15)  # 15 points per high-impact technique

    # 2. Tactic Priority (0-20 points)
    # Prioritize critical tactics: credential-access, lateral-movement, exfiltration, impact
    tactic_priority_score = 0
    all_tactics = set(tactics_a + tactics_b)
    for tactic in all_tactics:
        tactic_weight = _TACTIC_PRIORITY.get(tactic, 0)
        tactic_priority_score += tactic_weight
    # Normalize to 0-20 range (max realistic is ~20 with 2 critical tactics)
    score += min(20, tactic_priority_score)

    # 3. Query Specificity (0-20 points)
    specificity_a = _calculate_query_specificity(query_a)
    specificity_b = _calculate_query_specificity(query_b)
    avg_specificity = (specificity_a + specificity_b) / 2
    score += avg_specificity * 20

    # 4. False Positive Rate (0-25 points) - inverse scoring
    fp_rate_a = _estimate_false_positive_rate(query_a, corr.get("vendor", ""))
    fp_rate_b = _estimate_false_positive_rate(query_b, corr.get("vendor", ""))
    avg_fp_rate = (fp_rate_a + fp_rate_b) / 2
    score += (1.0 - avg_fp_rate) * 25  # Lower FP rate = higher score

    # 5. Attack Progression (0-25 points)
    # Check if tactics form a logical progression - this is the KEY metric for correlation value
    for tactic_a in tactics_a:
        for tactic_b in tactics_b:
            if (tactic_a, tactic_b) in _ATTACK_PROGRESSIONS:
                score += 25
                break
            elif (tactic_b, tactic_a) in _ATTACK_PROGRESSIONS:
                score += 25
                break

    # 6. Data Source Diversity (-10 to +20 points)
    # Bonus for correlations spanning multiple data sources
    diversity_score = _score_data_source_diversity(corr, corr.get("vendor", ""))
    score += diversity_score

    # NOTE: Semantic overlap is calculated and displayed as informational metadata
    # but is NOT used in correlation scoring. What matters is attack chain progression,
    # not whether queries use similar fields/indicators.

    return min(140.0, score)  # Max 140 now (added tactic priority bonus)


def _score_and_filter_correlations(
    correlations: List[Dict], file_info: Dict, min_relevance: float = 0.5, max_per_vendor: int = 60
) -> List[Dict]:
    """
    Score all correlations and return only those meeting the minimum relevance threshold.

    Args:
        correlations: List of correlation dictionaries
        file_info: File metadata dictionary
        min_relevance: Minimum relevance score threshold (default 0.5 = 50%)
        max_per_vendor: Maximum correlations per vendor (default 60)

    Returns:
        Filtered list of correlations with relevance_score >= min_relevance, capped at max_per_vendor
    """
    # Score each correlation
    scored_correlations = []
    for corr in correlations:
        score = _score_correlation(corr, file_info)
        corr["relevance_score"] = round(
            score / 140, 2
        )  # Normalize to 0-1 (max 140 with tactic priority + diversity)
        scored_correlations.append((score, corr))

    # Sort by score (descending)
    scored_correlations.sort(key=lambda x: x[0], reverse=True)

    # Filter by minimum relevance threshold (75% = score >= 75)
    min_score_threshold = min_relevance * 100
    top_correlations = [corr for score, corr in scored_correlations if score >= min_score_threshold]

    # Cap at max_per_vendor (default 25)
    if len(top_correlations) > max_per_vendor:
        top_correlations = top_correlations[:max_per_vendor]

    return top_correlations


def generate_correlations(group_name: str, yaml_dir: str, progress_prefix: str = "genai") -> Dict:
    """
    Scan YAMLs and produce vendor correlations (cross-vendor correlations disabled).
    - vendor_correlations: list of dicts where multiple queries from same vendor are paired
    - cross_vendor_correlations: empty list (disabled)

    Progress updates are written using `write_progress` with keys under the
    provided `group_name` progress JSON.

    Uses thread-safe locking to prevent duplicate processing of the same group.
    """
    # Get or create a lock for this specific group
    with _LOCKS_LOCK:
        if group_name not in _CORRELATION_LOCKS:
            _CORRELATION_LOCKS[group_name] = threading.Lock()
        group_lock = _CORRELATION_LOCKS[group_name]

    # Try to acquire the lock - if another thread is processing, exit immediately
    if not group_lock.acquire(blocking=False):
        print(
            f"GenAI: Correlation generation already in progress for '{group_name}', skipping duplicate call"
        )
        return {"vendor_correlations": [], "cross_vendor_correlations": []}

    try:
        files = _list_yaml_files(group_name, yaml_dir)
        # print(f"GenAI: Found {len(files)} YAML files for {group_name}")
        write_progress(
            group_name,
            {"status": "genai_started", "step": "loading", "total_files": len(files),
             "processed": 0, "total_pairs": 0},
        )

        # If configured to use a local model, attempt it and gracefully fallback
        mode = os.environ.get("GENAI_MODE", "heuristic").lower()
        # print(f"GenAI: Using mode '{mode}'")

        # Track available capabilities for logging only
        available_modes = ["heuristic"]
        if _HAS_ADVANCED_PARSING:
            available_modes.append("advanced_parsing")
        if _HAS_SEMANTIC_ANALYSIS:
            available_modes.append("semantic")
        if _HAS_AI_GENERATORS:
            available_modes.append("ai_generators")
        if _HAS_LLAMA or _HAS_TRANSFORMERS:
            available_modes.append("local_llm")
        # print(f"GenAI: Available capability modes: {', '.join(available_modes)}")

        # Set global generation mode to control downstream behavior
        global _GEN_MODE
        _GEN_MODE = mode if mode in available_modes else "heuristic"

        # Only run local LLM path if explicitly requested and supported
        if _GEN_MODE == "local_llm" and (_HAS_LLAMA or _HAS_TRANSFORMERS):
            try:
                results = _generate_with_local_llm(group_name, files)
                write_progress(
                    group_name,
                    {
                        "status": "genai_complete",
                        "vendor_count": len(results.get("vendor_correlations", [])),
                        "cross_count": len(results.get("cross_vendor_correlations", [])),
                    },
                )
                return results
            except Exception as e:
                print(f"GenAI: Local LLM generation failed: {e}, falling back to heuristic")
                _GEN_MODE = "heuristic"
        # Default case - run the heuristic generation
        results = _generate_with_heuristic(group_name, files)
        write_progress(
            group_name,
            {
                "status": "genai_complete",
                "step": "done",
                "vendor_count": len(results.get("vendor_correlations", [])),
            },
        )
        return results
    finally:
        # Always release the lock when done
        group_lock.release()
        # print(f"GenAI: Released correlation lock for '{group_name}'")


def process_genai(group_name: str):
    """
    Main entry point for GenAI processing that can be called from other modules.
    This function is the primary hook for correlation generation from app.py.

    Args:
        group_name: The group name to process
    """
    # print(f"process_genai called for group {group_name}")
    yaml_dir = GENERATE_DIR
    return generate_correlations(group_name, yaml_dir)


def process(group_name: str):
    """Alias for process_genai for compatibility."""
    # print(f"process alias called for group {group_name}")
    return process_genai(group_name)


def _merge_by_tactic(files: List[str], file_info: Dict) -> Dict[str, List[str]]:
    """
    Merge YAML files by their MITRE ATT&CK tactic.

    Returns:
        Dictionary mapping tactic name to list of file paths
    """
    tactic_groups = {}

    for file_path in files:
        tactics = _extract_tactics(file_path)
        for tactic in tactics:
            if tactic not in tactic_groups:
                tactic_groups[tactic] = []
            tactic_groups[tactic].append(file_path)

    # print(f"GenAI: Merged {len(files)} files into {len(tactic_groups)} tactic groups")
    # for tactic, paths in tactic_groups.items():
    #     print(f"  - {tactic}: {len(paths)} detections")

    return tactic_groups


def _merge_by_parent(files: List[str], file_info: Dict) -> Dict[str, List[str]]:
    """
    Merge YAML files by their parent technique ID (e.g., T1003 from T1003.001).

    Returns:
        Dictionary mapping parent technique ID to list of file paths
    """
    parent_groups = {}

    for file_path in files:
        techniques = _extract_technique_ids(file_path)
        for technique in techniques:
            # Extract parent (e.g., T1003 from T1003.001)
            parent = technique.split(".")[0] if "." in technique else technique
            if parent not in parent_groups:
                parent_groups[parent] = []
            parent_groups[parent].append(file_path)

    # print(f"GenAI: Merged {len(files)} files into {len(parent_groups)} parent technique groups")
    # for parent, paths in parent_groups.items():
    #     print(f"  - {parent}: {len(paths)} detections")

    return parent_groups


def _combine_queries_for_group(
    file_paths: List[str], file_info: Dict, vendor: str
) -> Tuple[str, List[str]]:
    """
    Combine multiple queries into a single merged query with OR logic.

    Returns:
        Tuple of (combined_query, list of individual queries)
    """
    queries = []
    for path in file_paths:
        query = file_info.get(path, {}).get("query", "")
        if query:
            # Clean up query
            if query.startswith("|\n"):
                query = query[2:].lstrip()
            queries.append(query)

    if not queries:
        return ("", [])

    # For now, return a simple comment indicating merged queries
    # In a production system, you'd want to parse and intelligently merge
    combined = f"-- Merged {len(queries)} detections --\n" + " UNION ".join(
        [f"({q})" for q in queries[:5]]
    )
    if len(queries) > 5:
        combined += f"\n-- ... and {len(queries) - 5} more queries"

    return (combined, queries)


def _build_join_correlation_query(corr_data: Dict, file_info: Dict) -> str:
    """
    Build a JOIN-based correlation query that chains events by DeviceName and AccountName.
    Merges techniques by tactic with inline comments showing technique attribution.

    Args:
        corr_data: Correlation data with query_a, query_b, techniques_involved, etc.
        file_info: Dictionary mapping file paths to their YAML data

    Returns:
        KQL query string with JOINs and technique comments (MDE only)
        or original combined query string for other vendors
    """
    # Get all queries - may contain UNION queries from super-merging
    query_a = corr_data.get("query_a", "")
    query_b = corr_data.get("query_b", "")
    vendor = corr_data.get("vendor", "").lower()

    if vendor == "googlesecops":
        from archer.build.secops import build_correlation_rule

        split = lambda q: [r for r in (q or "").split("\nUNION\n") if r.strip()]
        rule = build_correlation_rule(split(query_a), split(query_b),
                                      _source_label(corr_data.get("a")), _source_label(corr_data.get("b")))
        return rule or corr_data.get("combined_query", "")

    # Detect if this is a Splunk or non-MDE query
    is_splunk = (
        vendor == "splunk"
        or (isinstance(query_a, str) and query_a.lstrip().startswith("index="))
        or (isinstance(query_b, str) and query_b.lstrip().startswith("index="))
    )

    # For Splunk queries, rebuild the combined query using valid SPL syntax.
    # The merged query_a/query_b may contain an internal "\nUNION\n" separator that
    # is not valid SPL. Split those back out and recombine with _combine_splunk_queries_simple.
    if is_splunk:
        all_splunk_queries: List[str] = []
        for q in [query_a, query_b]:
            if "\nUNION\n" in q:
                all_splunk_queries.extend(q.split("\nUNION\n"))
            elif q.strip():
                all_splunk_queries.append(q)
        # Deduplicate while preserving order
        seen_q: List[str] = []
        for q in all_splunk_queries:
            if q.strip() and q.strip() not in seen_q:
                seen_q.append(q.strip())
        if len(seen_q) >= 2:
            return _combine_splunk_queries_simple(seen_q)
        elif len(seen_q) == 1:
            return seen_q[0]
        # Fallback: call _combine_queries to generate it
        return _combine_queries(vendor, query_a, query_b, corr_data.get("a"), corr_data.get("b"))

    # Get techniques involved to map queries to techniques
    techniques_involved = corr_data.get("techniques_involved", [])

    # Parse queries to extract table names and conditions
    queries_with_metadata = []

    # Split UNION queries into individual queries
    all_queries = []
    for query_text in [query_a, query_b]:
        if "UNION" in query_text:
            # Split by UNION
            parts = query_text.split("\nUNION\n")
            all_queries.extend(parts)
        elif query_text:
            all_queries.append(query_text)

    # Process each individual query
    for query in all_queries:
        query = query.strip()
        if not query:
            continue

        # Extract table name (first line of query)
        table_match = re.match(r"^(\w+)", query)
        table_name = table_match.group(1) if table_match else "DeviceEvents"

        # Extract just the condition part - skip "Timestamp > ago" lines
        # Get all "| where" clauses
        where_lines = []
        for line in query.split("\n"):
            stripped = line.strip()
            if stripped.startswith("| where") and "Timestamp > ago" not in stripped:
                # Extract just the condition after "| where"
                condition = stripped.replace("| where", "").strip()
                if condition:
                    where_lines.append(condition)

        # Join all where conditions
        where_clause = " and ".join(where_lines) if where_lines else ""

        # Try to match this query to a technique by looking for it in file_info
        technique_name = "Unknown"
        tactic = "Unknown"

        # Look through file_info to find matching query
        for path, info in file_info.items():
            if info.get("query", "").strip() == query:
                # Use the 'name' field from YAML if available, otherwise fall back to filename
                technique_name = info.get("name")
                if not technique_name:
                    basename = os.path.basename(path).replace(".yaml", "").replace(".yml", "")
                    technique_name = basename.split("_")[0] if "_" in basename else basename
                tactics = info.get("tactics", [])
                tactic = tactics[0] if tactics else "Unknown"
                break

        # If we couldn't match, try to infer from techniques_involved list
        if technique_name == "Unknown" and techniques_involved:
            # Use table name to guess technique (simple heuristic)
            for tech in techniques_involved:
                if tech.lower() in query.lower()[:200]:
                    technique_name = tech
                    break

            if technique_name == "Unknown":
                technique_name = techniques_involved[0]

        queries_with_metadata.append(
            {
                "technique": technique_name,
                "tactic": tactic,
                "table": table_name,
                "where": where_clause,
                "query": query,
            }
        )

    if not queries_with_metadata:
        return query_a + "\n" + query_b  # Fallback to UNION approach

    # Group by tactic and table
    by_tactic_table = {}
    for qm in queries_with_metadata:
        key = (qm["tactic"], qm["table"])
        if key not in by_tactic_table:
            by_tactic_table[key] = []
        by_tactic_table[key].append(qm)

    # Build the JOIN query
    join_parts = []
    first_table = None

    for (tactic, table), queries in by_tactic_table.items():
        # Merge where clauses with technique comments
        where_conditions = []
        for qm in queries:
            # Use technique name directly from YAML - it's already in correct MITRE ATT&CK format
            technique_comment = f"// {qm['technique']}"
            # Clean up where clause - remove timestamp filter and any remaining pipe operators
            where_clause = qm["where"]
            where_clause = where_clause.replace("Timestamp > ago(1d)", "").strip()
            where_clause = where_clause.replace("Timestamp > ago(1h)", "").strip()

            # Remove leading "and" or "or" if present
            where_clause = re.sub(r"^(?:and|or)\s+", "", where_clause, flags=re.IGNORECASE).strip()

            if where_clause:
                where_conditions.append(f"  {technique_comment}\n  ({where_clause})")

        # Build the merged where clause
        merged_where = " or\n".join(where_conditions)

        # Determine account field based on table
        account_field = _get_account_field_for_table(table)

        # Build this table's query
        table_query = f"""let {table}_{tactic.replace(' ', '')} = {table}
| where Timestamp > ago(1h)
| where {merged_where}
| project Timestamp, DeviceName, AccountName={account_field}, *;"""

        if first_table is None:
            first_table = f"{table}_{tactic.replace(' ', '')}"
            join_parts.append(table_query)
        else:
            join_parts.append(table_query)

    # If we only have one table group, return as-is
    if len(join_parts) == 1:
        return join_parts[0].replace("let ", "").replace(f"{first_table} = ", "")

    # Build JOIN chain
    join_query = "\n\n".join(join_parts)
    join_query += f"\n\n// Chain events by DeviceName and AccountName\n{first_table}"

    table_names = [f"{qm['table']}_{qm['tactic'].replace(' ', '')}" for qm in queries_with_metadata]
    for i, table_name in enumerate(table_names[1:], 1):
        join_query += f"""
| join kind=inner (
    {table_name}
) on DeviceName, AccountName
| where abs(datetime_diff('minute', Timestamp, Timestamp{i})) <= 60"""

    join_query += "\n| project *"

    return join_query


def _format_technique_name(technique_name: str) -> str:
    """
    Format technique names with proper spacing for display in comments.

    Examples:
        "PasstheHash" -> "Pass the Hash"
        "PasstheTicket" -> "Pass the Ticket"
        "Multi-FactorAuthentication" -> "Multi-Factor Authentication"
        "CloudServices" -> "Cloud Services"
        "Multi-Factor Authentication" -> "Multi-Factor Authentication" (already formatted)

    Args:
        technique_name: Raw technique name (from YAML 'name' field or filename)

    Returns:
        Formatted technique name with proper spacing
    """
    # If the name already has spaces, it's likely properly formatted from YAML - return as-is
    if " " in technique_name:
        return technique_name

    # Handle common patterns for filenames
    name = technique_name

    # Replace common compound words
    name = name.replace("Passthe", "Pass the ")
    name = name.replace("Multithe", "Multi the ")

    # Add space before capital letters (except at start)
    # This converts CamelCase to Camel Case
    name = re.sub(r"(?<!^)(?=[A-Z])", " ", name)

    # Clean up any double spaces
    name = " ".join(name.split())

    return name


def _get_account_field_for_table(table_name: str) -> str:
    """
    Get the appropriate account field name for a given MDE table.

    Args:
        table_name: MDE table name (DeviceFileEvents, DeviceProcessEvents, etc.)

    Returns:
        Field name to use for AccountName
    """
    # Map tables to their primary account field
    account_field_map = {
        "DeviceFileEvents": "InitiatingProcessAccountName",
        "DeviceProcessEvents": "AccountName",  # Has both AccountName and InitiatingProcessAccountName
        "DeviceEvents": "AccountName",
        "DeviceRegistryEvents": "InitiatingProcessAccountName",
        "DeviceNetworkEvents": "InitiatingProcessAccountName",
        "DeviceImageLoadEvents": "InitiatingProcessAccountName",
        "DeviceLogonEvents": "AccountName",
        "DeviceInfo": "LoggedOnUsers",  # Special case - no single account field
    }

    return account_field_map.get(table_name, "InitiatingProcessAccountName")


def _apply_correlation_grouping(correlations: List[Dict], file_info: Dict) -> List[Dict]:
    """
    Group each vendor's correlations separately. Merging is by technique pair, so
    grouping across vendors would splice YARA-L, KQL and SPL into one query.
    """
    by_vendor: Dict[str, List[Dict]] = {}
    for corr in correlations:
        by_vendor.setdefault(corr.get("vendor", "unknown"), []).append(corr)
    grouped: List[Dict] = []
    for vendor in sorted(by_vendor, key=_vendor_priority):
        grouped.extend(_group_vendor_correlations(by_vendor[vendor], file_info))
    return grouped


def _group_vendor_correlations(correlations: List[Dict], file_info: Dict) -> List[Dict]:
    """
    Group similar correlations and keep only the top-scored ones from each group.
    Correlations are grouped by full technique pair + data source to allow variety.
    Keeps up to 3 best correlations per group.

    Returns:
        Deduplicated list of correlations
    """
    # Group correlations by technique pair + data source
    grouped = {}
    for i, corr in enumerate(correlations):
        path_a = corr.get("a", "")
        path_b = corr.get("b", "")

        # Extract technique name from file_info (using proper names from YAML)
        # Fall back to filename extraction if not found in file_info
        technique_name_a = file_info.get(path_a, {}).get("name")
        if not technique_name_a:
            basename_a = os.path.basename(path_a).replace(".yaml", "").replace(".yml", "")
            technique_name_a = basename_a.split("_")[0] if "_" in basename_a else basename_a

        technique_name_b = file_info.get(path_b, {}).get("name")
        if not technique_name_b:
            basename_b = os.path.basename(path_b).replace(".yaml", "").replace(".yml", "")
            technique_name_b = basename_b.split("_")[0] if "_" in basename_b else basename_b

        # Debug first correlation
        if i == 0:
            print(f"   DEBUG technique_name_a: {technique_name_a}")
            print(f"   DEBUG technique_name_b: {technique_name_b}")

        # Create pair key with technique names (unique enough for grouping)
        pair_key = tuple(sorted([technique_name_a, technique_name_b]))

        if pair_key not in grouped:
            grouped[pair_key] = []
        grouped[pair_key].append(corr)

    # Merge correlations from each group into single multi-source correlations
    final_correlations = []
    print(
        f"   Grouping: {len(correlations)} correlations grouped into {len(grouped)} unique technique pairs"
    )
    for pair_key, corr_list in grouped.items():
        # Sort by relevance score (descending)
        corr_list.sort(key=lambda c: c.get("relevance_score", 0), reverse=True)

        if len(corr_list) == 1:
            # Single correlation - keep as is
            final_correlations.append(corr_list[0])
        else:
            # Multiple correlations with same technique pair - merge into one
            # Use the best correlation as the base and merge queries from others
            merged = corr_list[0].copy()

            # Collect all unique queries
            all_queries_a = [corr_list[0].get("query_a", "")]
            all_queries_b = [corr_list[0].get("query_b", "")]

            for corr in corr_list[1:]:
                query_a = corr.get("query_a", "")
                query_b = corr.get("query_b", "")
                if query_a and query_a not in all_queries_a:
                    all_queries_a.append(query_a)
                if query_b and query_b not in all_queries_b:
                    all_queries_b.append(query_b)

            # Combine queries - use internal UNION marker (for MDE/KQL only).
            # This marker is later resolved by _build_join_correlation_query.
            # For Splunk the marker is stripped and rebuilt into valid SPL there.
            if len(all_queries_a) > 1:
                merged["query_a"] = "\nUNION\n".join(all_queries_a)
            if len(all_queries_b) > 1:
                merged["query_b"] = "\nUNION\n".join(all_queries_b)

            # combined_query is intentionally left stale here; it will be
            # overwritten by _build_join_correlation_query below.
            merged["combined_query"] = merged.get("combined_query", "")

            print(
                f"      Merged {len(corr_list)} correlations for {pair_key} into 1 multi-source correlation"
            )
            final_correlations.append(merged)

    # Second-level grouping: Merge correlations that share one technique
    # Example: (A→B), (A→C), (A→D) becomes (A→(B OR C OR D))
    by_single_technique = {}
    for corr in final_correlations:
        path_a = corr.get("a", "")
        path_b = corr.get("b", "")

        # Extract technique name from file_info (using proper names from YAML)
        # Fall back to filename extraction if not found in file_info
        technique_name_a = file_info.get(path_a, {}).get("name")
        if not technique_name_a:
            basename_a = os.path.basename(path_a).replace(".yaml", "").replace(".yml", "")
            technique_name_a = basename_a.split("_")[0] if "_" in basename_a else basename_a

        technique_name_b = file_info.get(path_b, {}).get("name")
        if not technique_name_b:
            basename_b = os.path.basename(path_b).replace(".yaml", "").replace(".yml", "")
            technique_name_b = basename_b.split("_")[0] if "_" in basename_b else basename_b

        # Group by the first technique (A)
        if technique_name_a not in by_single_technique:
            by_single_technique[technique_name_a] = {}
        if technique_name_b not in by_single_technique[technique_name_a]:
            by_single_technique[technique_name_a][technique_name_b] = []
        by_single_technique[technique_name_a][technique_name_b].append(corr)

    # Merge correlations where one technique correlates with multiple others
    # BUT only if it's reasonable (3-10 targets) - don't super-merge if too many targets
    super_merged_correlations = []
    for tech_a, tech_b_dict in by_single_technique.items():
        num_targets = len(tech_b_dict)

        if num_targets == 1:
            # Single target technique - keep all correlations as-is
            for tech_b, corr_list in tech_b_dict.items():
                for corr in corr_list:
                    # Add techniques_involved field for consistency
                    if "techniques_involved" not in corr:
                        corr["techniques_involved"] = sorted([tech_a, tech_b])

                    # Build JOIN-based correlation query for this pair too
                    join_query = _build_join_correlation_query(corr, file_info)
                    corr["combined_query"] = join_query

                    super_merged_correlations.append(corr)
        elif num_targets == 2:
            # 2 targets - create single merged correlation (tech_a correlates with tech_b1 OR tech_b2)
            # This is a good use case for super-merging
            pass  # Continue to super-merge logic below
        elif 3 <= num_targets <= 10:
            # 3-10 targets - create multiple groups of correlations (up to 5 groups)
            pass  # Continue to super-merge logic below
        elif num_targets > 10:
            # Too many targets (>10) - skip super-merging and keep as individual correlations
            # This prevents creating one massive correlation from a popular technique
            print(
                f"      Skipping super-merge for '{tech_a}' ({num_targets} targets) - keeping as individual correlations"
            )
            for tech_b, corr_list in tech_b_dict.items():
                for corr in corr_list:
                    if "techniques_involved" not in corr:
                        corr["techniques_involved"] = sorted([tech_a, tech_b])

                    join_query = _build_join_correlation_query(corr, file_info)
                    corr["combined_query"] = join_query

                    super_merged_correlations.append(corr)
            continue  # Skip to next tech_a

        # Super-merge logic for 2-10 targets
        if 2 <= num_targets <= 10:
            # Multiple target techniques - create multiple super-correlations if needed
            # Each super-correlation has max 8 techniques and at least 2 tactics
            all_corrs = []
            for corr_list in tech_b_dict.values():
                all_corrs.extend(corr_list)
            all_corrs.sort(key=lambda c: c.get("relevance_score", 0), reverse=True)

            # Create multiple super-correlations (groups) instead of one huge correlation
            # Each group will have up to 8 techniques
            groups_created = 0
            max_groups = 5  # Limit to 5 super-correlations per tech_a to avoid over-generation
            corr_idx = 0

            while corr_idx < len(all_corrs) and groups_created < max_groups:
                # Start a new group
                techniques_involved = set()
                techniques_involved.add(tech_a)
                tactics_involved = set()

                # Get ALL tactics for tech_a (not just first)
                for path in [all_corrs[0].get("a", ""), all_corrs[0].get("b", "")]:
                    if path and path in file_info:
                        basename = os.path.basename(path).replace(".yaml", "").replace(".yml", "")
                        tech_name = basename.split("_")[0] if "_" in basename else basename
                        if tech_name == tech_a:
                            tactics = file_info[path].get("tactics", [])
                            tactics_involved.update(tactics)
                            break

                # Select correlations up to max 8 techniques for this group, ensuring >= 2 tactics
                selected_corrs = []
                all_queries_a = []
                all_queries_b = []

                while corr_idx < len(all_corrs):
                    corr = all_corrs[corr_idx]
                    corr_idx += 1

                    # Extract technique names and tactics from this correlation
                    path_a = corr.get("a", "")
                    path_b = corr.get("b", "")

                    basename_a = os.path.basename(path_a).replace(".yaml", "").replace(".yml", "")
                    basename_b = os.path.basename(path_b).replace(".yaml", "").replace(".yml", "")

                    tech_name_a = basename_a.split("_")[0] if "_" in basename_a else basename_a
                    tech_name_b = basename_b.split("_")[0] if "_" in basename_b else basename_b

                    # Get tactics for these techniques (use ALL tactics, not just first)
                    temp_tactics = set(tactics_involved)
                    if path_a in file_info:
                        tactics = file_info[path_a].get("tactics", [])
                        temp_tactics.update(tactics)
                    if path_b in file_info:
                        tactics = file_info[path_b].get("tactics", [])
                        temp_tactics.update(tactics)

                    # Check if adding this correlation would exceed 8 techniques
                    # Use techniques_involved from the correlation if it exists (for already-merged correlations)
                    corr_techniques = corr.get("techniques_involved", [tech_name_a, tech_name_b])
                    temp_techniques = set(techniques_involved)
                    temp_techniques.update(corr_techniques)

                    # Decision logic:
                    # 1. If we have < 2 tactics, keep adding to build up tactics (up to 8 techniques max)
                    # 2. If we have >= 2 tactics, only add if we're under 8 techniques
                    should_add = False
                    if len(tactics_involved) < 2:
                        # Still building up tactics - add if under 8 techniques
                        should_add = len(temp_techniques) <= 8
                    else:
                        # Have enough tactics - enforce strict 8 technique limit
                        should_add = len(temp_techniques) <= 8

                    if should_add:
                        techniques_involved = temp_techniques
                        tactics_involved = temp_tactics
                        selected_corrs.append(corr)

                        qa = corr.get("query_a", "")
                        qb = corr.get("query_b", "")
                        if qa and qa not in all_queries_a:
                            all_queries_a.append(qa)
                        if qb and qb not in all_queries_b:
                            all_queries_b.append(qb)

                    # Stop this group if we have 8 techniques and at least 2 tactics
                    if len(techniques_involved) >= 8 and len(tactics_involved) >= 2:
                        break

                # Skip if no correlations were selected for this group
                if not selected_corrs:
                    break

                # Use the first selected correlation as base
                base_corr = selected_corrs[0].copy()

                # Combine with UNION (for backward compatibility, but will be replaced by JOIN)
                if len(all_queries_a) > 1:
                    base_corr["query_a"] = "\nUNION\n".join(all_queries_a)
                if len(all_queries_b) > 1:
                    base_corr["query_b"] = "\nUNION\n".join(all_queries_b)

                # Store the list of all techniques involved in this merged correlation
                base_corr["techniques_involved"] = sorted(list(techniques_involved))

                # Collect ALL tactics from all techniques (not just first tactic)
                all_tactics_set = set()
                for tech_name in techniques_involved:
                    # Find the file for this technique
                    for path in [corr.get("a", "") for corr in selected_corrs] + [
                        corr.get("b", "") for corr in selected_corrs
                    ]:
                        if path and path in file_info:
                            basename = (
                                os.path.basename(path).replace(".yaml", "").replace(".yml", "")
                            )
                            path_tech_name = basename.split("_")[0] if "_" in basename else basename
                            if path_tech_name == tech_name:
                                tactics = file_info[path].get("tactics", [])
                                all_tactics_set.update(tactics)
                                break

                # Update the correlation with complete tactics
                base_corr["tactics"] = sorted(list(all_tactics_set))

                # Build JOIN-based correlation query (default behavior)
                join_query = _build_join_correlation_query(base_corr, file_info)
                base_corr["combined_query"] = join_query

                print(
                    f"      Super-merged group {groups_created + 1} for '{tech_a}': {len(selected_corrs)} correlations into 1 multi-technique correlation ({len(techniques_involved)} techniques, {len(all_tactics_set)} tactics)"
                )
                super_merged_correlations.append(base_corr)
                groups_created += 1

    final_correlations = super_merged_correlations
    print(f"   After super-merging: {len(final_correlations)} correlations")

    # Apply technique frequency limit: each technique can appear in multiple correlations
    # - Super-merged correlations (3+ techniques): unlimited frequency (already consolidated)
    # - Simple correlations (2 techniques): limit to 10 appearances for diversity
    technique_count = {}
    diverse_correlations = []

    # Sort by relevance score to prioritize best correlations
    final_correlations.sort(key=lambda c: c.get("relevance_score", 0), reverse=True)

    for corr in final_correlations:
        # Extract technique names from file paths (consistent with grouping logic)
        path_a = corr.get("a", "")
        path_b = corr.get("b", "")

        basename_a = os.path.basename(path_a).replace(".yaml", "").replace(".yml", "")
        basename_b = os.path.basename(path_b).replace(".yaml", "").replace(".yml", "")

        technique_name_a = basename_a.split("_")[0] if "_" in basename_a else basename_a
        technique_name_b = basename_b.split("_")[0] if "_" in basename_b else basename_b

        # Check if this is a super-merged correlation (3+ techniques)
        techniques_involved = corr.get("techniques_involved", [])
        is_super_merged = len(techniques_involved) >= 3

        if is_super_merged:
            # Super-merged correlations always pass (no frequency limit)
            diverse_correlations.append(corr)
        else:
            # Simple 2-technique correlations - apply frequency limit of 10
            all_techniques = {technique_name_a, technique_name_b}

            # Check if any technique has exceeded the limit
            max_occurrences = (
                max(technique_count.get(t, 0) for t in all_techniques) if all_techniques else 0
            )

            if max_occurrences < 20:  # Allow each technique in up to 20 simple correlations
                diverse_correlations.append(corr)
                # Update counts
                for t in all_techniques:
                    technique_count[t] = technique_count.get(t, 0) + 1

    print(
        f"   After frequency limiting: {len(diverse_correlations)} correlations (removed {len(final_correlations) - len(diverse_correlations)} due to technique frequency)"
    )
    return diverse_correlations


def _score_data_source_diversity(corr: Dict, vendor: str) -> float:
    """
    Score correlation based on data source diversity.
    Returns bonus/penalty points (-10 to +20).

    High diversity (different data sources) = bonus points
    Low diversity (same data source) = penalty points
    """
    query_a = corr.get("query_a", "")
    query_b = corr.get("query_b", "")

    # Extract tables/indexes from both queries
    tables_a = _extract_primary_tables(query_a, vendor)
    tables_b = _extract_primary_tables(query_b, vendor)

    if not tables_a or not tables_b:
        return 0  # Can't determine diversity

    # Calculate diversity ratio
    unique_tables = len(tables_a | tables_b)  # Union
    total_tables = len(tables_a) + len(tables_b)

    diversity_ratio = unique_tables / total_tables if total_tables > 0 else 0

    # Award points based on diversity
    if diversity_ratio > 0.8:  # Different sources (high diversity)
        return 20
    elif diversity_ratio < 0.4:  # Same source (low diversity)
        return -10
    else:  # Moderate diversity
        return 5


def _generate_with_heuristic(group_name: str, files: List[str]) -> Dict:
    """Generate correlations using a rule-based heuristic approach."""
    # print(f"GenAI: Running heuristic correlation generation for {len(files)} files")

    # Parse all files to extract vendor information and queries
    parsed = [_parse_yaml_for_vendor(p) for p in files]

    # Create lookup for easy access to file info including queries
    file_info = {p["path"]: p for p in parsed}

    # Logging for debugging
    vendor_counts = {}
    for p in parsed:
        v = p.get("vendor") or "unknown"
        vendor_counts[v] = vendor_counts.get(v, 0) + 1

    # print(f"GenAI: Vendor distribution: {vendor_counts}")

    # Group files by vendor
    by_vendor = {}
    for p in parsed:
        v = p.get("vendor") or "unknown"
        # No need for additional normalization since it's done in _parse_yaml_for_vendor
        by_vendor.setdefault(v, []).append(p["path"])

    # Check for merging options from environment variables
    merge_by_tactic = os.getenv("CORRELATION_MERGE_BY_TACTIC", "").lower() == "true"
    merge_by_parent = os.getenv("CORRELATION_MERGE_BY_PARENT", "").lower() == "true"

    # Apply merging if requested
    if merge_by_tactic:
        # print("GenAI: Merging detections by tactic before correlation")
        # Merge each vendor's files by tactic
        merged_by_vendor = {}
        for v, paths in by_vendor.items():
            tactic_groups = _merge_by_tactic(paths, file_info)
            # Convert tactic groups to list of lists (group representatives)
            merged_by_vendor[v] = list(tactic_groups.values())
        by_vendor_merged = merged_by_vendor
    elif merge_by_parent:
        # print("GenAI: Merging detections by parent technique before correlation")
        # Merge each vendor's files by parent technique
        merged_by_vendor = {}
        for v, paths in by_vendor.items():
            parent_groups = _merge_by_parent(paths, file_info)
            # Convert parent groups to list of lists (group representatives)
            merged_by_vendor[v] = list(parent_groups.values())
        by_vendor_merged = merged_by_vendor
    else:
        # No merging - use individual files
        by_vendor_merged = {v: [[p] for p in paths] for v, paths in by_vendor.items()}

    # Calculate total pairs across all vendors first for cumulative progress
    total_pairs_all_vendors = 0
    vendor_pair_counts = {}
    MAX_PAIRS_PER_VENDOR = 10000

    # Count the merged groups the loop below pairs, so the bar reaches 100% exactly
    for v, paths in by_vendor_merged.items():
        if v.lower() not in CORRELATION_VENDORS or len(paths) < 2:
            continue

        potential_pairs = len(paths) * (len(paths) - 1) // 2
        if potential_pairs > MAX_PAIRS_PER_VENDOR:
            max_files = int(math.sqrt(MAX_PAIRS_PER_VENDOR * 2)) + 1
            paths_limited = paths[:max_files]
            potential_pairs = len(paths_limited) * (len(paths_limited) - 1) // 2

        vendor_pair_counts[v] = potential_pairs
        total_pairs_all_vendors += potential_pairs

    # print(f"GenAI: Total pairs across all vendors: {total_pairs_all_vendors}")

    # Send initial progress with total
    write_progress(
        group_name,
        {
            "status": "genai_processing",
            "step": "pairing",
            "total_pairs": total_pairs_all_vendors,
            "processed": 0,
        },
    )
    last_report = time.monotonic()

    # Generate vendor correlations (files from same vendor)
    vendor_corr = []
    cumulative_count = 0  # Track progress across all vendors

    # SecOps first: it is the primary correlation platform
    for v, groups in sorted(by_vendor_merged.items(), key=lambda kv: _vendor_priority(kv[0])):
        if v.lower() not in CORRELATION_VENDORS:
            continue

        if len(groups) < 2:
            # print(
            #     f"GenAI: Vendor '{v}' has only {len(groups)} group(s), skipping intra-vendor correlations"
            # )
            continue

        # Calculate potential number of pairs (groups, not individual files)
        potential_pairs = len(groups) * (len(groups) - 1) // 2
        # if merge_by_tactic or merge_by_parent:
        #     print(f"GenAI: Vendor '{v}' has {len(groups)} merged groups, potentially {potential_pairs} pairs")
        # else:
        #     print(f"GenAI: Vendor '{v}' has {len(groups)} files, potentially {potential_pairs} pairs")

        # Limit the number of pairs to avoid performance issues
        if potential_pairs > MAX_PAIRS_PER_VENDOR:
            # print(
            #     f"GenAI: Limiting {v} to {MAX_PAIRS_PER_VENDOR} pairs (from potential {potential_pairs})"
            # )
            # Limit by taking only the first N groups
            max_groups = int(math.sqrt(MAX_PAIRS_PER_VENDOR * 2)) + 1
            groups = groups[:max_groups]
            # print(f"GenAI: Limited to first {len(groups)} groups")
            potential_pairs = len(groups) * (len(groups) - 1) // 2

        # Send progress update at start of each vendor
        # print(f"GenAI: Starting vendor '{v}' - {cumulative_count} pairs completed so far")
        write_progress(
            group_name,
            {
                "status": "genai_processing",
                "total_pairs": total_pairs_all_vendors,
                "processed": cumulative_count,
            },
        )

        # Generate pairs using combinatorial approach
        count = 0
        pairs_evaluated = 0  # Track all pairs evaluated (including filtered ones)

        # Track filter statistics
        filter_stats = {
            "generic_terms": 0,
            "identical_queries": 0,
            "excessive_overlap": 0,
            "insufficient_overlap": 0,
            "same_table": 0,
            "no_progression": 0,
            "no_high_impact": 0,
        }

        for i in range(len(groups)):
            for j in range(i + 1, len(groups)):
                group_a = groups[i]  # List of file paths in group A
                group_b = groups[j]  # List of file paths in group B

                # Increment pairs_evaluated for every pair we look at
                pairs_evaluated += 1
                cumulative_count += 1

                # Report on a timer: later filters skip pairs with `continue`, and a
                # file write per pair would slow the loop down
                if time.monotonic() - last_report >= 0.4:
                    last_report = time.monotonic()
                    write_progress(
                        group_name,
                        {
                            "status": "genai_processing",
                            "step": "pairing",
                            "total_pairs": total_pairs_all_vendors,
                            "processed": cumulative_count,
                        },
                    )

                # For merged groups, use the first file as representative
                # (In production, you'd want to combine queries intelligently)
                path_a = group_a[0] if isinstance(group_a, list) else group_a
                path_b = group_b[0] if isinstance(group_b, list) else group_b

                # Get queries from our file_info lookup
                query_a = file_info.get(path_a, {}).get("query", "")
                query_b = file_info.get(path_b, {}).get("query", "")

                # Clean up queries - remove leading "|\n  " if present
                if query_a and query_a.startswith("|\n"):
                    query_a = query_a[2:].lstrip()
                if query_b and query_b.startswith("|\n"):
                    query_b = query_b[2:].lstrip()

                # Detect the query language from content
                detected_vendor = v.lower()
                if _is_yaral(query_a) and _is_yaral(query_b):
                    detected_vendor = "googlesecops"
                elif query_a.lstrip().startswith("index=") or query_b.lstrip().startswith("index="):
                    detected_vendor = "splunk"
                elif query_a.lstrip().startswith("Device") or query_b.lstrip().startswith("Device"):
                    detected_vendor = "mde"

                # Filter out queries with only generic terms
                skip_pair = False
                skip_reason = None
                if _has_only_generic_terms(query_a) or _has_only_generic_terms(query_b):
                    skip_pair = True
                    skip_reason = "generic_terms"

                # Filter out identical queries (normalizing whitespace for comparison)
                if not skip_pair:
                    # Normalize whitespace and compare
                    normalized_a = " ".join(query_a.split())
                    normalized_b = " ".join(query_b.split())
                    if normalized_a == normalized_b:
                        skip_pair = True
                        skip_reason = "identical_queries"

                # PHASE 1 FILTER 1: Skip pairs with excessive semantic overlap (>80% = near duplicates)
                # Balanced threshold to reduce noise while allowing related correlations
                if not skip_pair:
                    overlap_pct = _estimate_semantic_overlap_kql(query_a, query_b)
                    if overlap_pct > 80:
                        skip_pair = True
                        skip_reason = "excessive_overlap"
                    # NOTE: Minimum overlap filter (<20%) disabled - too aggressive
                    # Attack progression is sufficient for ensuring relatedness

                # PHASE 1 FILTER 2: Same-table filter DISABLED
                # Correlating techniques from the same data source is valuable
                # The scoring system will prioritize diverse data sources via data source diversity scoring
                # if not skip_pair:
                #     tables_a = _extract_primary_tables(query_a, detected_vendor)
                #     tables_b = _extract_primary_tables(query_b, detected_vendor)
                #     # If both queries use identical table sets, skip
                #     if tables_a and tables_b and tables_a == tables_b:
                #         # Check if they're different subtechniques - if so, allow
                #         techniques_a = _extract_technique_ids(path_a)
                #         techniques_b = _extract_technique_ids(path_b)
                #         # Extract base technique IDs (e.g., T1003 from T1003.001)
                #         base_a = set(t.split('.')[0] for t in techniques_a)
                #         base_b = set(t.split('.')[0] for t in techniques_b)
                #         # Allow only if same base technique but different subtechniques
                #         if not (base_a == base_b and techniques_a != techniques_b):
                #             skip_pair = True
                #             skip_reason = "same_table"

                # PHASE 1 FILTER 3: MANDATORY attack progression check
                # Only correlate detections that follow logical attack chain progression
                if not skip_pair:
                    has_progression = _check_attack_progression(path_a, path_b)
                    if not has_progression:
                        skip_pair = True
                        skip_reason = "no_progression"

                # NOTE: High-impact requirement removed as hard filter
                # It's still used in scoring (see _score_correlation function)
                # This allows correlations between lower-priority techniques if they follow attack progression

                # Track filter statistics
                if skip_pair and skip_reason:
                    filter_stats[skip_reason] += 1

                # Skip pair if filtered out
                if skip_pair:
                    continue

                # Generate combined query
                combined_query = _combine_queries(detected_vendor, query_a, query_b, path_a, path_b)

                # Remove semantic overlap text from query
                if combined_query:
                    combined_query = re.sub(r";\s*\d+%\s*semantic overlap", "", combined_query)

                # Extract tactics from both files
                tactics_set = set()
                for path in [path_a, path_b]:
                    if path in file_info:
                        path_tactics = file_info[path].get("tactics", [])
                        if path_tactics:
                            tactics_set.update(path_tactics)

                vendor_corr.append(
                    {
                        "vendor": detected_vendor,
                        "a": path_a,
                        "b": path_b,
                        "query_a": query_a,
                        "query_b": query_b,
                        "combined_query": combined_query,
                        "tactics": sorted(list(tactics_set)),  # Add tactics field
                    }
                )
                count += 1

        # Log filter statistics for this vendor
        total_filtered = sum(filter_stats.values())
        # print(f"✅ Generated {count} correlation(s) for vendor '{v}'")
        # if total_filtered > 0:
        #     print(f"  Filter breakdown:")
        #     if filter_stats["generic_terms"] > 0:
        #         print(f"    - Generic terms: {filter_stats['generic_terms']}")
        #     if filter_stats["identical_queries"] > 0:
        #         print(f"    - Identical queries: {filter_stats['identical_queries']}")
        #     if filter_stats["excessive_overlap"] > 0:
        #         print(f"    - Excessive overlap (>75%): {filter_stats['excessive_overlap']}")
        #     if filter_stats["insufficient_overlap"] > 0:
        #         print(f"    - Insufficient overlap (<20%): {filter_stats['insufficient_overlap']}")
        #     if filter_stats["same_table"] > 0:
        #         print(f"    - Same table/index: {filter_stats['same_table']}")
        #     if filter_stats["no_progression"] > 0:
        #         print(f"    - No attack progression: {filter_stats['no_progression']}")
        #     if filter_stats["no_high_impact"] > 0:
        #         print(f"    - No high-impact technique: {filter_stats['no_high_impact']}")

    # print(f"GenAI: Total correlations before filtering: {len(vendor_corr)}")

    write_progress(
        group_name,
        {
            "status": "genai_processing",
            "step": "scoring",
            "total_pairs": total_pairs_all_vendors,
            "processed": cumulative_count,
        },
    )

    # Score correlations but don't filter aggressively
    # MODIFIED: Reduced filtering to allow more correlations through
    if vendor_corr:
        # Separate correlations by vendor
        by_vendor_corr = {}
        for corr in vendor_corr:
            vendor = corr.get("vendor", "unknown")
            if vendor not in by_vendor_corr:
                by_vendor_corr[vendor] = []
            by_vendor_corr[vendor].append(corr)

        # Score and filter each vendor (balanced threshold)
        filtered_corr = []
        for vendor, corrs in by_vendor_corr.items():
            print(f"\n   Vendor: {vendor} - {len(corrs)} raw correlations")

            # Use config relevance threshold (default 75%)
            from archer.config import CoreConfig

            min_relevance = CoreConfig.correlation_min_relevance

            top_vendor_corrs = _score_and_filter_correlations(
                corrs, file_info, min_relevance=min_relevance,
                max_per_vendor=CORRELATION_CAP.get(vendor, 60),
            )
            print(
                f"   Kept {len(top_vendor_corrs)}/{len(corrs)} after relevance filtering (>= {min_relevance:.0%})"
            )
            filtered_corr.extend(top_vendor_corrs)

        vendor_corr = filtered_corr

    # Pairing is done; grouping and writing the results file remain
    write_progress(
        group_name,
        {
            "status": "genai_processing",
            "step": "grouping",
            "total_pairs": total_pairs_all_vendors,
            "processed": cumulative_count,
        },
    )
    # print(f"GenAI: Completed processing {cumulative_count} total pairs across all vendors")

    # Apply correlation grouping to reduce redundancy (keeps best correlation per technique pair)
    if vendor_corr:
        print(f"   Before grouping: {len(vendor_corr)} correlations")
        vendor_corr = _apply_correlation_grouping(vendor_corr, file_info)
        print(f"   After grouping: {len(vendor_corr)} correlations")
        pass

    print(f"📊 Final correlation count: {len(vendor_corr)} correlations")

    # No cross-vendor correlations - explicitly create an empty list
    cross_corr = []
    # print(f"GenAI: Cross-vendor Correlations disabled")

    # Write results to correlation JSON file
    results = {
        "vendor_correlations": vendor_corr,
        "cross_vendor_correlations": cross_corr,  # Empty list
    }

    out_dir = CORRELATE_DIR
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{group_name}.json")

    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        # print(f"GenAI: Wrote correlation results to {out_path}")
    except Exception as e:
        print(f"GenAI: Error writing correlations file: {e}")

    return results


def _normalize_kql_spacing(q: str) -> str:
    """Ensure exactly three spaces before each KQL pipe."""
    if not isinstance(q, str):
        return q
    q = re.sub(r"^[ \t]*\|", "   |", q, flags=re.MULTILINE)
    q = q.replace("\n|", "\n   |")
    return q


def _collapse_double_newlines(text: str) -> str:
    """Reduce double or multiple consecutive newlines to a single newline."""
    if not isinstance(text, str):
        return text
    return re.sub(r"\n[ \t]*\n+", "\n", text)


# Heuristic semantic overlap (KQL)
_KQL_STOPWORDS = {
    "let",
    "query",
    "union",
    "where",
    "summarize",
    "project",
    "by",
    "and",
    "or",
    "has",
    "has_any",
    "has_all",
    "contains",
    "startswith",
    "endswith",
    "in",
    "not",
    "ago",
    "timestamp",
    "device",
    "name",
    "id",
    "type",
    "true",
    "false",
    "count",
    "as",
    "join",
    "extend",
    "take",
    "top",
    "sort",
    "order",
    "desc",
    "asc",
    # common schema/columns stripped from overlap scoring
    "devicename",
    "deviceid",
    "actiontype",
    "accountname",
    "accountupn",
    "filename",
    "folderpath",
    "sha256",
    "sha1",
    "processcommandline",
    "initiatingprocesscommandline",
    "initiatingprocessaccountname",
    "initiatingprocessaccountupn",
    "initiatingprocessfolderpath",
    "initiatingprocesssha256",
    "initiatingprocessparentfilename",
    "timestamp",
}


def _tokenize_for_overlap(text: str) -> set:
    if not isinstance(text, str) or not text:
        return set()
    # pull alnum tokens length>=3, lowercase
    toks = re.findall(r"[A-Za-z_][A-Za-z_0-9]{2,}", text)
    toks = [t.lower() for t in toks]
    return {t for t in toks if t not in _KQL_STOPWORDS}


def _estimate_semantic_overlap_kql(q1: str, q2: str) -> int:
    """Estimate semantic overlap between two KQL queries as a percentage (0-100)."""
    s1 = _tokenize_for_overlap(q1)
    s2 = _tokenize_for_overlap(q2)
    if not s1 or not s2:
        return 0
    inter = len(s1 & s2)
    union = len(s1 | s2)
    if union == 0:
        return 0
    return max(0, min(100, int(round((inter / union) * 100))))


def _basic_combine_queries(
    vendor: str,
    query_a: str,
    query_b: str,
    source_a: Optional[str] = None,
    source_b: Optional[str] = None,
) -> str:
    """Basic fallback method for combining queries."""
    # Handle Splunk queries
    if (
        vendor == "splunk"
        or (isinstance(query_a, str) and query_a.lstrip().startswith("index="))
        or (isinstance(query_b, str) and query_b.lstrip().startswith("index="))
    ):
        # Extract index from each query if present
        index_a_match = re.search(r"index\s*=\s*(\w+)", query_a)
        index_b_match = re.search(r"index\s*=\s*(\w+)", query_b)

        index_a = index_a_match.group(1) if index_a_match else None
        index_b = index_b_match.group(1) if index_b_match else None

        # Use the same index if possible
        index = index_a or index_b or "edr_events"

        # Extract search terms (everything after the index and before | table)
        search_a = ""
        if index_a_match:
            search_start = query_a.find(index_a) + len(index_a)
            search_a = query_a[search_start:].strip()
            table_index = search_a.find("| table ")
            if table_index > 0:
                search_a = search_a[:table_index].strip()
        else:
            search_a = query_a.strip()
            table_index = search_a.find("| table ")
            if table_index > 0:
                search_a = search_a[:table_index].strip()

        search_b = ""
        if index_b_match:
            search_start = query_b.find(index_b) + len(index_b)
            search_b = query_b[search_start:].strip()
            table_index = search_b.find("| table ")
            if table_index > 0:
                search_b = search_b[:table_index].strip()
        else:
            search_b = query_b.strip()
            table_index = search_b.find("| table ")
            if table_index > 0:
                search_b = search_b[:table_index].strip()

        # Build proper correlation using transaction to find devices where BOTH patterns occur
        def clean_duplicates(search_str):
            """Remove duplicate OR conditions"""
            if not search_str:
                return search_str
            parts = re.split(r"\s+OR\s+", search_str, flags=re.IGNORECASE)
            seen = set()
            unique = []
            for p in parts:
                normalized = " ".join(p.strip().strip("()").split())
                if normalized and normalized not in seen:
                    unique.append(p.strip().strip("()"))
                    seen.add(normalized)
            return unique[0] if len(unique) == 1 else " OR ".join(unique)

        search_a_clean = clean_duplicates(search_a)
        search_b_clean = clean_duplicates(search_b)

        combined = f"""index={index} earliest=-1d
  ({search_a_clean}) OR ({search_b_clean})
  | eval pattern_a=if(({search_a_clean}), "true", "false")
  | eval pattern_b=if(({search_b_clean}), "true", "false")
  | transaction host maxspan=1h
  | search pattern_a="true" AND pattern_b="true"
  | stats count AS event_count, min(_time) AS first_seen, max(_time) AS last_seen, values(file_name) AS file_names, values(process_command_line) AS command_lines, values(user) AS accounts BY host
  | eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
  | where event_count >= 2
  | sort - event_count"""

        return _collapse_double_newlines(combined)

    # Handle MDE/KQL queries
    elif vendor == "googlesecops":
        from archer.build.secops import build_correlation_rule

        rule = build_correlation_rule(query_a, query_b, source_a or "", source_b or "")
        if rule:
            return rule
        return f"// Could not build a SecOps correlation from {source_a or 'Query A'} and {source_b or 'Query B'}"

    elif vendor in ["mde", "microsoft", "sentinel", "kql"]:
        # Normalize labels
        label_a = (source_a or "Query A").strip()
        label_b = (source_b or "Query B").strip()

        # Normalize inner queries' pipe spacing first
        qa = _normalize_kql_spacing(query_a or "")
        qb = _normalize_kql_spacing(query_b or "")

        # Proper KQL join syntax using inner join on common correlation keys
        combined_kql = f"""// Correlation: {label_a} + {label_b}
// Query A: {label_a}
let QueryA = materialize(
    {qa}
    | extend CorrelationKey = strcat(DeviceId, "_", bin(Timestamp, 1h))
    | project Timestamp, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, CorrelationKey, QueryA_Match = "true"
);
// Query B: {label_b}
let QueryB = materialize(
    {qb}
    | extend CorrelationKey = strcat(DeviceId, "_", bin(Timestamp, 1h))
    | project Timestamp, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, CorrelationKey, QueryB_Match = "true"
);
// Join queries on same device within same hour window
QueryA
| join kind=inner (QueryB) on CorrelationKey
| where Timestamp > ago(1d) and Timestamp1 > ago(1d)
| project CorrelationTimestamp = Timestamp, DeviceId, DeviceName, AccountName,
          QueryA_File = FileName, QueryA_Command = ProcessCommandLine,
          QueryB_File = FileName1, QueryB_Command = ProcessCommandLine1
| summarize CorrelationCount = count(),
            QueryA_Files = make_set(QueryA_File),
            QueryB_Files = make_set(QueryB_File),
            FirstSeen = min(CorrelationTimestamp),
            LastSeen = max(CorrelationTimestamp)
            by DeviceId, DeviceName, AccountName
| where CorrelationCount >= 1  // Both patterns observed on same device within 1 hour
"""
        return _collapse_double_newlines(_normalize_kql_spacing(combined_kql))

    # Generic combination for other vendors
    else:
        return _collapse_double_newlines(
            f"""
// Combined Query
// {source_a or 'Query A'}:
{query_a}

// {source_b or 'Query B'}:
{query_b}

// TODO: Combine these queries using the appropriate method for {vendor}
"""
        )


def build_correlation_queries(
    yaml_dir: str = None,
    output_file: str = None,
    min_queries: int = 2,
    max_queries: int = 5,
    threat_group: str = None,
) -> Dict:
    """
    Read YAML files, assess query relevance, build correlation searches, and save to JSON.

    This function:
    1. Reads all YAML files from the specified directory
    2. Extracts detection queries and metadata (threat group, platform, tactics, severity)
    3. Assesses relevance of each query against all others based on:
       - Shared threat groups (tags)
       - Compatible platforms
       - Related attack paths (tactics)
       - Severity/likelihood scores
    4. Builds correlation searches combining min_queries to max_queries queries
    5. Ensures no duplicate tactics in correlations
    6. Summarizes the correlation results
    7. Saves all queries in a single JSON output file

    Args:
        yaml_dir: Directory containing YAML files (default: data/groups)
        output_file: Output JSON file path (default: data/correlate/correlation_queries.json)
        min_queries: Minimum number of queries to include in a correlation (default: 2)
        max_queries: Maximum number of queries to include in a correlation (default: 5)
        threat_group: Filter to only correlate queries for specific threat group (optional)

    Returns:
        Dictionary containing all correlation queries and metadata
    """
    import yaml
    from collections import defaultdict

    # Set defaults
    if yaml_dir is None:
        yaml_dir = GENERATE_DIR
    if output_file is None:
        # Use group name in output file if specified
        if threat_group:
            safe_group_name = threat_group.replace(" ", "_").replace("(", "").replace(")", "")
            output_file = os.path.join(CORRELATE_DIR, f"{safe_group_name}.json")
        else:
            output_file = os.path.join(CORRELATE_DIR, "correlation_queries.json")

    # print(f"Scanning YAML files in {yaml_dir}...")
    import time

    # time.sleep(0.5)

    # Step 1: Read all YAML files and extract metadata
    yaml_files = [
        os.path.join(yaml_dir, f) for f in os.listdir(yaml_dir) if f.endswith((".yaml", ".yml"))
    ]

    # print(f"Found {len(yaml_files)} YAML files")
    # time.sleep(0.5)

    queries_data = []
    for yaml_path in yaml_files:
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "query" not in data:
                continue

            # Extract metadata including OSINT enrichment data
            query_info = {
                "id": data.get("id", os.path.basename(yaml_path)),
                "name": data.get("name", "Unknown"),
                "description": data.get("description", ""),
                "severity": data.get("severity", "Medium"),
                "tactics": data.get("tactics", []),
                "tags": data.get("tags", []),
                "platform": _detect_platform(data),
                "connector_id": data.get("requiredDataConnectors", [{}])[0].get(
                    "connectorId", "Unknown"
                ),
                "query": data.get("query", ""),
                "file_path": yaml_path,
                "metadata": data.get("metadata", {}),
                # OSINT enrichment metadata
                "osint_compared": data.get("osint_compared", False),
                "osint_enhanced": data.get("osint_enhanced", False),
                "osint_sources": data.get("osint_sources", []),
                "osint_indicators": data.get("osint_indicators", {}),
                "osint_query_snippets": data.get("osint_query_snippets", []),
                "comparison_date": data.get("comparison_date", None),
            }
            queries_data.append(query_info)

        except Exception as e:
            print(f"Error reading {yaml_path}: {e}")
            continue

    # print(f"Successfully parsed {len(queries_data)} queries")
    time.sleep(0.5)

    # Filter by threat group if specified (case-insensitive partial match)
    if threat_group:
        threat_group_lower = threat_group.lower()
        filtered_queries = [
            q
            for q in queries_data
            if any(
                threat_group_lower in tag.lower()
                for tag in q.get("tags", [])
                if tag and isinstance(tag, str)
            )
        ]
        if len(filtered_queries) == 0:
            print(f"\n❌ No queries found for threat group '{threat_group}'")
            return {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_queries_analyzed": 0,
                "total_correlations": 0,
                "min_queries_per_correlation": min_queries,
                "max_queries_per_correlation": max_queries,
                "threat_group": threat_group,
                "output_file": output_file,
                "correlations": [],
                "query_inventory": [],
            }
        elif len(filtered_queries) == 1:
            print(
                f"\n❌ Only 1 query found for threat group '{threat_group}' - need at least {min_queries} for correlation"
            )
            return {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_queries_analyzed": 1,
                "total_correlations": 0,
                "min_queries_per_correlation": min_queries,
                "max_queries_per_correlation": max_queries,
                "threat_group": threat_group,
                "output_file": output_file,
                "correlations": [],
                "query_inventory": filtered_queries,
            }
        # print(f"Filtered to {len(filtered_queries)} queries for threat group '{threat_group}'")
        time.sleep(0.5)
        queries_data = filtered_queries

    # Step 2: Assess relevance and build correlation groups
    # print("Assessing query relevance...")
    # time.sleep(0.5)
    correlation_groups = _build_correlation_groups(queries_data, min_queries, max_queries)

    # Step 3: Build correlation searches
    # print(f"Building {len(correlation_groups)} correlation searches...")
    # time.sleep(0.5)
    correlations = []

    for idx, group in enumerate(correlation_groups, 1):
        correlation = _build_correlation_search(group, idx)
        correlations.append(correlation)

    # Step 4: Prepare output structure
    output_data = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_queries_analyzed": len(queries_data),
        "total_correlations": len(correlations),
        "min_queries_per_correlation": min_queries,
        "output_file": output_file,
        "correlations": correlations,
        "query_inventory": [
            {
                "id": q["id"],
                "name": q["name"],
                "platform": q["platform"],
                "tags": q["tags"],
                "tactics": q["tactics"],
                "severity": q["severity"],
            }
            for q in queries_data
        ],
    }

    # Step 5: Save to JSON file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    # print(f"Correlation queries saved to {output_file}")
    time.sleep(0.5)
    return output_data


def _detect_platform(yaml_data: Dict) -> str:
    """Detect the platform/vendor from YAML data."""
    connector_id = yaml_data.get("requiredDataConnectors", [{}])[0].get("connectorId", "")

    if connector_id == "MicrosoftThreatProtection":
        return "mde"
    elif connector_id == "Splunk":
        return "splunk"
    elif connector_id in ["GoogleSecOps"]:
        return "googlesecops"
    elif connector_id in ["Elastic", "ElasticSecurity"]:
        return "elastic"

    # Fallback: check query content
    query = yaml_data.get("query", "")
    if query.lstrip().startswith("index="):
        return "splunk"
    elif query.lstrip().startswith("Device"):
        return "mde"
    elif "rule " in query and ("events:" in query or "match:" in query):  # YARA-L for Google SecOps
        return "googlesecops"
    elif query.lstrip().startswith("FROM ") or " FROM " in query.upper()[:100]:  # Elastic EQL/ES|QL
        return "elastic"
    elif query.strip().startswith("event."):  # Elastic field pattern
        return "elastic"

    return "unknown"


def _calculate_relevance_score(query_a: Dict, query_b: Dict) -> float:
    """
    Calculate relevance score between two queries based on:
    - Shared threat groups (tags)
    - Platform compatibility
    - Related attack paths (tactics)
    - Severity alignment

    Returns a score from 0.0 to 1.0
    """
    score = 0.0

    # 1. Shared threat groups (40% weight)
    tags_a = set(query_a.get("tags", []))
    tags_b = set(query_b.get("tags", []))
    if tags_a and tags_b:
        tag_overlap = len(tags_a & tags_b) / len(tags_a | tags_b)
        score += tag_overlap * 0.4

    # 2. Platform compatibility (20% weight)
    if query_a.get("platform") == query_b.get("platform"):
        score += 0.2

    # 3. Related attack paths/tactics (30% weight)
    tactics_a = set(query_a.get("tactics", []))
    tactics_b = set(query_b.get("tactics", []))
    if tactics_a and tactics_b:
        tactic_overlap = len(tactics_a & tactics_b) / len(tactics_a | tactics_b)
        score += tactic_overlap * 0.3

    # 4. Severity alignment (10% weight)
    severity_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    sev_a = severity_map.get(query_a.get("severity", "Medium"), 2)
    sev_b = severity_map.get(query_b.get("severity", "Medium"), 2)
    severity_diff = abs(sev_a - sev_b)
    severity_score = max(0, 1 - (severity_diff / 3))  # Normalize 0-1
    score += severity_score * 0.1

    return score


def _build_correlation_groups(
    queries: List[Dict], min_queries: int, max_queries: int = 5
) -> List[List[Dict]]:
    """
    Group queries into correlation sets based on relevance scores.
    Each group contains queries that are highly related.
    Ensures no duplicate tactics in a correlation.
    """
    from collections import defaultdict

    # Group by shared tags (threat groups)
    groups_by_tag = defaultdict(list)
    for query in queries:
        for tag in query.get("tags", []):
            groups_by_tag[tag].append(query)

    # Build correlation groups
    correlation_groups = []

    for tag, tag_queries in groups_by_tag.items():
        if len(tag_queries) < min_queries:
            continue

        # Further group by platform within each tag
        platform_groups = defaultdict(list)
        for query in tag_queries:
            platform_groups[query["platform"]].append(query)

        for platform, platform_queries in platform_groups.items():
            if len(platform_queries) < min_queries:
                continue

            # Group queries by their technique combination (sorted tactics)
            # This ensures all queries with the same techniques are merged into one correlation
            technique_groups = defaultdict(list)
            for query in platform_queries:
                # Create a unique key from sorted tactics
                tactics_key = tuple(sorted(query.get("tactics", [])))
                technique_groups[tactics_key].append(query)

            # Build one correlation per technique combination
            for tactics_key, technique_queries in technique_groups.items():
                if len(technique_queries) >= min_queries:
                    # Take up to max_queries for this technique
                    correlation_group = technique_queries[:max_queries]
                    correlation_groups.append(correlation_group)

    return correlation_groups


def _build_correlation_search(queries: List[Dict], correlation_id: int) -> Dict:
    """
    Build a correlation search from multiple queries and summarize results.
    """
    if not queries:
        return {}

    # Determine platform
    platform = queries[0].get("platform", "unknown")

    # Collect metadata including OSINT enrichment
    all_tags = set()
    all_tactics = set()
    all_names = []
    osint_enriched_queries = []
    all_osint_sources = set()
    all_osint_indicators = {}

    for q in queries:
        all_tags.update(q.get("tags", []))
        all_tactics.update(q.get("tactics", []))
        all_names.append(q.get("name", "Unknown"))

        # Track OSINT enrichment per query
        if q.get("osint_compared") or q.get("osint_enhanced"):
            osint_enriched_queries.append({
                "name": q.get("name", "Unknown"),
                "osint_enhanced": q.get("osint_enhanced", False),
                "osint_sources": q.get("osint_sources", []),
                "osint_indicators": q.get("osint_indicators", {}),
                "osint_query_snippets": q.get("osint_query_snippets", []),
            })

            # Aggregate OSINT sources
            all_osint_sources.update(q.get("osint_sources", []))

            # Aggregate OSINT indicators by type
            for indicator_type, values in q.get("osint_indicators", {}).items():
                if indicator_type not in all_osint_indicators:
                    all_osint_indicators[indicator_type] = set()
                if isinstance(values, list):
                    all_osint_indicators[indicator_type].update(values)
                elif isinstance(values, str):
                    all_osint_indicators[indicator_type].add(values)

    # Build combined query based on platform
    if platform == "mde":
        combined_query = _combine_mde_queries([q["query"] for q in queries])
    elif platform == "splunk":
        combined_query = _combine_splunk_queries_simple([q["query"] for q in queries])
    else:
        combined_query = "// Unsupported platform for correlation"

    # Generate summary
    summary = _generate_correlation_summary(queries, all_tags, all_tactics)

    # Filter out None values before sorting
    clean_tags = sorted([t for t in all_tags if t is not None])
    clean_tactics = sorted([t for t in all_tactics if t is not None])

    # Convert OSINT indicator sets to sorted lists for JSON serialization
    osint_indicators_serializable = {
        indicator_type: sorted(list(values))
        for indicator_type, values in all_osint_indicators.items()
        if values  # Only include non-empty indicator types
    }

    correlation_result = {
        "correlation_id": f"CORR-{correlation_id:04d}",
        "name": f"Correlation: {' + '.join(all_names[:3])}{'...' if len(all_names) > 3 else ''}",
        "summary": summary,
        "platform": platform,
        "threat_groups": clean_tags,
        "tactics": clean_tactics,
        "query_count": len(queries),
        "queries_included": [
            {"id": q["id"], "name": q["name"], "file": os.path.basename(q["file_path"])}
            for q in queries
        ],
        "combined_query": combined_query,
        "relevance_scores": [
            {
                "query_pair": f"{queries[i]['name']} <-> {queries[j]['name']}",
                "score": round(_calculate_relevance_score(queries[i], queries[j]), 3),
            }
            for i in range(len(queries))
            for j in range(i + 1, min(i + 3, len(queries)))  # Limit pairs for readability
        ],
    }

    # Add OSINT enrichment metadata if any queries were enriched
    if osint_enriched_queries:
        correlation_result["osint_enriched"] = True
        correlation_result["osint_sources"] = sorted(list(all_osint_sources))
        correlation_result["osint_indicators"] = osint_indicators_serializable
        correlation_result["osint_enriched_queries"] = osint_enriched_queries
        correlation_result["osint_enrichment_count"] = len(osint_enriched_queries)
    else:
        correlation_result["osint_enriched"] = False

    return correlation_result


def _combine_mde_queries(query_list: List[str]) -> str:
    """Combine multiple MDE/KQL queries into a single correlation search using proper join syntax."""
    if not query_list or len(query_list) < 2:
        return "// Error: Need at least 2 queries to correlate"

    # Build let statements for each query with correlation keys
    let_statements = []
    for idx, query in enumerate(query_list, 1):
        query_clean = _normalize_kql_spacing(query.strip())
        let_statements.append(
            f"""// Detection Query {idx}
let Query{idx} = materialize(
    {query_clean}
    | extend CorrelationKey = strcat(DeviceId, "_", bin(Timestamp, 1h))
    | extend DetectionSource{idx} = "Query{idx}"
    | project Timestamp, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, CorrelationKey, DetectionSource{idx}
);"""
        )

    # Build progressive joins starting with Query1
    join_chain = "Query1"
    for idx in range(2, len(query_list) + 1):
        # Use leftanti for "OR" logic - match if ANY query matches
        # Use inner for "AND" logic - match if ALL queries match
        # For correlation, we want "OR" to catch any combination
        join_chain += f"\n| join kind=fullouter (Query{idx}) on CorrelationKey"

    # Complete correlation query
    combined = "\n\n".join(let_statements)
    combined += f"\n\n// Correlation: Match if 2+ detection patterns fire on same device within 1 hour\n{join_chain}"
    combined += "\n| where Timestamp > ago(1d) or " + " or ".join(
        [f"Timestamp{i} > ago(1d)" for i in range(1, len(query_list))]
    )
    combined += "\n| extend MatchCount = "
    # Count how many detection sources matched
    match_conditions = " + ".join(
        [f"iff(isnotempty(DetectionSource{i}), 1, 0)" for i in range(1, len(query_list) + 1)]
    )
    combined += match_conditions
    combined += "\n| where MatchCount >= 2  // At least 2 different detection patterns matched"
    combined += "\n| project DeviceId, DeviceName, AccountName, MatchCount,"
    combined += "\n          " + ", ".join(
        [f"DetectionSource{i}" for i in range(1, len(query_list) + 1)]
    )
    combined += "\n| summarize DetectionCount = count(),"
    combined += (
        "\n            DetectionSources = make_set_if(strcat("
        + ", ".join([f"DetectionSource{i}" for i in range(1, len(query_list) + 1)])
        + "), isnotempty(strcat("
        + ", ".join([f"DetectionSource{i}" for i in range(1, len(query_list) + 1)])
        + ")))"
    )
    combined += "\n            by DeviceId, DeviceName, AccountName"
    combined += "\n| order by DetectionCount desc"

    return combined


def _combine_splunk_queries_simple(query_list: List[str]) -> str:
    """Combine multiple Splunk queries into a proper correlation search using transaction."""
    # Extract index from first query
    index_match = re.search(r"index\s*=\s*(\w+)", query_list[0])
    index = index_match.group(1) if index_match else "edr_events"

    search_conditions = []
    eval_statements = []
    search_filters = []

    for idx, query in enumerate(query_list, 1):
        # Extract search condition (remove index= and table commands)
        search = query.strip()
        search = re.sub(r"index\s*=\s*\w+\s*earliest=[^\n]*\n", "", search)
        search = re.sub(r"\|\s*table\s+.*$", "", search, flags=re.MULTILINE).strip()
        search = re.sub(r"\|\s*stats\s+.*$", "", search, flags=re.MULTILINE).strip()
        search = re.sub(r"\|\s*eval\s+.*$", "", search, flags=re.MULTILINE).strip()

        if search:
            # Clean up duplicates and unnecessary parentheses
            parts = re.split(r"\s+OR\s+", search, flags=re.IGNORECASE)
            seen = set()
            unique = []
            for p in parts:
                normalized = " ".join(p.strip().strip("()").split())
                if normalized and normalized not in seen:
                    unique.append(p.strip().strip("()"))
                    seen.add(normalized)

            clean_search = unique[0] if len(unique) == 1 else " OR ".join(unique)
            search_conditions.append(f"({clean_search})")
            eval_statements.append(f'  | eval pattern_{idx}=if(({clean_search}), "true", "false")')
            search_filters.append(f'pattern_{idx}="true"')

    # Build correlation using transaction to find hosts where ALL patterns occur
    combined = f"""index={index} earliest=-1d
  {' OR '.join(search_conditions)}
{''.join(eval_statements)}
  | transaction host maxspan=1h
  | search {' AND '.join(search_filters)}
  | stats count AS event_count, min(_time) AS first_seen, max(_time) AS last_seen, values(file_name) AS file_names, values(process_command_line) AS command_lines, values(user) AS accounts BY host
  | eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
  | where event_count >= {len(query_list)}
  | sort - event_count"""

    return combined


def _generate_correlation_summary(queries: List[Dict], tags: set, tactics: set) -> str:
    """Generate a human-readable summary of the correlation search."""
    # Filter out None values before sorting
    clean_tags = sorted([t for t in tags if t is not None]) if tags else []
    clean_tactics = sorted([t for t in tactics if t is not None]) if tactics else []

    summary_lines = [
        f"This correlation search combines {len(queries)} detection queries to identify coordinated attack patterns.",
        f"\nThreat Groups: {', '.join(clean_tags) if clean_tags else 'None'}",
        f"Attack Tactics: {', '.join(clean_tactics) if clean_tactics else 'None'}",
        f"\nThe correlation fires when at least 2 of the following detection patterns are observed:",
    ]

    for idx, q in enumerate(queries, 1):
        summary_lines.append(f"  {idx}. {q['name']}")

    summary_lines.append(
        "\nThis approach increases detection confidence by requiring multiple related indicators,"
        " reducing false positives while identifying sophisticated attack campaigns."
    )

    return "\n".join(summary_lines)


# Make sure key functions are explicitly exposed at the module level
__all__ = ["generate_correlations", "process", "process_genai", "build_correlation_queries"]

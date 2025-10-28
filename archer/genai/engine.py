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
from ..build.progress import write_progress
from ..config import GENERATE_DIR, CORRELATE_DIR

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
    if not os.path.isdir(yaml_dir):
        return []
    return [
        os.path.join(yaml_dir, f)
        for f in os.listdir(yaml_dir)
        if f.endswith(".yaml") or f.endswith(".yml")
    ]


def _parse_yaml_for_vendor(path: str) -> Dict:
    """
    Parse a YAML file to extract vendor information and search query content.

    Returns a dictionary with:
    - path: the file path
    - vendor: detected vendor (or None)
    - query: the search query if found (or None)
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except Exception:
        return {"path": path, "vendor": None, "query": None}

    vendor = None
    query = None
    connector_id = None

    # Look for the connectorId field to determine vendor
    for line in text.splitlines():
        line_lower = line.lower().strip()
        if line_lower.startswith("connectorid:"):
            connector_id = line.split(":", 1)[1].strip()
            break

    # Set vendor based on connectorId
    if connector_id:
        if connector_id == "Splunk":
            vendor = "splunk"
        elif connector_id == "MicrosoftThreatProtection":
            vendor = "mde"

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

    # fallback: try filename hints if vendor not found
    if not vendor:
        name = os.path.basename(path).lower()
        if "splunk" in name:
            vendor = "splunk"
        elif "kql" in name or "mde" in name or "microsoft" in name or "sentinel" in name:
            vendor = "mde"

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

    return {"path": path, "vendor": vendor, "query": query}


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
    if is_splunk_a or is_splunk_b:
        detected_vendor = "splunk"
    elif is_mde_a and is_mde_b:
        detected_vendor = "mde"

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
    ("initial-access", "execution"),
    ("initial-access", "persistence"),
    ("execution", "privilege-escalation"),
    ("privilege-escalation", "defense-evasion"),
    ("privilege-escalation", "credential-access"),
    ("credential-access", "lateral-movement"),
    ("lateral-movement", "collection"),
    ("collection", "exfiltration"),
    ("defense-evasion", "persistence"),
]


def _extract_technique_ids(file_path: str) -> List[str]:
    """Extract MITRE technique IDs from YAML file path or content."""
    technique_ids = []

    # Extract from filename (e.g., T1003.001_splunk.yaml)
    basename = os.path.basename(file_path)
    matches = re.findall(r"T\d{4}(?:\.\d{3})?", basename)
    technique_ids.extend(matches)

    # Try to extract from file content if no matches
    if not technique_ids and os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read(500)  # Read first 500 chars
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


def _score_correlation(corr: Dict, file_info: Dict) -> float:
    """
    Score a correlation based on multiple factors.
    Returns score from 0-100 (higher is better).
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

    # 2. Query Specificity (0-20 points)
    specificity_a = _calculate_query_specificity(query_a)
    specificity_b = _calculate_query_specificity(query_b)
    avg_specificity = (specificity_a + specificity_b) / 2
    score += avg_specificity * 20

    # 3. False Positive Rate (0-20 points) - inverse scoring
    fp_rate_a = _estimate_false_positive_rate(query_a, corr.get("vendor", ""))
    fp_rate_b = _estimate_false_positive_rate(query_b, corr.get("vendor", ""))
    avg_fp_rate = (fp_rate_a + fp_rate_b) / 2
    score += (1.0 - avg_fp_rate) * 20  # Lower FP rate = higher score

    # 4. Semantic Overlap (0-15 points)
    # Re-calculate semantic overlap for scoring
    overlap = _estimate_semantic_overlap_kql(query_a, query_b)
    if overlap > 50:  # Already filtered to >50%
        # Normalize 50-100% to 0-15 points
        score += ((overlap - 50) / 50) * 15

    # 5. Attack Progression (0-15 points)
    # Check if tactics form a logical progression
    for tactic_a in tactics_a:
        for tactic_b in tactics_b:
            if (tactic_a, tactic_b) in _ATTACK_PROGRESSIONS:
                score += 15
                break
            elif (tactic_b, tactic_a) in _ATTACK_PROGRESSIONS:
                score += 15
                break

    return min(100.0, score)


def _score_and_filter_correlations(
    correlations: List[Dict], file_info: Dict, min_relevance: float = 0.5
) -> List[Dict]:
    """
    Score all correlations and return only those meeting the minimum relevance threshold.

    Args:
        correlations: List of correlation dictionaries
        file_info: File metadata dictionary
        min_relevance: Minimum relevance score threshold (default 0.5 = 50%)

    Returns:
        Filtered list of correlations with relevance_score >= min_relevance
    """
    print(f"GenAI: Scoring {len(correlations)} correlations...")

    # Score each correlation
    scored_correlations = []
    for corr in correlations:
        score = _score_correlation(corr, file_info)
        corr["relevance_score"] = round(score / 100, 2)  # Normalize to 0-1
        scored_correlations.append((score, corr))

    # Sort by score (descending)
    scored_correlations.sort(key=lambda x: x[0], reverse=True)

    # Log score distribution
    if scored_correlations:
        scores = [s[0] for s in scored_correlations]
        print(f"GenAI: Score distribution:")
        print(f"  Top score: {scores[0]:.1f}")
        print(f"  Median score: {scores[len(scores)//2]:.1f}")
        print(f"  Lowest score: {scores[-1]:.1f}")

    # Filter by minimum relevance threshold (50% = score >= 50)
    min_score_threshold = min_relevance * 100
    top_correlations = [corr for score, corr in scored_correlations if score >= min_score_threshold]

    print(
        f"GenAI: Keeping {len(top_correlations)}/{len(correlations)} correlations with relevance >= {min_relevance:.0%} (score >= {min_score_threshold:.1f})"
    )

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
        print(f"GenAI: Found {len(files)} YAML files for {group_name}")
        write_progress(
            group_name,
            {"status": "genai_started", "total_files": len(files), "processed": 0},
        )

        # If configured to use a local model, attempt it and gracefully fallback
        mode = os.environ.get("GENAI_MODE", "heuristic").lower()
        print(f"GenAI: Using mode '{mode}'")

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
        print(f"GenAI: Available capability modes: {', '.join(available_modes)}")

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
                "vendor_count": len(results.get("vendor_correlations", [])),
                "cross_count": 0,  # Always 0 now
            },
        )
        return results
    finally:
        # Always release the lock when done
        group_lock.release()
        print(f"GenAI: Released correlation lock for '{group_name}'")


def process_genai(group_name: str):
    """
    Main entry point for GenAI processing that can be called from other modules.
    This function is the primary hook for correlation generation from app.py.

    Args:
        group_name: The group name to process
    """
    print(f"process_genai called for group {group_name}")
    yaml_dir = GENERATE_DIR
    return generate_correlations(group_name, yaml_dir)


def process(group_name: str):
    """Alias for process_genai for compatibility."""
    print(f"process alias called for group {group_name}")
    return process_genai(group_name)


def _generate_with_heuristic(group_name: str, files: List[str]) -> Dict:
    """Generate correlations using a rule-based heuristic approach."""
    print(f"GenAI: Running heuristic correlation generation for {len(files)} files")

    # Parse all files to extract vendor information and queries
    parsed = [_parse_yaml_for_vendor(p) for p in files]

    # Create lookup for easy access to file info including queries
    file_info = {p["path"]: p for p in parsed}

    # Logging for debugging
    vendor_counts = {}
    for p in parsed:
        v = p.get("vendor") or "unknown"
        vendor_counts[v] = vendor_counts.get(v, 0) + 1

    print(f"GenAI: Vendor distribution: {vendor_counts}")

    # Group files by vendor
    by_vendor = {}
    for p in parsed:
        v = p.get("vendor") or "unknown"
        # No need for additional normalization since it's done in _parse_yaml_for_vendor
        by_vendor.setdefault(v, []).append(p["path"])

    # Calculate total pairs across all vendors first for cumulative progress
    total_pairs_all_vendors = 0
    vendor_pair_counts = {}
    MAX_PAIRS_PER_VENDOR = 10000

    for v, paths in by_vendor.items():
        if v.lower() not in ["mde", "splunk"] or len(paths) < 2:
            continue

        potential_pairs = len(paths) * (len(paths) - 1) // 2
        if potential_pairs > MAX_PAIRS_PER_VENDOR:
            max_files = int(math.sqrt(MAX_PAIRS_PER_VENDOR * 2)) + 1
            paths_limited = paths[:max_files]
            potential_pairs = len(paths_limited) * (len(paths_limited) - 1) // 2

        vendor_pair_counts[v] = potential_pairs
        total_pairs_all_vendors += potential_pairs

    print(f"GenAI: Total pairs across all vendors: {total_pairs_all_vendors}")

    # Send initial progress with total
    write_progress(
        group_name,
        {
            "status": "genai_processing",
            "total_pairs": total_pairs_all_vendors,
            "processed": 0,
        },
    )

    # Generate vendor correlations (files from same vendor)
    vendor_corr = []
    cumulative_count = 0  # Track progress across all vendors

    for v, paths in by_vendor.items():
        # Only process MDE and Splunk vendors
        if v.lower() not in ["mde", "splunk"]:
            print(f"GenAI: Skipping vendor '{v}' as it's not MDE or Splunk")
            continue

        if len(paths) < 2:
            print(
                f"GenAI: Vendor '{v}' has only {len(paths)} file(s), skipping intra-vendor correlations"
            )
            continue

        # Calculate potential number of pairs
        potential_pairs = len(paths) * (len(paths) - 1) // 2
        print(f"GenAI: Vendor '{v}' has {len(paths)} files, potentially {potential_pairs} pairs")

        # Limit the number of pairs to avoid performance issues
        if potential_pairs > MAX_PAIRS_PER_VENDOR:
            print(
                f"GenAI: Limiting {v} to {MAX_PAIRS_PER_VENDOR} pairs (from potential {potential_pairs})"
            )
            # Limit by taking only the first N files
            max_files = int(math.sqrt(MAX_PAIRS_PER_VENDOR * 2)) + 1
            paths = paths[:max_files]
            print(f"GenAI: Limited to first {len(paths)} files")
            potential_pairs = len(paths) * (len(paths) - 1) // 2

        # Send progress update at start of each vendor
        print(f"GenAI: Starting vendor '{v}' - {cumulative_count} pairs completed so far")
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
        for i in range(len(paths)):
            for j in range(i + 1, len(paths)):
                path_a = paths[i]
                path_b = paths[j]

                # Increment pairs_evaluated for every pair we look at
                pairs_evaluated += 1
                cumulative_count += 1

                # Get queries from our file_info lookup
                query_a = file_info.get(path_a, {}).get("query", "")
                query_b = file_info.get(path_b, {}).get("query", "")

                # Clean up queries - remove leading "|\n  " if present
                if query_a and query_a.startswith("|\n"):
                    query_a = query_a[2:].lstrip()
                if query_b and query_b.startswith("|\n"):
                    query_b = query_b[2:].lstrip()

                # Detect if these are Splunk queries by checking for index=
                detected_vendor = v.lower()
                if query_a.lstrip().startswith("index=") or query_b.lstrip().startswith("index="):
                    detected_vendor = "splunk"
                elif query_a.lstrip().startswith("Device") or query_b.lstrip().startswith("Device"):
                    detected_vendor = "mde"

                # Filter out queries with only generic terms
                skip_pair = False
                if _has_only_generic_terms(query_a) or _has_only_generic_terms(query_b):
                    skip_pair = True

                # Filter out identical queries (normalizing whitespace for comparison)
                if not skip_pair:
                    # Normalize whitespace and compare
                    normalized_a = " ".join(query_a.split())
                    normalized_b = " ".join(query_b.split())
                    if normalized_a == normalized_b:
                        skip_pair = True

                # KQL-only filter: require semantic overlap > 50% to include result
                if not skip_pair and detected_vendor in ["mde", "microsoft", "sentinel", "kql"]:
                    ov = _estimate_semantic_overlap_kql(query_a, query_b)
                    if ov <= 50:
                        skip_pair = True

                # Update progress periodically with cumulative count (every 10 pairs evaluated)
                if cumulative_count % 10 == 0:
                    print(
                        f"GenAI: Evaluated {cumulative_count} pairs total ({count} kept for vendor '{v}')"
                    )
                    write_progress(
                        group_name,
                        {
                            "status": "genai_processing",
                            "total_pairs": total_pairs_all_vendors,
                            "processed": cumulative_count,
                        },
                    )

                # Skip pair if filtered out
                if skip_pair:
                    continue

                # Generate combined query
                combined_query = _combine_queries(detected_vendor, query_a, query_b, path_a, path_b)

                vendor_corr.append(
                    {
                        "vendor": detected_vendor,
                        "a": path_a,
                        "b": path_b,
                        "query_a": query_a,
                        "query_b": query_b,
                        "combined_query": combined_query,
                    }
                )
                count += 1

        print(f"GenAI: Generated {count} pairs for vendor '{v}'")

    print(f"GenAI: Total correlations before filtering: {len(vendor_corr)}")

    # Score and filter correlations to keep 10% per vendor based on detection count
    if vendor_corr:
        # Separate correlations by vendor
        by_vendor_corr = {}
        for corr in vendor_corr:
            vendor = corr.get("vendor", "unknown")
            if vendor not in by_vendor_corr:
                by_vendor_corr[vendor] = []
            by_vendor_corr[vendor].append(corr)

        # Filter each vendor separately to get top 10% (minimum 10)
        filtered_corr = []
        for vendor, corrs in by_vendor_corr.items():
            # Count detection files for this vendor
            vendor_detection_count = len(by_vendor.get(vendor, []))

            print(
                f"GenAI: Vendor '{vendor}' has {vendor_detection_count} detections, filtering {len(corrs)} correlations by 50% relevance threshold"
            )
            top_vendor_corrs = _score_and_filter_correlations(
                corrs, file_info, min_relevance=0.5
            )
            print(f"GenAI: Kept {len(top_vendor_corrs)} correlations for vendor '{vendor}'")
            filtered_corr.extend(top_vendor_corrs)

        vendor_corr = filtered_corr
        print(f"GenAI: Total filtered correlations across all vendors: {len(vendor_corr)}")

    # Send final progress update with complete count
    write_progress(
        group_name,
        {
            "status": "genai_complete",
            "total_pairs": total_pairs_all_vendors,
            "processed": cumulative_count,
        },
    )
    print(f"GenAI: Completed processing {cumulative_count} total pairs across all vendors")

    # No cross-vendor correlations - explicitly create an empty list
    cross_corr = []
    print(f"GenAI: Cross-vendor correlations disabled")

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
        print(f"GenAI: Wrote correlation results to {out_path}")
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
  | transaction properties.DeviceName maxspan=1h
  | search pattern_a="true" AND pattern_b="true"
  | stats count AS event_count, min(_time) AS first_seen, max(_time) AS last_seen, values(properties.FileName) AS file_names, values(properties.ProcessCommandLine) AS command_lines, values(properties.AccountName) AS accounts BY properties.DeviceName
  | eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
  | where event_count >= 2
  | sort - event_count"""

        return _collapse_double_newlines(combined)

    # Handle MDE/KQL queries
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
        yaml_dir: Directory containing YAML files (default: data/generate)
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

    print(f"Scanning YAML files in {yaml_dir}...")
    import time

    time.sleep(0.5)

    # Step 1: Read all YAML files and extract metadata
    yaml_files = [
        os.path.join(yaml_dir, f) for f in os.listdir(yaml_dir) if f.endswith((".yaml", ".yml"))
    ]

    print(f"Found {len(yaml_files)} YAML files")
    time.sleep(0.5)

    queries_data = []
    for yaml_path in yaml_files:
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "query" not in data:
                continue

            # Extract metadata
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
            }
            queries_data.append(query_info)

        except Exception as e:
            print(f"Error reading {yaml_path}: {e}")
            continue

    print(f"Successfully parsed {len(queries_data)} queries")
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
        print(f"Filtered to {len(filtered_queries)} queries for threat group '{threat_group}'")
        time.sleep(0.5)
        queries_data = filtered_queries

    # Step 2: Assess relevance and build correlation groups
    print("Assessing query relevance...")
    time.sleep(0.5)
    correlation_groups = _build_correlation_groups(queries_data, min_queries, max_queries)

    # Step 3: Build correlation searches
    print(f"Building {len(correlation_groups)} correlation searches...")
    time.sleep(0.5)
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

    print(f"Correlation queries saved to {output_file}")
    time.sleep(0.5)
    return output_data


def _detect_platform(yaml_data: Dict) -> str:
    """Detect the platform/vendor from YAML data."""
    connector_id = yaml_data.get("requiredDataConnectors", [{}])[0].get("connectorId", "")

    if connector_id == "MicrosoftThreatProtection":
        return "mde"
    elif connector_id == "Splunk":
        return "splunk"

    # Fallback: check query content
    query = yaml_data.get("query", "")
    if query.lstrip().startswith("index="):
        return "splunk"
    elif query.lstrip().startswith("Device"):
        return "mde"

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

            # Build correlations ensuring no duplicate tactics
            # Group queries by unique tactics
            used_queries = set()

            while len(platform_queries) >= min_queries:
                correlation_group = []
                used_tactics = set()

                for query in platform_queries:
                    query_id = query.get("id")
                    if query_id in used_queries:
                        continue

                    # Get tactics for this query
                    query_tactics = query.get("tactics", [])

                    # Check if this query's tactics overlap with already used tactics
                    if any(tactic in used_tactics for tactic in query_tactics):
                        continue

                    # Add query to correlation group
                    correlation_group.append(query)
                    used_tactics.update(query_tactics)
                    used_queries.add(query_id)

                    # Stop if we hit max_queries
                    if len(correlation_group) >= max_queries:
                        break

                # Only add if we meet minimum requirements
                if len(correlation_group) >= min_queries:
                    correlation_groups.append(correlation_group)
                    # Remove used queries from pool
                    platform_queries = [
                        q for q in platform_queries if q.get("id") not in used_queries
                    ]
                else:
                    # Can't build more correlations
                    break

    return correlation_groups


def _build_correlation_search(queries: List[Dict], correlation_id: int) -> Dict:
    """
    Build a correlation search from multiple queries and summarize results.
    """
    if not queries:
        return {}

    # Determine platform
    platform = queries[0].get("platform", "unknown")

    # Collect metadata
    all_tags = set()
    all_tactics = set()
    all_names = []

    for q in queries:
        all_tags.update(q.get("tags", []))
        all_tactics.update(q.get("tactics", []))
        all_names.append(q.get("name", "Unknown"))

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

    return {
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

    # Build correlation using transaction to find devices where ALL patterns occur
    combined = f"""index={index} earliest=-1d
  {' OR '.join(search_conditions)}
{''.join(eval_statements)}
  | transaction properties.DeviceName maxspan=1h
  | search {' AND '.join(search_filters)}
  | stats count AS event_count, min(_time) AS first_seen, max(_time) AS last_seen, values(properties.FileName) AS file_names, values(properties.ProcessCommandLine) AS command_lines, values(properties.AccountName) AS accounts BY properties.DeviceName
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

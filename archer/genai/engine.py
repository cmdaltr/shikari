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
from typing import List, Dict, Tuple, Optional
from ..build.progress import write_progress

# Global generation mode; set in generate_correlations
_GEN_MODE: str = "heuristic"

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
        elif (
            "kql" in name or "mde" in name or "microsoft" in name or "sentinel" in name
        ):
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


def _combine_queries(
    vendor: str, query_a: str, query_b: str, a: str = None, b: str = None
) -> str:
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
            os.path.basename(a)
            .replace("_microsoft_defender.yaml", "")
            .replace(".yaml", "")
            if a and isinstance(a, str)
            else "Query A"
        )
        source_b = (
            os.path.basename(b)
            .replace("_microsoft_defender.yaml", "")
            .replace(".yaml", "")
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


def generate_correlations(
    group_name: str, yaml_dir: str, progress_prefix: str = "genai"
) -> Dict:
    """
    Scan YAMLs and produce vendor correlations (cross-vendor correlations disabled).
    - vendor_correlations: list of dicts where multiple queries from same vendor are paired
    - cross_vendor_correlations: empty list (disabled)

    Progress updates are written using `write_progress` with keys under the
    provided `group_name` progress JSON.
    """
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


def process_genai(group_name: str):
    """
    Main entry point for GenAI processing that can be called from other modules.
    This function is the primary hook for correlation generation from app.py.

    Args:
        group_name: The group name to process
    """
    print(f"process_genai called for group {group_name}")
    yaml_dir = os.path.join("data", "generate")
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

    # Generate vendor correlations (files from same vendor)
    vendor_corr = []
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
        print(
            f"GenAI: Vendor '{v}' has {len(paths)} files, potentially {potential_pairs} pairs"
        )

        # Limit the number of pairs to avoid performance issues
        MAX_PAIRS_PER_VENDOR = 10000
        if potential_pairs > MAX_PAIRS_PER_VENDOR:
            print(
                f"GenAI: Limiting {v} to {MAX_PAIRS_PER_VENDOR} pairs (from potential {potential_pairs})"
            )
            # Limit by taking only the first N files
            max_files = int(math.sqrt(MAX_PAIRS_PER_VENDOR * 2)) + 1
            paths = paths[:max_files]
            print(f"GenAI: Limited to first {len(paths)} files")

        # Generate pairs using combinatorial approach
        count = 0
        for i in range(len(paths)):
            for j in range(i + 1, len(paths)):
                path_a = paths[i]
                path_b = paths[j]

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
                if query_a.lstrip().startswith("index=") or query_b.lstrip().startswith(
                    "index="
                ):
                    detected_vendor = "splunk"
                elif query_a.lstrip().startswith(
                    "Device"
                ) or query_b.lstrip().startswith("Device"):
                    detected_vendor = "mde"

                # KQL-only filter: require semantic overlap > 50% to include result
                if detected_vendor in ["mde", "microsoft", "sentinel", "kql"]:
                    ov = _estimate_semantic_overlap_kql(query_a, query_b)
                    if ov <= 50:
                        continue

                # Generate combined query
                combined_query = _combine_queries(
                    detected_vendor, query_a, query_b, path_a, path_b
                )

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

                # Update progress periodically
                if count % 10 == 0:
                    print(f"GenAI: Generated {count} pairs so far for vendor '{v}'")
                    write_progress(
                        group_name,
                        {"status": "genai_processing", "processed": count},
                    )

        print(f"GenAI: Generated {count} pairs for vendor '{v}'")

    # No cross-vendor correlations - explicitly create an empty list
    cross_corr = []
    print(f"GenAI: Cross-vendor correlations disabled")

    # Write results to correlation JSON file
    results = {
        "vendor_correlations": vendor_corr,
        "cross_vendor_correlations": cross_corr,  # Empty list
    }

    out_dir = os.path.join("data", "correlate")
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

        # Combine with simple OR
        combined = f"""index={index} earliest=-1d
  (({search_a}) OR ({search_b}))
  | stats count BY AccountName AccountUpn ActionType DeviceName FileName FolderPath ProcessCommandLine InitiatingProcessAccountName InitiatingProcessAccountUpn InitiatingProcessCommandLine InitiatingProcessFileName InitiatingProcessFolderPath InitiatingProcessParentFileName user user_HVT_Flags user_LanID user_active user_bunit user_category user_email user_employee_number user_first user_id user_identity user_last user_location user_locked_out user_managedBy user_nick user_org user_phone user_prefix user_startDate user_status user_supervisor_employee_number user_type user_watchlist user_work_city user_work_country"""

        return _collapse_double_newlines(combined)

    # Handle MDE/KQL queries
    elif vendor in ["mde", "microsoft", "sentinel", "kql"]:
        # Normalize labels
        label_a = (source_a or "Query A").strip()
        label_b = (source_b or "Query B").strip()

        # Normalize inner queries' pipe spacing first
        qa = _normalize_kql_spacing(query_a or "")
        qb = _normalize_kql_spacing(query_b or "")

        # Use three spaces before pipes in the tail, too
        combined_kql = f"""// {label_a}
let query_a = (
    {qa}
);
// {label_b}
let query_b = (
    {qb}
);
// Combined query
union query_a, query_b
   | where Timestamp > ago(1d)
   | project DeviceId, DeviceName, Timestamp, ProcessId, FileName, AccountName
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
    threat_group: str = None
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
        yaml_dir = os.path.join("data", "generate")
    if output_file is None:
        # Use group name in output file if specified
        if threat_group:
            safe_group_name = threat_group.replace(" ", "_").replace("(", "").replace(")", "")
            output_file = os.path.join("data", "correlate", f"{safe_group_name}.json")
        else:
            output_file = os.path.join("data", "correlate", "correlation_queries.json")

    print(f"Scanning YAML files in {yaml_dir}...")
    import time
    time.sleep(0.5)

    # Step 1: Read all YAML files and extract metadata
    yaml_files = [
        os.path.join(yaml_dir, f)
        for f in os.listdir(yaml_dir)
        if f.endswith(('.yaml', '.yml')) and f != 'latest.yaml'
    ]

    print(f"Found {len(yaml_files)} YAML files")
    time.sleep(0.5)

    queries_data = []
    for yaml_path in yaml_files:
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data or 'query' not in data:
                continue

            # Extract metadata
            query_info = {
                'id': data.get('id', os.path.basename(yaml_path)),
                'name': data.get('name', 'Unknown'),
                'description': data.get('description', ''),
                'severity': data.get('severity', 'Medium'),
                'tactics': data.get('tactics', []),
                'tags': data.get('tags', []),
                'platform': _detect_platform(data),
                'connector_id': data.get('requiredDataConnectors', [{}])[0].get('connectorId', 'Unknown'),
                'query': data.get('query', ''),
                'file_path': yaml_path,
                'metadata': data.get('metadata', {}),
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
            q for q in queries_data
            if any(threat_group_lower in tag.lower() for tag in q.get('tags', []) if tag and isinstance(tag, str))
        ]
        if len(filtered_queries) == 0:
            print(f"\n❌ No queries found for threat group '{threat_group}'")
            return {
                'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_queries_analyzed': 0,
                'total_correlations': 0,
                'min_queries_per_correlation': min_queries,
                'max_queries_per_correlation': max_queries,
                'threat_group': threat_group,
                'output_file': output_file,
                'correlations': [],
                'query_inventory': []
            }
        elif len(filtered_queries) == 1:
            print(f"\n❌ Only 1 query found for threat group '{threat_group}' - need at least {min_queries} for correlation")
            return {
                'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_queries_analyzed': 1,
                'total_correlations': 0,
                'min_queries_per_correlation': min_queries,
                'max_queries_per_correlation': max_queries,
                'threat_group': threat_group,
                'output_file': output_file,
                'correlations': [],
                'query_inventory': filtered_queries
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
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_queries_analyzed': len(queries_data),
        'total_correlations': len(correlations),
        'min_queries_per_correlation': min_queries,
        'output_file': output_file,
        'correlations': correlations,
        'query_inventory': [
            {
                'id': q['id'],
                'name': q['name'],
                'platform': q['platform'],
                'tags': q['tags'],
                'tactics': q['tactics'],
                'severity': q['severity'],
            }
            for q in queries_data
        ]
    }

    # Step 5: Save to JSON file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)

    print(f"Correlation queries saved to {output_file}")
    time.sleep(0.5)
    return output_data


def _detect_platform(yaml_data: Dict) -> str:
    """Detect the platform/vendor from YAML data."""
    connector_id = yaml_data.get('requiredDataConnectors', [{}])[0].get('connectorId', '')

    if connector_id == 'MicrosoftThreatProtection':
        return 'mde'
    elif connector_id == 'Splunk':
        return 'splunk'

    # Fallback: check query content
    query = yaml_data.get('query', '')
    if query.lstrip().startswith('index='):
        return 'splunk'
    elif query.lstrip().startswith('Device'):
        return 'mde'

    return 'unknown'


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
    tags_a = set(query_a.get('tags', []))
    tags_b = set(query_b.get('tags', []))
    if tags_a and tags_b:
        tag_overlap = len(tags_a & tags_b) / len(tags_a | tags_b)
        score += tag_overlap * 0.4

    # 2. Platform compatibility (20% weight)
    if query_a.get('platform') == query_b.get('platform'):
        score += 0.2

    # 3. Related attack paths/tactics (30% weight)
    tactics_a = set(query_a.get('tactics', []))
    tactics_b = set(query_b.get('tactics', []))
    if tactics_a and tactics_b:
        tactic_overlap = len(tactics_a & tactics_b) / len(tactics_a | tactics_b)
        score += tactic_overlap * 0.3

    # 4. Severity alignment (10% weight)
    severity_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
    sev_a = severity_map.get(query_a.get('severity', 'Medium'), 2)
    sev_b = severity_map.get(query_b.get('severity', 'Medium'), 2)
    severity_diff = abs(sev_a - sev_b)
    severity_score = max(0, 1 - (severity_diff / 3))  # Normalize 0-1
    score += severity_score * 0.1

    return score


def _build_correlation_groups(queries: List[Dict], min_queries: int, max_queries: int = 5) -> List[List[Dict]]:
    """
    Group queries into correlation sets based on relevance scores.
    Each group contains queries that are highly related.
    Ensures no duplicate tactics in a correlation.
    """
    from collections import defaultdict

    # Group by shared tags (threat groups)
    groups_by_tag = defaultdict(list)
    for query in queries:
        for tag in query.get('tags', []):
            groups_by_tag[tag].append(query)

    # Build correlation groups
    correlation_groups = []

    for tag, tag_queries in groups_by_tag.items():
        if len(tag_queries) < min_queries:
            continue

        # Further group by platform within each tag
        platform_groups = defaultdict(list)
        for query in tag_queries:
            platform_groups[query['platform']].append(query)

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
                    query_id = query.get('id')
                    if query_id in used_queries:
                        continue

                    # Get tactics for this query
                    query_tactics = query.get('tactics', [])

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
                    platform_queries = [q for q in platform_queries if q.get('id') not in used_queries]
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
    platform = queries[0].get('platform', 'unknown')

    # Collect metadata
    all_tags = set()
    all_tactics = set()
    all_names = []

    for q in queries:
        all_tags.update(q.get('tags', []))
        all_tactics.update(q.get('tactics', []))
        all_names.append(q.get('name', 'Unknown'))

    # Build combined query based on platform
    if platform == 'mde':
        combined_query = _combine_mde_queries([q['query'] for q in queries])
    elif platform == 'splunk':
        combined_query = _combine_splunk_queries_simple([q['query'] for q in queries])
    else:
        combined_query = "// Unsupported platform for correlation"

    # Generate summary
    summary = _generate_correlation_summary(queries, all_tags, all_tactics)

    # Filter out None values before sorting
    clean_tags = sorted([t for t in all_tags if t is not None])
    clean_tactics = sorted([t for t in all_tactics if t is not None])

    return {
        'correlation_id': f"CORR-{correlation_id:04d}",
        'name': f"Correlation: {' + '.join(all_names[:3])}{'...' if len(all_names) > 3 else ''}",
        'summary': summary,
        'platform': platform,
        'threat_groups': clean_tags,
        'tactics': clean_tactics,
        'query_count': len(queries),
        'queries_included': [
            {
                'id': q['id'],
                'name': q['name'],
                'file': os.path.basename(q['file_path'])
            }
            for q in queries
        ],
        'combined_query': combined_query,
        'relevance_scores': [
            {
                'query_pair': f"{queries[i]['name']} <-> {queries[j]['name']}",
                'score': round(_calculate_relevance_score(queries[i], queries[j]), 3)
            }
            for i in range(len(queries))
            for j in range(i + 1, min(i + 3, len(queries)))  # Limit pairs for readability
        ]
    }


def _combine_mde_queries(query_list: List[str]) -> str:
    """Combine multiple MDE/KQL queries into a single correlation search."""
    combined_parts = []

    for idx, query in enumerate(query_list, 1):
        query_clean = _normalize_kql_spacing(query.strip())
        combined_parts.append(f"""// Query {idx}
let query_{idx} = (
    {query_clean}
);""")

    # Union all queries
    union_clause = "union " + ", ".join([f"query_{i}" for i in range(1, len(query_list) + 1)])

    combined = "\n\n".join(combined_parts)
    combined += f"\n\n// Correlation search combining {len(query_list)} queries\n{union_clause}"
    combined += "\n   | where Timestamp > ago(1d)"
    combined += "\n   | summarize CorrelationCount=count() by DeviceId, DeviceName, Timestamp, AccountName"
    combined += "\n   | where CorrelationCount >= 2  // At least 2 different detection patterns matched"

    return combined


def _combine_splunk_queries_simple(query_list: List[str]) -> str:
    """Combine multiple Splunk queries into a single correlation search."""
    # Extract index from first query
    index_match = re.search(r'index\s*=\s*(\w+)', query_list[0])
    index = index_match.group(1) if index_match else 'edr_events'

    search_conditions = []
    for idx, query in enumerate(query_list, 1):
        # Extract search condition (remove index= and table commands)
        search = query.strip()
        search = re.sub(r'index\s*=\s*\w+\s*earliest=[^\n]*\n', '', search)
        search = re.sub(r'\|\s*table\s+.*$', '', search, flags=re.MULTILINE).strip()
        if search:
            search_conditions.append(f"({search})")

    combined = f"""index={index} earliest=-1d
  ({' OR '.join(search_conditions)})
  | stats count as CorrelationCount, values(*) as * by AccountName, DeviceName, _time
  | where CorrelationCount >= 2
  | table _time, AccountName, DeviceName, CorrelationCount, ActionType, FileName, ProcessCommandLine"""

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

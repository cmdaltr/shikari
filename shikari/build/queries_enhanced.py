"""
Enhanced Query Builder with GenAI and Few-Shot Learning

This module enhances query generation by:
1. Using high-quality example queries from open source repositories
2. Injecting relevant examples into LLM prompts (few-shot learning)
3. Respecting organizational field schemas (schemaSplunk.json, schemaMDE.json)
4. Fallback to template-based generation if GenAI is unavailable

To enable enhanced generation, set environment variable:
    SHIKARI_ENHANCED_QUERIES=true
"""

import os
from typing import List, Dict, Optional

# Import base query generation functions
from .queries import (
    compile_mde_queries as _compile_mde_queries_basic,
    compile_splunk_queries as _compile_splunk_queries_basic,
)

# Flag to enable/disable enhanced generation
ENHANCED_QUERIES_ENABLED = os.environ.get("SHIKARI_ENHANCED_QUERIES", "false").lower() in [
    "true",
    "1",
    "yes",
]


def _get_enhancer():
    """Lazy-load the query prompt enhancer."""
    try:
        from ..genai.query_prompt_enhancer import get_enhancer

        return get_enhancer()
    except ImportError as e:
        print(f"Warning: Could not load query enhancer: {e}")
        return None


def _get_llm_generator():
    """Lazy-load the LLM generator for query creation."""
    try:
        # Check if we have local LLM capability
        from ..genai.models import get_generator

        generator = get_generator(os.environ.get("GENAI_MODEL", "local"))
        return generator
    except ImportError:
        print("Warning: LLM generator not available, using template-based queries")
        return None


def compile_mde_queries_enhanced(
    indicator_mapping: Dict,
    indicators: List[str],
    indicator_type: str,
    mde_queries: List[str],
    technique_id: str = None,
    technique_name: str = None,
    technique_description: str = None,
    tactic: str = None,
) -> List[str]:
    """
    Compile MDE/KQL queries with GenAI enhancement.

    Args:
        indicator_mapping: Mapping of indicator types to tables and fields
        indicators: List of indicators to detect
        indicator_type: Type of indicator (cmd, reg, evt, sw)
        mde_queries: Existing queries list to append to
        technique_id: MITRE ATT&CK technique ID (for context)
        technique_name: Technique name (for context)
        technique_description: Technique description (for context)
        tactic: MITRE ATT&CK tactic (for context)

    Returns:
        List of MDE/KQL queries
    """
    # If enhancement disabled or no context provided, use basic generation
    if (
        not ENHANCED_QUERIES_ENABLED
        or not technique_id
        or not technique_name
        or not technique_description
    ):
        return _compile_mde_queries_basic(
            indicator_mapping, indicators, indicator_type, mde_queries
        )

    # Try enhanced generation
    enhancer = _get_enhancer()
    llm_generator = _get_llm_generator()

    if not enhancer or not llm_generator:
        # Fallback to basic generation
        return _compile_mde_queries_basic(
            indicator_mapping, indicators, indicator_type, mde_queries
        )

    # Generate enhanced prompt with examples
    try:
        prompt = enhancer.enhance_query_generation_prompt(
            technique_id=technique_id,
            technique_name=technique_name,
            technique_description=technique_description[:500],  # Limit description length
            vendor="mde",
            indicator_type=indicator_type,
            indicators=indicators,
            tactic=tactic,
            num_examples=2,  # Include 2 examples for few-shot learning
        )

        # Generate query using LLM
        print(
            f"    Using GenAI to generate KQL query for {technique_id} ({indicator_type})"
        )
        result = llm_generator.generate_query(prompt, vendor="mde")

        if result and "query" in result:
            generated_query = result["query"]

            # Validate the query has the expected structure
            if _validate_kql_query(generated_query):
                # Ensure proper table selection from indicator_mapping
                for table, fields in indicator_mapping[indicator_type]["MDE"].items():
                    # If the generated query uses this table, add it
                    if table in generated_query:
                        mde_queries.append(generated_query)
                        print(f"      ✓ Generated enhanced KQL query for {table}")
                        return mde_queries

                # If no specific table match, add the query anyway
                mde_queries.append(generated_query)
                print(f"      ✓ Generated enhanced KQL query")
                return mde_queries
            else:
                print(f"      ⚠ Generated query failed validation, using template")

    except Exception as e:
        print(f"      ⚠ Enhanced generation failed: {e}, using template")

    # Fallback to basic generation
    return _compile_mde_queries_basic(
        indicator_mapping, indicators, indicator_type, mde_queries
    )


def compile_splunk_queries_enhanced(
    indicator_mapping: Dict,
    indicators: List[str],
    indicator_type: str,
    splunk_queries: List[str],
    technique_id: str = None,
    technique_name: str = None,
    technique_description: str = None,
    tactic: str = None,
) -> List[str]:
    """
    Compile Splunk queries with GenAI enhancement.

    Args:
        indicator_mapping: Mapping of indicator types to indices and fields
        indicators: List of indicators to detect
        indicator_type: Type of indicator (cmd, reg, evt, sw)
        splunk_queries: Existing queries list to append to
        technique_id: MITRE ATT&CK technique ID (for context)
        technique_name: Technique name (for context)
        technique_description: Technique description (for context)
        tactic: MITRE ATT&CK tactic (for context)

    Returns:
        List of Splunk SPL queries
    """
    # If enhancement disabled or no context provided, use basic generation
    if (
        not ENHANCED_QUERIES_ENABLED
        or not technique_id
        or not technique_name
        or not technique_description
    ):
        return _compile_splunk_queries_basic(
            indicator_mapping, indicators, indicator_type, splunk_queries
        )

    # Try enhanced generation
    enhancer = _get_enhancer()
    llm_generator = _get_llm_generator()

    if not enhancer or not llm_generator:
        # Fallback to basic generation
        return _compile_splunk_queries_basic(
            indicator_mapping, indicators, indicator_type, splunk_queries
        )

    # Generate enhanced prompt with examples
    try:
        prompt = enhancer.enhance_query_generation_prompt(
            technique_id=technique_id,
            technique_name=technique_name,
            technique_description=technique_description[:500],
            vendor="splunk",
            indicator_type=indicator_type,
            indicators=indicators,
            tactic=tactic,
            num_examples=2,
        )

        # Generate query using LLM
        print(
            f"    Using GenAI to generate Splunk query for {technique_id} ({indicator_type})"
        )
        result = llm_generator.generate_query(prompt, vendor="splunk")

        if result and "query" in result:
            generated_query = result["query"]

            # Validate the query has the expected structure
            if _validate_splunk_query(generated_query):
                # Ensure proper index selection from indicator_mapping
                for index, fields in indicator_mapping[indicator_type]["Splunk"].items():
                    # If the generated query uses this index, add it
                    if index.replace("index=", "") in generated_query:
                        splunk_queries.append(generated_query)
                        print(f"      ✓ Generated enhanced Splunk query for {index}")
                        return splunk_queries

                # If no specific index match, add the query anyway
                splunk_queries.append(generated_query)
                print(f"      ✓ Generated enhanced Splunk query")
                return splunk_queries
            else:
                print(f"      ⚠ Generated query failed validation, using template")

    except Exception as e:
        print(f"      ⚠ Enhanced generation failed: {e}, using template")

    # Fallback to basic generation
    return _compile_splunk_queries_basic(
        indicator_mapping, indicators, indicator_type, splunk_queries
    )


def _validate_kql_query(query: str) -> bool:
    """
    Validate that a KQL query has the expected structure.

    Args:
        query: KQL query string

    Returns:
        True if valid, False otherwise
    """
    if not query or not isinstance(query, str):
        return False

    query_lower = query.lower().strip()

    # Must start with a Device table or contain union
    if not (
        query_lower.startswith("device")
        or query_lower.startswith("alert")
        or "union" in query_lower
    ):
        return False

    # Should have at least one where clause
    if "where" not in query_lower:
        return False

    # Should reference Timestamp or another time field
    if "timestamp" not in query_lower and "ago(" not in query_lower:
        return False

    return True


def _validate_splunk_query(query: str) -> bool:
    """
    Validate that a Splunk query has the expected structure.

    Args:
        query: Splunk SPL query string

    Returns:
        True if valid, False otherwise
    """
    if not query or not isinstance(query, str):
        return False

    query_lower = query.lower().strip()

    # Must start with index=
    if not query_lower.startswith("index="):
        return False

    # Should have a time window
    if "earliest=" not in query_lower:
        return False

    # Should have at least one search term or field filter
    if "=" not in query_lower[20:]:  # Skip the index= part
        return False

    return True


# Public API - use these functions instead of the basic ones
def compile_mde_queries(
    indicator_mapping: Dict,
    indicators: List[str],
    indicator_type: str,
    mde_queries: List[str],
    **kwargs,
) -> List[str]:
    """
    Compile MDE queries with automatic enhancement if enabled.

    Additional kwargs:
        technique_id, technique_name, technique_description, tactic
    """
    return compile_mde_queries_enhanced(
        indicator_mapping,
        indicators,
        indicator_type,
        mde_queries,
        technique_id=kwargs.get("technique_id"),
        technique_name=kwargs.get("technique_name"),
        technique_description=kwargs.get("technique_description"),
        tactic=kwargs.get("tactic"),
    )


def compile_splunk_queries(
    indicator_mapping: Dict,
    indicators: List[str],
    indicator_type: str,
    splunk_queries: List[str],
    **kwargs,
) -> List[str]:
    """
    Compile Splunk queries with automatic enhancement if enabled.

    Additional kwargs:
        technique_id, technique_name, technique_description, tactic
    """
    return compile_splunk_queries_enhanced(
        indicator_mapping,
        indicators,
        indicator_type,
        splunk_queries,
        technique_id=kwargs.get("technique_id"),
        technique_name=kwargs.get("technique_name"),
        technique_description=kwargs.get("technique_description"),
        tactic=kwargs.get("tactic"),
    )

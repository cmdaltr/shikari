"""
RAG-based Query Enhancement for Detection Generation

This module provides RAG (Retrieval-Augmented Generation) enhancement for
detection queries. It's called during the detection generation pipeline to
improve query quality using community examples.

Integration: Called from detections.py before construct_yaml()
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Global KB instance for reuse
_KB_INSTANCE = None
_KB_ENABLED = None


def is_rag_enabled() -> bool:
    """
    Check if RAG enhancement is enabled.

    Returns:
        True if RAG is enabled, False otherwise
    """
    global _KB_ENABLED

    # Cache the result
    if _KB_ENABLED is not None:
        return _KB_ENABLED

    # Check environment variable
    env_enabled = os.getenv('ENABLE_RAG', 'true').lower()
    if env_enabled in ['false', '0', 'no', 'off']:
        _KB_ENABLED = False
        return False

    # Check if KB is available
    try:
        from archer.ai.rag import DetectionKnowledgeBase

        kb = DetectionKnowledgeBase(auto_build=False)
        _KB_ENABLED = kb.is_available()

        if not _KB_ENABLED:
            print(" ℹ️  RAG enhancement disabled (knowledge base not available)")
            print("    Run: python scripts/config/build_embeddings.py")

        return _KB_ENABLED

    except Exception as e:
        print(f" ℹ️  RAG enhancement disabled ({e})")
        _KB_ENABLED = False
        return False


def get_knowledge_base():
    """
    Get or create the knowledge base instance.

    Returns:
        DetectionKnowledgeBase instance or None if not available
    """
    global _KB_INSTANCE

    if not is_rag_enabled():
        return None

    if _KB_INSTANCE is None:
        try:
            from archer.ai.rag import DetectionKnowledgeBase
            _KB_INSTANCE = DetectionKnowledgeBase(auto_build=False)
        except Exception as e:
            print(f" ⚠️  Failed to initialize knowledge base: {e}")
            return None

    return _KB_INSTANCE


def enhance_query_with_rag(
    original_query: str,
    technique_id: str,
    platform: str,
    technique_name: Optional[str] = None,
    min_fidelity: float = 0.7,
    top_k: int = 5
) -> Tuple[str, Dict]:
    """
    Enhance a detection query using RAG.

    Args:
        original_query: Original generated query
        technique_id: MITRE ATT&CK technique ID
        platform: Platform name (Splunk, MicrosoftThreatProtection, etc.)
        technique_name: Optional technique name for context
        min_fidelity: Minimum fidelity score for examples
        top_k: Number of examples to retrieve

    Returns:
        Tuple of (enhanced_query, enhancement_metadata)
    """
    kb = get_knowledge_base()

    if not kb:
        return original_query, {'enhanced': False, 'reason': 'KB not available'}

    try:
        # Find similar examples
        examples = kb.find_similar_detections(
            technique_id=technique_id,
            platform=platform,
            top_k=top_k,
            min_fidelity=min_fidelity
        )

        if not examples:
            return original_query, {
                'enhanced': False,
                'reason': 'No similar examples found',
                'technique_id': technique_id,
                'platform': platform
            }

        # Check if LLM is available
        llm_provider = os.getenv('RAG_LLM_PROVIDER', 'openai')
        if llm_provider == 'openai' and not os.getenv('OPENAI_API_KEY'):
            # No LLM available, return original with metadata about examples found
            return original_query, {
                'enhanced': False,
                'reason': 'LLM not configured',
                'examples_found': len(examples),
                'avg_fidelity': sum(e['detection'].get('fidelity_score', 0) for e in examples) / len(examples),
                'note': 'Set OPENAI_API_KEY to enable LLM enhancement'
            }

        # Enhance with LLM
        print(f" 🎯 RAG: Found {len(examples)} similar examples (avg fidelity: {sum(e['detection'].get('fidelity_score', 0) for e in examples) / len(examples):.2f})")
        print(f" 🤖 RAG: Enhancing query with {llm_provider}...")

        enhanced_query = kb.enhance_query_with_examples(
            original_query=original_query,
            examples=examples,
            llm_provider=llm_provider,
            technique_id=technique_id
        )

        if enhanced_query and enhanced_query != original_query:
            print(f" ✅ RAG: Query enhanced successfully")
            return enhanced_query, {
                'enhanced': True,
                'examples_used': len(examples),
                'llm_provider': llm_provider,
                'avg_example_fidelity': sum(e['detection'].get('fidelity_score', 0) for e in examples) / len(examples),
                'technique_id': technique_id,
                'platform': platform
            }
        else:
            return original_query, {
                'enhanced': False,
                'reason': 'LLM returned no changes',
                'examples_found': len(examples)
            }

    except Exception as e:
        print(f" ⚠️  RAG enhancement error: {e}")
        return original_query, {
            'enhanced': False,
            'reason': f'Error: {e}'
        }


def enhance_indicators_with_rag(
    identifiers: Dict,
    technique_id: str,
    platform: str,
    top_k: int = 3
) -> Tuple[Dict, Dict]:
    """
    Enhance indicators using RAG examples.

    This extracts additional indicators from similar high-quality detections.

    Args:
        identifiers: Current indicators dict
        technique_id: MITRE ATT&CK technique ID
        platform: Platform name
        top_k: Number of examples to retrieve

    Returns:
        Tuple of (enhanced_identifiers, metadata)
    """
    kb = get_knowledge_base()

    if not kb:
        return identifiers, {'enhanced': False}

    try:
        examples = kb.find_similar_detections(
            technique_id=technique_id,
            platform=platform,
            top_k=top_k,
            min_fidelity=0.8  # Higher threshold for indicator extraction
        )

        if not examples:
            return identifiers, {'enhanced': False, 'reason': 'No examples found'}

        # Extract indicators from examples
        additional_indicators = {}
        for example in examples:
            detection = example['detection']
            example_indicators = detection.get('indicators', [])

            # Parse indicators (format varies by source)
            if isinstance(example_indicators, list):
                for indicator in example_indicators:
                    if isinstance(indicator, dict):
                        ind_type = indicator.get('type', 'unknown')
                        ind_value = indicator.get('value') or indicator.get('values', [])

                        if ind_type not in additional_indicators:
                            additional_indicators[ind_type] = []

                        if isinstance(ind_value, list):
                            additional_indicators[ind_type].extend(ind_value)
                        else:
                            additional_indicators[ind_type].append(ind_value)

        if additional_indicators:
            # Merge with existing identifiers
            enhanced = identifiers.copy()
            for ind_type, values in additional_indicators.items():
                if ind_type in enhanced:
                    enhanced[ind_type].extend([v for v in values if v not in enhanced[ind_type]])
                else:
                    enhanced[ind_type] = values

            return enhanced, {
                'enhanced': True,
                'examples_used': len(examples),
                'indicators_added': sum(len(v) for v in additional_indicators.values())
            }

        return identifiers, {'enhanced': False, 'reason': 'No additional indicators found'}

    except Exception as e:
        print(f" ⚠️  RAG indicator enhancement error: {e}")
        return identifiers, {'enhanced': False, 'reason': f'Error: {e}'}


# For backward compatibility and easy import
__all__ = [
    'is_rag_enabled',
    'enhance_query_with_rag',
    'enhance_indicators_with_rag',
    'get_knowledge_base'
]

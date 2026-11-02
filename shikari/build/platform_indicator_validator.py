"""
Platform-Indicator Validation Module

This module validates that indicators are appropriate for the technique and platform
before generating detections. It prevents cross-platform contamination and ensures
semantic relevance of indicators.

Key Functions:
- validate_indicators_for_platform(): Check if indicators are valid for a platform
- validate_detection_before_generation(): Pre-generation validation
- get_valid_indicators(): Filter indicators to only valid ones for technique/platform
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
import logging
from shikari import paths

logger = logging.getLogger(__name__)


def load_validation_matrix() -> Dict:
    """Load the technique-platform-indicator validation matrix"""
    matrix_file = (
        paths.BESPOKE / "mappings" / "techniquePlatformIndicators.json"
    )

    if not matrix_file.exists():
        logger.warning(f"Validation matrix not found at {matrix_file}")
        return {}

    try:
        with open(matrix_file, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading validation matrix: {e}")
        return {}


# Load validation matrix once at module level
VALIDATION_MATRIX = load_validation_matrix()


def normalize_platform_name(platform: str) -> str:
    """
    Normalize platform names to match validation matrix keys

    Examples:
    - "windows" -> "Windows"
    - "azure_signin" -> "Azure AD"
    - "aws_cloudtrail" -> "AWS"
    """
    if not platform:
        return ""

    platform_lower = platform.lower()

    # Cloud platforms
    if "azure" in platform_lower and ("ad" in platform_lower or "activedirectory" in platform_lower):
        return "Azure AD"
    elif "azure" in platform_lower:
        return "Azure"
    elif "aws" in platform_lower:
        return "AWS"
    elif "gcp" in platform_lower or "google" in platform_lower:
        return "GCP"
    elif "office365" in platform_lower or "o365" in platform_lower:
        return "Office 365"
    elif "okta" in platform_lower:
        return "Okta"

    # OS platforms
    elif "windows" in platform_lower or "microsoft_windows" in platform_lower:
        return "Windows"
    elif "linux" in platform_lower or "unix" in platform_lower:
        return "Linux"
    elif "macos" in platform_lower or "darwin" in platform_lower:
        return "macOS"

    # Return capitalized version if no match
    return platform.capitalize()


def get_technique_validation_rules(technique_id: str) -> Optional[Dict]:
    """
    Get validation rules for a technique

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., T1136, T1136.001)

    Returns:
        Validation rules dict or None if not found
    """
    if not VALIDATION_MATRIX:
        return None

    # Try direct lookup
    if technique_id in VALIDATION_MATRIX:
        return VALIDATION_MATRIX[technique_id]

    # Try parent technique for sub-techniques
    if "." in technique_id:
        parent_id = technique_id.split(".")[0]
        if parent_id in VALIDATION_MATRIX:
            parent_rules = VALIDATION_MATRIX[parent_id]
            # Check if sub-technique exists
            sub_techniques = parent_rules.get("sub_techniques", {})
            if technique_id in sub_techniques:
                return {"sub_techniques": {technique_id: sub_techniques[technique_id]}}
            # Return parent rules if sub-technique not found
            return parent_rules

    return None


def validate_indicator_for_platform(
    indicator: str,
    indicator_type: str,
    platform: str,
    technique_id: str
) -> Tuple[bool, str]:
    """
    Validate a single indicator for a technique and platform

    Args:
        indicator: The indicator value (e.g., "net user", "wmic.exe")
        indicator_type: Type (cmd, evt, sw, api, operation, etc.)
        platform: Target platform (Windows, Linux, Azure AD, AWS, etc.)
        technique_id: MITRE ATT&CK technique ID

    Returns:
        Tuple of (is_valid, reason)
    """
    # Normalize platform name
    normalized_platform = normalize_platform_name(platform)

    # Get validation rules for technique
    rules = get_technique_validation_rules(technique_id)
    if not rules:
        # No rules = allow by default
        return True, "No validation rules found"

    # Navigate to the right sub-technique rules if applicable
    if "." in technique_id and "sub_techniques" in rules:
        sub_technique_rules = rules["sub_techniques"].get(technique_id, {})
        platform_rules = sub_technique_rules.get("platforms", {}).get(normalized_platform, {})
    else:
        # Parent technique or technique without sub-techniques
        platform_rules = rules.get("platforms", {}).get(normalized_platform, {})

    if not platform_rules:
        # No rules for this platform = allow
        return True, f"No validation rules for {normalized_platform}"

    # Check invalid indicators first (these are explicitly forbidden)
    invalid_indicators = platform_rules.get("invalid_indicators", {})
    invalid_list = invalid_indicators.get(indicator_type, [])
    indicator_lower = indicator.lower()

    for invalid_pattern in invalid_list:
        invalid_pattern_lower = invalid_pattern.lower()
        if invalid_pattern_lower in indicator_lower or indicator_lower in invalid_pattern_lower:
            reason = invalid_indicators.get("reason", "Invalid for this platform")
            return False, f"Invalid indicator: {reason}"

    # Check valid indicators (at least one pattern should match)
    valid_indicators = platform_rules.get("valid_indicators", {})
    valid_list = valid_indicators.get(indicator_type, [])

    if not valid_list:
        # No valid indicators defined for this type = allow
        return True, f"No valid indicator patterns defined for {indicator_type}"

    # Check if indicator matches any valid pattern
    for valid_pattern in valid_list:
        valid_pattern_lower = valid_pattern.lower()
        if valid_pattern_lower in indicator_lower or indicator_lower in valid_pattern_lower:
            return True, "Matches valid pattern"

    # Indicator doesn't match any valid pattern
    return False, f"Indicator doesn't match any valid patterns for {normalized_platform}"


def validate_indicators_for_platform(
    indicators: Dict[str, List[str]],
    platform: str,
    technique_id: str
) -> Tuple[bool, List[str], Dict[str, List[str]]]:
    """
    Validate all indicators for a technique and platform

    Args:
        indicators: Dict of {indicator_type: [indicator_values]}
        platform: Target platform
        technique_id: MITRE ATT&CK technique ID

    Returns:
        Tuple of (all_valid, error_messages, filtered_indicators)
        - all_valid: True if no invalid indicators found
        - error_messages: List of error messages for invalid indicators
        - filtered_indicators: Dict with only valid indicators
    """
    error_messages = []
    filtered_indicators = {}
    all_valid = True

    for indicator_type, indicator_list in indicators.items():
        valid_indicators_for_type = []

        for indicator in indicator_list:
            is_valid, reason = validate_indicator_for_platform(
                indicator,
                indicator_type,
                platform,
                technique_id
            )

            if is_valid:
                valid_indicators_for_type.append(indicator)
            else:
                all_valid = False
                error_msg = f"[{platform}] [{indicator_type}] '{indicator}': {reason}"
                error_messages.append(error_msg)

        if valid_indicators_for_type:
            filtered_indicators[indicator_type] = valid_indicators_for_type

    return all_valid, error_messages, filtered_indicators


def validate_detection_before_generation(
    technique_id: str,
    platform: str,
    data_source: str,
    indicators: Dict[str, List[str]],
    strict_mode: bool = False
) -> Tuple[bool, str, Dict[str, List[str]]]:
    """
    Validate that a detection makes sense before generating it

    Args:
        technique_id: MITRE ATT&CK technique ID
        platform: Target platform
        data_source: Data source name (e.g., "azure_signin")
        indicators: Dict of {indicator_type: [indicator_values]}
        strict_mode: If True, require at least one valid indicator

    Returns:
        Tuple of (should_generate, error_message, filtered_indicators)
        - should_generate: True if detection should be generated
        - error_message: Explanation if should_generate is False
        - filtered_indicators: Indicators with invalid ones removed
    """
    # Validate indicators
    all_valid, error_messages, filtered_indicators = validate_indicators_for_platform(
        indicators,
        platform,
        technique_id
    )

    # In strict mode, reject if ANY invalid indicators found
    if strict_mode and not all_valid:
        error_summary = f"Invalid indicators found:\n" + "\n".join(error_messages[:5])
        if len(error_messages) > 5:
            error_summary += f"\n... and {len(error_messages) - 5} more"
        return False, error_summary, filtered_indicators

    # In non-strict mode, only reject if NO valid indicators remain
    if not filtered_indicators:
        return False, f"No valid indicators for {technique_id} on {platform}", {}

    # Check if we have at least one valid indicator
    total_valid = sum(len(v) for v in filtered_indicators.values())
    if total_valid == 0:
        return False, f"No valid indicators for {technique_id} on {platform}", {}

    # Log warnings but allow generation
    if error_messages:
        logger.info(f"Filtered {len(error_messages)} invalid indicators for {technique_id} on {platform}")
        for msg in error_messages[:3]:  # Log first 3
            logger.debug(f"  - {msg}")

    return True, "", filtered_indicators


def get_valid_indicator_types_for_platform(platform: str, technique_id: str) -> Set[str]:
    """
    Get the set of valid indicator types for a technique on a platform

    Args:
        platform: Target platform
        technique_id: MITRE ATT&CK technique ID

    Returns:
        Set of valid indicator types (cmd, evt, sw, api, operation, etc.)
    """
    normalized_platform = normalize_platform_name(platform)
    rules = get_technique_validation_rules(technique_id)

    if not rules:
        return set()

    # Navigate to platform rules
    if "." in technique_id and "sub_techniques" in rules:
        sub_technique_rules = rules["sub_techniques"].get(technique_id, {})
        platform_rules = sub_technique_rules.get("platforms", {}).get(normalized_platform, {})
    else:
        platform_rules = rules.get("platforms", {}).get(normalized_platform, {})

    if not platform_rules:
        return set()

    # Get valid indicator types
    valid_indicators = platform_rules.get("valid_indicators", {})
    return set(valid_indicators.keys())


def is_cloud_platform(platform: str) -> bool:
    """Check if platform is a cloud platform (no command-line indicators)"""
    normalized = normalize_platform_name(platform)
    cloud_platforms = {"Azure AD", "Azure", "AWS", "GCP", "Office 365", "Okta", "SaaS"}
    return normalized in cloud_platforms

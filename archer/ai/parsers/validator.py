"""
Query validation utilities for Splunk SPL and KQL queries.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .splunk import validate_splunk_query
from .mde import validate_kql_query


class QueryValidator:
    """
    Validates detection queries across supported SIEM vendors.

    Supported vendors: "splunk", "mde", "sentinel", "kql"
    """

    VENDOR_ALIASES = {
        "splunk": "splunk",
        "spl": "splunk",
        "mde": "kql",
        "sentinel": "kql",
        "kql": "kql",
        "defender": "kql",
    }

    def validate(self, query: str, vendor: str) -> Tuple[bool, str]:
        """
        Validate a query string for the given vendor.

        Returns:
            (True, "") if valid
            (False, reason) if invalid
        """
        canonical = self.VENDOR_ALIASES.get(vendor.lower(), "unknown")

        if canonical == "splunk":
            return validate_splunk_query(query)
        elif canonical == "kql":
            return validate_kql_query(query)
        else:
            # Unknown vendor — return a soft pass with a note
            if not query or not query.strip():
                return False, "Query is empty"
            return True, ""

    def validate_all(
        self, queries: Dict[str, str]
    ) -> Dict[str, Tuple[bool, str]]:
        """
        Validate a dict of {vendor: query} pairs.

        Returns a dict of {vendor: (valid, reason)}.
        """
        return {
            vendor: self.validate(q, vendor)
            for vendor, q in queries.items()
        }

    def filter_valid(self, queries: Dict[str, str]) -> Dict[str, str]:
        """Return only the valid queries from a {vendor: query} dict."""
        return {
            vendor: q
            for vendor, q in queries.items()
            if self.validate(q, vendor)[0]
        }


def test_combined_query(
    combined: str,
    vendor: str,
    original_a: Optional[str] = None,
    original_b: Optional[str] = None,
) -> Dict:
    """
    Run a structural test on a combined query.

    Returns a result dict with keys:
        valid (bool), reason (str), warnings (list[str])
    """
    validator = QueryValidator()
    valid, reason = validator.validate(combined, vendor)

    warnings: List[str] = []

    if original_a and original_b:
        # Sanity: combined should be longer than either input
        if len(combined) < max(len(original_a), len(original_b)):
            warnings.append(
                "Combined query is shorter than one of the originals — "
                "part of the logic may have been dropped"
            )

    # Check for common combination artefacts
    if "| |" in combined:
        warnings.append("Double pipe detected in combined query")

    if vendor.lower() in ("splunk", "spl"):
        if combined.count("[") != combined.count("]"):
            warnings.append("Unbalanced subsearch brackets in combined query")

    return {
        "valid": valid,
        "reason": reason,
        "warnings": warnings,
    }

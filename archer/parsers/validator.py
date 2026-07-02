"""
Query validation and testing module.

This module provides functions to validate, test, and improve queries.
"""

import re
import json
import os
from typing import Dict, Tuple, List, Optional

from .splunk import validate_splunk_query
from .mde import validate_kql_query
from ..config import VALIDATION_CACHE_DIR


class QueryValidator:
    """Class for validating and testing queries."""
    
    def __init__(self, cache_dir: str = None):
        """
        Initialize the validator.
        
        Args:
            cache_dir: Directory to store validation cache
        """
        self.cache_dir = cache_dir or VALIDATION_CACHE_DIR
        os.makedirs(self.cache_dir, exist_ok=True)
        self._load_field_mappings()
    
    def _load_field_mappings(self):
        """Load field mappings for different platforms."""
        self.field_mappings = {
            "splunk": set(),
            "mde": set()
        }
        
        # Try to load field lists if they exist
        mapping_file = os.path.join(self.cache_dir, "field_mappings.json")
        if os.path.exists(mapping_file):
            try:
                with open(mapping_file, 'r') as f:
                    data = json.load(f)
                    for platform, fields in data.items():
                        self.field_mappings[platform] = set(fields)
            except Exception as e:
                print(f"Error loading field mappings: {e}")
    
    def validate_query(self, query: str, platform: str) -> Tuple[bool, str]:
        """
        Validate a query for the given platform.
        
        Args:
            query: The query string to validate
            platform: The query platform/vendor (splunk, mde)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not query or not isinstance(query, str):
            return False, "Query is empty or not a string"
            
        platform = platform.lower() if platform else ""
        
        if platform == "splunk" or query.lstrip().startswith("index="):
            return validate_splunk_query(query)
        elif platform in ["mde", "microsoft", "sentinel", "kql"] or query.lstrip().startswith("Device"):
            return validate_kql_query(query)
        else:
            return False, f"Unsupported platform: {platform}"
    
    def check_fields_exist(self, query: str, platform: str) -> Tuple[bool, List[str]]:
        """
        Check if fields used in the query exist in the platform schema.
        
        Args:
            query: The query string to check
            platform: The query platform/vendor
            
        Returns:
            Tuple of (all_fields_exist, unknown_fields)
        """
        platform = platform.lower() if platform else ""
        unknown_fields = []
        
        # Extract field names using regex
        field_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_\.]*)\b'
        potential_fields = set(re.findall(field_pattern, query))
        
        # Skip known keywords and operators
        skip_words = {
            "splunk": {"index", "source", "sourcetype", "host", "earliest", "latest", 
                      "stats", "table", "fields", "search", "where", "by", "as", 
                      "rename", "eval", "sort", "limit", "head", "tail", "top", "rare"},
            "mde": {"where", "project", "distinct", "summarize", "extend", "join", 
                   "union", "let", "ago", "and", "or", "not", "has", "contains", 
                   "startswith", "endswith", "has_any", "has_all", "count", "sum", 
                   "avg", "min", "max", "datetime_diff"}
        }
        
        if platform in skip_words:
            potential_fields -= skip_words[platform]
        
        # If we have known fields for this platform, check against them
        if platform in self.field_mappings and self.field_mappings[platform]:
            for field in potential_fields:
                if field not in self.field_mappings[platform]:
                    unknown_fields.append(field)
            
            return len(unknown_fields) == 0, unknown_fields
        
        # If no known fields, we can't validate
        return True, []
    
    def suggest_query_improvements(self, query: str, platform: str) -> Dict:
        """
        Suggest improvements for the query.
        
        Args:
            query: The query to improve
            platform: The query platform/vendor
            
        Returns:
            Dict with suggested improvements
        """
        platform = platform.lower() if platform else ""
        suggestions = []
        
        # Check query validity first
        is_valid, error_msg = self.validate_query(query, platform)
        if not is_valid:
            suggestions.append({
                "type": "error",
                "message": error_msg,
                "suggestion": "Fix the syntax error before proceeding"
            })
            return {"valid": False, "suggestions": suggestions}
        
        # Platform-specific suggestions
        if platform == "splunk" or query.lstrip().startswith("index="):
            if "index=*" in query:
                suggestions.append({
                    "type": "warning",
                    "message": "Using index=* can be inefficient",
                    "suggestion": "Specify only the indexes you need"
                })
                
            if not re.search(r'earliest\s*=', query):
                suggestions.append({
                    "type": "improvement",
                    "message": "No time range specified",
                    "suggestion": "Add 'earliest=-1d' to limit the query timeframe"
                })
                
        elif platform in ["mde", "microsoft", "sentinel", "kql"]:
            if not re.search(r'where\s+timestamp', query) and not re.search(r'ago\(', query):
                suggestions.append({
                    "type": "improvement",
                    "message": "No time filter found",
                    "suggestion": "Add 'where timestamp > ago(1d)' to limit the query timeframe"
                })
        
        # Check for wildcard usage
        if "*" in query and not re.search(r'"[^"]*\*[^"]*"', query) and not re.search(r"'[^']*\*[^']*'", query):
            suggestions.append({
                "type": "performance",
                "message": "Unquoted wildcard (*) found",
                "suggestion": "Consider using more specific filters instead of wildcards"
            })
        
        return {
            "valid": True,
            "suggestions": suggestions
        }


def test_combined_query(combined_query: str, platform: str) -> Dict:
    """
    Test a combined query for validity and potential issues.
    
    Args:
        combined_query: The combined query to test
        platform: The query platform/vendor
        
    Returns:
        Dict with test results
    """
    validator = QueryValidator()
    
    # Validate syntax
    is_valid, error_msg = validator.validate_query(combined_query, platform)
    
    # Check for field existence
    fields_exist, unknown_fields = validator.check_fields_exist(combined_query, platform)
    
    # Get improvement suggestions
    improvements = validator.suggest_query_improvements(combined_query, platform)
    
    return {
        "valid": is_valid,
        "error": error_msg if not is_valid else "",
        "unknown_fields": unknown_fields,
        "improvements": improvements.get("suggestions", []) if is_valid else []
    }

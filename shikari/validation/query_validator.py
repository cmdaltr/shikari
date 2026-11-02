"""
Query Validator

Validates detection query syntax and logic.
Platform-specific validation for Splunk, Elastic, KQL, etc.
"""

import re
from typing import Dict, List, Optional


class QueryValidator:
    """Validates detection query syntax and logic."""

    def __init__(self):
        """Initialize query validator."""
        self.validators = {
            'splunk': self._validate_splunk,
            'elastic': self._validate_elastic,
            'elasticsearch': self._validate_elastic,
            'kql': self._validate_kql,
            'microsoftthreatprotection': self._validate_kql,
            'microsoft defender': self._validate_kql,
        }

    def validate(self, query: str, platform: str) -> Dict:
        """
        Validate a detection query.

        Args:
            query: The detection query
            platform: Platform name

        Returns:
            Validation result dictionary with:
                - valid: Boolean indicating if query is valid
                - errors: List of error messages
                - warnings: List of warning messages
                - suggestions: List of improvement suggestions
        """
        platform_lower = platform.lower()

        # Get platform-specific validator
        validator = self.validators.get(platform_lower, self._validate_generic)

        # Run validation
        result = validator(query)

        # Add common validations
        result = self._add_common_validations(query, result)

        return result

    def _validate_splunk(self, query: str) -> Dict:
        """Validate Splunk SPL query."""
        errors = []
        warnings = []
        suggestions = []

        # Check for basic SPL syntax
        # 1. Unclosed quotes
        if query.count('"') % 2 != 0:
            errors.append("Unclosed double quotes detected")

        if query.count("'") % 2 != 0:
            errors.append("Unclosed single quotes detected")

        # 2. Unclosed parentheses
        if query.count('(') != query.count(')'):
            errors.append("Mismatched parentheses")

        # 3. Unclosed brackets
        if query.count('[') != query.count(']'):
            errors.append("Mismatched square brackets")

        # 4. Check for common SPL commands
        common_commands = ['search', 'where', 'stats', 'eval', 'table', 'fields', 'rex', 'rename']
        has_command = any(cmd in query.lower() for cmd in common_commands)

        if not has_command and not query.strip().startswith('index='):
            warnings.append("Query doesn't contain common SPL commands. Verify syntax.")

        # 5. Check for wildcard usage
        if '*' in query:
            if query.count('*') > 10:
                warnings.append("Excessive wildcard usage may impact performance")

        # 6. Check for time modifiers
        if 'earliest' not in query.lower() and 'latest' not in query.lower():
            suggestions.append("Consider adding time constraints (earliest/latest) for better performance")

        # 7. Check for potentially expensive operations
        expensive_ops = ['transaction', 'join', 'append', 'appendcols']
        for op in expensive_ops:
            if op in query.lower():
                warnings.append(f"'{op}' command can be resource-intensive. Consider alternatives if possible")

        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'suggestions': suggestions
        }

    def _validate_elastic(self, query: str) -> Dict:
        """Validate Elastic EQL/KQL query."""
        errors = []
        warnings = []
        suggestions = []

        # Check for basic syntax
        # 1. Unclosed quotes
        if query.count('"') % 2 != 0:
            errors.append("Unclosed double quotes detected")

        # 2. Unclosed parentheses/brackets
        if query.count('(') != query.count(')'):
            errors.append("Mismatched parentheses")

        if query.count('[') != query.count(']'):
            errors.append("Mismatched square brackets")

        if query.count('{') != query.count('}'):
            errors.append("Mismatched curly braces")

        # 3. Check for EQL keywords
        eql_keywords = ['where', 'and', 'or', 'not', 'sequence', 'join', 'until']
        has_eql = any(keyword in query.lower() for keyword in eql_keywords)

        # 4. Check for field syntax (field:value or field.keyword)
        has_field_syntax = ':' in query or '.' in query

        if not has_eql and not has_field_syntax:
            warnings.append("Query may not be valid EQL/KQL syntax")

        # 5. Check for wildcard usage
        if '*' in query and query.count('*') > 15:
            warnings.append("Excessive wildcard usage may impact performance")

        # 6. Suggest using .keyword for exact matches
        if '=' in query and '.keyword' not in query:
            suggestions.append("Consider using .keyword suffix for exact string matches")

        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'suggestions': suggestions
        }

    def _validate_kql(self, query: str) -> Dict:
        """Validate KQL (Kusto Query Language) query."""
        errors = []
        warnings = []
        suggestions = []

        # Check for basic KQL syntax
        # 1. Unclosed quotes
        if query.count('"') % 2 != 0:
            errors.append("Unclosed double quotes detected")

        if query.count("'") % 2 != 0:
            errors.append("Unclosed single quotes detected")

        # 2. Unclosed parentheses
        if query.count('(') != query.count(')'):
            errors.append("Mismatched parentheses")

        # 3. Check for KQL operators
        kql_operators = ['where', 'project', 'extend', 'summarize', 'join', 'union']
        has_operator = any(op in query.lower() for op in kql_operators)

        # 4. Check for table name (KQL queries typically start with table name)
        lines = query.strip().split('\n')
        first_line = lines[0].strip() if lines else ''

        if first_line and not has_operator and not first_line[0].isupper():
            warnings.append("KQL queries typically start with a table name (e.g., 'DeviceProcessEvents')")

        # 5. Check for piping
        if '|' not in query:
            suggestions.append("Consider using pipes (|) to chain KQL operators")

        # 6. Check for time filters
        time_operators = ['timestamp', 'ago(', 'startofday', 'endofday']
        has_time_filter = any(op in query.lower() for op in time_operators)

        if not has_time_filter:
            suggestions.append("Consider adding time filters for better performance")

        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'suggestions': suggestions
        }

    def _validate_generic(self, query: str) -> Dict:
        """Generic query validation for unknown platforms."""
        errors = []
        warnings = []
        suggestions = []

        # Basic syntax checks
        if query.count('"') % 2 != 0:
            errors.append("Unclosed double quotes detected")

        if query.count('(') != query.count(')'):
            errors.append("Mismatched parentheses")

        if len(query.strip()) == 0:
            errors.append("Query is empty")

        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'suggestions': suggestions
        }

    def _add_common_validations(self, query: str, result: Dict) -> Dict:
        """Add common validations applicable to all platforms."""
        # Check query length
        if len(query) < 10:
            result['warnings'].append("Query is very short. Verify it's complete.")

        if len(query) > 5000:
            result['warnings'].append("Query is very long. Consider breaking it down for maintainability.")

        # Check for SQL injection patterns (if query uses dynamic values)
        sql_injection_patterns = [
            r';\s*drop\s+table',
            r';\s*delete\s+from',
            r'union\s+select',
            r'exec\s*\(',
            r'execute\s*\('
        ]

        for pattern in sql_injection_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                result['warnings'].append("Query contains patterns similar to SQL injection. Verify intent.")

        # Check for hardcoded credentials
        cred_patterns = [
            r'password\s*=\s*["\']?\w+',
            r'api[_-]?key\s*=\s*["\']?\w+',
            r'secret\s*=\s*["\']?\w+'
        ]

        for pattern in cred_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                result['errors'].append("Query contains what appears to be hardcoded credentials. Remove sensitive data.")

        # Check for excessive OR conditions (potential performance issue)
        or_count = len(re.findall(r'\bOR\b', query, re.IGNORECASE))
        if or_count > 20:
            result['warnings'].append(f"Query has {or_count} OR conditions. This may impact performance.")

        # Check for comments (ensure they're intentional)
        if '//' in query or '/*' in query or '--' in query:
            result['suggestions'].append("Query contains comments. Ensure they're intentional and well-documented.")

        return result

    def check_logic(self, query: str, platform: str) -> Dict:
        """
        Check query logic for potential issues.

        Args:
            query: The detection query
            platform: Platform name

        Returns:
            Logic validation result with warnings about:
                - Contradictory conditions
                - Always-true conditions
                - Always-false conditions
        """
        warnings = []

        # Check for contradictory AND conditions
        # e.g., field=value1 AND field=value2 (where value1 != value2)
        and_conditions = re.findall(r'(\w+)\s*=\s*"?(\w+)"?\s+AND\s+\1\s*=\s*"?(\w+)"?', query, re.IGNORECASE)

        for field, val1, val2 in and_conditions:
            if val1 != val2:
                warnings.append(
                    f"Contradictory condition: {field}={val1} AND {field}={val2}. "
                    f"This will never match."
                )

        # Check for redundant OR conditions
        # e.g., field=value OR field=value
        or_conditions = re.findall(r'(\w+\s*=\s*"?\w+"?)\s+OR\s+\1', query, re.IGNORECASE)
        if or_conditions:
            warnings.append("Redundant OR conditions detected. Simplify query.")

        # Check for NOT NOT (double negation)
        if re.search(r'NOT\s+NOT', query, re.IGNORECASE):
            warnings.append("Double negation (NOT NOT) detected. Simplify logic.")

        return {
            'has_issues': len(warnings) > 0,
            'warnings': warnings
        }

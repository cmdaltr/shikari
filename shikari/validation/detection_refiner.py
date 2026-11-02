"""
Detection Refiner

Uses LLM to analyze detection failures and suggest query improvements.
Provides iterative refinement until detection achieves desired accuracy.
"""

import logging
import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from .detection_tester import ValidationResult, FailureAnalysis

logger = logging.getLogger(__name__)


class RefinementType(Enum):
    """Types of query refinements"""
    FIELD_FIX = "field_fix"           # Incorrect field name
    PATTERN_FIX = "pattern_fix"       # Pattern too specific/broad
    LOGIC_FIX = "logic_fix"           # AND/OR issues
    EXCLUSION_ADD = "exclusion_add"   # Add exclusion for FP
    SCOPE_ADJUST = "scope_adjust"     # Adjust query scope
    SYNTAX_FIX = "syntax_fix"         # Syntax errors


@dataclass
class RefinementSuggestion:
    """A suggested refinement to the detection query"""
    refinement_type: RefinementType
    description: str
    original_snippet: str
    suggested_snippet: str
    confidence: float  # 0.0 to 1.0
    explanation: str
    auto_applicable: bool = True  # Can be automatically applied

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "type": self.refinement_type.value,
            "description": self.description,
            "original": self.original_snippet,
            "suggested": self.suggested_snippet,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "auto_applicable": self.auto_applicable,
        }


class DetectionRefiner:
    """Uses LLM to suggest detection improvements"""

    # Vendor-specific field mappings for common fixes
    FIELD_MAPPINGS = {
        "splunk": {
            "CommandLine": ["process.command_line", "command_line", "cmdline"],
            "NewProcessName": ["process.executable", "process_name", "Image"],
            "ParentProcessName": ["parent.executable", "ParentImage"],
            "User": ["user.name", "username", "AccountName"],
        },
        "elastic": {
            "process.command_line": ["CommandLine", "cmdline", "command"],
            "process.name": ["FileName", "NewProcessName", "Image"],
            "process.executable": ["NewProcessName", "Image", "process_path"],
            "user.name": ["User", "AccountName", "username"],
        },
        "secops": {
            "target.process.command_line": ["CommandLine", "process.command_line"],
            "target.process.file.full_path": ["process.executable", "NewProcessName"],
            "principal.user.user_display_name": ["User", "user.name"],
        },
        "mde": {
            "ProcessCommandLine": ["CommandLine", "command_line", "cmdline"],
            "FileName": ["process.name", "NewProcessName", "Image"],
            "InitiatingProcessFileName": ["ParentProcessName", "parent.name"],
            "AccountName": ["User", "user.name", "username"],
        },
    }

    def __init__(self, llm_provider=None):
        """
        Initialize the refiner.

        Args:
            llm_provider: LLM provider for AI-assisted refinement
        """
        self.llm = llm_provider
        self._init_llm_if_needed()

    def _init_llm_if_needed(self):
        """Initialize default LLM provider if not provided"""
        if self.llm is None:
            try:
                from shikari.ai.llm.providers import LLMFactory
                import os
                if os.getenv("OPENAI_API_KEY"):
                    self.llm = LLMFactory.create("openai")
                elif os.getenv("ANTHROPIC_API_KEY"):
                    self.llm = LLMFactory.create("anthropic")
                elif os.getenv("GOOGLE_API_KEY"):
                    self.llm = LLMFactory.create("google")
            except Exception as e:
                logger.info(f"LLM not available for refinement: {e}")

    def suggest_refinements(
        self,
        original_query: str,
        vendor: str,
        failure_analysis: FailureAnalysis,
        sample_events: List[Dict],
        validation_result: ValidationResult,
    ) -> List[RefinementSuggestion]:
        """
        Generate query improvement suggestions based on failure analysis.

        Args:
            original_query: The original detection query
            vendor: SIEM vendor
            failure_analysis: Analysis of why detection failed
            sample_events: Sample events (for context)
            validation_result: The validation result

        Returns:
            List of refinement suggestions ordered by confidence
        """
        suggestions = []

        # Rule-based suggestions
        suggestions.extend(
            self._generate_rule_based_suggestions(
                original_query, vendor, failure_analysis, sample_events, validation_result
            )
        )

        # LLM-based suggestions
        if self.llm:
            llm_suggestions = self._generate_llm_suggestions(
                original_query, vendor, failure_analysis, sample_events, validation_result
            )
            suggestions.extend(llm_suggestions)

        # Sort by confidence
        suggestions.sort(key=lambda x: x.confidence, reverse=True)

        return suggestions

    def _generate_rule_based_suggestions(
        self,
        query: str,
        vendor: str,
        failure_analysis: FailureAnalysis,
        sample_events: List[Dict],
        result: ValidationResult,
    ) -> List[RefinementSuggestion]:
        """Generate suggestions based on rule-based analysis"""
        suggestions = []

        # Check for field name mismatches
        if failure_analysis.failure_type in ("NO_MATCHES", "PARTIAL_MATCH"):
            field_suggestions = self._check_field_names(query, vendor, sample_events)
            suggestions.extend(field_suggestions)

        # Check for pattern issues
        if result.false_negatives > 0:
            pattern_suggestions = self._check_patterns(query, vendor, result.missed_events)
            suggestions.extend(pattern_suggestions)

        # Check for false positive reduction
        if result.false_positives > 0:
            fp_suggestions = self._suggest_exclusions(query, vendor, result.false_positive_events)
            suggestions.extend(fp_suggestions)

        # Check for syntax issues
        syntax_suggestions = self._check_syntax(query, vendor)
        suggestions.extend(syntax_suggestions)

        return suggestions

    def _check_field_names(
        self,
        query: str,
        vendor: str,
        sample_events: List[Dict],
    ) -> List[RefinementSuggestion]:
        """Check for field name mismatches and suggest fixes"""
        suggestions = []

        if not sample_events:
            return suggestions

        # Get all field names from sample events
        event_fields = self._get_all_fields(sample_events[0])

        # Get field names used in query
        query_fields = self._extract_fields_from_query(query, vendor)

        # Check for mismatches
        mappings = self.FIELD_MAPPINGS.get(vendor, {})

        for query_field in query_fields:
            if query_field not in event_fields:
                # Try to find a matching field
                for event_field in event_fields:
                    # Check direct alternatives
                    for correct, alternatives in mappings.items():
                        if query_field.lower() in [a.lower() for a in alternatives]:
                            if correct in event_fields or event_field.lower() == correct.lower():
                                suggestions.append(RefinementSuggestion(
                                    refinement_type=RefinementType.FIELD_FIX,
                                    description=f"Field '{query_field}' may not exist",
                                    original_snippet=query_field,
                                    suggested_snippet=correct,
                                    confidence=0.85,
                                    explanation=f"The field '{query_field}' was not found in the events. "
                                              f"'{correct}' is the correct field name for {vendor}.",
                                ))
                                break

        return suggestions

    def _get_all_fields(self, obj: Dict, prefix: str = "") -> set:
        """Get all field names from a nested dict"""
        fields = set()
        for key, value in obj.items():
            full_key = f"{prefix}.{key}" if prefix else key
            fields.add(full_key)
            if isinstance(value, dict):
                fields.update(self._get_all_fields(value, full_key))
        return fields

    def _extract_fields_from_query(self, query: str, vendor: str) -> List[str]:
        """Extract field names used in a query"""
        fields = []

        if vendor == "splunk":
            # Match field= or field IN
            matches = re.findall(r'(\w+)\s*[=!<>]', query)
            fields.extend(matches)
        elif vendor == "elastic":
            # Match field: or field.subfield
            matches = re.findall(r'([a-z_][a-z0-9_.]*)\s*:', query, re.IGNORECASE)
            fields.extend(matches)
        elif vendor == "secops":
            # UDM fields: bare in a search (target.process...), $e.-prefixed in a join or rule
            from shikari.build.udm import _ROOTS

            matches = re.findall(r'(?<![\w.])(?:\$\w+\.)?((?:' + "|".join(_ROOTS) + r')\.[a-z_.]+)', query, re.IGNORECASE)
            fields.extend(matches)
        elif vendor == "mde":
            # Match field contains or field ==
            matches = re.findall(r'(\w+)\s+(?:contains|has|==|!=)', query, re.IGNORECASE)
            fields.extend(matches)

        return fields

    def _check_patterns(
        self,
        query: str,
        vendor: str,
        missed_events: List[Dict],
    ) -> List[RefinementSuggestion]:
        """Check if query patterns are too specific"""
        suggestions = []

        if not missed_events:
            return suggestions

        # Extract values from missed events
        for event in missed_events[:3]:  # Check first 3 missed events
            # Get command line or similar field
            cmd = None
            for field in ["ProcessCommandLine", "CommandLine", "command_line"]:
                cmd = self._get_nested_value(event, field)
                if cmd:
                    break

            if not cmd:
                cmd = str(self._get_nested_value(event, "process.command_line") or
                         self._get_nested_value(event, "target.process.command_line") or "")

            if cmd and len(cmd) > 10:
                # Look for this value (or parts of it) in the query
                # If not found, suggest adding it
                cmd_parts = cmd.lower().split()
                for part in cmd_parts:
                    if len(part) > 3 and part not in query.lower():
                        suggestions.append(RefinementSuggestion(
                            refinement_type=RefinementType.PATTERN_FIX,
                            description=f"Query may be missing pattern: '{part}'",
                            original_snippet="",
                            suggested_snippet=f"OR ... contains '{part}'",
                            confidence=0.6,
                            explanation=f"Missed events contain '{part}' which is not in the query. "
                                       "Consider adding this as an alternative pattern.",
                            auto_applicable=False,
                        ))
                        break

        return suggestions

    def _suggest_exclusions(
        self,
        query: str,
        vendor: str,
        false_positive_events: List[Dict],
    ) -> List[RefinementSuggestion]:
        """Suggest exclusions to reduce false positives"""
        suggestions = []

        if not false_positive_events:
            return suggestions

        # Find common patterns in false positives
        common_values = {}
        for event in false_positive_events:
            for field in ["FileName", "process.name", "NewProcessName"]:
                value = self._get_nested_value(event, field)
                if value:
                    value = value.lower()
                    common_values[value] = common_values.get(value, 0) + 1

        # Suggest exclusions for common FP patterns
        for value, count in common_values.items():
            if count >= 2 or count == len(false_positive_events):
                if vendor == "splunk":
                    exclusion = f' NOT (NewProcessName="*{value}*")'
                elif vendor == "elastic":
                    exclusion = f' and not process.name:"{value}"'
                elif vendor == "secops":
                    exclusion = f' and not target.process.file.full_path = /{re.escape(value).replace("/", chr(92) + "/")}/ nocase'
                elif vendor == "mde":
                    exclusion = f' and FileName !contains "{value}"'
                else:
                    exclusion = f"NOT {value}"

                suggestions.append(RefinementSuggestion(
                    refinement_type=RefinementType.EXCLUSION_ADD,
                    description=f"Exclude '{value}' to reduce false positives",
                    original_snippet="",
                    suggested_snippet=exclusion,
                    confidence=0.75,
                    explanation=f"'{value}' appears in {count} false positive events. "
                               f"Adding an exclusion will reduce noise.",
                ))

        return suggestions

    def _check_syntax(self, query: str, vendor: str) -> List[RefinementSuggestion]:
        """Check for common syntax issues"""
        suggestions = []

        if vendor == "splunk":
            # Check for common Splunk issues
            if '==' in query:
                suggestions.append(RefinementSuggestion(
                    refinement_type=RefinementType.SYNTAX_FIX,
                    description="Splunk uses single = for comparison, not ==",
                    original_snippet="==",
                    suggested_snippet="=",
                    confidence=0.9,
                    explanation="In SPL, use single equals sign for comparisons.",
                ))

        elif vendor == "elastic":
            # Check for Elastic issues
            if '"*' in query and '*"' in query:
                pass  # Wildcards are OK in some contexts
            if ': *' in query:
                suggestions.append(RefinementSuggestion(
                    refinement_type=RefinementType.SYNTAX_FIX,
                    description="Avoid space between : and wildcard",
                    original_snippet=": *",
                    suggested_snippet=":*",
                    confidence=0.8,
                    explanation="In Elasticsearch, wildcards should follow the colon directly.",
                ))

        elif vendor == "mde":
            # Check for MDE/KQL issues
            if '==' in query and 'contains' not in query.lower():
                pass  # == is valid in KQL
            if 'like' in query.lower():
                suggestions.append(RefinementSuggestion(
                    refinement_type=RefinementType.SYNTAX_FIX,
                    description="KQL uses 'matches regex' instead of 'like'",
                    original_snippet="like",
                    suggested_snippet="matches regex",
                    confidence=0.85,
                    explanation="MDE/KQL doesn't support 'like'. Use 'matches regex' or 'contains'.",
                ))

        return suggestions

    def _get_nested_value(self, obj: Dict, path: str) -> Any:
        """Get nested value using dot notation"""
        parts = path.split(".")
        current = obj
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
            if current is None:
                return None
        return current

    def _generate_llm_suggestions(
        self,
        query: str,
        vendor: str,
        failure_analysis: FailureAnalysis,
        sample_events: List[Dict],
        result: ValidationResult,
    ) -> List[RefinementSuggestion]:
        """Generate suggestions using LLM"""
        try:
            prompt = self._build_refinement_prompt(
                query, vendor, failure_analysis, sample_events, result
            )

            response = self.llm.generate(
                prompt=prompt,
                system_prompt=self._get_system_prompt(),
                temperature=0.3,  # Lower temperature for more focused suggestions
                max_tokens=2048,
            )

            return self._parse_llm_suggestions(response.content)

        except Exception as e:
            logger.warning(f"LLM refinement failed: {e}")
            return []

    def _get_system_prompt(self) -> str:
        """Get system prompt for LLM refinement"""
        return """You are a detection engineering expert specializing in SIEM query optimization.
Your task is to analyze failed detection queries and suggest specific improvements.

When suggesting refinements:
1. Be specific - provide exact code snippets
2. Explain why the change will help
3. Prioritize fixes that will have the biggest impact
4. Consider both false negatives and false positives

Output your suggestions as a JSON array with this structure:
[
  {
    "type": "field_fix|pattern_fix|logic_fix|exclusion_add|scope_adjust|syntax_fix",
    "description": "Brief description",
    "original": "Original snippet",
    "suggested": "Improved snippet",
    "confidence": 0.0-1.0,
    "explanation": "Why this helps"
  }
]"""

    def _build_refinement_prompt(
        self,
        query: str,
        vendor: str,
        failure_analysis: FailureAnalysis,
        sample_events: List[Dict],
        result: ValidationResult,
    ) -> str:
        """Build prompt for LLM refinement"""
        # Limit sample events for prompt size
        sample_str = json.dumps(sample_events[:2], indent=2) if sample_events else "No samples"

        return f"""Analyze this {vendor} detection query and suggest improvements:

## Original Query
```
{query}
```

## Failure Analysis
- Type: {failure_analysis.failure_type}
- Description: {failure_analysis.description}
- Potential causes: {', '.join(failure_analysis.potential_causes)}

## Validation Results
- True Positives: {result.true_positives}
- False Negatives: {result.false_negatives}
- False Positives: {result.false_positives}
- Precision: {result.precision:.2%}
- Recall: {result.recall:.2%}

## Sample Events (that should have matched)
```json
{sample_str}
```

Suggest specific query improvements. Output only valid JSON."""

    def _parse_llm_suggestions(self, response: str) -> List[RefinementSuggestion]:
        """Parse LLM response into suggestions"""
        try:
            # Find JSON in response
            json_match = re.search(r'\[[\s\S]*\]', response)
            if not json_match:
                return []

            data = json.loads(json_match.group())

            suggestions = []
            for item in data:
                try:
                    ref_type = RefinementType(item.get("type", "pattern_fix"))
                    suggestions.append(RefinementSuggestion(
                        refinement_type=ref_type,
                        description=item.get("description", ""),
                        original_snippet=item.get("original", ""),
                        suggested_snippet=item.get("suggested", ""),
                        confidence=float(item.get("confidence", 0.5)),
                        explanation=item.get("explanation", ""),
                    ))
                except (ValueError, KeyError) as e:
                    logger.debug(f"Skipping invalid suggestion: {e}")

            return suggestions

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM suggestions: {e}")
            return []

    def apply_refinement(
        self,
        query: str,
        suggestion: RefinementSuggestion,
    ) -> str:
        """
        Apply a refinement suggestion to a query.

        Args:
            query: Original query
            suggestion: Refinement to apply

        Returns:
            Modified query
        """
        if not suggestion.auto_applicable:
            logger.warning("Refinement not auto-applicable, returning original query")
            return query

        original = suggestion.original_snippet
        suggested = suggestion.suggested_snippet

        if original and original in query:
            # Simple replacement
            return query.replace(original, suggested, 1)
        elif suggestion.refinement_type == RefinementType.EXCLUSION_ADD:
            # Add exclusion at the end of query
            return query.rstrip() + " " + suggested
        else:
            # Cannot auto-apply
            logger.info(f"Could not auto-apply refinement: {suggestion.description}")
            return query

    def apply_all_refinements(
        self,
        query: str,
        suggestions: List[RefinementSuggestion],
        min_confidence: float = 0.7,
    ) -> str:
        """
        Apply all applicable refinements above confidence threshold.

        Args:
            query: Original query
            suggestions: List of refinements
            min_confidence: Minimum confidence to apply

        Returns:
            Modified query
        """
        modified = query

        for suggestion in suggestions:
            if suggestion.confidence >= min_confidence and suggestion.auto_applicable:
                modified = self.apply_refinement(modified, suggestion)

        return modified

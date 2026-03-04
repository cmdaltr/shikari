"""
Detection Tester

Tests detection queries against sample events and analyzes results.
Provides detailed feedback on detection effectiveness.
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ValidationStatus(Enum):
    """Status of a validation test"""
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    ERROR = "error"


@dataclass
class ValidationResult:
    """Result of a detection validation test"""
    status: ValidationStatus
    true_positives: int = 0      # Malicious events detected
    false_negatives: int = 0     # Malicious events missed
    false_positives: int = 0     # Benign events flagged
    true_negatives: int = 0      # Benign events correctly ignored
    execution_time_ms: float = 0
    error_message: Optional[str] = None
    suggestions: List[str] = field(default_factory=list)
    matched_events: List[Dict] = field(default_factory=list)
    missed_events: List[Dict] = field(default_factory=list)
    false_positive_events: List[Dict] = field(default_factory=list)
    query_error: Optional[str] = None
    raw_response: Optional[Dict] = None

    @property
    def passed(self) -> bool:
        """Check if validation passed"""
        return self.status == ValidationStatus.PASSED

    @property
    def precision(self) -> float:
        """Calculate precision (TP / (TP + FP))"""
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def recall(self) -> float:
        """Calculate recall (TP / (TP + FN))"""
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def f1_score(self) -> float:
        """Calculate F1 score"""
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "status": self.status.value,
            "passed": self.passed,
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1_score": round(self.f1_score, 3),
            "execution_time_ms": self.execution_time_ms,
            "error_message": self.error_message,
            "suggestions": self.suggestions,
            "query_error": self.query_error,
        }


@dataclass
class FailureAnalysis:
    """Detailed analysis of why a detection failed"""
    failure_type: str
    description: str
    affected_events: List[Dict[str, Any]]
    potential_causes: List[str]
    suggested_fixes: List[str]


class DetectionTester:
    """Tests detections against sample events"""

    def __init__(self, docker_manager=None):
        """
        Initialize detection tester.

        Args:
            docker_manager: DockerSIEMManager instance for executing queries
        """
        self.docker_manager = docker_manager

    def test_detection(
        self,
        query: str,
        vendor: str,
        session_id: str,
        malicious_events: List[Dict],
        benign_events: List[Dict],
    ) -> ValidationResult:
        """
        Test a detection query against sample events.

        Args:
            query: Detection query in vendor-specific syntax
            vendor: SIEM vendor (splunk, elastic, secops, mde)
            session_id: Validation session ID
            malicious_events: Events that SHOULD trigger the detection
            benign_events: Events that should NOT trigger the detection

        Returns:
            ValidationResult with detailed metrics
        """
        if not self.docker_manager:
            return ValidationResult(
                status=ValidationStatus.ERROR,
                error_message="No Docker manager configured. Cannot execute query.",
            )

        start_time = datetime.utcnow()

        try:
            # Clear any existing events
            self._clear_siem_events(session_id, vendor)

            # Ingest all events
            all_events = malicious_events + benign_events
            if not self.docker_manager.ingest_events(session_id, vendor, all_events):
                return ValidationResult(
                    status=ValidationStatus.ERROR,
                    error_message="Failed to ingest events into SIEM",
                )

            # Execute the query
            query_result = self.docker_manager.execute_query(session_id, vendor, query)

            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            if query_result.get("status") == "error":
                return ValidationResult(
                    status=ValidationStatus.ERROR,
                    error_message=f"Query execution failed: {query_result.get('error')}",
                    query_error=query_result.get("error"),
                    execution_time_ms=execution_time,
                )

            # Analyze results
            matched_events = query_result.get("results", [])

            return self._analyze_results(
                matched_events=matched_events,
                malicious_events=malicious_events,
                benign_events=benign_events,
                execution_time_ms=execution_time,
                raw_response=query_result,
            )

        except Exception as e:
            logger.error(f"Detection test error: {e}")
            return ValidationResult(
                status=ValidationStatus.ERROR,
                error_message=str(e),
            )

    def _clear_siem_events(self, session_id: str, vendor: str):
        """Clear existing events from the SIEM"""
        try:
            instance = self.docker_manager.active_instances.get(
                f"{vendor}_{session_id}"
            )
            if instance and vendor in ("secops", "mde"):
                import requests
                requests.post(f"{instance.get_api_url()}/api/clear", timeout=5)
        except Exception as e:
            logger.warning(f"Could not clear events: {e}")

    def _analyze_results(
        self,
        matched_events: List[Dict],
        malicious_events: List[Dict],
        benign_events: List[Dict],
        execution_time_ms: float,
        raw_response: Dict,
    ) -> ValidationResult:
        """Analyze query results against expected matches"""
        # Create fingerprints for matching
        malicious_fingerprints = {self._event_fingerprint(e) for e in malicious_events}
        benign_fingerprints = {self._event_fingerprint(e) for e in benign_events}
        matched_fingerprints = {self._event_fingerprint(e) for e in matched_events}

        # Calculate metrics
        true_positives = len(malicious_fingerprints & matched_fingerprints)
        false_negatives = len(malicious_fingerprints - matched_fingerprints)
        false_positives = len(benign_fingerprints & matched_fingerprints)
        true_negatives = len(benign_fingerprints - matched_fingerprints)

        # Find specific events
        missed_events = [
            e for e in malicious_events
            if self._event_fingerprint(e) not in matched_fingerprints
        ]
        fp_events = [
            e for e in benign_events
            if self._event_fingerprint(e) in matched_fingerprints
        ]

        # Determine status
        if false_negatives == 0 and false_positives == 0 and true_positives > 0:
            status = ValidationStatus.PASSED
        elif true_positives > 0 and (false_negatives > 0 or false_positives > 0):
            status = ValidationStatus.PARTIAL
        elif true_positives == 0 and false_negatives > 0:
            status = ValidationStatus.FAILED
        else:
            status = ValidationStatus.FAILED

        # Generate suggestions
        suggestions = self._generate_suggestions(
            true_positives, false_negatives, false_positives,
            missed_events, fp_events
        )

        return ValidationResult(
            status=status,
            true_positives=true_positives,
            false_negatives=false_negatives,
            false_positives=false_positives,
            true_negatives=true_negatives,
            execution_time_ms=execution_time_ms,
            suggestions=suggestions,
            matched_events=matched_events[:10],  # Limit stored events
            missed_events=missed_events[:10],
            false_positive_events=fp_events[:10],
            raw_response=raw_response,
        )

    def _event_fingerprint(self, event: Dict) -> str:
        """
        Create a fingerprint for event matching.
        Uses key fields that should be unique per event.
        """
        # Try various field combinations for fingerprinting
        key_fields = [
            # Splunk
            ("_time", "CommandLine", "NewProcessName"),
            # Elastic
            ("@timestamp", "process.command_line", "process.executable"),
            # Chronicle
            ("metadata.event_timestamp", "target.process.command_line"),
            # MDE
            ("Timestamp", "ProcessCommandLine", "FileName"),
        ]

        for fields in key_fields:
            parts = []
            for field in fields:
                value = self._get_nested_value(event, field)
                if value is not None:
                    parts.append(str(value))
            if parts:
                return "|".join(parts)

        # Fallback: use str representation
        import json
        return json.dumps(event, sort_keys=True)

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

    def _generate_suggestions(
        self,
        tp: int,
        fn: int,
        fp: int,
        missed: List[Dict],
        false_positives: List[Dict],
    ) -> List[str]:
        """Generate improvement suggestions based on results"""
        suggestions = []

        if fn > 0:
            suggestions.append(
                f"Detection missed {fn} malicious events. "
                "Consider broadening the query pattern or checking field names."
            )

            # Analyze missed events for common patterns
            if missed:
                common_fields = self._find_common_fields(missed)
                if common_fields:
                    suggestions.append(
                        f"Missed events contain these fields: {', '.join(common_fields[:5])}. "
                        "Verify your query targets the correct fields."
                    )

        if fp > 0:
            suggestions.append(
                f"Detection triggered on {fp} benign events (false positives). "
                "Consider adding exclusions or making the pattern more specific."
            )

        if tp == 0 and fn > 0:
            suggestions.append(
                "No malicious events were detected. The query may have syntax errors "
                "or target non-existent fields. Check the query structure."
            )

        if tp > 0 and fn == 0 and fp == 0:
            suggestions.append(
                "Excellent! Detection caught all malicious events with no false positives."
            )

        return suggestions

    def _find_common_fields(self, events: List[Dict]) -> List[str]:
        """Find fields that are common across events"""
        if not events:
            return []

        def get_all_keys(d: Dict, prefix: str = "") -> set:
            keys = set()
            for k, v in d.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.add(full_key)
                if isinstance(v, dict):
                    keys.update(get_all_keys(v, full_key))
            return keys

        all_keys = [get_all_keys(e) for e in events]
        if not all_keys:
            return []

        common = all_keys[0]
        for keys in all_keys[1:]:
            common &= keys

        return list(common)

    def analyze_failure(
        self,
        query: str,
        vendor: str,
        result: ValidationResult,
        malicious_events: List[Dict],
    ) -> FailureAnalysis:
        """
        Analyze why a detection failed and provide detailed feedback.

        Args:
            query: The detection query
            vendor: SIEM vendor
            result: The validation result
            malicious_events: The events that should have been detected

        Returns:
            FailureAnalysis with detailed breakdown
        """
        potential_causes = []
        suggested_fixes = []

        if result.query_error:
            failure_type = "QUERY_ERROR"
            description = f"Query execution error: {result.query_error}"
            potential_causes.append("Query syntax error")
            potential_causes.append("Invalid field names in query")
            suggested_fixes.append("Check query syntax for the target platform")
            suggested_fixes.append("Verify field names match the schema")

        elif result.false_negatives > 0 and result.true_positives == 0:
            failure_type = "NO_MATCHES"
            description = "Query did not match any malicious events"
            potential_causes.append("Query pattern too specific")
            potential_causes.append("Field names may not match the event schema")
            potential_causes.append("Case sensitivity issues")
            suggested_fixes.append("Broaden the search pattern")
            suggested_fixes.append("Verify field names in the events")
            suggested_fixes.append("Try case-insensitive matching")

        elif result.false_negatives > 0:
            failure_type = "PARTIAL_MATCH"
            description = f"Query matched some but not all malicious events ({result.true_positives}/{result.true_positives + result.false_negatives})"

            # Analyze differences between matched and missed
            if result.matched_events and result.missed_events:
                potential_causes.append("Query may be missing some indicator variations")
                potential_causes.append("Missed events may have slightly different patterns")
                suggested_fixes.append("Add additional OR conditions for variations")
                suggested_fixes.append("Use wildcards or regex for more flexible matching")

        elif result.false_positives > 0:
            failure_type = "FALSE_POSITIVES"
            description = f"Query incorrectly matched {result.false_positives} benign events"
            potential_causes.append("Query pattern too broad")
            potential_causes.append("Missing exclusion conditions")
            suggested_fixes.append("Add NOT conditions to exclude benign patterns")
            suggested_fixes.append("Make the pattern more specific")
            suggested_fixes.append("Add additional context requirements (parent process, file path)")

        else:
            failure_type = "UNKNOWN"
            description = "Unknown failure reason"
            potential_causes.append("Unable to determine failure cause")
            suggested_fixes.append("Review query and events manually")

        return FailureAnalysis(
            failure_type=failure_type,
            description=description,
            affected_events=result.missed_events + result.false_positive_events,
            potential_causes=potential_causes,
            suggested_fixes=suggested_fixes,
        )

    def test_detection_offline(
        self,
        query: str,
        vendor: str,
        malicious_events: List[Dict],
        benign_events: List[Dict],
    ) -> ValidationResult:
        """
        Test a detection query offline (without Docker).

        Uses basic pattern matching for approximate validation.
        Useful for quick syntax checks before full validation.

        Args:
            query: Detection query
            vendor: SIEM vendor
            malicious_events: Events that should match
            benign_events: Events that should not match

        Returns:
            Approximate ValidationResult
        """
        # Extract patterns from query
        patterns = self._extract_patterns(query, vendor)

        if not patterns:
            return ValidationResult(
                status=ValidationStatus.ERROR,
                error_message="Could not extract patterns from query for offline testing",
            )

        # Test patterns against events
        malicious_matches = 0
        benign_matches = 0
        matched_events = []
        missed_events = []
        fp_events = []

        for event in malicious_events:
            if self._event_matches_patterns(event, patterns):
                malicious_matches += 1
                matched_events.append(event)
            else:
                missed_events.append(event)

        for event in benign_events:
            if self._event_matches_patterns(event, patterns):
                benign_matches += 1
                fp_events.append(event)

        # Calculate metrics
        true_positives = malicious_matches
        false_negatives = len(malicious_events) - malicious_matches
        false_positives = benign_matches
        true_negatives = len(benign_events) - benign_matches

        # Determine status
        if false_negatives == 0 and false_positives == 0 and true_positives > 0:
            status = ValidationStatus.PASSED
        elif true_positives > 0:
            status = ValidationStatus.PARTIAL
        else:
            status = ValidationStatus.FAILED

        suggestions = self._generate_suggestions(
            true_positives, false_negatives, false_positives,
            missed_events, fp_events
        )
        suggestions.insert(0, "Note: This is an offline (approximate) validation. "
                             "Run with Docker for accurate results.")

        return ValidationResult(
            status=status,
            true_positives=true_positives,
            false_negatives=false_negatives,
            false_positives=false_positives,
            true_negatives=true_negatives,
            suggestions=suggestions,
            matched_events=matched_events[:10],
            missed_events=missed_events[:10],
            false_positive_events=fp_events[:10],
        )

    def _extract_patterns(self, query: str, vendor: str) -> List[Dict[str, Any]]:
        """Extract matching patterns from a query"""
        import re
        patterns = []

        # Simple pattern extraction - looks for common comparison patterns
        if vendor == "splunk":
            # Match field="value" or field=value
            matches = re.findall(r'(\w+)\s*=\s*["\']?([^"\'\s\|]+)["\']?', query)
            for field, value in matches:
                patterns.append({"field": field, "value": value, "type": "contains"})

        elif vendor == "elastic":
            # Match field.name: value or wildcards
            matches = re.findall(r'([a-z_.]+)\s*:\s*["\']?([^"\'\s]+)["\']?', query, re.IGNORECASE)
            for field, value in matches:
                patterns.append({"field": field, "value": value.strip("*"), "type": "contains"})

        elif vendor == "secops":
            # Match re.regex patterns (YARA-L)
            matches = re.findall(r're\.regex\(\$\w+\.([^,]+),\s*`([^`]+)`\)', query)
            for field, pattern in matches:
                patterns.append({"field": field.strip(), "value": pattern, "type": "regex"})

        elif vendor == "mde":
            # Match field contains "value" or field == "value"
            matches = re.findall(r'(\w+)\s+(?:contains|has|==)\s+["\']([^"\']+)["\']', query, re.IGNORECASE)
            for field, value in matches:
                patterns.append({"field": field, "value": value, "type": "contains"})

        return patterns

    def _event_matches_patterns(self, event: Dict, patterns: List[Dict]) -> bool:
        """Check if an event matches the extracted patterns"""
        import re

        for pattern in patterns:
            field = pattern["field"]
            value = pattern["value"]
            pattern_type = pattern["type"]

            # Get field value from event
            event_value = self._get_nested_value(event, field)
            if event_value is None:
                # Try case-insensitive field lookup
                for key in event.keys():
                    if key.lower() == field.lower():
                        event_value = event[key]
                        break

            if event_value is None:
                continue

            event_value = str(event_value).lower()
            check_value = value.lower()

            if pattern_type == "contains":
                if check_value in event_value:
                    return True
            elif pattern_type == "regex":
                try:
                    if re.search(value, event_value, re.IGNORECASE):
                        return True
                except re.error:
                    pass

        return False

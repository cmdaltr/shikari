"""
Validation Orchestrator

Coordinates the detection validation workflow:
1. Start SIEM containers
2. Generate sample events
3. Test detections
4. Analyze failures and suggest refinements
5. Iterate until user is satisfied
"""

import logging
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from . import (
    check_docker_available,
    get_docker_siem_manager,
    get_event_generator,
    get_detection_tester,
    get_detection_refiner,
    ValidationResult,
    GeneratedEventSet,
    RefinementSuggestion,
)

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """Validation session status"""
    CREATED = "created"
    STARTING_SIEMS = "starting_siems"
    SIEMS_READY = "siems_ready"
    GENERATING_EVENTS = "generating_events"
    EVENTS_READY = "events_ready"
    TESTING = "testing"
    AWAITING_REFINEMENT = "awaiting_refinement"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class ValidationSession:
    """Represents a validation session"""
    session_id: str
    technique_id: str
    technique_name: str
    query: str
    vendor: str
    status: SessionStatus = SessionStatus.CREATED
    created_at: datetime = field(default_factory=datetime.utcnow)
    events: Optional[GeneratedEventSet] = None
    validation_results: List[ValidationResult] = field(default_factory=list)
    refinement_history: List[Dict] = field(default_factory=list)
    current_query: str = ""
    iteration: int = 0
    error_message: Optional[str] = None
    docker_available: bool = True

    def __post_init__(self):
        self.current_query = self.query

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "session_id": self.session_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "original_query": self.query,
            "current_query": self.current_query,
            "vendor": self.vendor,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "iteration": self.iteration,
            "docker_available": self.docker_available,
            "error_message": self.error_message,
            "latest_result": self.validation_results[-1].to_dict() if self.validation_results else None,
        }


class ValidationOrchestrator:
    """Coordinates the detection validation workflow"""

    def __init__(self):
        """Initialize the orchestrator"""
        self.sessions: Dict[str, ValidationSession] = {}
        self.docker_manager = None
        self.event_generator = None
        self.detection_tester = None
        self.detection_refiner = None

        # Check Docker availability
        self.docker_available, self.docker_message = check_docker_available()

        if self.docker_available:
            self._init_components()

    def _init_components(self):
        """Initialize validation components"""
        try:
            DockerManager = get_docker_siem_manager()
            self.docker_manager = DockerManager()

            EventGenerator = get_event_generator()
            self.event_generator = EventGenerator()

            DetectionTester = get_detection_tester()
            self.detection_tester = DetectionTester(self.docker_manager)

            DetectionRefiner = get_detection_refiner()
            self.detection_refiner = DetectionRefiner()

        except Exception as e:
            logger.error(f"Failed to initialize validation components: {e}")
            self.docker_available = False
            self.docker_message = f"Failed to initialize: {str(e)}"

    def get_docker_status(self) -> Dict[str, Any]:
        """Get Docker availability status"""
        # Docker started after the server (OrbStack waking up) shouldn't need a restart to be seen
        if not self.docker_available and self.docker_manager is None:
            self.docker_available, self.docker_message = check_docker_available()
            if self.docker_available:
                self._init_components()
        return {
            "available": self.docker_available,
            "message": self.docker_message,
            "supported_vendors": ["splunk", "elastic", "secops", "mde"] if self.docker_available else [],
        }

    def create_session(
        self,
        technique_id: str,
        technique_name: str,
        query: str,
        vendor: str,
        indicators: Optional[Dict[str, List[str]]] = None,
    ) -> ValidationSession:
        """
        Create a new validation session.

        Args:
            technique_id: MITRE ATT&CK technique ID
            technique_name: Technique name
            query: Detection query to validate
            vendor: Target SIEM vendor
            indicators: Optional indicators for event generation

        Returns:
            New ValidationSession
        """
        session_id = str(uuid.uuid4())

        session = ValidationSession(
            session_id=session_id,
            technique_id=technique_id,
            technique_name=technique_name,
            query=query,
            vendor=vendor.lower(),
            docker_available=self.docker_available,
        )

        if not self.docker_available:
            session.status = SessionStatus.ERROR
            session.error_message = self.docker_message

        self.sessions[session_id] = session

        logger.info(f"Created validation session {session_id} for {technique_id}")

        return session

    def start_siem(self, session_id: str, port_offset: int = 0) -> Dict[str, Any]:
        """
        Start SIEM container for a session.

        Args:
            session_id: Session ID
            port_offset: Port offset to avoid conflicts

        Returns:
            Status dict
        """
        session = self._get_session(session_id)

        if not self.docker_available:
            return {
                "success": False,
                "error": self.docker_message,
            }

        session.status = SessionStatus.STARTING_SIEMS

        try:
            instance = self.docker_manager.start_siem(
                vendor=session.vendor,
                session_id=session_id,
                port_offset=port_offset,
            )

            session.status = SessionStatus.SIEMS_READY

            return {
                "success": True,
                "vendor": session.vendor,
                "url": instance.get_url(),
                "api_url": instance.get_api_url(),
                "status": instance.status,
                "from_compose": instance.from_compose,
                "container_type": "docker-compose" if instance.from_compose else "ephemeral",
            }

        except Exception as e:
            logger.error(f"Failed to start SIEM: {e}")
            session.status = SessionStatus.ERROR
            session.error_message = str(e)
            return {
                "success": False,
                "error": str(e),
            }

    def generate_events(
        self,
        session_id: str,
        indicators: Dict[str, List[str]],
        malicious_count: int = 10,
        benign_count: int = 20,
    ) -> Dict[str, Any]:
        """
        Generate sample events for a session.

        Args:
            session_id: Session ID
            indicators: Technique indicators
            malicious_count: Number of malicious events
            benign_count: Number of benign events

        Returns:
            Status dict with event counts
        """
        session = self._get_session(session_id)
        session.status = SessionStatus.GENERATING_EVENTS

        try:
            event_set = self.event_generator.generate_events(
                technique_id=session.technique_id,
                technique_name=session.technique_name,
                indicators=indicators,
                vendor=session.vendor,
                malicious_count=malicious_count,
                benign_count=benign_count,
            )

            session.events = event_set
            session.status = SessionStatus.EVENTS_READY

            return {
                "success": True,
                "malicious_count": len(event_set.malicious_events),
                "benign_count": len(event_set.benign_events),
                "event_type": event_set.generation_metadata.get("event_type"),
            }

        except Exception as e:
            logger.error(f"Failed to generate events: {e}")
            session.status = SessionStatus.ERROR
            session.error_message = str(e)
            return {
                "success": False,
                "error": str(e),
            }

    def test_detection(
        self,
        session_id: str,
        query: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Test a detection query against generated events.

        Args:
            session_id: Session ID
            query: Query to test (uses session query if not provided)

        Returns:
            Validation result dict
        """
        session = self._get_session(session_id)

        if session.events is None:
            return {
                "success": False,
                "error": "No events generated. Call generate_events first.",
            }

        query = query or session.current_query
        session.status = SessionStatus.TESTING
        session.iteration += 1

        try:
            result = self.detection_tester.test_detection(
                query=query,
                vendor=session.vendor,
                session_id=session_id,
                malicious_events=session.events.malicious_events,
                benign_events=session.events.benign_events,
            )

            session.validation_results.append(result)
            session.current_query = query

            if result.passed:
                session.status = SessionStatus.COMPLETED
            else:
                session.status = SessionStatus.AWAITING_REFINEMENT

            return {
                "success": True,
                "result": result.to_dict(),
                "iteration": session.iteration,
            }

        except Exception as e:
            logger.error(f"Detection test failed: {e}")
            session.status = SessionStatus.ERROR
            session.error_message = str(e)
            return {
                "success": False,
                "error": str(e),
            }

    def get_refinement_suggestions(
        self,
        session_id: str,
    ) -> Dict[str, Any]:
        """
        Get refinement suggestions for the current detection.

        Args:
            session_id: Session ID

        Returns:
            Dict with suggestions list
        """
        session = self._get_session(session_id)

        if not session.validation_results:
            return {
                "success": False,
                "error": "No validation results. Run test_detection first.",
            }

        latest_result = session.validation_results[-1]

        if latest_result.passed:
            return {
                "success": True,
                "suggestions": [],
                "message": "Detection passed, no refinements needed.",
            }

        try:
            # Analyze the failure
            failure_analysis = self.detection_tester.analyze_failure(
                query=session.current_query,
                vendor=session.vendor,
                result=latest_result,
                malicious_events=session.events.malicious_events,
            )

            # Get suggestions
            suggestions = self.detection_refiner.suggest_refinements(
                original_query=session.current_query,
                vendor=session.vendor,
                failure_analysis=failure_analysis,
                sample_events=session.events.malicious_events,
                validation_result=latest_result,
            )

            return {
                "success": True,
                "suggestions": [s.to_dict() for s in suggestions],
                "failure_analysis": {
                    "type": failure_analysis.failure_type,
                    "description": failure_analysis.description,
                    "causes": failure_analysis.potential_causes,
                },
            }

        except Exception as e:
            logger.error(f"Failed to get refinements: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    def apply_refinement(
        self,
        session_id: str,
        suggestion_index: int,
    ) -> Dict[str, Any]:
        """
        Apply a refinement suggestion.

        Args:
            session_id: Session ID
            suggestion_index: Index of suggestion to apply

        Returns:
            Dict with new query
        """
        session = self._get_session(session_id)

        # Get current suggestions
        suggestions_result = self.get_refinement_suggestions(session_id)
        if not suggestions_result.get("success"):
            return suggestions_result

        suggestions = suggestions_result.get("suggestions", [])

        if suggestion_index < 0 or suggestion_index >= len(suggestions):
            return {
                "success": False,
                "error": f"Invalid suggestion index: {suggestion_index}",
            }

        suggestion_dict = suggestions[suggestion_index]

        # Reconstruct suggestion object
        from .detection_refiner import RefinementSuggestion, RefinementType
        suggestion = RefinementSuggestion(
            refinement_type=RefinementType(suggestion_dict["type"]),
            description=suggestion_dict["description"],
            original_snippet=suggestion_dict["original"],
            suggested_snippet=suggestion_dict["suggested"],
            confidence=suggestion_dict["confidence"],
            explanation=suggestion_dict["explanation"],
        )

        # Apply refinement
        new_query = self.detection_refiner.apply_refinement(
            query=session.current_query,
            suggestion=suggestion,
        )

        # Record in history
        session.refinement_history.append({
            "iteration": session.iteration,
            "suggestion": suggestion_dict,
            "old_query": session.current_query,
            "new_query": new_query,
        })

        session.current_query = new_query

        return {
            "success": True,
            "new_query": new_query,
            "applied_suggestion": suggestion_dict,
        }

    def stop_session(self, session_id: str) -> Dict[str, Any]:
        """
        Stop a validation session and cleanup resources.

        Args:
            session_id: Session ID

        Returns:
            Status dict
        """
        if session_id not in self.sessions:
            return {"success": False, "error": "Session not found"}

        session = self.sessions[session_id]

        # Stop SIEM container
        if self.docker_manager:
            try:
                self.docker_manager.stop_siem(session_id, session.vendor)
            except Exception as e:
                logger.warning(f"Error stopping SIEM: {e}")

        session.status = SessionStatus.STOPPED

        return {
            "success": True,
            "session_id": session_id,
            "final_query": session.current_query,
            "iterations": session.iteration,
            "passed": session.validation_results[-1].passed if session.validation_results else False,
        }

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session details"""
        if session_id not in self.sessions:
            return None
        return self.sessions[session_id].to_dict()

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all active sessions"""
        return [s.to_dict() for s in self.sessions.values()]

    def _get_session(self, session_id: str) -> ValidationSession:
        """Get session or raise error"""
        if session_id not in self.sessions:
            raise ValueError(f"Session not found: {session_id}")
        return self.sessions[session_id]

    def cleanup_all(self):
        """Cleanup all sessions and containers"""
        for session_id in list(self.sessions.keys()):
            self.stop_session(session_id)
        self.sessions.clear()


# Global orchestrator instance
_orchestrator: Optional[ValidationOrchestrator] = None


def get_orchestrator() -> ValidationOrchestrator:
    """Get or create the global orchestrator instance"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ValidationOrchestrator()
    return _orchestrator

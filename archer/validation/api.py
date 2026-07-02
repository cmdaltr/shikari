"""
Validation API Routes

FastAPI routes for the detection validation feature.
Import these routes into the main app.py.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import logging

from .orchestrator import get_orchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/validation", tags=["validation"])


# Request/Response Models

class DockerStatusResponse(BaseModel):
    """Docker availability status"""
    available: bool
    message: str
    supported_vendors: List[str]


class CreateSessionRequest(BaseModel):
    """Request to create a validation session"""
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID")
    technique_name: str = Field(..., description="Technique name")
    query: str = Field(..., description="Detection query to validate")
    vendor: str = Field(..., description="Target SIEM vendor")
    indicators: Optional[Dict[str, List[str]]] = Field(
        default=None, description="Technique indicators"
    )


class SessionResponse(BaseModel):
    """Validation session details"""
    session_id: str
    technique_id: str
    technique_name: str
    original_query: str
    current_query: str
    vendor: str
    status: str
    created_at: str
    iteration: int
    docker_available: bool
    error_message: Optional[str]
    latest_result: Optional[Dict[str, Any]]


class StartSIEMRequest(BaseModel):
    """Request to start SIEM container"""
    session_id: str
    port_offset: int = Field(default=0, description="Port offset to avoid conflicts")


class GenerateEventsRequest(BaseModel):
    """Request to generate sample events"""
    session_id: str
    indicators: Dict[str, List[str]] = Field(
        ..., description="Indicators for event generation"
    )
    malicious_count: int = Field(default=10, description="Number of malicious events")
    benign_count: int = Field(default=20, description="Number of benign events")


class TestDetectionRequest(BaseModel):
    """Request to test a detection"""
    session_id: str
    query: Optional[str] = Field(
        default=None, description="Query to test (uses session query if not provided)"
    )


class ApplyRefinementRequest(BaseModel):
    """Request to apply a refinement"""
    session_id: str
    suggestion_index: int = Field(
        ..., description="Index of suggestion to apply"
    )


# Routes

@router.get("/docker-status", response_model=DockerStatusResponse)
async def get_docker_status():
    """
    Check if Docker is available for validation.

    Returns Docker availability status and supported SIEM vendors.
    This should be checked before attempting to start a validation session.
    """
    orchestrator = get_orchestrator()
    return orchestrator.get_docker_status()


@router.get("/siem-availability", response_model=Dict[str, Any])
async def get_siem_availability():
    """
    Check which SIEM containers are available via docker-compose profiles.

    Returns status of each SIEM indicating if it's running via docker-compose
    and provides start commands for unavailable SIEMs.

    Use this to show users which validation targets are ready without
    needing to spawn ephemeral containers.
    """
    orchestrator = get_orchestrator()

    if not orchestrator.docker_manager:
        return {
            "available": False,
            "message": "Docker is not available",
            "siems": {},
        }

    compose_status = orchestrator.docker_manager.get_compose_status()

    available_count = sum(1 for s in compose_status.values() if s.get("available"))

    return {
        "available": True,
        "message": f"{available_count} of {len(compose_status)} SIEM containers running",
        "siems": compose_status,
        "start_all_command": "docker-compose --profile validation up -d",
    }


@router.post("/cleanup-siem/{vendor}", response_model=Dict[str, Any])
async def cleanup_siem_container(vendor: str):
    """
    Stop a docker-compose SIEM container.

    Use this to clean up SIEM containers when you're done with validation.
    Pass 'all' as vendor to stop all SIEM containers.

    Note: This only stops docker-compose containers, not ephemeral ones
    (which are automatically cleaned up when sessions end).
    """
    orchestrator = get_orchestrator()

    if not orchestrator.docker_manager:
        raise HTTPException(status_code=503, detail="Docker is not available")

    if vendor.lower() == "all":
        result = orchestrator.docker_manager.stop_all_compose_containers()
    else:
        result = orchestrator.docker_manager.stop_compose_container(vendor.lower())

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


@router.post("/sessions", response_model=Dict[str, Any])
async def create_session(request: CreateSessionRequest):
    """
    Create a new validation session.

    This creates a session but does not start any containers.
    Use /start-siem to start the SIEM container.
    """
    orchestrator = get_orchestrator()

    session = orchestrator.create_session(
        technique_id=request.technique_id,
        technique_name=request.technique_name,
        query=request.query,
        vendor=request.vendor,
        indicators=request.indicators,
    )

    return {"success": True, "session": session.to_dict()}


@router.get("/sessions/{session_id}", response_model=Dict[str, Any])
async def get_session(session_id: str):
    """Get details of a validation session."""
    orchestrator = get_orchestrator()
    session = orchestrator.get_session(session_id)

    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    return session


@router.get("/sessions", response_model=List[Dict[str, Any]])
async def list_sessions():
    """List all active validation sessions."""
    orchestrator = get_orchestrator()
    return orchestrator.list_sessions()


@router.post("/start-siem", response_model=Dict[str, Any])
async def start_siem(request: StartSIEMRequest):
    """
    Start or connect to SIEM container for a validation session.

    First checks for running docker-compose profile containers:
    - If found: Uses the existing container (faster, recommended)
    - If not found: Spawns an ephemeral container on-demand

    Docker-compose containers persist between sessions and are managed separately.
    Ephemeral containers are stopped when the session ends.

    Use /siem-availability to check which containers are pre-started.
    """
    orchestrator = get_orchestrator()

    result = orchestrator.start_siem(
        session_id=request.session_id,
        port_offset=request.port_offset,
    )

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))

    return result


@router.post("/generate-events", response_model=Dict[str, Any])
async def generate_events(request: GenerateEventsRequest):
    """
    Generate sample events for testing.

    Creates malicious events (that should trigger the detection) and
    benign events (that should not trigger false positives).
    """
    orchestrator = get_orchestrator()

    result = orchestrator.generate_events(
        session_id=request.session_id,
        indicators=request.indicators,
        malicious_count=request.malicious_count,
        benign_count=request.benign_count,
    )

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))

    return result


@router.post("/test", response_model=Dict[str, Any])
async def test_detection(request: TestDetectionRequest):
    """
    Test a detection query against sample events.

    Returns validation metrics including true/false positives/negatives,
    precision, recall, and suggestions for improvement.
    """
    orchestrator = get_orchestrator()

    result = orchestrator.test_detection(
        session_id=request.session_id,
        query=request.query,
    )

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))

    return result


@router.get("/suggestions/{session_id}", response_model=Dict[str, Any])
async def get_refinement_suggestions(session_id: str):
    """
    Get refinement suggestions for a failed detection.

    Analyzes why the detection failed and suggests specific query improvements.
    """
    orchestrator = get_orchestrator()

    result = orchestrator.get_refinement_suggestions(session_id)

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


@router.post("/refine", response_model=Dict[str, Any])
async def apply_refinement(request: ApplyRefinementRequest):
    """
    Apply a refinement suggestion to the query.

    Returns the updated query which can then be tested again.
    """
    orchestrator = get_orchestrator()

    result = orchestrator.apply_refinement(
        session_id=request.session_id,
        suggestion_index=request.suggestion_index,
    )

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


@router.post("/stop/{session_id}", response_model=Dict[str, Any])
async def stop_session(session_id: str):
    """
    Stop a validation session and cleanup resources.

    Stops the SIEM container and marks the session as stopped.
    Returns the final query and validation results.
    """
    orchestrator = get_orchestrator()

    result = orchestrator.stop_session(session_id)

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result


@router.get("/status/{session_id}", response_model=Dict[str, Any])
async def get_validation_status(session_id: str):
    """
    Get the current status of a validation session.

    Returns session status, latest validation result, and SIEM container status.
    """
    orchestrator = get_orchestrator()

    session = orchestrator.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    # Get SIEM status if docker manager is available
    siem_status = None
    if orchestrator.docker_manager:
        siem_status = orchestrator.docker_manager.get_status(session_id)

    return {
        "session": session,
        "siem_status": siem_status,
    }


# Convenience endpoint for quick validation (all-in-one)
class QuickValidateRequest(BaseModel):
    """Request for quick validation (all steps in one call)"""
    technique_id: str
    technique_name: str
    query: str
    vendor: str
    indicators: Dict[str, List[str]]
    malicious_count: int = 10
    benign_count: int = 20


@router.post("/quick-validate", response_model=Dict[str, Any])
async def quick_validate(request: QuickValidateRequest):
    """
    Perform a complete validation in one call.

    This creates a session, starts the SIEM, generates events,
    tests the detection, and returns the result.

    Useful for one-shot validation without iterative refinement.
    """
    orchestrator = get_orchestrator()

    # Check Docker availability
    docker_status = orchestrator.get_docker_status()
    if not docker_status["available"]:
        raise HTTPException(
            status_code=503,
            detail=f"Docker not available: {docker_status['message']}"
        )

    try:
        # Create session
        session = orchestrator.create_session(
            technique_id=request.technique_id,
            technique_name=request.technique_name,
            query=request.query,
            vendor=request.vendor,
        )

        # Start SIEM
        siem_result = orchestrator.start_siem(session.session_id)
        if not siem_result.get("success"):
            raise Exception(siem_result.get("error", "Failed to start SIEM"))

        # Generate events
        events_result = orchestrator.generate_events(
            session_id=session.session_id,
            indicators=request.indicators,
            malicious_count=request.malicious_count,
            benign_count=request.benign_count,
        )
        if not events_result.get("success"):
            raise Exception(events_result.get("error", "Failed to generate events"))

        # Test detection
        test_result = orchestrator.test_detection(session.session_id)
        if not test_result.get("success"):
            raise Exception(test_result.get("error", "Failed to test detection"))

        # Get suggestions if failed
        suggestions = []
        if not test_result["result"]["passed"]:
            suggestions_result = orchestrator.get_refinement_suggestions(session.session_id)
            if suggestions_result.get("success"):
                suggestions = suggestions_result.get("suggestions", [])

        return {
            "success": True,
            "session_id": session.session_id,
            "result": test_result["result"],
            "suggestions": suggestions,
            "message": "Validation complete. Use session_id for further refinement."
        }

    except Exception as e:
        logger.error(f"Quick validation failed: {e}")
        # Try to cleanup
        if 'session' in locals():
            orchestrator.stop_session(session.session_id)
        raise HTTPException(status_code=500, detail=str(e))

"""
Detection Query Validation Module

This module provides validation capabilities for detection queries:
- Field validation (ensuring fields exist in target platform)
- Query syntax validation
- Logic validation
- Test data validation
- SIEM container management for live validation
- Sample event generation
- Detection testing and refinement
"""

import subprocess
import logging
from typing import Tuple

from .field_validator import FieldValidator
from .query_validator import QueryValidator
from .test_runner import TestRunner

logger = logging.getLogger(__name__)


def check_docker_available() -> Tuple[bool, str]:
    """
    Check if Docker is available for validation testing.

    Returns:
        Tuple of (is_available, message)
        - is_available: True if Docker is installed and running
        - message: Human-readable status message
    """
    try:
        # Check if docker command exists
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            return False, "Docker is not installed. Install Docker Desktop to enable detection validation with SIEM containers."

        # Check if Docker daemon is running
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return False, "Docker is installed but not running. Start the Docker daemon to enable detection validation."

        return True, "Docker is available for validation testing."

    except FileNotFoundError:
        return False, "Docker is not installed. Install Docker Desktop to enable detection validation with SIEM containers."
    except subprocess.TimeoutExpired:
        return False, "Docker is not responding. Restart Docker to enable detection validation."
    except Exception as e:
        logger.warning(f"Docker check error: {e}")
        return False, f"Could not verify Docker status: {str(e)}"


# Lazy imports for Docker-dependent classes to avoid import errors when Docker is not available
def get_docker_siem_manager():
    """Get DockerSIEMManager class (lazy import to handle Docker unavailability)"""
    from .docker_manager import DockerSIEMManager
    return DockerSIEMManager


def get_event_generator():
    """Get SampleEventGenerator class (lazy import)"""
    from .event_generator import SampleEventGenerator
    return SampleEventGenerator


def get_detection_tester():
    """Get DetectionTester class (lazy import)"""
    from .detection_tester import DetectionTester
    return DetectionTester


def get_detection_refiner():
    """Get DetectionRefiner class (lazy import)"""
    from .detection_refiner import DetectionRefiner
    return DetectionRefiner


# Import non-Docker classes directly
from .event_generator import GeneratedEventSet
from .detection_tester import ValidationResult, ValidationStatus, FailureAnalysis
from .detection_refiner import RefinementSuggestion, RefinementType


def get_validation_router():
    """Get the FastAPI router for validation endpoints"""
    from .api import router
    return router


def get_orchestrator():
    """Get the global validation orchestrator instance"""
    from .orchestrator import get_orchestrator as _get_orchestrator
    return _get_orchestrator()


__all__ = [
    # Core validators
    'FieldValidator',
    'QueryValidator',
    'TestRunner',
    # Docker check
    'check_docker_available',
    # Lazy imports
    'get_docker_siem_manager',
    'get_event_generator',
    'get_detection_tester',
    'get_detection_refiner',
    # Data classes
    'GeneratedEventSet',
    'ValidationResult',
    'ValidationStatus',
    'FailureAnalysis',
    'RefinementSuggestion',
    'RefinementType',
    # API
    'get_validation_router',
    'get_orchestrator',
]

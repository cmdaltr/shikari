"""
Archer Configuration Module

Centralized configuration for optional features and integrations.
"""

import os


# ========== Directory Path Constants ==========
# These constants are used throughout Archer to maintain consistent paths
DATA_DIR = "data"
GENERATE_DIR = os.path.join(DATA_DIR, "generate")
CORRELATE_DIR = os.path.join(DATA_DIR, "correlate")
DRAFTS_DIR = os.path.join(DATA_DIR, "drafts")
UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
BLOG_DIR = os.path.join(DATA_DIR, "blog_analysis")
ATTACK_FLOWS_DIR = os.path.join(DATA_DIR, "attack_flows")
PROGRESS_DIR = os.path.join(DATA_DIR, "progress")
PROFILE_PICS_DIR = os.path.join(DATA_DIR, "profile_pictures")
VALIDATION_CACHE_DIR = os.path.join(DATA_DIR, "validation_cache")
AI_CACHE_DIR = os.path.join(DATA_DIR, "ai_cache")
CVE_CACHE_DIR = os.path.join(DATA_DIR, "cve_cache")

# ========== Common Constants ==========
# Severity order for comparison (highest to lowest priority)
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


class EmulationConfig:
    """Configuration for adversary emulation integrations."""

    enabled = os.getenv("ENABLE_EMULATION", "false").lower() == "true"

    # Atomic Red Team
    atomic_path = os.getenv("ATOMIC_REDTEAM_PATH", "/opt/atomic-red-team")
    atomic_runner = os.getenv("ATOMIC_RUNNER", "powershell")  # powershell, bash, cmd

    # MITRE CALDERA
    caldera_url = os.getenv("CALDERA_API_URL", "http://localhost:8888")
    caldera_api_key = os.getenv("CALDERA_API_KEY")

    # MACAT
    macat_path = os.getenv("MACAT_PATH")

    # Output settings
    output_dir = os.getenv("EMULATION_OUTPUT_DIR", "data/emulation")
    evidence_dir = os.getenv("EMULATION_EVIDENCE_DIR", "data/emulation/evidence")

    @classmethod
    def is_atomic_configured(cls) -> bool:
        """Check if Atomic Red Team is properly configured."""
        import os.path
        return cls.enabled and os.path.exists(cls.atomic_path)

    @classmethod
    def is_caldera_configured(cls) -> bool:
        """Check if CALDERA is properly configured."""
        return cls.enabled and cls.caldera_api_key is not None


class VECTRConfig:
    """Configuration for VECTR integration."""

    enabled = os.getenv("ENABLE_VECTR", "false").lower() == "true"

    # VECTR API settings
    url = os.getenv("VECTR_URL", "https://localhost:8081")
    api_token = os.getenv("VECTR_API_TOKEN")

    # Default values
    default_campaign = os.getenv("VECTR_DEFAULT_CAMPAIGN", "Archer-ThreatHunt")
    default_environment = os.getenv("VECTR_DEFAULT_ENVIRONMENT", "Production")

    # Output settings
    output_dir = os.getenv("VECTR_OUTPUT_DIR", "data/vectr")

    @classmethod
    def is_configured(cls) -> bool:
        """Check if VECTR is properly configured."""
        return cls.enabled and cls.api_token is not None


class CoreConfig:
    """Core Archer configuration."""

    # Data directories
    generate_dir = os.getenv("GENERATE_DIR", "data/generate")
    correlate_dir = os.getenv("CORRELATE_DIR", "data/correlate")
    hunt_dir = os.getenv("HUNT_DIR", "data/hunt")
    progress_dir = os.getenv("PROGRESS_DIR", "data/progress")

    # GenAI settings
    genai_mode = os.getenv("GENAI_MODE", "heuristic")
    llama_model_path = os.getenv("LLAMA_MODEL_PATH")

    # Correlation settings
    correlation_min_relevance = float(os.getenv("CORRELATION_MIN_RELEVANCE", "0.5"))

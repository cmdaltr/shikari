"""
GenAI Module - Correlation Query Generation

This module provides correlation query generation capabilities using:
- Heuristic-based query combination (default)
- Advanced parsing with semantic analysis
- AI-powered generation (optional, via local LLMs or remote APIs)

Main Components:
- engine.py: Core correlation generation engine
- models.py: AI provider implementations (LocalLLMGenerator, RemoteAPIGenerator)
"""

from .engine import (
    generate_correlations,
    build_correlation_queries,
    process_genai,
    process,
)

__all__ = [
    "generate_correlations",
    "build_correlation_queries",
    "process_genai",
    "process",
]

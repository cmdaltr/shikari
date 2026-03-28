"""
RAG (Retrieval-Augmented Generation) System for Detection Enhancement.

This module provides:
- Knowledge base management
- Vector embeddings and similarity search
- Query enhancement using retrieved examples
- LLM integration for example-guided generation
"""

from .knowledge_base import DetectionKnowledgeBase
from .retrieval import DetectionRetriever
from .embeddings import EmbeddingGenerator
from .enhancer import QueryEnhancer

__all__ = [
    'DetectionKnowledgeBase',
    'DetectionRetriever',
    'EmbeddingGenerator',
    'QueryEnhancer',
]

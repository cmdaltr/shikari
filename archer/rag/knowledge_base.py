"""
Detection Knowledge Base Manager

Main interface for interacting with the detection knowledge base.
Combines retrieval, enhancement, and query generation.
"""

import os
from pathlib import Path
from typing import List, Dict, Optional
import yaml

from .retrieval import DetectionRetriever
from .embeddings import EmbeddingGenerator


class DetectionKnowledgeBase:
    """
    Main interface for the detection knowledge base.

    Provides high-level methods for:
    - Finding similar detection examples
    - Enhancing queries with retrieved examples
    - Managing the knowledge base
    """

    def __init__(
        self,
        kb_path: Optional[Path] = None,
        auto_build: bool = True
    ):
        """
        Initialize knowledge base.

        Args:
            kb_path: Path to external detections (default: data/external/detections)
            auto_build: Automatically build index if not found
        """
        if kb_path is None:
            kb_path = Path("data/external/detections")

        self.kb_path = Path(kb_path)
        self.index_path = self.kb_path / "embeddings" / "vector_store.faiss"
        self.metadata_path = self.kb_path / "embeddings" / "metadata.json"

        self.retriever = None
        self._initialize_retriever(auto_build)

    def _initialize_retriever(self, auto_build: bool):
        """Initialize or build the retriever."""
        if self.index_path.exists() and self.metadata_path.exists():
            try:
                self.retriever = DetectionRetriever(
                    self.index_path,
                    self.metadata_path,
                    self.kb_path
                )
                print(f"✓ Knowledge base loaded from {self.kb_path}")
            except Exception as e:
                print(f"Warning: Failed to load knowledge base: {e}")
                if auto_build:
                    print("Attempting to rebuild index...")
                    self._build_index()
        elif auto_build:
            print("Knowledge base index not found. Building index...")
            self._build_index()
        else:
            print("Warning: Knowledge base index not found")
            print("Run: python scripts/build_embeddings.py")

    def _build_index(self):
        """Build the vector index."""
        generator = EmbeddingGenerator()
        stats = generator.build_index(
            self.kb_path,
            self.kb_path / "embeddings"
        )

        if stats['success']:
            self.retriever = DetectionRetriever(
                self.index_path,
                self.metadata_path,
                self.kb_path
            )

    def find_similar_detections(
        self,
        technique_id: str,
        platform: str,
        top_k: int = 5,
        min_fidelity: float = 0.7
    ) -> List[Dict]:
        """
        Find similar high-quality detection examples.

        Args:
            technique_id: MITRE ATT&CK technique ID
            platform: Platform (Splunk, MicrosoftThreatProtection, etc.)
            top_k: Number of examples to return
            min_fidelity: Minimum fidelity score

        Returns:
            List of detection examples with similarity scores
        """
        if not self.retriever:
            print("Warning: Knowledge base not initialized")
            return []

        try:
            results = self.retriever.search_by_technique(
                technique_id=technique_id,
                platform=platform,
                top_k=top_k,
                min_fidelity=min_fidelity
            )
            return results
        except Exception as e:
            print(f"Error searching knowledge base: {e}")
            return []

    def enhance_query_with_examples(
        self,
        original_query: str,
        examples: List[Dict],
        llm_provider: str = "openai",
        technique_id: Optional[str] = None
    ) -> str:
        """
        Enhance query using retrieved examples and LLM.

        Args:
            original_query: Original detection query
            examples: List of example detections
            llm_provider: LLM provider ("openai", "ollama", "anthropic")
            technique_id: Optional technique ID for context

        Returns:
            Enhanced query
        """
        if not examples:
            return original_query

        try:
            from .enhancer import QueryEnhancer

            enhancer = QueryEnhancer(llm_provider=llm_provider)
            enhanced_query = enhancer.enhance_query(
                original_query=original_query,
                examples=examples,
                technique_id=technique_id
            )

            return enhanced_query

        except ImportError:
            print("Warning: Query enhancer not available, returning original query")
            return original_query
        except Exception as e:
            print(f"Warning: Failed to enhance query: {e}")
            return original_query

    def get_statistics(self) -> Dict:
        """Get knowledge base statistics."""
        if not self.retriever:
            return {'error': 'Knowledge base not initialized'}

        return self.retriever.get_statistics()

    def is_available(self) -> bool:
        """Check if knowledge base is available and ready."""
        return self.retriever is not None

    def get_example_count(self) -> int:
        """Get total number of examples in knowledge base."""
        if not self.retriever:
            return 0

        stats = self.get_statistics()
        return stats.get('total_detections', 0)


def main():
    """Test the knowledge base."""
    kb = DetectionKnowledgeBase()

    if not kb.is_available():
        print("Knowledge base not available")
        return

    print()
    print("=" * 70)
    print("Testing Detection Knowledge Base")
    print("=" * 70)
    print()

    # Show statistics
    stats = kb.get_statistics()
    print(f"Total Detections: {stats['total_detections']}")
    print(f"Average Fidelity: {stats['average_fidelity']}")
    print()

    # Test search
    print("Testing search for T1003.001 (LSASS Memory) on Splunk:")
    print()

    results = kb.find_similar_detections(
        technique_id="T1003.001",
        platform="Splunk",
        top_k=3
    )

    for i, result in enumerate(results, 1):
        print(f"{i}. {result['metadata']['technique_name']}")
        print(f"   Similarity: {result['similarity']:.3f}")
        print(f"   Fidelity: {result['metadata']['fidelity_score']}")
        print()


if __name__ == "__main__":
    main()

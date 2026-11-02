"""
Detection retrieval using vector similarity search.

Finds similar high-quality detection examples from the knowledge base.
"""

import json
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import yaml


class DetectionRetriever:
    """
    Retrieve similar detection examples using vector similarity.

    Uses FAISS for fast similarity search on embedded detections.
    """

    def __init__(
        self,
        index_path: Path,
        metadata_path: Path,
        kb_path: Path,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    ):
        """
        Initialize retriever.

        Args:
            index_path: Path to FAISS index file
            metadata_path: Path to metadata JSON
            kb_path: Path to knowledge base root
            model_name: Name of embedding model to use
        """
        self.index_path = index_path
        self.metadata_path = metadata_path
        self.kb_path = kb_path
        self.model_name = model_name

        self.index = None
        self.metadata = None
        self.model = None

        self._load_index()
        self._load_metadata()
        self._load_model()

    def _load_index(self):
        """Load FAISS index."""
        try:
            import faiss
            self.index = faiss.read_index(str(self.index_path))
            print(f"✓ Loaded FAISS index: {self.index.ntotal} vectors")
        except ImportError:
            print("Error: faiss not installed")
            print("Install with: pip install faiss-cpu")
            raise
        except Exception as e:
            print(f"Error loading index from {self.index_path}: {e}")
            raise

    def _load_metadata(self):
        """Load metadata."""
        with open(self.metadata_path, 'r') as f:
            self.metadata = json.load(f)
        print(f"✓ Loaded metadata: {len(self.metadata['detections'])} detections")

    def _load_model(self):
        """Load embedding model."""
        try:
            from sentence_transformers import SentenceTransformer
            # Use local_files_only to avoid SSL issues with HuggingFace
            try:
                self.model = SentenceTransformer(self.model_name, local_files_only=True)
            except Exception:
                self.model = SentenceTransformer(self.model_name)
        except ImportError:
            print("Error: sentence-transformers not installed")
            raise

    def search(
        self,
        query_text: str,
        top_k: int = 5,
        min_similarity: float = 0.0,
        filters: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Search for similar detections.

        Args:
            query_text: Query text (e.g., "T1003.001 LSASS memory dump on Windows")
            top_k: Number of results to return
            min_similarity: Minimum similarity score (0-1)
            filters: Optional filters (e.g., {'platform': 'Splunk', 'tactic': 'credential_access'})

        Returns:
            List of dictionaries with detection info and similarity scores
        """
        # Generate query embedding
        query_embedding = self.model.encode(query_text, convert_to_numpy=True)
        query_embedding = query_embedding.reshape(1, -1).astype('float32')

        # Normalize for cosine similarity
        import faiss
        faiss.normalize_L2(query_embedding)

        # Search
        # Get extra results to account for filtering
        search_k = top_k * 3 if filters else top_k
        distances, indices = self.index.search(query_embedding, search_k)

        # Build results
        results = []
        for i, (dist, idx) in enumerate(zip(distances[0], indices[0])):
            if idx < 0 or idx >= len(self.metadata['detections']):
                continue

            detection_meta = self.metadata['detections'][idx]
            file_path = self.kb_path / self.metadata['file_paths'][idx]

            # Apply filters
            if filters:
                if not self._matches_filters(detection_meta, filters):
                    continue

            # Check minimum similarity
            similarity = float(dist)
            if similarity < min_similarity:
                continue

            # Load full detection
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    detection = yaml.safe_load(f)
            except Exception as e:
                print(f"Warning: Could not load {file_path}: {e}")
                continue

            result = {
                'detection': detection,
                'similarity': similarity,
                'file_path': str(file_path.relative_to(self.kb_path)),
                'rank': i + 1,
                'metadata': detection_meta
            }

            results.append(result)

            if len(results) >= top_k:
                break

        return results

    def search_by_technique(
        self,
        technique_id: str,
        platform: Optional[str] = None,
        top_k: int = 5,
        min_fidelity: float = 0.7
    ) -> List[Dict]:
        """
        Search for detections by technique ID.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1003.001")
            platform: Optional platform filter (e.g., "Splunk", "MicrosoftThreatProtection")
            top_k: Number of results to return
            min_fidelity: Minimum fidelity score

        Returns:
            List of similar detections
        """
        # Construct query
        query_parts = [f"Technique {technique_id}"]
        if platform:
            query_parts.append(f"Platform {platform}")

        query_text = " ".join(query_parts)

        # Build filters
        filters = {}
        if platform:
            filters['platform'] = platform

        # Search
        results = self.search(query_text, top_k=top_k, filters=filters)

        # Filter by fidelity
        results = [
            r for r in results
            if r['detection'].get('fidelity_score', 0) >= min_fidelity
        ]

        return results

    def _matches_filters(self, detection_meta: Dict, filters: Dict) -> bool:
        """Check if detection matches filters."""
        for key, value in filters.items():
            if detection_meta.get(key) != value:
                return False
        return True

    def get_statistics(self) -> Dict:
        """Get statistics about the knowledge base."""
        if not self.metadata:
            return {}

        detections = self.metadata['detections']

        # Count by platform
        platforms = {}
        for d in detections:
            platform = d.get('platform', 'unknown')
            platforms[platform] = platforms.get(platform, 0) + 1

        # Count by tactic
        tactics = {}
        for d in detections:
            tactic = d.get('tactic', 'unknown')
            tactics[tactic] = tactics.get(tactic, 0) + 1

        # Count by source
        sources = {}
        for d in detections:
            source = d.get('source', 'unknown')
            sources[source] = sources.get(source, 0) + 1

        # Average fidelity
        fidelity_scores = [d.get('fidelity_score', 0) for d in detections if d.get('fidelity_score')]
        avg_fidelity = sum(fidelity_scores) / len(fidelity_scores) if fidelity_scores else 0

        return {
            'total_detections': len(detections),
            'platforms': platforms,
            'tactics': tactics,
            'sources': sources,
            'average_fidelity': round(avg_fidelity, 2)
        }


def main():
    """Main function for testing."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python retrieval.py <knowledge_base_path> [technique_id] [platform]")
        sys.exit(1)

    kb_path = Path(sys.argv[1])
    index_path = kb_path / "embeddings" / "vector_store.faiss"
    metadata_path = kb_path / "embeddings" / "metadata.json"

    if not index_path.exists():
        print(f"Error: Index not found at {index_path}")
        print("Run: python scripts/config/build_embeddings.py first")
        sys.exit(1)

    retriever = DetectionRetriever(index_path, metadata_path, kb_path)

    # Print statistics
    print()
    print("=" * 70)
    print("Knowledge Base Statistics")
    print("=" * 70)
    stats = retriever.get_statistics()
    print(f"Total Detections: {stats['total_detections']}")
    print(f"Average Fidelity: {stats['average_fidelity']}")
    print()
    print("By Platform:")
    for platform, count in sorted(stats['platforms'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {platform}: {count}")
    print()

    # Test search if technique provided
    if len(sys.argv) >= 3:
        technique_id = sys.argv[2]
        platform = sys.argv[3] if len(sys.argv) >= 4 else None

        print("=" * 70)
        print(f"Searching for: {technique_id}" + (f" on {platform}" if platform else ""))
        print("=" * 70)
        print()

        results = retriever.search_by_technique(technique_id, platform=platform, top_k=5)

        if not results:
            print("No results found")
        else:
            for i, result in enumerate(results, 1):
                print(f"{i}. Similarity: {result['similarity']:.3f}")
                print(f"   Technique: {result['metadata']['technique_id']} - {result['metadata']['technique_name']}")
                print(f"   Platform: {result['metadata']['platform']}")
                print(f"   Fidelity: {result['metadata']['fidelity_score']}")
                print(f"   Source: {result['metadata']['source']}")
                print(f"   File: {result['file_path']}")
                print()


if __name__ == "__main__":
    main()

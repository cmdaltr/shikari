"""
Embedding generation for detection examples.

Generates vector embeddings from detection examples for similarity search.
"""

import os
import json
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import yaml


class EmbeddingGenerator:
    """
    Generate embeddings for detection examples using sentence transformers.

    Uses a lightweight model that runs locally without GPU requirements.
    """

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        """
        Initialize embedding generator.

        Args:
            model_name: Name of sentence-transformers model to use
        """
        self.model_name = model_name
        self.model = None
        self._load_model()

    def _load_model(self):
        """Load the embedding model."""
        try:
            from sentence_transformers import SentenceTransformer
            print(f"Loading embedding model: {self.model_name}")
            # Use local_files_only to avoid SSL issues with HuggingFace
            # Fall back to online if local cache doesn't exist
            try:
                self.model = SentenceTransformer(self.model_name, local_files_only=True)
            except Exception:
                print("Local model not found, downloading...")
                self.model = SentenceTransformer(self.model_name)
            print("✓ Model loaded successfully")
        except ImportError:
            print("Error: sentence-transformers not installed")
            print("Install with: pip install sentence-transformers")
            raise
        except Exception as e:
            print(f"Error loading model: {e}")
            raise

    def generate_embedding(self, text: str) -> np.ndarray:
        """
        Generate embedding for a single text.

        Args:
            text: Text to embed

        Returns:
            Numpy array of embeddings
        """
        if not self.model:
            raise RuntimeError("Model not loaded")

        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding

    def generate_embeddings_batch(self, texts: List[str], batch_size: int = 32) -> np.ndarray:
        """
        Generate embeddings for multiple texts.

        Args:
            texts: List of texts to embed
            batch_size: Batch size for processing

        Returns:
            Numpy array of embeddings (shape: [num_texts, embedding_dim])
        """
        if not self.model:
            raise RuntimeError("Model not loaded")

        embeddings = self.model.encode(
            texts,
            convert_to_numpy=True,
            batch_size=batch_size,
            show_progress_bar=True
        )

        return embeddings

    def create_detection_text(self, detection: Dict) -> str:
        """
        Create searchable text representation of a detection.

        Combines technique ID, name, platform, and query for embedding.

        Args:
            detection: Detection dictionary

        Returns:
            Text representation for embedding
        """
        parts = []

        # Technique information
        if 'technique_id' in detection:
            parts.append(f"Technique: {detection['technique_id']}")

        if 'technique_name' in detection:
            parts.append(f"Name: {detection['technique_name']}")

        # Tactic
        if 'tactic' in detection:
            parts.append(f"Tactic: {detection['tactic']}")

        # Platform
        if 'platform' in detection:
            parts.append(f"Platform: {detection['platform']}")

        # Query/detection logic
        if 'query' in detection:
            query = detection['query']
            if isinstance(query, str):
                # Truncate very long queries
                query_text = query[:500] if len(query) > 500 else query
                parts.append(f"Query: {query_text}")

        # Explanation/description
        if 'explanation' in detection:
            explanation = detection['explanation']
            if isinstance(explanation, str):
                explanation_text = explanation[:300] if len(explanation) > 300 else explanation
                parts.append(f"Description: {explanation_text}")

        return " | ".join(parts)

    def load_detections_from_kb(self, kb_path: Path) -> Tuple[List[Dict], List[Path]]:
        """
        Load all detection examples from knowledge base.

        Args:
            kb_path: Path to knowledge base directory

        Returns:
            Tuple of (detections list, file paths list)
        """
        detections = []
        file_paths = []

        detection_dir = kb_path / "detection_examples"
        if not detection_dir.exists():
            print(f"Warning: Detection examples directory not found: {detection_dir}")
            return detections, file_paths

        print(f"Loading detections from: {detection_dir}")

        # Find all YAML files
        yaml_files = list(detection_dir.glob("**/*.yaml")) + list(detection_dir.glob("**/*.yml"))

        print(f"Found {len(yaml_files)} detection files")

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    detection = yaml.safe_load(f)

                if detection and isinstance(detection, dict):
                    detections.append(detection)
                    file_paths.append(yaml_file)

            except Exception as e:
                print(f"Warning: Error loading {yaml_file.name}: {e}")

        print(f"✓ Loaded {len(detections)} detections")

        return detections, file_paths

    def build_index(
        self,
        kb_path: Path,
        output_path: Path,
        index_type: str = "faiss"
    ) -> Dict:
        """
        Build vector index from knowledge base.

        Args:
            kb_path: Path to knowledge base
            output_path: Path to save index
            index_type: Type of index ('faiss' or 'annoy')

        Returns:
            Dictionary with build statistics
        """
        print("=" * 70)
        print("Building Vector Index")
        print("=" * 70)
        print()

        # Load detections
        detections, file_paths = self.load_detections_from_kb(kb_path)

        if not detections:
            print("Error: No detections found in knowledge base")
            return {'success': False, 'error': 'No detections found'}

        # Generate text representations
        print("Generating text representations...")
        texts = [self.create_detection_text(d) for d in detections]

        # Generate embeddings
        print("Generating embeddings...")
        embeddings = self.generate_embeddings_batch(texts)

        print(f"✓ Generated {len(embeddings)} embeddings")
        print(f"  Embedding dimension: {embeddings.shape[1]}")

        # Build index
        if index_type == "faiss":
            index = self._build_faiss_index(embeddings)
        else:
            raise ValueError(f"Unsupported index type: {index_type}")

        # Save index
        output_path.mkdir(parents=True, exist_ok=True)

        if index_type == "faiss":
            index_file = output_path / "vector_store.faiss"
            self._save_faiss_index(index, index_file)

        # Save metadata
        metadata = {
            'file_paths': [str(p.relative_to(kb_path)) for p in file_paths],
            'detections': [
                {
                    'technique_id': d.get('technique_id'),
                    'technique_name': d.get('technique_name'),
                    'platform': d.get('platform'),
                    'tactic': d.get('tactic'),
                    'fidelity_score': d.get('fidelity_score'),
                    'source': d.get('source'),
                }
                for d in detections
            ],
            'index_type': index_type,
            'model_name': self.model_name,
            'embedding_dim': int(embeddings.shape[1]),
            'num_vectors': len(embeddings),
            'build_date': str(Path(output_path).stat().st_mtime)
        }

        metadata_file = output_path / "metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        print(f"✓ Saved index to: {index_file}")
        print(f"✓ Saved metadata to: {metadata_file}")

        stats = {
            'success': True,
            'num_detections': len(detections),
            'embedding_dim': int(embeddings.shape[1]),
            'index_file': str(index_file),
            'metadata_file': str(metadata_file)
        }

        print()
        print("=" * 70)
        print("Build Complete")
        print("=" * 70)
        print(f"Detections indexed: {stats['num_detections']}")
        print(f"Embedding dimension: {stats['embedding_dim']}")
        print()

        return stats

    def _build_faiss_index(self, embeddings: np.ndarray):
        """Build FAISS index from embeddings."""
        try:
            import faiss
        except ImportError:
            print("Error: faiss not installed")
            print("Install with: pip install faiss-cpu")
            raise

        # Normalize embeddings for cosine similarity
        faiss.normalize_L2(embeddings)

        # Create index
        dimension = embeddings.shape[1]
        index = faiss.IndexFlatIP(dimension)  # Inner product (cosine similarity)

        # Add vectors
        index.add(embeddings.astype('float32'))

        print(f"✓ Built FAISS index with {index.ntotal} vectors")

        return index

    def _save_faiss_index(self, index, output_file: Path):
        """Save FAISS index to file."""
        import faiss
        faiss.write_index(index, str(output_file))


def main():
    """Main function for testing."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python embeddings.py <knowledge_base_path>")
        sys.exit(1)

    kb_path = Path(sys.argv[1])
    output_path = kb_path / "embeddings"

    generator = EmbeddingGenerator()
    stats = generator.build_index(kb_path, output_path)

    if stats['success']:
        print("Success!")
    else:
        print(f"Failed: {stats.get('error')}")
        sys.exit(1)


if __name__ == "__main__":
    main()

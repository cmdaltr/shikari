#!/usr/bin/env python3
"""
Build vector embeddings for detection knowledge base.

This script generates embeddings for all detection examples and builds
a FAISS index for fast similarity search.

Usage:
    python scripts/build_embeddings.py
    python scripts/build_embeddings.py --kb-path data/external/detections
    python scripts/build_embeddings.py --model sentence-transformers/all-MiniLM-L6-v2
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from archer.rag.embeddings import EmbeddingGenerator


def main():
    parser = argparse.ArgumentParser(
        description="Build vector embeddings for detection knowledge base",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Build embeddings with default settings
  python scripts/build_embeddings.py

  # Use custom knowledge base path
  python scripts/build_embeddings.py --kb-path /path/to/kb

  # Use different embedding model
  python scripts/build_embeddings.py --model sentence-transformers/all-mpnet-base-v2

Models:
  - all-MiniLM-L6-v2: Fast, 384 dimensions (default)
  - all-mpnet-base-v2: Better quality, 768 dimensions, slower
  - all-MiniLM-L12-v2: Balance of speed and quality, 384 dimensions
        """
    )

    parser.add_argument(
        '--kb-path',
        type=Path,
        default=Path('data/external/detections'),
        help='Path to external detections directory (default: data/external/detections)'
    )

    parser.add_argument(
        '--output',
        type=Path,
        help='Output directory for embeddings (default: <kb-path>/embeddings)'
    )

    parser.add_argument(
        '--model',
        type=str,
        default='sentence-transformers/all-MiniLM-L6-v2',
        help='Sentence transformers model to use (default: all-MiniLM-L6-v2)'
    )

    parser.add_argument(
        '--incremental',
        action='store_true',
        help='Incremental build (only process new files)'
    )

    args = parser.parse_args()

    # Set output path
    output_path = args.output or (args.kb_path / 'embeddings')

    # Check if KB exists
    if not args.kb_path.exists():
        print(f"Error: Knowledge base not found at {args.kb_path}")
        print("Run setup first: python scripts/setup_knowledge_base.py")
        sys.exit(1)

    detection_examples = args.kb_path / 'detection_examples'
    if not detection_examples.exists():
        print(f"Error: No detection examples found at {detection_examples}")
        print("Import community rules first: python scripts/import_community_rules.py --all")
        sys.exit(1)

    # Count detection files
    yaml_files = list(detection_examples.glob("**/*.yaml")) + list(detection_examples.glob("**/*.yml"))
    if not yaml_files:
        print(f"Error: No YAML files found in {detection_examples}")
        print("Import community rules first: python scripts/import_community_rules.py --all")
        sys.exit(1)

    print(f"Found {len(yaml_files)} detection files")
    print()

    # Build embeddings
    try:
        generator = EmbeddingGenerator(model_name=args.model)
        stats = generator.build_index(
            kb_path=args.kb_path,
            output_path=output_path
        )

        if stats['success']:
            print()
            print("✓ Embeddings built successfully!")
            print()
            print("Next steps:")
            print("  1. Test retrieval:")
            print(f"     python scripts/test_retrieval.py --technique T1003.001 --platform Splunk")
            print()
            print("  2. Test enhancement:")
            print(f"     python scripts/test_enhancement.py --technique T1003.001")
            print()
            print("  3. Use in Archer:")
            print(f"     python archer.py generate APT29")
            print()
        else:
            print(f"✗ Failed to build embeddings: {stats.get('error')}")
            sys.exit(1)

    except KeyboardInterrupt:
        print()
        print("Build cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

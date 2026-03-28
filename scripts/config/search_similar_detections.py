#!/usr/bin/env python3
"""
Test detection retrieval from knowledge base.

This script tests the RAG retrieval system by searching for similar
detection examples.

Usage:
    python scripts/config/search_similar_detections.py --technique T1003.001 --platform Splunk
    python scripts/config/search_similar_detections.py --technique T1059.001 --top-k 10
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from archer.ai.rag.knowledge_base import DetectionKnowledgeBase


def main():
    parser = argparse.ArgumentParser(
        description="Test detection retrieval from knowledge base",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Search for LSASS memory dump detections on Splunk
  python scripts/config/search_similar_detections.py --technique T1003.001 --platform Splunk

  # Search for PowerShell execution with more results
  python scripts/config/search_similar_detections.py --technique T1059.001 --top-k 10

  # Search with minimum fidelity threshold
  python scripts/config/search_similar_detections.py --technique T1003.001 --min-fidelity 0.85
        """
    )

    parser.add_argument(
        '--technique',
        required=True,
        help='MITRE ATT&CK technique ID (e.g., T1003.001)'
    )

    parser.add_argument(
        '--platform',
        choices=['Splunk', 'MicrosoftThreatProtection', 'Elastic', 'GoogleSecOps'],
        help='Platform to search for (optional)'
    )

    parser.add_argument(
        '--top-k',
        type=int,
        default=5,
        help='Number of results to return (default: 5)'
    )

    parser.add_argument(
        '--min-fidelity',
        type=float,
        default=0.7,
        help='Minimum fidelity score (default: 0.7)'
    )

    parser.add_argument(
        '--kb-path',
        type=Path,
        default=Path('data/external/detections'),
        help='Path to external detections (default: data/external/detections)'
    )

    parser.add_argument(
        '--show-query',
        action='store_true',
        help='Show full query content'
    )

    args = parser.parse_args()

    # Initialize KB
    print("Initializing knowledge base...")
    kb = DetectionKnowledgeBase(kb_path=args.kb_path, auto_build=False)

    if not kb.is_available():
        print()
        print("Error: Knowledge base not available")
        print()
        print("Make sure you have:")
        print("  1. Imported community rules: python scripts/config/import_community_rules.py --all")
        print("  2. Built embeddings: python scripts/config/build_embeddings.py")
        sys.exit(1)

    # Show KB stats
    print()
    print("=" * 70)
    print("Knowledge Base Statistics")
    print("=" * 70)
    stats = kb.get_statistics()
    print(f"Total Detections: {stats['total_detections']}")
    print(f"Average Fidelity: {stats['average_fidelity']}")
    print()

    # Search
    print("=" * 70)
    search_desc = f"Searching: {args.technique}"
    if args.platform:
        search_desc += f" on {args.platform}"
    print(search_desc)
    print("=" * 70)
    print()

    results = kb.find_similar_detections(
        technique_id=args.technique,
        platform=args.platform,
        top_k=args.top_k,
        min_fidelity=args.min_fidelity
    )

    if not results:
        print("No results found")
        print()
        if args.platform:
            print(f"Try searching without platform filter:")
            print(f"  python scripts/config/search_similar_detections.py --technique {args.technique}")
        if args.min_fidelity > 0.7:
            print(f"Try lowering fidelity threshold:")
            print(f"  python scripts/config/search_similar_detections.py --technique {args.technique} --min-fidelity 0.6")
        sys.exit(0)

    # Display results
    for i, result in enumerate(results, 1):
        detection = result['detection']
        metadata = result['metadata']

        print(f"{i}. {metadata['technique_name']}")
        print(f"   Technique: {metadata['technique_id']}")
        print(f"   Platform: {metadata['platform']}")
        print(f"   Tactic: {metadata['tactic']}")
        print(f"   Fidelity: {metadata['fidelity_score']}")
        print(f"   Similarity: {result['similarity']:.3f}")
        print(f"   Source: {metadata.get('source', 'unknown')}")
        print(f"   File: {result['file_path']}")

        if args.show_query:
            query = detection.get('query', 'N/A')
            if isinstance(query, str):
                # Truncate long queries
                if len(query) > 300:
                    query_preview = query[:300] + "..."
                else:
                    query_preview = query
                print(f"\n   Query Preview:\n   {query_preview}\n")
            print()
        else:
            print()

    print("=" * 70)
    print(f"Found {len(results)} similar detections")
    print("=" * 70)
    print()

    if not args.show_query and results:
        print("Tip: Use --show-query to see full query content")
        print()


if __name__ == "__main__":
    main()

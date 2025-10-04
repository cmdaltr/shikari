#!/usr/bin/env python3
"""
Correlation Query Builder Script

This script reads YAML detection files, assesses their relevance based on threat groups,
platforms, attack paths, and severity, then builds correlation searches combining
related queries. Results are saved to a JSON output file.

Usage:
    python gorgon/parsers/correlations.py [--yaml-dir PATH] [--output PATH] [--min-queries N]

Examples:
    # Use defaults (data/queries -> data/correlations/correlation_queries.json)
    python gorgon/parsers/correlations.py

    # Specify custom paths
    python gorgon/parsers/correlations.py --yaml-dir ./detections --output ./results.json

    # Require at least 3 queries per correlation
    python gorgon/parsers/correlations.py --min-queries 3
"""

import argparse
import sys
import os
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from gorgon.genai import build_correlation_queries


def main():
    parser = argparse.ArgumentParser(
        description="Build correlation queries from YAML detection files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Use defaults
  %(prog)s

  # Custom paths
  %(prog)s --yaml-dir ./my-detections --output ./correlations.json

  # Require 3+ queries per correlation
  %(prog)s --min-queries 3
        """
    )

    parser.add_argument(
        '--yaml-dir',
        type=str,
        default=None,
        help='Directory containing YAML detection files (default: data/queries)'
    )

    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Output JSON file path (default: data/correlations/correlation_queries.json)'
    )

    parser.add_argument(
        '--min-queries',
        type=int,
        default=2,
        help='Minimum number of queries to include in a correlation (default: 2)'
    )

    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    # Print banner
    print("=" * 70)
    print("Correlation Query Builder")
    print("=" * 70)
    print()

    try:
        result = build_correlation_queries(
            yaml_dir=args.yaml_dir,
            output_file=args.output,
            min_queries=args.min_queries
        )

        print()
        print("=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"Total queries analyzed: {result['total_queries_analyzed']}")
        print(f"Correlations built: {result['total_correlations']}")
        print(f"Minimum queries per correlation: {result['min_queries_per_correlation']}")
        print()

        if args.verbose and result['total_correlations'] > 0:
            print("Correlation Details:")
            print("-" * 70)
            for corr in result['correlations']:
                print(f"\n{corr['correlation_id']}: {corr['name']}")
                print(f"  Platform: {corr['platform']}")
                print(f"  Threat Groups: {', '.join(corr['threat_groups'])}")
                print(f"  Tactics: {', '.join(corr['tactics'][:5])}{'...' if len(corr['tactics']) > 5 else ''}")
                print(f"  Queries: {corr['query_count']}")

        print()
        print(f"✓ Output saved to: {args.output or 'data/correlations/correlation_queries.json'}")
        print()

        return 0

    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("\nPlease ensure the YAML directory exists and contains detection files.", file=sys.stderr)
        return 1

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

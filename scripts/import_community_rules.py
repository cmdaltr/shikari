#!/usr/bin/env python3
"""
Community Detection Rules Importer

Imports detection rules from community repositories:
- Sigma Project (https://github.com/SigmaHQ/sigma)
- Splunk Security Content (https://github.com/splunk/security_content)
- Elastic Detection Rules (https://github.com/elastic/detection-rules)
- Microsoft Sentinel (https://github.com/Azure/Azure-Sentinel)

Usage:
    python scripts/import_community_rules.py --source sigma
    python scripts/import_community_rules.py --source splunk
    python scripts/import_community_rules.py --all
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from archer.importers import SigmaImporter, SplunkImporter, ElasticImporter


def import_sigma(input_dir: Path, output_dir: Path, min_level: str = 'medium'):
    """Import Sigma rules."""
    print("=" * 70)
    print("Importing Sigma Rules")
    print("=" * 70)
    print()

    sigma_rules_path = input_dir / "rules"
    if not sigma_rules_path.exists():
        print(f"Error: Sigma rules directory not found: {sigma_rules_path}")
        print("Please clone the Sigma repository first:")
        print("  cd data/external/repos")
        print("  git clone https://github.com/SigmaHQ/sigma.git")
        return None

    importer = SigmaImporter(str(sigma_rules_path), str(output_dir))
    stats = importer.import_all(min_level=min_level)

    return stats


def import_splunk(input_dir: Path, output_dir: Path, min_risk_score: int = 40):
    """Import Splunk Security Content."""
    print("=" * 70)
    print("Importing Splunk Security Content")
    print("=" * 70)
    print()

    if not input_dir.exists():
        print(f"Error: Splunk repository not found: {input_dir}")
        print("Please clone the Splunk Security Content repository first:")
        print("  cd data/external/repos")
        print("  git clone https://github.com/splunk/security_content.git")
        return None

    importer = SplunkImporter(str(input_dir), str(output_dir))
    stats = importer.import_all(min_risk_score=min_risk_score)

    return stats


def import_elastic(input_dir: Path, output_dir: Path, min_severity: str = 'medium'):
    """Import Elastic Detection Rules."""
    print("=" * 70)
    print("Importing Elastic Detection Rules")
    print("=" * 70)
    print()

    if not input_dir.exists():
        print(f"Error: Elastic repository not found: {input_dir}")
        print("Please clone the Elastic Detection Rules repository first:")
        print("  cd data/external/repos")
        print("  git clone https://github.com/elastic/detection-rules.git elastic")
        return None

    importer = ElasticImporter(str(input_dir), str(output_dir))
    stats = importer.import_all(min_severity=min_severity)

    return stats


def import_sentinel(input_dir: Path, output_dir: Path):
    """Import Microsoft Sentinel rules."""
    print("=" * 70)
    print("Importing Microsoft Sentinel Rules")
    print("=" * 70)
    print()

    # TODO: Implement Sentinel importer
    print("Sentinel importer coming soon...")
    return {'imported': 0}


def main():
    parser = argparse.ArgumentParser(
        description="Import community detection rules into Archer knowledge base",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import Sigma rules (medium and above)
  python scripts/import_community_rules.py --source sigma

  # Import Sigma rules (high and critical only)
  python scripts/import_community_rules.py --source sigma --min-level high

  # Import Splunk Security Content
  python scripts/import_community_rules.py --source splunk

  # Import all sources
  python scripts/import_community_rules.py --all

Prerequisites:
  Clone community repositories first:
    cd data/external/repos
    git clone https://github.com/SigmaHQ/sigma.git
    git clone https://github.com/splunk/security_content.git
    git clone https://github.com/elastic/detection-rules.git
    git clone https://github.com/Azure/Azure-Sentinel.git
        """
    )

    parser.add_argument(
        '--source',
        choices=['sigma', 'splunk', 'elastic', 'sentinel'],
        help='Source repository to import from'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Import from all available sources'
    )

    parser.add_argument(
        '--input',
        type=Path,
        default=Path('data/external/repos'),
        help='Input directory containing cloned repositories (default: data/external/repos)'
    )

    parser.add_argument(
        '--output',
        type=Path,
        default=Path('data/external/detections'),
        help='Output directory for external detections (default: data/external/detections)'
    )

    parser.add_argument(
        '--min-level',
        choices=['low', 'medium', 'high', 'critical'],
        default='medium',
        help='Minimum rule level to import (default: medium)'
    )

    parser.add_argument(
        '--update',
        action='store_true',
        help='Update existing rules (overwrite)'
    )

    args = parser.parse_args()

    if not args.source and not args.all:
        parser.error("Either --source or --all must be specified")

    # Ensure output directory exists
    args.output.mkdir(parents=True, exist_ok=True)

    total_stats = {
        'sigma': None,
        'splunk': None,
        'elastic': None,
        'sentinel': None
    }

    # Import from specified source(s)
    if args.all or args.source == 'sigma':
        sigma_path = args.input / 'sigma'
        if sigma_path.exists():
            total_stats['sigma'] = import_sigma(sigma_path, args.output, args.min_level)
            print()
        else:
            print(f"Warning: Sigma repository not found at {sigma_path}")
            print("Run: cd data/external/repos && git clone https://github.com/SigmaHQ/sigma.git")
            print()

    if args.all or args.source == 'splunk':
        splunk_path = args.input / 'splunk'
        if splunk_path.exists():
            total_stats['splunk'] = import_splunk(splunk_path, args.output)
            print()
        else:
            print(f"Warning: Splunk Security Content not found at {splunk_path}")
            print("Run: cd data/external/repos && git clone https://github.com/splunk/security_content.git splunk")
            print()

    if args.all or args.source == 'elastic':
        elastic_path = args.input / 'elastic'
        if elastic_path.exists():
            total_stats['elastic'] = import_elastic(elastic_path, args.output)
            print()
        else:
            print(f"Warning: Elastic Detection Rules not found at {elastic_path}")
            print("Run: cd data/external/repos && git clone https://github.com/elastic/detection-rules.git elastic")
            print()

    if args.all or args.source == 'sentinel':
        sentinel_path = args.input / 'Azure-Sentinel'
        if sentinel_path.exists():
            total_stats['sentinel'] = import_sentinel(sentinel_path, args.output)
            print()
        else:
            print(f"Warning: Microsoft Sentinel rules not found at {sentinel_path}")
            print("Run: cd data/external/repos && git clone https://github.com/Azure/Azure-Sentinel.git")
            print()

    # Print summary
    print("=" * 70)
    print("IMPORT SUMMARY")
    print("=" * 70)
    total_imported = 0
    for source, stats in total_stats.items():
        if stats:
            imported = stats.get('imported', 0)
            total_imported += imported
            print(f"{source.capitalize()}: {imported} rules imported")

    print(f"\nTotal: {total_imported} rules imported to knowledge base")
    print(f"Location: {args.output}/detection_examples/")
    print()
    print("Next steps:")
    print("  1. Review imported rules")
    print("  2. Build vector embeddings: python scripts/build_embeddings.py")
    print("  3. Test retrieval: python scripts/test_retrieval.py --technique T1003.001")
    print()


if __name__ == "__main__":
    main()

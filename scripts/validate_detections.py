#!/usr/bin/env python3
"""
Detection Validation Script

Validates detection queries in the knowledge base.

Usage:
    python scripts/validate_detections.py                    # Validate all detections
    python scripts/validate_detections.py --platform Splunk  # Validate only Splunk
    python scripts/validate_detections.py --query "..."      # Validate a single query
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from archer.validation.test_runner import TestRunner


def main():
    parser = argparse.ArgumentParser(
        description="Validate detection queries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate all detections in knowledge base
  python scripts/validate_detections.py

  # Validate only Splunk detections
  python scripts/validate_detections.py --platform Splunk

  # Validate a single query
  python scripts/validate_detections.py --query 'index=windows EventCode=4688' --platform Splunk

  # Generate detailed report
  python scripts/validate_detections.py --report
        """
    )

    parser.add_argument(
        '--platform',
        type=str,
        help='Validate only detections for specific platform (Splunk, Elastic, etc.)'
    )

    parser.add_argument(
        '--query',
        type=str,
        help='Validate a single query string'
    )

    parser.add_argument(
        '--kb-path',
        type=Path,
        default=Path('data/external/detections'),
        help='Path to external detections (default: data/external/detections)'
    )

    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate detailed validation report'
    )

    parser.add_argument(
        '--save',
        action='store_true',
        default=True,
        help='Save validation results (default: True)'
    )

    args = parser.parse_args()

    # Initialize test runner
    test_runner = TestRunner(str(args.kb_path))

    # Validate single query
    if args.query:
        if not args.platform:
            print("Error: --platform required when validating a single query")
            return 1

        print(f"Validating query for platform: {args.platform}")
        print()

        result = test_runner.test_query(args.query, args.platform)

        print("Query Validation Results:")
        print("=" * 70)

        if result['passed']:
            print("✓ Query passed validation")
        else:
            print("✗ Query failed validation")

        if result['errors']:
            print()
            print("Errors:")
            for error in result['errors']:
                print(f"  - {error}")

        if result['warnings']:
            print()
            print("Warnings:")
            for warning in result['warnings']:
                print(f"  - {warning}")

        if result['suggestions']:
            print()
            print("Suggestions:")
            for suggestion in result['suggestions']:
                print(f"  - {suggestion}")

        return 0 if result['passed'] else 1

    # Validate all detections
    results = test_runner.run_all_tests()

    # Generate report
    if args.report:
        print()
        report = test_runner.generate_report(results)
        print(report)

        # Save report to file
        report_path = Path('data/validation/validation_results')
        report_path.mkdir(parents=True, exist_ok=True)

        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = report_path / f'validation_report_{timestamp}.txt'

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)

        print()
        print(f"Report saved to: {report_file}")

    # Return exit code based on results
    return 0 if results['failed'] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

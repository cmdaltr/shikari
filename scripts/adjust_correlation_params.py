#!/usr/bin/env python3
"""
Test Correlation Parameters

This script tests different correlation parameter configurations and reports
the number of correlations generated.

Usage:
    python scripts/test_correlation_params.py --threshold 0.40 --per-vendor 25 --tech-freq 20
    python scripts/test_correlation_params.py -t 40 -v 25 -f 20
"""

import argparse
import json
import time
import subprocess
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def update_correlation_config(threshold, per_vendor, tech_freq):
    """Update correlation configuration files with new parameters"""
    print(f"Updating configuration files...")
    print(f"  - Threshold: {threshold*100:.0f}%")
    print(f"  - Per-vendor limit: {per_vendor}")
    print(f"  - Tech frequency limit: {tech_freq}")

    # Update config.py
    config_path = os.path.join(os.path.dirname(__file__), '..', 'archer', 'config.py')
    with open(config_path, 'r') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if 'correlation_min_relevance = float(os.getenv("CORRELATION_MIN_RELEVANCE"' in line:
            lines[i] = f'    correlation_min_relevance = float(os.getenv("CORRELATION_MIN_RELEVANCE", "{threshold}"))\n'

    with open(config_path, 'w') as f:
        f.writelines(lines)

    # Update engine.py
    engine_path = os.path.join(os.path.dirname(__file__), '..', 'archer', 'genai', 'engine.py')
    with open(engine_path, 'r') as f:
        content = f.read()

    # Update max_per_vendor parameter default (handle any existing value)
    import re
    content = re.sub(
        r'max_per_vendor: int = \d+',
        f'max_per_vendor: int = {per_vendor}',
        content
    )

    # Update tech frequency limit
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'if max_occurrences <' in line and 'simple correlations' in line:
            lines[i] = f'            if max_occurrences < {tech_freq}:  # Allow each technique in up to {tech_freq} simple correlations'
            break

    with open(engine_path, 'w') as f:
        f.write('\n'.join(lines))

    print("  ✓ Configuration files updated\n")
    time.sleep(3)  # Wait for server reload


def trigger_generation():
    """Trigger correlation generation via API"""
    print("Triggering correlation generation...")

    result = subprocess.run([
        'curl', '-s', '-X', 'POST',
        'http://127.0.0.1:8000/generate',
        '-H', 'Content-Type: application/x-www-form-urlencoded',
        '-d', 'group_name=Scattered+Spider&run_correlation=true'
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"  ✗ Failed to trigger generation: {result.stderr}")
        return False

    print("  ✓ Generation triggered\n")
    return True


def wait_for_completion(timeout=300):
    """Wait for generation to complete"""
    print("Waiting for generation to complete...")

    progress_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'progress', 'Scattered Spider.json')
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            with open(progress_path, 'r') as f:
                progress = json.load(f)
                status = progress.get('status', '')

                if status == 'complete':
                    print("  ✓ Generation complete\n")
                    return True

                # Show progress
                processed = progress.get('processed', 0)
                total = progress.get('total_pairs', 1)
                pct = (processed / total * 100) if total > 0 else 0
                print(f"  Progress: {processed}/{total} ({pct:.1f}%) - {status}    ", end='\r')
        except:
            pass

        time.sleep(2)

    print("  ✗ Generation timed out")
    return False


def get_correlation_count():
    """Get the number of correlations generated"""
    corr_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'correlate', 'Scattered Spider.json')

    try:
        with open(corr_path, 'r') as f:
            data = json.load(f)
            vendor_correlations = data.get('vendor_correlations', [])

            # Count by vendor
            vendor_counts = {}
            for corr in vendor_correlations:
                vendor = corr.get('vendor', 'unknown')
                vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

            return {
                'total': len(vendor_correlations),
                'by_vendor': vendor_counts
            }
    except Exception as e:
        print(f"  ✗ Error reading correlations: {e}")
        return {'total': 0, 'by_vendor': {}}


def main():
    parser = argparse.ArgumentParser(
        description='Test correlation parameters and report the number of correlations generated.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with 40% threshold, 25 per-vendor limit, and 20 tech frequency limit
  %(prog)s --threshold 0.40 --per-vendor 25 --tech-freq 20

  # Same as above using short options and percentage notation
  %(prog)s -t 40 -v 25 -f 20

  # Test with high limits
  %(prog)s -t 30 -v 100 -f 40

Parameters:
  Threshold:
    Minimum relevance score (0-100%%) required for correlations.
    Higher values = fewer, higher-quality correlations.
    Recommended: 30-50%%

  Per-Vendor Limit:
    Maximum correlations per vendor (MDE, Splunk, etc.).
    Higher values allow more correlations per vendor.
    Recommended: 25-50

  Tech Frequency Limit:
    Maximum times a technique can appear as first technique in correlations.
    Higher values allow more correlations using popular techniques.
    Recommended: 20-30
        """
    )

    parser.add_argument(
        '-t', '--threshold',
        type=float,
        required=True,
        metavar='PERCENT',
        help='Correlation relevance threshold (0-100%% or 0.0-1.0). Example: 40 or 0.40'
    )

    parser.add_argument(
        '-v', '--per-vendor',
        type=int,
        required=True,
        metavar='COUNT',
        help='Maximum correlations per vendor. Example: 25'
    )

    parser.add_argument(
        '-f', '--tech-freq',
        type=int,
        required=True,
        metavar='COUNT',
        help='Maximum technique frequency limit. Example: 20'
    )

    args = parser.parse_args()

    # Normalize threshold to 0.0-1.0 range
    threshold = args.threshold
    if threshold > 1.0:
        threshold = threshold / 100.0

    # Validate inputs
    if not (0.0 <= threshold <= 1.0):
        parser.error("Threshold must be between 0-100% or 0.0-1.0")

    if args.per_vendor < 1:
        parser.error("Per-vendor limit must be at least 1")

    if args.tech_freq < 1:
        parser.error("Tech frequency limit must be at least 1")

    print("=" * 80)
    print("CORRELATION PARAMETER TEST")
    print("=" * 80)
    print()

    # Update configuration
    update_correlation_config(threshold, args.per_vendor, args.tech_freq)

    # Trigger generation
    if not trigger_generation():
        sys.exit(1)

    # Wait for completion
    if not wait_for_completion():
        sys.exit(1)

    # Get results
    results = get_correlation_count()

    # Display results
    print("=" * 80)
    print("RESULTS")
    print("=" * 80)
    print()
    print(f"Threshold:           {threshold*100:.0f}%")
    print(f"Per-Vendor Limit:    {args.per_vendor}")
    print(f"Tech Frequency:      {args.tech_freq}")
    print()
    print(f"Total Correlations:  {results['total']}")
    print()

    if results['by_vendor']:
        print("By Vendor:")
        for vendor, count in sorted(results['by_vendor'].items()):
            print(f"  - {vendor:15s}: {count:3d} correlations")
    print()
    print("=" * 80)


if __name__ == '__main__':
    main()

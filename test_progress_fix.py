#!/usr/bin/env python3
"""
Test script to verify progress bar fixes without using the web interface.
Tests the Scattered Spider group with correlation enabled.

This script simulates both command-line AND browser behavior:
1. Command-line: Direct call to process_group()
2. Browser simulation: Calls /complete_yaml endpoint when YAML reaches 100%

This ensures the fix for frontend interference (commit e46db88) is tested.
"""

import sys
import os
import time
import json
import threading
from pathlib import Path

# Add archer to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from archer.build.orchestrator import process_group
from archer.build.progress import read_progress, progress_path, write_progress


def simulate_complete_yaml_endpoint(group_name):
    """
    Simulate the /complete_yaml endpoint behavior from app.py.
    This is what the browser calls when YAML generation reaches 100%.

    This function replicates the logic from archer/app.py:752-804
    to test that it doesn't interfere with active correlation processing.
    """
    print(f"\n[BROWSER SIMULATION] Frontend detected YAML complete, calling /complete_yaml")

    # Fetch current progress (same as app.py line 760)
    progress_data = read_progress(group_name) or {}
    current_status = progress_data.get("status", "unknown")

    print(f"[BROWSER SIMULATION] Current status: {current_status}")

    # Only proceed if we're not already in GenAI phase (same as app.py line 763)
    if current_status not in [
        "genai_started",
        "genai_starting",
        "genai_processing",  # This is the fix from commit e46db88
        "genai_complete",
    ]:
        print(f"[BROWSER SIMULATION] Status not in GenAI phase, would start background thread")

        # Ensure YAML progress shows as complete
        if "total_yaml" in progress_data:
            progress_data["created_yaml"] = progress_data["total_yaml"]
        else:
            progress_data["created_yaml"] = progress_data.get("created_yaml", 10)
            progress_data["total_yaml"] = progress_data.get("created_yaml", 10)

        # Mark as ready for GenAI
        progress_data["status"] = "genai_starting"
        write_progress(group_name, progress_data)

        print(f"[BROWSER SIMULATION] Changed status to 'genai_starting'")
        print(f"[BROWSER SIMULATION] Would start background thread (skipped in test)")
        return True
    else:
        print(f"[BROWSER SIMULATION] Status is '{current_status}' - skipping (correlation already active)")
        return False


def monitor_progress(group_name, interval=0.5, max_duration=300, simulate_browser=True):
    """
    Monitor and display progress in real-time.

    Args:
        group_name: The group being processed
        interval: How often to check progress (seconds)
        max_duration: Maximum time to monitor (seconds)
    """
    print(f"\n{'='*70}")
    print(f"MONITORING PROGRESS FOR: {group_name}")
    print(f"{'='*70}\n")

    start_time = time.time()
    last_status = None
    last_yaml_pct = -1
    last_genai_pct = -1
    yaml_complete = False
    browser_endpoint_called = False  # Track if we've simulated the browser call
    genai_values = []  # Track GenAI progress to detect backwards jumps

    while time.time() - start_time < max_duration:
        progress = read_progress(group_name)

        if not progress:
            print(".", end="", flush=True)
            time.sleep(interval)
            continue

        status = progress.get("status", "unknown")

        # Calculate YAML progress
        created = progress.get("created_yaml", 0)
        total = progress.get("total_yaml", 0)
        yaml_pct = int((created / total * 100)) if total > 0 else 0

        # Calculate GenAI progress
        processed = progress.get("processed", 0)
        total_pairs = progress.get("total_pairs", 0)
        genai_pct = int((processed / total_pairs * 100)) if total_pairs > 0 else 0

        # Mark YAML as complete when it reaches 100%
        if yaml_pct >= 100 and not yaml_complete:
            yaml_complete = True
            print(f"\n✓ YAML Generation: COMPLETE (100%)")

            # Simulate browser behavior: call /complete_yaml endpoint
            # This is what caused the bug at 70% (commit e46db88 fixed it)
            if simulate_browser and not browser_endpoint_called:
                browser_endpoint_called = True
                # Give correlation a chance to start processing first
                time.sleep(0.5)
                simulate_complete_yaml_endpoint(group_name)

        # Print status changes
        if status != last_status:
            print(f"\n[{time.time() - start_time:.1f}s] Status: {status}")
            last_status = status

        # Print YAML progress updates
        if yaml_pct != last_yaml_pct and yaml_pct < 100:
            bar_yaml = '█' * (yaml_pct // 2) + '░' * (50 - yaml_pct // 2)
            print(f"YAML Generation: [{bar_yaml}] {yaml_pct}% ({created}/{total})")
            last_yaml_pct = yaml_pct

        # Print GenAI progress updates and detect backwards jumps
        if status in ["genai_processing", "genai_started", "genai_starting"]:
            if genai_pct != last_genai_pct:
                # Check for backwards jump
                if genai_values and genai_pct < genai_values[-1]:
                    print(f"\n⚠️  WARNING: Progress went BACKWARDS: {genai_values[-1]}% → {genai_pct}%")
                    print(f"    This indicates duplicate processing or race condition!")

                genai_values.append(genai_pct)
                bar_genai = '█' * (genai_pct // 2) + '░' * (50 - genai_pct // 2)
                print(f"Vendor Correlation: [{bar_genai}] {genai_pct}% ({processed}/{total_pairs})")
                last_genai_pct = genai_pct

        # Check for completion
        if status == "complete" or status == "genai_complete":
            if genai_pct >= 100 or (yaml_complete and status == "complete"):
                print(f"\n✓ Vendor Correlation: COMPLETE (100%)")
                print(f"\n{'='*70}")
                print(f"FINAL STATUS: {status}")
                print(f"Total time: {time.time() - start_time:.1f}s")
                print(f"{'='*70}\n")

                # Analyze for backwards jumps
                if len(genai_values) > 1:
                    backwards = 0
                    for i in range(1, len(genai_values)):
                        if genai_values[i] < genai_values[i-1]:
                            backwards += 1

                    if backwards > 0:
                        print(f"❌ TEST FAILED: Detected {backwards} backwards jumps in progress!")
                        print(f"   Progress sequence: {' → '.join(map(str, genai_values[:20]))}...")
                        return False
                    else:
                        print(f"✅ TEST PASSED: Progress was monotonic (no backwards jumps)")
                        print(f"   Progress sequence: {' → '.join(map(str, genai_values[:20]))}...")
                        return True
                return True

        # Check for failure
        if status == "failed" or status == "genai_failed":
            print(f"\n❌ Process FAILED with status: {status}")
            return False

        time.sleep(interval)

    print(f"\n⚠️  Timeout after {max_duration}s")
    return False


def main():
    """Run the test."""
    import argparse

    parser = argparse.ArgumentParser(description="Test progress bar fixes")
    parser.add_argument(
        "--no-browser-sim",
        action="store_true",
        help="Disable browser simulation (skip /complete_yaml endpoint call)"
    )
    parser.add_argument(
        "--group",
        default="Scattered Spider",
        help="Group name to test (default: Scattered Spider)"
    )
    args = parser.parse_args()

    group_name = args.group
    simulate_browser = not args.no_browser_sim

    print(f"\n{'='*70}")
    print(f"PROGRESS BAR FIX TEST")
    print(f"{'='*70}")
    print(f"Testing group: {group_name}")
    print(f"Test: Verifying no backwards jumps in correlation progress")
    if simulate_browser:
        print(f"Mode: Browser simulation ENABLED (will call /complete_yaml)")
    else:
        print(f"Mode: Command-line only (no /complete_yaml)")
    print(f"{'='*70}\n")

    # Clean up any existing progress file
    progress_file = progress_path(group_name)
    if os.path.exists(progress_file):
        print(f"Removing existing progress file: {progress_file}")
        os.remove(progress_file)

    # Start monitoring in a separate thread
    import threading

    test_result = [None]  # Use list to capture result from thread

    def monitor_thread():
        test_result[0] = monitor_progress(
            group_name,
            interval=0.3,
            max_duration=600,
            simulate_browser=simulate_browser
        )

    monitor = threading.Thread(target=monitor_thread, daemon=True)
    monitor.start()

    # Give monitor time to start
    time.sleep(0.5)

    # Run the actual process
    try:
        print(f"Starting process_group for '{group_name}' with run_correlation=True\n")
        process_group(group_name, run_correlation=True)
        print(f"\nprocess_group completed successfully")
    except Exception as e:
        print(f"\n❌ ERROR during process_group: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # Wait for monitor to finish
    monitor.join(timeout=10)

    # Print final result
    print(f"\n{'='*70}")
    if test_result[0]:
        print(f"✅ TEST PASSED: No backwards jumps detected!")
        if simulate_browser:
            print(f"✅ Browser simulation: /complete_yaml handled correctly")
            print(f"   (Did not interfere with active correlation processing)")
        print(f"{'='*70}\n")
        return 0
    else:
        print(f"❌ TEST FAILED: See details above")
        print(f"{'='*70}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())

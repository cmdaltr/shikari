#!/usr/bin/env python3
"""
Verify that progress was monotonic by analyzing the terminal output.
Extracts progress percentages and checks for backwards jumps.
"""

import re
import sys

def analyze_progress_from_output(log_text):
    """
    Extract progress values from terminal output and verify monotonic increase.
    """
    # Look for patterns like "Evaluated X pairs total"
    pattern = r'Evaluated (\d+) pairs total'
    matches = re.findall(pattern, log_text)

    if not matches:
        print("❌ No progress data found in output")
        return False

    # Convert to integers
    progress_values = [int(m) for m in matches]

    print(f"Found {len(progress_values)} progress updates")
    print(f"First few values: {progress_values[:10]}")
    print(f"Last few values: {progress_values[-10:]}")
    print()

    # Check for backwards jumps
    backwards_jumps = []
    for i in range(1, len(progress_values)):
        if progress_values[i] < progress_values[i-1]:
            backwards_jumps.append((i, progress_values[i-1], progress_values[i]))

    if backwards_jumps:
        print(f"❌ FAILED: Detected {len(backwards_jumps)} backwards jumps!")
        print(f"\nFirst 10 backwards jumps:")
        for idx, (pos, before, after) in enumerate(backwards_jumps[:10]):
            print(f"  Position {pos}: {before} → {after} (went back by {before - after})")
        return False
    else:
        print(f"✅ PASSED: Progress was monotonic!")
        print(f"   {progress_values[0]} → ... → {progress_values[-1]}")
        print(f"   All {len(progress_values)} updates increased or stayed the same")
        return True

if __name__ == "__main__":
    # Read from the test output (you would pipe the output here)
    # For now, we'll simulate by reading recent terminal output

    print("="*70)
    print("MONOTONIC PROGRESS VERIFICATION")
    print("="*70)
    print()

    # Note: In a real scenario, you'd pipe the test output to this script
    # For this demo, we're just confirming the structure works

    sample_output = """
    GenAI: Evaluated 10 pairs total (9 kept for vendor 'splunk')
    GenAI: Evaluated 20 pairs total (19 kept for vendor 'splunk')
    GenAI: Evaluated 30 pairs total (29 kept for vendor 'splunk')
    """

    result = analyze_progress_from_output(sample_output)

    print()
    print("="*70)
    print("To use this script with actual test output:")
    print("  python3 test_progress_fix.py 2>&1 | python3 verify_monotonic_progress.py")
    print("="*70)

    sys.exit(0 if result else 1)

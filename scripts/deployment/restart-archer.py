#!/usr/bin/env python3
"""
restart-archer.py - Restart the Archer application
Uses only standard library - no external dependencies
"""

import subprocess
import sys
import time
from pathlib import Path


def get_script_dir():
    """Get the directory containing this script."""
    return Path(__file__).parent


def get_python():
    """Get the Python executable."""
    return sys.executable


def main():
    port = 8000
    background = False
    reload_enabled = True

    # Parse arguments
    args = sys.argv[1:]
    pass_through_args = []

    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ["-p", "--port"] and i + 1 < len(args):
            port = int(args[i + 1])
            pass_through_args.extend([arg, args[i + 1]])
            i += 2
        elif arg in ["-b", "--background"]:
            background = True
            pass_through_args.append(arg)
            i += 1
        elif arg in ["--no-reload"]:
            reload_enabled = False
            pass_through_args.append(arg)
            i += 1
        elif arg in ["-h", "--help"]:
            print("Usage: restart-archer.py [options]")
            print()
            print("Options:")
            print("  -b, --background    Run in background (detached)")
            print("  -p, --port PORT     Specify port (default: 8000)")
            print("  --no-reload         Disable auto-reload")
            print("  -h, --help          Show this help message")
            return 0
        else:
            i += 1

    print("=" * 50)
    print("   ARCHER RESTART")
    print("=" * 50)
    print()

    script_dir = get_script_dir()
    python = get_python()

    # Step 1: Stop Archer
    print("Stopping Archer...")
    stop_script = script_dir / "stop-archer.py"

    if not stop_script.exists():
        print(f"Error: stop-archer.py not found at {stop_script}")
        return 1

    stop_result = subprocess.run(
        [python, str(stop_script), "-p", str(port)],
        capture_output=True,
        text=True
    )

    if stop_result.returncode != 0 and "No Archer processes found" not in stop_result.stdout:
        print("Warning: Stop command returned non-zero exit code")
        if stop_result.stdout:
            print(stop_result.stdout)

    # Wait for processes to fully terminate
    print("Waiting for processes to terminate...")
    time.sleep(2)

    # Step 2: Start Archer
    print()
    print("Starting Archer...")
    start_script = script_dir / "start-archer.py"

    if not start_script.exists():
        print(f"Error: start-archer.py not found at {start_script}")
        return 1

    # Build start command
    start_cmd = [python, str(start_script)] + pass_through_args

    if background:
        # Run start script and return
        result = subprocess.run(start_cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        return result.returncode
    else:
        # Run start script in foreground (will block)
        try:
            subprocess.run(start_cmd)
        except KeyboardInterrupt:
            print("\nStopped.")

    return 0


if __name__ == "__main__":
    sys.exit(main())

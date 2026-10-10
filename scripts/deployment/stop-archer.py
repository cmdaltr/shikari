#!/usr/bin/env python3
"""
stop-archer.py - Stop the Archer application
Uses only standard library - no external dependencies
"""

import subprocess
import sys
import time


def run_command(cmd):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception:
        return ""


def find_processes_by_pattern(pattern):
    """Find PIDs matching a pattern."""
    if sys.platform == "win32":
        # Windows: use WMIC
        output = run_command(
            f'wmic process where "commandline like \'%{pattern}%\'" get processid 2>nul'
        )
        pids = []
        for line in output.split('\n'):
            line = line.strip()
            if line.isdigit():
                pids.append(int(line))
        return pids
    else:
        # Unix: use pgrep
        output = run_command(f"pgrep -f '{pattern}'")
        if output:
            return [int(pid) for pid in output.split('\n') if pid.strip()]
        return []


def find_processes_on_port(port):
    """Find PIDs using a specific port."""
    if sys.platform == "win32":
        output = run_command(f"netstat -ano | findstr :{port} | findstr LISTENING")
        pids = set()
        for line in output.split('\n'):
            parts = line.split()
            if len(parts) >= 5:
                try:
                    pids.add(int(parts[-1]))
                except ValueError:
                    pass
        return list(pids)
    else:
        output = run_command(f"lsof -nP -iTCP:{port} -sTCP:LISTEN -t")
        if output:
            return [int(pid) for pid in output.split('\n') if pid.strip()]
        return []


def get_process_info(pid):
    """Get process command line for a PID."""
    if sys.platform == "win32":
        output = run_command(
            f'wmic process where processid={pid} get commandline 2>nul'
        )
        lines = [l.strip() for l in output.split('\n') if l.strip() and l.strip() != 'CommandLine']
        return lines[0][:80] if lines else "<unknown>"
    else:
        output = run_command(f"ps -p {pid} -o command=")
        return output[:80] if output else "<unknown>"


def kill_process(pid):
    """Kill a single process."""
    if sys.platform == "win32":
        result = run_command(f"taskkill /F /PID {pid} 2>&1")
        return "SUCCESS" in result or "not found" in result.lower()
    else:
        result = run_command(f"kill -9 {pid} 2>&1")
        return "No such process" not in result


def main():
    port = 8000
    verbose = False

    # Parse arguments
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg in ["-p", "--port"] and i + 1 < len(args):
            port = int(args[i + 1])
        elif arg in ["-v", "--verbose"]:
            verbose = True
        elif arg in ["-h", "--help"]:
            print("Usage: stop-archer.py [options]")
            print()
            print("Options:")
            print("  -p, --port PORT     Specify port (default: 8000)")
            print("  -v, --verbose       Show detailed process information")
            print("  -h, --help          Show this help message")
            return 0

    print("=" * 50)
    print("   ARCHER STOP")
    print("=" * 50)
    print()

    all_pids = set()
    found_any = False

    # Find uvicorn processes running archer.app
    pids = find_processes_by_pattern("uvicorn archer.app")
    if pids:
        if verbose:
            print(f"Found {len(pids)} uvicorn process(es)")
        all_pids.update(pids)
        found_any = True

    # Find processes on the specified port
    pids = find_processes_on_port(port)
    if pids:
        if verbose:
            print(f"Found {len(pids)} process(es) on port {port}")
        all_pids.update(pids)
        found_any = True

    # Also check alternative ports 8001-8010
    for alt_port in range(8001, 8011):
        pids = find_processes_on_port(alt_port)
        if pids:
            if verbose:
                print(f"Found {len(pids)} process(es) on port {alt_port}")
            all_pids.update(pids)
            found_any = True

    if not found_any:
        print("No Archer processes found running.")
        return 0

    # Display processes to be killed
    print(f"Found {len(all_pids)} Archer process(es):")
    for pid in all_pids:
        info = get_process_info(pid)
        print(f"  PID {pid}: {info}")

    print()
    print("Stopping processes...")

    # Kill all found processes
    killed = 0
    failed = 0
    for pid in all_pids:
        if kill_process(pid):
            killed += 1
        else:
            failed += 1

    # Wait for processes to terminate
    time.sleep(1)

    # Verify termination
    still_running = 0
    for pid in all_pids:
        if sys.platform == "win32":
            check = run_command(f'tasklist /FI "PID eq {pid}" 2>nul')
            if str(pid) in check:
                still_running += 1
        else:
            check = run_command(f"ps -p {pid} 2>&1")
            if check and "PID" in check:
                still_running += 1

    print()
    if still_running == 0:
        print(f"Successfully stopped {killed} Archer process(es).")
    else:
        print(f"Stopped {killed} process(es), but {still_running} may still be running.")
        print("Try running with elevated privileges or use kill-archer.py for a more thorough cleanup.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

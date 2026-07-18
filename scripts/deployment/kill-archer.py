#!/usr/bin/env python3
"""
kill-archer.py - Kill all Archer-related processes
Uses only standard library - no external dependencies
"""

import subprocess
import sys
import time
import re


def run_command(cmd):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"Error running command: {e}")
        return ""


def find_processes_by_pattern(pattern):
    """Find PIDs matching a pattern using pgrep."""
    output = run_command(f"pgrep -f '{pattern}'")
    if output:
        return [int(pid) for pid in output.split('\n') if pid.strip()]
    return []


def find_processes_on_port(port):
    """Find PIDs using a specific port using lsof."""
    output = run_command(f"lsof -ti:{port}")
    if output:
        return [int(pid) for pid in output.split('\n') if pid.strip()]
    return []


def get_process_info(pid):
    """Get process command line for a PID."""
    try:
        output = run_command(f"ps -p {pid} -o command=")
        return output[:100] if output else "<unknown>"
    except:
        return "<unknown>"


def kill_processes(pids, description):
    """
    Kill a list of PIDs.
    Returns: (killed_count, failed_count)
    """
    if not pids:
        return 0, 0

    # Remove duplicates
    pids = list(set(pids))

    print(f"\nFound {description}:")
    for pid in pids:
        cmd_info = get_process_info(pid)
        print(f"  PID {pid}: {cmd_info}")

    killed = 0
    failed = 0

    for pid in pids:
        result = run_command(f"kill -9 {pid} 2>&1")
        if "No such process" not in result and result == "":
            killed += 1
        else:
            failed += 1
            if result:
                print(f"  ⚠️  Failed to kill PID {pid}: {result}")

    # Wait for processes to die
    time.sleep(0.5)

    # Verify
    still_running = 0
    for pid in pids:
        check = run_command(f"ps -p {pid} 2>&1")
        if check and "No such process" not in check:
            still_running += 1

    if still_running == 0:
        print(f"✅ Successfully killed {killed} process(es)")
    else:
        print(f"⚠️  {still_running} process(es) may still be running")

    return killed, failed


def main():
    print("🔍 Searching for Archer processes...\n")

    total_killed = 0
    total_failed = 0
    found_any = False

    # 1. Kill uvicorn processes running archer.app
    pids = find_processes_by_pattern("uvicorn archer.app")
    if pids:
        killed, failed = kill_processes(pids, "Uvicorn server processes")
        total_killed += killed
        total_failed += failed
        found_any = True

    # 2. Kill Python processes with 'archer' in command line
    pids = find_processes_by_pattern("python.*archer")
    if pids:
        killed, failed = kill_processes(pids, "Python processes in archer directory")
        total_killed += killed
        total_failed += failed
        found_any = True

    # 3. Kill processes using port 8000 (Archer's default port)
    pids = find_processes_on_port(8000)
    if pids:
        killed, failed = kill_processes(pids, "processes using port 8000")
        total_killed += killed
        total_failed += failed
        found_any = True

    # 4. Kill processes using port 8001-8010 (alternative Archer ports)
    for port in range(8001, 8011):
        pids = find_processes_on_port(port)
        if pids:
            killed, failed = kill_processes(pids, f"processes using port {port}")
            total_killed += killed
            total_failed += failed
            found_any = True

    # 5. Kill StatReload processes related to archer
    pids = find_processes_by_pattern("StatReload.*archer")
    if pids:
        killed, failed = kill_processes(pids, "StatReload processes")
        total_killed += killed
        total_failed += failed
        found_any = True

    # 6. Kill git clone processes for OSINT repos
    for repo in ['Azure-Sentinel', 'elastic', 'splunk', 'mitre']:
        pids = find_processes_by_pattern(f"git clone.*{repo}")
        if pids:
            killed, failed = kill_processes(pids, f"Git clone processes for {repo}")
            total_killed += killed
            total_failed += failed
            found_any = True

    # 7. Kill update_osint_repos.py processes
    pids = find_processes_by_pattern("update_osint_repos")
    if pids:
        killed, failed = kill_processes(pids, "OSINT repository update processes")
        total_killed += killed
        total_failed += failed
        found_any = True

    # Summary
    print("\n" + "="*60)
    if not found_any:
        print("✨ No Archer processes found running")
    else:
        print(f"🎯 Killed {total_killed} Archer process(es)")
        if total_failed > 0:
            print(f"⚠️  Failed to kill {total_failed} process(es)")

    # Check for any remaining processes
    print("\n🔍 Checking for any remaining related processes...")

    remaining_pids = set()
    for pattern in ["archer", "uvicorn"]:
        pids = find_processes_by_pattern(pattern)
        remaining_pids.update(pids)

    # Check ports
    for port in range(8000, 8011):
        pids = find_processes_on_port(port)
        remaining_pids.update(pids)

    if remaining_pids:
        print("⚠️  Found some remaining processes:")
        for pid in remaining_pids:
            cmd_info = get_process_info(pid)
            print(f"  PID {pid}: {cmd_info}")
    else:
        print("✅ No remaining Archer processes detected")

    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
status-archer.py - Check the status of the Archer application
Uses only standard library - no external dependencies
"""

import subprocess
import sys
import socket
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError


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
        output = run_command(
            f'wmic process where "commandline like \'%{pattern}%\'" get processid,commandline 2>nul'
        )
        processes = []
        lines = output.split('\n')[1:]  # Skip header
        for line in lines:
            line = line.strip()
            if line:
                parts = line.rsplit(None, 1)
                if len(parts) == 2 and parts[1].isdigit():
                    processes.append((int(parts[1]), parts[0][:60]))
        return processes
    else:
        output = run_command(f"pgrep -f '{pattern}'")
        if not output:
            return []

        processes = []
        for pid in output.split('\n'):
            if pid.strip():
                pid = int(pid.strip())
                cmd = run_command(f"ps -p {pid} -o command=")
                processes.append((pid, cmd[:60] if cmd else "<unknown>"))
        return processes


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
        output = run_command(f"lsof -ti:{port}")
        if output:
            return [int(pid) for pid in output.split('\n') if pid.strip()]
        return []


def check_http_health(host, port, timeout=3):
    """Check if the HTTP server is responding."""
    try:
        url = f"http://{host}:{port}/health"
        response = urlopen(url, timeout=timeout)
        return response.status == 200, "healthy"
    except URLError as e:
        # Try root endpoint
        try:
            url = f"http://{host}:{port}/"
            response = urlopen(url, timeout=timeout)
            return True, "responding"
        except:
            return False, str(e.reason) if hasattr(e, 'reason') else "connection failed"
    except Exception as e:
        return False, str(e)


def check_port_open(port):
    """Check if a port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex(('127.0.0.1', port))
        return result == 0
    finally:
        sock.close()


def get_uptime(pid):
    """Get process uptime."""
    if sys.platform == "win32":
        return None  # Not easily available on Windows
    else:
        output = run_command(f"ps -p {pid} -o etime=")
        return output.strip() if output else None


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
            print("Usage: status-archer.py [options]")
            print()
            print("Options:")
            print("  -p, --port PORT     Specify port (default: 8000)")
            print("  -v, --verbose       Show detailed information")
            print("  -h, --help          Show this help message")
            return 0

    print("=" * 50)
    print("   ARCHER STATUS")
    print("=" * 50)
    print()

    # Check for running processes
    uvicorn_procs = find_processes_by_pattern("uvicorn archer.app")
    port_procs = find_processes_on_port(port)
    port_open = check_port_open(port)
    http_healthy, http_status = check_http_health("127.0.0.1", port)

    # Determine overall status
    if uvicorn_procs and port_open and http_healthy:
        status = "RUNNING"
        status_icon = "[OK]"
    elif uvicorn_procs or port_procs:
        status = "PARTIAL"
        status_icon = "[!!]"
    else:
        status = "STOPPED"
        status_icon = "[--]"

    print(f"Status: {status_icon} {status}")
    print()

    # Port status
    print(f"Port {port}:")
    if port_open:
        print(f"  Port: open")
        print(f"  HTTP: {http_status}")
    else:
        print(f"  Port: closed")

    print()

    # Process information
    print("Processes:")
    if uvicorn_procs:
        for pid, cmd in uvicorn_procs:
            uptime = get_uptime(pid)
            uptime_str = f" (uptime: {uptime})" if uptime else ""
            print(f"  PID {pid}{uptime_str}")
            if verbose:
                print(f"    {cmd}")
    else:
        print("  No uvicorn processes found")

    # Check alternative ports
    alt_ports_in_use = []
    for alt_port in range(8001, 8011):
        if check_port_open(alt_port):
            alt_ports_in_use.append(alt_port)

    if alt_ports_in_use:
        print()
        print("Other ports in use:")
        for p in alt_ports_in_use:
            print(f"  Port {p}: open")

    # Log file status
    log_file = Path(__file__).parent.parent.parent / "logs" / "archer.log"
    if log_file.exists():
        print()
        print(f"Log file: {log_file}")
        if verbose:
            # Show last few lines
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    last_lines = lines[-5:] if len(lines) >= 5 else lines
                    print("  Last log entries:")
                    for line in last_lines:
                        print(f"    {line.rstrip()}")
            except Exception:
                pass

    print()

    # Provide helpful commands
    if status == "STOPPED":
        print("To start Archer:")
        print("  python scripts/deployment/start-archer.py")
    elif status == "RUNNING":
        print("To stop Archer:")
        print("  python scripts/deployment/stop-archer.py")
        print()
        print(f"Web UI: http://127.0.0.1:{port}")

    return 0 if status == "RUNNING" else 1


if __name__ == "__main__":
    sys.exit(main())

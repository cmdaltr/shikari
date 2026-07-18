#!/usr/bin/env python3
"""
start-archer.py - Start the Archer application
Uses only standard library - no external dependencies
"""

import subprocess
import sys
import os
import json
from datetime import datetime
from pathlib import Path


def get_project_root():
    """Get the project root directory."""
    return Path(__file__).parent.parent.parent


def find_python():
    """Find the Python executable to use."""
    root = get_project_root()

    # Check for virtual environment
    venv_python_unix = root / ".venv" / "bin" / "python3"
    venv_python_win = root / ".venv" / "Scripts" / "python.exe"

    if sys.platform == "win32" and venv_python_win.exists():
        return str(venv_python_win)
    elif venv_python_unix.exists():
        return str(venv_python_unix)
    else:
        return sys.executable


def check_port_in_use(port):
    """Check if a port is already in use."""
    if sys.platform == "win32":
        result = subprocess.run(
            f"netstat -ano | findstr :{port}",
            shell=True, capture_output=True, text=True
        )
    else:
        result = subprocess.run(
            f"lsof -ti:{port}",
            shell=True, capture_output=True, text=True
        )
    return bool(result.stdout.strip())


def check_and_build_osint_index(root: Path, python_cmd: str, max_age_hours: float = 24):
    """
    Rebuild the OSINT technique index (data/cache/osint_technique_index.json)
    if it's missing or older than max_age_hours. Uses --skip-clone so this
    never triggers a fresh repo clone (that's update_osint.py's job) -- it
    only re-indexes whatever's already on disk, which takes seconds.

    Non-fatal: archer/build/osint_comparison.py falls back to live OSINT
    searches automatically if the index isn't there, so a failure here
    should never block startup.
    """
    index_path = root / "data" / "cache" / "osint_technique_index.json"
    build_script = root / "scripts" / "data" / "build_osint_index.py"

    if not build_script.exists():
        return

    needs_build = True
    if index_path.exists():
        try:
            with open(index_path) as f:
                data = json.load(f)
            generated_at = datetime.fromisoformat(data["generated_at"].rstrip("Z"))
            age_hours = (datetime.utcnow() - generated_at).total_seconds() / 3600
            needs_build = age_hours > max_age_hours
        except Exception:
            needs_build = True

    if not needs_build:
        return

    print("Building OSINT technique index (missing or stale)...")
    try:
        result = subprocess.run(
            [python_cmd, str(build_script), "--skip-clone"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            print("✓ OSINT technique index ready")
        else:
            print("⚠️  OSINT technique index build failed, continuing without it")
            if result.stderr:
                print(result.stderr[-500:])
    except subprocess.TimeoutExpired:
        print("⚠️  OSINT technique index build timed out, continuing without it")
    except Exception as e:
        print(f"⚠️  Could not build OSINT technique index: {e}")
    print()


def main():
    port = 8000
    host = "0.0.0.0"

    # Parse arguments
    args = sys.argv[1:]
    background = False
    reload_enabled = True
    skip_index = False

    for i, arg in enumerate(args):
        if arg in ["-b", "--background"]:
            background = True
        elif arg in ["-p", "--port"] and i + 1 < len(args):
            port = int(args[i + 1])
        elif arg in ["--no-reload"]:
            reload_enabled = False
        elif arg in ["--skip-index"]:
            skip_index = True
        elif arg in ["-h", "--help"]:
            print("Usage: start-archer.py [options]")
            print()
            print("Options:")
            print("  -b, --background    Run in background (detached)")
            print("  -p, --port PORT     Specify port (default: 8000)")
            print("  --no-reload         Disable auto-reload")
            print("  --skip-index        Don't build/refresh the OSINT technique index")
            print("  -h, --help          Show this help message")
            return 0

    print("=" * 50)
    print("   ARCHER START")
    print("=" * 50)
    print()

    # Check if already running
    if check_port_in_use(port):
        print(f"Port {port} is already in use.")
        print("Archer may already be running. Use status-archer.py to check.")
        print("Use stop-archer.py to stop the existing instance first.")
        return 1

    root = get_project_root()
    python_cmd = find_python()

    if not skip_index:
        check_and_build_osint_index(root, python_cmd)

    print(f"Project root: {root}")
    print(f"Python: {python_cmd}")
    print(f"Port: {port}")
    print(f"Mode: {'background' if background else 'foreground'}")
    print(f"Auto-reload: {'enabled' if reload_enabled else 'disabled'}")
    print()

    # Build uvicorn command
    cmd = [
        python_cmd, "-m", "uvicorn",
        "archer.app:app",
        "--host", host,
        "--port", str(port),
    ]

    if reload_enabled:
        cmd.append("--reload")

    if background:
        print("Starting Archer in background...")

        # Create log directory
        log_dir = root / "logs"
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / "archer.log"

        if sys.platform == "win32":
            # Windows: use start /B
            with open(log_file, "w") as log:
                subprocess.Popen(
                    cmd,
                    cwd=root,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
                )
        else:
            # Unix: use nohup-style background
            with open(log_file, "w") as log:
                subprocess.Popen(
                    cmd,
                    cwd=root,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )

        print(f"Archer started in background on http://{host}:{port}")
        print(f"Logs: {log_file}")
        print()
        print("Use status-archer.py to check status")
        print("Use stop-archer.py to stop the server")
    else:
        print(f"Starting Archer on http://{host}:{port}")
        print("Press Ctrl+C to stop")
        print()

        try:
            subprocess.run(cmd, cwd=root)
        except KeyboardInterrupt:
            print("\nStopped.")

    return 0


if __name__ == "__main__":
    sys.exit(main())

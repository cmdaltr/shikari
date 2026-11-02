#!/usr/bin/env python3
"""
Shikari Clean Start Script (Cross-Platform)

This script:
1. Kills all running Python/uvicorn processes
2. Clears Python cache (__pycache__ and .pyc files)
3. Starts a fresh Shikari server on port 8000

Works on Windows, macOS, and Linux.
"""

import sys
import os
import shutil
import subprocess
import time
from pathlib import Path
import signal


def print_header():
    """Print script header."""
    print("=" * 40)
    print("   SHIKARI CLEAN START SCRIPT")
    print("=" * 40)
    print()
    print("This script will:")
    print("  1. Kill all running Python/uvicorn processes")
    print("  2. Clear Python cache (__pycache__ and .pyc files)")
    print("  3. Start a fresh Shikari server on port 8000")
    print()
    print("WARNING: This will stop ALL Python processes!")
    print()


def confirm():
    """Ask for user confirmation."""
    try:
        response = input("Do you want to continue? (y/N): ").strip().lower()
        return response == 'y'
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.")
        return False


def kill_processes():
    """Kill all Python/uvicorn processes (cross-platform)."""
    print("\n=== SHIKARI CLEAN START ===")
    print("Killing all existing servers...")

    if sys.platform == "win32":
        # Windows
        try:
            # Kill Python processes
            subprocess.run(
                ["taskkill", "/F", "/IM", "python.exe"],
                capture_output=True,
                timeout=10
            )
            subprocess.run(
                ["taskkill", "/F", "/IM", "python3.exe"],
                capture_output=True,
                timeout=10
            )
            subprocess.run(
                ["taskkill", "/F", "/IM", "pythonw.exe"],
                capture_output=True,
                timeout=10
            )
        except Exception as e:
            print(f"Note: Some processes may not exist: {e}")
    else:
        # Unix/Linux/macOS
        try:
            subprocess.run(
                ["killall", "-9", "python3"],
                capture_output=True,
                timeout=10
            )
            subprocess.run(
                ["pkill", "-9", "-f", "uvicorn"],
                capture_output=True,
                timeout=10
            )
        except Exception as e:
            print(f"Note: Some processes may not exist: {e}")

    # Wait for processes to die
    time.sleep(3)


def clear_cache():
    """Clear Python cache files."""
    print("Clearing Python cache...")

    root = Path(__file__).parent.parent

    # Remove __pycache__ directories
    for pycache in root.rglob("__pycache__"):
        try:
            shutil.rmtree(pycache)
        except Exception:
            pass

    # Remove .pyc files
    for pyc in root.rglob("*.pyc"):
        try:
            pyc.unlink()
        except Exception:
            pass


def start_server():
    """Start Shikari server."""
    print("Starting fresh server on port 8000...")

    root = Path(__file__).parent.parent
    venv_python = root / ".venv" / "bin" / "python3"
    venv_python_win = root / ".venv" / "Scripts" / "python.exe"

    # Determine which Python to use
    if venv_python_win.exists():
        python_cmd = str(venv_python_win)
    elif venv_python.exists():
        python_cmd = str(venv_python)
    else:
        python_cmd = sys.executable

    # Start uvicorn
    try:
        subprocess.run(
            [
                python_cmd, "-m", "uvicorn",
                "shikari.app:app",
                "--host", "127.0.0.1",
                "--port", "8000",
                "--reload"
            ],
            cwd=root
        )
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

    print("Server started! Visit http://localhost:8000")


def main():
    """Main function."""
    print_header()

    if not confirm():
        print("Aborted.")
        sys.exit(1)

    kill_processes()
    clear_cache()
    start_server()


if __name__ == "__main__":
    main()

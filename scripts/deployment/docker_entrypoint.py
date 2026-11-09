#!/usr/bin/env python3
"""
Docker entrypoint script for Shikari.

This script checks if OSINT repositories need to be initialized before
starting the Shikari application. Works cross-platform (Linux, Windows, macOS).
"""

import os
import sys
import subprocess
from pathlib import Path


def print_banner():
    """Print the startup banner."""
    print("=" * 50)
    print("  Shikari Docker Entrypoint")
    print("=" * 50)


def check_osint_repos():
    """Check if OSINT repositories are initialized."""
    elastic_path = Path("data/repos/elastic")
    splunk_path = Path("data/repos/splunk")

    return elastic_path.exists() and splunk_path.exists()


def initialize_osint_repos():
    """Initialize OSINT repositories."""
    print()
    print("🔍 OSINT repositories not found. Initializing...")
    print("This will take 15-20 minutes on first run.")
    print()

    try:
        # Run the update script with --force flag
        result = subprocess.run(
            [sys.executable, "scripts/data/update_osint.py", "--force"],
            check=True
        )

        print()
        print("✅ OSINT repositories initialized successfully!")
        return True

    except subprocess.CalledProcessError as e:
        print()
        print(f"⚠️  Warning: OSINT initialization failed: {e}")
        print("Continuing anyway - repositories can be initialized later.")
        return False
    except Exception as e:
        print()
        print(f"⚠️  Warning: Unexpected error during OSINT initialization: {e}")
        print("Continuing anyway - repositories can be initialized later.")
        return False


def main():
    """Main entrypoint logic."""
    print_banner()

    # Check if OSINT repos exist
    if check_osint_repos():
        print("✅ OSINT repositories already present, skipping clone.")
    else:
        initialize_osint_repos()

    print()
    print("🚀 Starting Shikari application...")
    print("=" * 50)
    print()

    # Execute the main command passed to the container
    # In Python, we use os.execvp to replace the current process
    if len(sys.argv) > 1:
        # Get the command and arguments
        cmd = sys.argv[1:]
        # Hot reload for development only (docker compose with SHIKARI_RELOAD=1)
        if os.environ.get("SHIKARI_RELOAD") == "1" and cmd[0] == "uvicorn" and "--reload" not in cmd:
            cmd.append("--reload")
        try:
            os.execvp(cmd[0], cmd)
        except Exception as e:
            print(f"❌ Failed to start application: {e}")
            sys.exit(1)
    else:
        print("❌ No command specified to run")
        sys.exit(1)


if __name__ == "__main__":
    main()

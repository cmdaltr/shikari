#!/usr/bin/env python3
"""
OSINT Repository Update Script for Air-Gapped Environments

This standalone script clones/updates all OSINT detection repositories used by Archer.
It can be run on an internet-connected machine, and the repos can then be copied
to air-gapped environments.

Usage:
    python3 update_osint_repos.py [--force]

Options:
    --force     Force update even if repos were recently updated

Air-Gapped Deployment:
    1. Run this script on an internet-connected machine
    2. Copy the entire 'data/osint_repos/' directory to your air-gapped environment
    3. Place it in the same relative location in your Archer installation
"""

import os
import subprocess
import sys
import json
from pathlib import Path
from datetime import datetime, timedelta
import time
import argparse

# Repository configurations (must match archer/build/osint_repos.py)
REPOS = {
    "sigma": {
        "url": "https://github.com/SigmaHQ/sigma.git",
        "path": "data/osint_repos/sigma",
        "search_dir": "rules",
        "description": "SigmaHQ Detection Rules"
    },
    "elastic": {
        "url": "https://github.com/elastic/detection-rules.git",
        "path": "data/osint_repos/elastic",
        "search_dir": "rules",
        "description": "Elastic Security Detection Rules"
    },
    "mitre_car": {
        "url": "https://github.com/mitre-attack/car.git",
        "path": "data/osint_repos/mitre_car",
        "search_dir": "analytics",
        "description": "MITRE Cyber Analytics Repository"
    },
    "splunk": {
        "url": "https://github.com/splunk/security_content.git",
        "path": "data/osint_repos/splunk",
        "search_dir": "detections",
        "description": "Splunk Security Content"
    },
    "azure_sentinel": {
        "url": "https://github.com/Azure/Azure-Sentinel.git",
        "path": "data/osint_repos/azure_sentinel",
        "search_dir": "Detections",
        "description": "Azure Sentinel Detection Rules"
    }
}

REPOS_BASE_DIR = Path("data/osint_repos")
UPDATE_INTERVAL = timedelta(hours=1)


def print_banner():
    """Print script banner."""
    print("=" * 80)
    print("ARCHER OSINT REPOSITORY UPDATER")
    print("=" * 80)
    print()


def get_last_update_time(repo_name: str) -> datetime | None:
    """Get the last update timestamp for a repo."""
    repo_path = Path(REPOS[repo_name]["path"])
    timestamp_file = repo_path / ".last_update"

    if timestamp_file.exists():
        try:
            with open(timestamp_file) as f:
                timestamp_str = f.read().strip()
                return datetime.fromisoformat(timestamp_str)
        except:
            return None
    return None


def set_last_update_time(repo_name: str):
    """Set the last update timestamp for a repo."""
    repo_path = Path(REPOS[repo_name]["path"])
    timestamp_file = repo_path / ".last_update"

    with open(timestamp_file, "w") as f:
        f.write(datetime.now().isoformat())


def needs_update(repo_name: str) -> bool:
    """Check if a repo needs to be updated."""
    last_update = get_last_update_time(repo_name)

    if last_update is None:
        return True

    return datetime.now() - last_update > UPDATE_INTERVAL


def get_repo_size(repo_path: Path) -> str:
    """Get human-readable size of a repository."""
    try:
        result = subprocess.run(
            ["du", "-sh", str(repo_path)],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.split()[0]
    except:
        pass
    return "unknown"


def clone_or_update_repo(repo_name: str, force: bool = False) -> bool:
    """
    Clone or update a repository.

    Args:
        repo_name: Name of the repo (sigma, elastic, etc.)
        force: Force update even if not needed

    Returns:
        True if successful, False otherwise
    """
    if repo_name not in REPOS:
        print(f"❌ Unknown repository: {repo_name}")
        return False

    repo_config = REPOS[repo_name]
    repo_path = Path(repo_config["path"])

    print(f"\n{'─' * 80}")
    print(f"📦 {repo_config['description']}")
    print(f"{'─' * 80}")

    # Check if update is needed
    if not force and repo_path.exists() and not needs_update(repo_name):
        last_update = get_last_update_time(repo_name)
        size = get_repo_size(repo_path)
        print(f"✓ Already up to date")
        print(f"  Last updated: {last_update.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Size: {size}")
        return True

    # Ensure parent directory exists
    REPOS_BASE_DIR.mkdir(parents=True, exist_ok=True)

    try:
        if repo_path.exists():
            # Update existing repo
            print(f"📥 Updating repository...")
            start_time = time.time()

            result = subprocess.run(
                ["git", "-C", str(repo_path), "pull", "--depth", "1"],
                capture_output=True,
                text=True,
                timeout=900  # 15 minute timeout for large repos
            )

            elapsed = time.time() - start_time

            if result.returncode != 0:
                print(f"⚠️  Git pull failed, attempting fresh clone...")
                # Remove and re-clone
                subprocess.run(["rm", "-rf", str(repo_path)])
                return clone_or_update_repo(repo_name, force=True)

            print(f"✓ Updated in {elapsed:.1f} seconds")
        else:
            # Clone new repo
            print(f"📥 Cloning repository (this may take 10 seconds to 15 minutes depending on size)...")
            start_time = time.time()

            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_config["url"], str(repo_path)],
                capture_output=True,
                text=True,
                timeout=900  # 15 minute timeout for large repos
            )

            elapsed = time.time() - start_time

            if result.returncode != 0:
                print(f"❌ Failed to clone: {result.stderr}")
                return False

            print(f"✓ Cloned in {elapsed:.1f} seconds")

        # Update timestamp
        set_last_update_time(repo_name)

        # Show size
        size = get_repo_size(repo_path)
        print(f"  Size: {size}")

        return True

    except subprocess.TimeoutExpired:
        print(f"❌ Timeout while updating {repo_name}")
        return False
    except Exception as e:
        print(f"❌ Error updating {repo_name}: {e}")
        return False


def get_file_count(search_dir: Path) -> int:
    """Get count of files in a directory."""
    if not search_dir.exists():
        return 0

    try:
        result = subprocess.run(
            ["find", str(search_dir), "-type", "f"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return len([line for line in result.stdout.split('\n') if line.strip()])
    except:
        pass
    return 0


def print_summary(success_count: int, total_count: int):
    """Print summary of update operation."""
    print(f"\n{'=' * 80}")
    print("UPDATE SUMMARY")
    print(f"{'=' * 80}")
    print(f"Repositories processed: {total_count}")
    print(f"Successful updates: {success_count}")
    print(f"Failed updates: {total_count - success_count}")

    if success_count == total_count:
        print("\n✅ All repositories updated successfully!")
    else:
        print(f"\n⚠️  {total_count - success_count} repository/repositories failed to update")

    # Calculate total size
    total_size_mb = 0
    total_files = 0

    print(f"\n{'Repository':<20} {'Size':<10} {'Files':<10} {'Status':<15}")
    print("─" * 80)

    for repo_name, config in REPOS.items():
        repo_path = Path(config["path"])

        if repo_path.exists():
            size = get_repo_size(repo_path)
            search_dir = repo_path / config["search_dir"]
            file_count = get_file_count(search_dir)
            total_files += file_count

            last_update = get_last_update_time(repo_name)
            status = "Ready" if last_update else "Unknown"

            print(f"{repo_name:<20} {size:<10} {file_count:<10} {status:<15}")
        else:
            print(f"{repo_name:<20} {'N/A':<10} {'N/A':<10} {'Not cloned':<15}")

    print("─" * 80)
    print(f"{'TOTAL':<20} {'~455MB':<10} {total_files:<10}")

    print(f"\n📂 Repositories location: {REPOS_BASE_DIR.absolute()}")
    print("\nFor air-gapped deployment:")
    print("  1. Copy the entire 'data/osint_repos/' directory")
    print("  2. Transfer to your air-gapped environment")
    print("  3. Place in the same location relative to your Archer installation")
    print()


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Update OSINT repositories for Archer detection enrichment"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force update even if repos were recently updated"
    )
    args = parser.parse_args()

    print_banner()

    print(f"Starting update process...")
    print(f"Force update: {'Yes' if args.force else 'No'}")
    print(f"Repositories to process: {len(REPOS)}")

    success_count = 0
    total_count = len(REPOS)

    for repo_name in REPOS.keys():
        if clone_or_update_repo(repo_name, force=args.force):
            success_count += 1

    print_summary(success_count, total_count)

    # Exit with appropriate code
    if success_count == total_count:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()

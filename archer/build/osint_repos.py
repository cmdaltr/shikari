"""
OSINT Repository Management

This module manages local clones of OSINT detection repositories for fast,
offline searching without API rate limits.

Repositories:
- SigmaHQ/sigma: Detection rules in Sigma format
- elastic/detection-rules: Elastic Security detection rules

Strategy:
- Clone repos to data/osint_repos/
- Use --depth 1 for shallow clones (faster, smaller)
- Update once per day (check .last_update timestamp)
- Search locally using grep/file scanning
"""

import os
import subprocess
import json
from pathlib import Path
from datetime import datetime, timedelta
import time

# Repository configurations
REPOS = {
    "sigma": {
        "url": "https://github.com/SigmaHQ/sigma.git",
        "path": "data/osint_repos/sigma",
        "search_dir": "rules",
    },
    "elastic": {
        "url": "https://github.com/elastic/detection-rules.git",
        "path": "data/osint_repos/elastic",
        "search_dir": "rules",
    },
    "mitre_car": {
        "url": "https://github.com/mitre-attack/car.git",
        "path": "data/osint_repos/mitre_car",
        "search_dir": "analytics",
    },
    "splunk": {
        "url": "https://github.com/splunk/security_content.git",
        "path": "data/osint_repos/splunk",
        "search_dir": "detections",
    },
    "azure_sentinel": {
        "url": "https://github.com/Azure/Azure-Sentinel.git",
        "path": "data/osint_repos/azure_sentinel",
        "search_dir": "Detections",
    }
}

REPOS_BASE_DIR = Path("data/osint_repos")
UPDATE_INTERVAL = timedelta(hours=1)  # Update every hour


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

    # Check if update is needed
    if not force and repo_path.exists() and not needs_update(repo_name):
        print(f"✓ {repo_name} is up to date (last updated: {get_last_update_time(repo_name)})")
        return True

    # Ensure parent directory exists
    REPOS_BASE_DIR.mkdir(parents=True, exist_ok=True)

    try:
        if repo_path.exists():
            # Update existing repo
            print(f"📥 Updating {repo_name} repository...")
            result = subprocess.run(
                ["git", "-C", str(repo_path), "pull", "--depth", "1"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                print(f"⚠️  Git pull failed for {repo_name}, attempting fresh clone...")
                # Remove and re-clone
                subprocess.run(["rm", "-rf", str(repo_path)])
                return clone_or_update_repo(repo_name, force=True)
        else:
            # Clone new repo
            print(f"📥 Cloning {repo_name} repository (this may take 10-30 seconds)...")
            start_time = time.time()

            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_config["url"], str(repo_path)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            elapsed = time.time() - start_time
            print(f"✓ Cloned {repo_name} in {elapsed:.1f} seconds")

            if result.returncode != 0:
                print(f"❌ Failed to clone {repo_name}: {result.stderr}")
                return False

        # Update timestamp
        set_last_update_time(repo_name)
        print(f"✓ {repo_name} repository ready")
        return True

    except subprocess.TimeoutExpired:
        print(f"❌ Timeout while updating {repo_name}")
        return False
    except Exception as e:
        print(f"❌ Error updating {repo_name}: {e}")
        return False


def ensure_repos_ready() -> bool:
    """
    Ensure all OSINT repos are cloned and up to date.

    Returns:
        True if all repos are ready, False otherwise
    """
    print("🔍 Checking OSINT repositories...")

    all_ready = True
    for repo_name in REPOS.keys():
        if not clone_or_update_repo(repo_name):
            all_ready = False

    return all_ready


def search_repo_for_technique(repo_name: str, technique_id: str) -> list[str]:
    """
    Search a repository for files mentioning a technique ID.

    Args:
        repo_name: Name of the repo to search
        technique_id: MITRE ATT&CK technique ID (e.g., "T1078")

    Returns:
        List of file paths that mention the technique
    """
    if repo_name not in REPOS:
        return []

    repo_config = REPOS[repo_name]
    repo_path = Path(repo_config["path"])
    search_dir = repo_path / repo_config["search_dir"]

    if not search_dir.exists():
        return []

    try:
        # Use grep for fast searching
        result = subprocess.run(
            ["grep", "-r", "-l", technique_id, str(search_dir)],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            files = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            return files
        else:
            return []

    except Exception as e:
        print(f"⚠️  Error searching {repo_name}: {e}")
        return []


def get_repo_stats() -> dict:
    """Get statistics about the local OSINT repos."""
    stats = {}

    for repo_name, config in REPOS.items():
        repo_path = Path(config["path"])

        if not repo_path.exists():
            stats[repo_name] = {"status": "not_cloned"}
            continue

        # Get size
        result = subprocess.run(
            ["du", "-sh", str(repo_path)],
            capture_output=True,
            text=True
        )
        size = result.stdout.split()[0] if result.returncode == 0 else "unknown"

        # Get file count
        search_dir = repo_path / config["search_dir"]
        file_count = 0
        if search_dir.exists():
            result = subprocess.run(
                ["find", str(search_dir), "-type", "f"],
                capture_output=True,
                text=True
            )
            file_count = len(result.stdout.split('\n')) - 1

        stats[repo_name] = {
            "status": "ready",
            "size": size,
            "file_count": file_count,
            "last_update": get_last_update_time(repo_name).isoformat() if get_last_update_time(repo_name) else None
        }

    return stats


if __name__ == "__main__":
    # Test the module
    print("Testing OSINT Repository Management\n")

    # Ensure repos are ready
    ensure_repos_ready()

    # Get stats
    print("\nRepository Statistics:")
    stats = get_repo_stats()
    for repo_name, repo_stats in stats.items():
        print(f"\n{repo_name}:")
        for key, value in repo_stats.items():
            print(f"  {key}: {value}")

    # Test search
    print("\nTesting search for T1078 (Valid Accounts):")
    for repo_name in REPOS.keys():
        files = search_repo_for_technique(repo_name, "T1078")
        print(f"  {repo_name}: Found {len(files)} files")
        if files:
            print(f"    Example: {files[0]}")

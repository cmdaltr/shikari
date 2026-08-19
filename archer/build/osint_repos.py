"""
OSINT Repository Management

This module manages local clones of OSINT detection repositories for fast,
offline searching without API rate limits.

Repositories:
- elastic/detection-rules: Elastic Security detection rules

Strategy:
- Clone repos to data/osint_repos/
- Use --depth 1 for shallow clones (faster, smaller)
- Update once per day (check .last_update timestamp)
- Search locally using grep/file scanning
"""

import os
import shutil
import subprocess
import json
from pathlib import Path
from datetime import datetime, timedelta
import time

# Repository configurations
from ..config import OSINT_REPOS_DIR

# Per-repo clone/pull timeout in seconds. Azure-Sentinel is far larger than the
# other repos (solutions, workbooks, notebooks) and routinely needs several
# minutes even with --depth 1 — a shared 30s timeout killed the clone mid-fetch
# every time, leaving a corrupted .git dir that then failed every retry too.
DEFAULT_TIMEOUT = 60

REPOS = {
    "elastic": {
        "url": "https://github.com/elastic/detection-rules.git",
        "path": os.path.join(OSINT_REPOS_DIR, "elastic"),
        "search_dir": "rules",
        "timeout": DEFAULT_TIMEOUT,
    },
    "mitre_car": {
        "url": "https://github.com/mitre-attack/car.git",
        "path": os.path.join(OSINT_REPOS_DIR, "mitre_car"),
        "search_dir": "analytics",
        "timeout": DEFAULT_TIMEOUT,
    },
    "splunk": {
        "url": "https://github.com/splunk/security_content.git",
        "path": os.path.join(OSINT_REPOS_DIR, "splunk"),
        "search_dir": "detections",
        "timeout": DEFAULT_TIMEOUT,
    },
    "azure_sentinel": {
        "url": "https://github.com/Azure/Azure-Sentinel.git",
        "path": os.path.join(OSINT_REPOS_DIR, "azure_sentinel"),
        "search_dir": "Detections",
        "timeout": 1200,
    }
}

REPOS_BASE_DIR = Path(OSINT_REPOS_DIR)
UPDATE_INTERVAL = timedelta(hours=1)  # Update every hour

# Files renamed after clone/pull, keyed by repo name. Azure-Sentinel ships
# Visa_VTI_Logo.svg under its workbook assets; renamed to VTI-Logo.svg here.
POST_CLONE_RENAMES = {
    "azure_sentinel": {
        "Visa_VTI_Logo.svg": "VTI-Logo.svg",
    },
}


def _apply_post_clone_renames(repo_name: str, repo_path: Path):
    """Rename known files within a freshly cloned/updated repo."""
    renames = POST_CLONE_RENAMES.get(repo_name)
    if not renames:
        return

    for old_name, new_name in renames.items():
        for match in repo_path.rglob(old_name):
            target = match.with_name(new_name)
            if target.exists():
                continue
            match.rename(target)
            print(f"✓ Renamed {match.relative_to(repo_path)} -> {new_name}")


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
        repo_name: Name of the repo (elastic, mitre_car, splunk, azure_sentinel)
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

    timeout = repo_config.get("timeout", DEFAULT_TIMEOUT)

    try:
        if repo_path.exists():
            # Update existing repo
            print(f"📥 Updating {repo_name} repository...")
            result = subprocess.run(
                ["git", "-C", str(repo_path), "pull", "--depth", "1"],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode != 0:
                print(f"⚠️  Git pull failed for {repo_name}, attempting fresh clone...")
                # Remove and re-clone
                shutil.rmtree(repo_path, ignore_errors=True)
                return clone_or_update_repo(repo_name, force=True)
        else:
            # Clone new repo
            print(f"📥 Cloning {repo_name} repository (timeout {timeout}s)...")
            start_time = time.time()

            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_config["url"], str(repo_path)],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            elapsed = time.time() - start_time
            print(f"✓ Cloned {repo_name} in {elapsed:.1f} seconds")

            if result.returncode != 0:
                print(f"❌ Failed to clone {repo_name}: {result.stderr}")
                shutil.rmtree(repo_path, ignore_errors=True)
                return False

        # Apply any post-clone renames before touching the timestamp
        _apply_post_clone_renames(repo_name, repo_path)

        # Update timestamp
        set_last_update_time(repo_name)
        print(f"✓ {repo_name} repository ready")
        return True

    except subprocess.TimeoutExpired:
        print(f"❌ Timeout while updating {repo_name} (exceeded {timeout}s)")
        # A killed clone/pull leaves a corrupted, half-written .git dir behind
        # (broken HEAD, stale shallow.lock) that fails every subsequent retry
        # too — clear it so the next attempt starts from a clean state.
        shutil.rmtree(repo_path, ignore_errors=True)
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

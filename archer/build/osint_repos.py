"""
OSINT Repository Management

This module manages local clones of OSINT detection repositories for fast,
offline searching without API rate limits.

Repositories:
- elastic/detection-rules: Elastic Security detection rules
- splunk/security_content: Splunk Security Content
- Azure/Azure-Sentinel: Microsoft Sentinel analytic rules
- chronicle/detection-rules: Google SecOps YARA-L rules

Strategy:
- Clone repos to data/repos/
- Use --depth 1 for shallow clones (faster, smaller)
- Update once per day (check .last_update timestamp)
- Search locally using grep/file scanning
- Without git (Windows, or a Mac without the developer tools) download GitHub's
  tarball of the default branch instead, keeping only the rule folders
"""

from __future__ import annotations

import os
import shutil
import subprocess
import json
import tarfile
from fnmatch import fnmatch
from pathlib import Path
from datetime import datetime, timedelta
import time

import requests

# Repository configurations
from ..config import OSINT_REPOS_DIR

# Per-repo clone/pull timeout in seconds.
DEFAULT_TIMEOUT = 60

REPOS = {
    "elastic": {
        "url": "https://github.com/elastic/detection-rules.git",
        "path": os.path.join(OSINT_REPOS_DIR, "elastic"),
        "search_dir": "rules",
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
        # Rules live in Detections/ and, since Microsoft moved most of them, in each
        # solution's Analytic Rules/ (about 2,300 rules against 480). The whole repo
        # (workbooks, notebooks, data) is several GB and timed out even at 1200s, so only
        # those folders are checked out, blobless: about 20 MB in seconds
        "search_dirs": ["Detections", "Solutions"],
        "sparse": ["/Detections/", "/Solutions/*/Analytic Rules/"],
        "timeout": 600,
    },
    # Google's YARA-L rules for SecOps. Only rules/community is checked out:
    # rules/_deprecated (most of the repo's .yaral files) and the tooling are left out
    "chronicle": {
        "url": "https://github.com/chronicle/detection-rules.git",
        "path": os.path.join(OSINT_REPOS_DIR, "chronicle"),
        "search_dir": "rules/community",
        "sparse": ["/rules/community/"],
        "timeout": DEFAULT_TIMEOUT,
    },
}

REPOS_BASE_DIR = Path(OSINT_REPOS_DIR)
UPDATE_INTERVAL = timedelta(hours=1)  # Update every hour
# A tarball is the whole branch every time, so it's fetched at most daily, and only when
# the branch has moved. Sparse repos are the huge ones (Azure-Sentinel's tarball is 3.4 GB,
# over 12 minutes on a fast line): weekly
TARBALL_UPDATE_INTERVAL = timedelta(days=1)
SPARSE_TARBALL_UPDATE_INTERVAL = timedelta(days=7)
COMMIT_FILE = ".commit"

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

    if (Path(REPOS[repo_name]["path"]) / ".git").exists():
        interval = UPDATE_INTERVAL
    else:
        interval = SPARSE_TARBALL_UPDATE_INTERVAL if REPOS[repo_name].get("sparse") else TARBALL_UPDATE_INTERVAL
    return datetime.now() - last_update > interval


_GIT = None


def git_available() -> bool:
    """git that can run. On a Mac without the developer tools /usr/bin/git is a stub that
    opens an "install the command line developer tools" dialog, so that counts as no git."""
    global _GIT
    if _GIT is None:
        found = shutil.which("git")
        if found and found == "/usr/bin/git" and os.uname().sysname == "Darwin":
            found = found if subprocess.run(["xcode-select", "-p"], capture_output=True).returncode == 0 else None
        _GIT = bool(found)
        if not _GIT:
            print("git isn't installed: the OSINT detection repositories are downloaded as tarballs")
    return _GIT


def _github_slug(url: str) -> str:
    return url.removeprefix("https://github.com/").removesuffix(".git")


def _wanted(rel: str, sparse: list[str]) -> bool:
    """Whether a path in the repo falls under one of the sparse-checkout patterns, which
    name folders ("/Detections/") and whose * stops at a / as it does in git."""
    parts = rel.split("/")
    for pattern in sparse:
        segs = pattern.strip("/").split("/")
        if len(parts) > len(segs) and all(fnmatch(p, s) for p, s in zip(parts, segs)):
            return True
    return False


def _head_commit(slug: str) -> dict | None:
    """The default branch's latest commit, or None if GitHub won't say (rate limit, offline)."""
    try:
        r = requests.get(f"https://api.github.com/repos/{slug}/commits/HEAD", timeout=15,
                         headers={"Accept": "application/vnd.github+json"})
        r.raise_for_status()
        data = r.json()
        return {"sha": data["sha"], "date": data["commit"]["committer"]["date"]}
    except (requests.RequestException, KeyError, ValueError):
        return None


def _saved_commit(repo_path: Path) -> dict | None:
    try:
        return json.loads((repo_path / COMMIT_FILE).read_text())
    except (OSError, ValueError):
        return None


def commit_date(repo_name: str) -> str | None:
    """YYYY-MM-DD of the commit a tarball download came from."""
    saved = _saved_commit(Path(REPOS[repo_name]["path"]))
    return saved["date"][:10] if saved and saved.get("date") else None


def download_tarball(repo_name: str, timeout: int) -> bool:
    """Fetch the default branch without git and keep only the rule folders. The tarball
    is streamed, so a sparse repo only ever writes its rules to disk."""
    repo_config = REPOS[repo_name]
    repo_path = Path(repo_config["path"])
    slug = _github_slug(repo_config["url"])
    sparse = repo_config.get("sparse")

    head = _head_commit(slug)
    saved = _saved_commit(repo_path)
    if head and saved and head["sha"] == saved.get("sha") and repo_path.exists():
        print(f"✓ {repo_name} hasn't changed since {saved['date'][:10]}")
        return True

    print(f"📥 Downloading {repo_name} (no git, timeout {timeout}s)...")
    start_time = time.time()
    tmp = repo_path.with_name(repo_path.name + ".download")
    shutil.rmtree(tmp, ignore_errors=True)
    root = tmp.resolve()
    try:
        with requests.get(f"https://codeload.github.com/{slug}/tar.gz/HEAD", stream=True, timeout=60) as r:
            r.raise_for_status()
            with tarfile.open(fileobj=r.raw, mode="r|gz") as tar:
                for member in tar:
                    if time.time() - start_time > timeout:
                        raise TimeoutError
                    # Names are "<repo>-<sha>/<path>"; links are skipped rather than trusted
                    rel = member.name.partition("/")[2]
                    if not rel or not member.isfile() or (sparse and not _wanted(rel, sparse)):
                        continue
                    target = tmp / rel
                    if not target.resolve().is_relative_to(root):
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
    except TimeoutError:
        print(f"❌ Timeout while downloading {repo_name} (exceeded {timeout}s)")
        shutil.rmtree(tmp, ignore_errors=True)
        return False
    except (requests.RequestException, tarfile.TarError, OSError) as e:
        print(f"❌ Failed to download {repo_name}: {e}")
        shutil.rmtree(tmp, ignore_errors=True)
        return False

    tmp.mkdir(exist_ok=True)
    if head:
        (tmp / COMMIT_FILE).write_text(json.dumps(head))
    shutil.rmtree(repo_path, ignore_errors=True)
    tmp.rename(repo_path)
    print(f"✓ Downloaded {repo_name} in {time.time() - start_time:.1f} seconds")
    return True


def clone_or_update_repo(repo_name: str, force: bool = False) -> bool:
    """
    Clone or update a repository.

    Args:
        repo_name: Name of the repo (elastic, splunk, azure_sentinel, chronicle)
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

    if not git_available():
        # A whole-branch download takes far longer than a blobless sparse clone; a stalled
        # one still fails after 60s without data
        if not download_tarball(repo_name, 3600 if repo_config.get("sparse") else max(timeout, 300)):
            return False
        _apply_post_clone_renames(repo_name, repo_path)
        set_last_update_time(repo_name)
        print(f"✓ {repo_name} repository ready")
        return True

    try:
        if repo_path.exists() and not (repo_path / ".git").exists():
            # A tarball download from before git was installed: clone over it
            shutil.rmtree(repo_path, ignore_errors=True)
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

            sparse = repo_config.get("sparse")
            cmd = ["git", "clone", "--depth", "1"]
            if sparse:
                cmd += ["--filter=blob:none", "--sparse"]
            result = subprocess.run(
                cmd + [repo_config["url"], str(repo_path)],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if result.returncode == 0 and sparse:
                result = subprocess.run(
                    ["git", "-C", str(repo_path), "sparse-checkout", "set", "--no-cone", *sparse],
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


def search_paths(repo_name: str) -> list[Path]:
    """The folders of a repo that hold its rules (those that exist)."""
    repo_config = REPOS[repo_name]
    repo_path = Path(repo_config["path"])
    dirs = repo_config.get("search_dirs") or [repo_config["search_dir"]]
    return [repo_path / d for d in dirs if (repo_path / d).exists()]


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

    dirs = search_paths(repo_name)
    if not dirs:
        return []

    try:
        if not shutil.which("grep"):
            # Windows: the same substring match grep -l makes
            needle = technique_id.encode()
            return [str(f) for d in dirs for f in d.rglob("*") if f.is_file() and needle in f.read_bytes()]

        # Use grep for fast searching
        result = subprocess.run(
            ["grep", "-r", "-l", technique_id, *map(str, dirs)],
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

        # Get size (du and find don't exist on Windows)
        total = sum(f.stat().st_size for f in repo_path.rglob("*") if f.is_file())
        size = f"{total / 1048576:.0f}M"

        # Get file count
        search_dir = repo_path / config["search_dir"]
        file_count = sum(1 for f in search_dir.rglob("*") if f.is_file()) if search_dir.exists() else 0

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

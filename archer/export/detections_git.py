"""
Detections as code (#20): export a run to a git repository and diff two exports.

Each export writes the run's detection YAMLs to stable paths —
``<group>/<siem>/<technique_id>_<name>.yaml`` — and commits them, so a Regenerate after an ATT&CK
release becomes a commit whose diff shows exactly which queries were added, removed or changed.
Plain subprocess git, no GitPython dependency. No AI.
"""

import os
import re
import subprocess
from typing import Dict, List, Optional

CONNECTOR_SIEM = {"GoogleSecOps": "secops", "MicrosoftThreatProtection": "mde",
                  "Splunk": "splunk", "Elastic": "elastic"}
_GIT_ID = ["-c", "user.name=Archer", "-c", "user.email=archer@localhost"]


def _run(repo: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=check)
    except FileNotFoundError:
        # Windows doesn't come with git, and the installed app doesn't bundle it
        raise RuntimeError("git isn't installed: install it from git-scm.com to export detections") from None


def ensure_repo(repo: str) -> None:
    """Create the repo with an empty initial commit if it isn't one already."""
    os.makedirs(repo, exist_ok=True)
    if not os.path.isdir(os.path.join(repo, ".git")):
        _run(repo, "init", "-q")
        _run(repo, *_GIT_ID, "commit", "--allow-empty", "-q", "-m", "Archer detections repository")


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "")).strip("_") or "x"


def _siem_of(doc: dict) -> str:
    connector = ((doc.get("requiredDataConnectors") or [{}])[0] or {}).get("connectorId", "")
    return CONNECTOR_SIEM.get(connector, _slug(connector).lower() or "other")


def export_run(group: str, generate_dir: str, repo: str, list_files, message: Optional[str] = None,
               exclude_unavailable: bool = True) -> Dict:
    """Write a group's current detections into the repo under <group>/ and commit.

    list_files(group, generate_dir) -> [yaml paths] (inject group_yaml_files). Returns the commit
    sha, the paths written, and the name-status against the previous commit. With
    exclude_unavailable, a detection that needs a data source the estate doesn't ingest (#12) is
    left out of the commit rather than pushed as a rule that can never fire; the excluded ones are
    returned in `excluded`."""
    import yaml

    from archer.build.availability import load as _load_avail, missing_sources

    ensure_repo(repo)
    avail = _load_avail() if exclude_unavailable else {}
    group_dir = os.path.join(repo, _slug(group))
    # Rewrite the group's tree each export so removed detections disappear from the diff
    if os.path.isdir(group_dir):
        _run(repo, "rm", "-r", "-q", "--ignore-unmatch", _slug(group), check=False)
        # rm may leave the working copy; clear any residue
        for root, _dirs, files in os.walk(group_dir, topdown=False):
            for f in files:
                os.remove(os.path.join(root, f))
    written = []
    excluded = []
    for name in list_files(group, generate_dir):
        path = os.path.join(generate_dir, os.path.basename(name))
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            doc = yaml.safe_load(text) or {}
        except (OSError, ValueError, yaml.YAMLError):
            continue
        if exclude_unavailable and avail:
            miss = missing_sources(doc, avail)
            if miss:
                excluded.append({"file": os.path.basename(name),
                                 "missing": sorted({m["dataType"] for m in miss})})
                continue
        tid = _slug(doc.get("technique_id") or "T0000")
        siem = _siem_of(doc)
        # Keep the original filename (it encodes the technique and the data table) so several
        # detections for one technique+SIEM stay distinct instead of overwriting each other.
        stem = _slug(os.path.splitext(os.path.basename(name))[0])
        rel = os.path.join(_slug(group), siem, f"{tid}_{stem}.yaml")
        dest = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(text)
        written.append(rel)

    _run(repo, "add", "-A", _slug(group))
    status = _run(repo, "status", "--porcelain", "--", _slug(group)).stdout.strip()
    if not status:
        head = _run(repo, "rev-parse", "HEAD").stdout.strip()
        return {"committed": False, "commit": head, "files": written, "changes": [], "excluded": excluded}
    msg = message or f"{group}: {len(written)} detections"
    _run(repo, *_GIT_ID, "commit", "-q", "-m", msg, "--", _slug(group))
    head = _run(repo, "rev-parse", "HEAD").stdout.strip()
    name_status = _run(repo, "diff", "--name-status", "--no-renames", "HEAD~1", "HEAD", "--", _slug(group), check=False).stdout
    return {"committed": True, "commit": head, "branch": _branch(repo), "files": written,
            "changes": _parse_name_status(name_status), "excluded": excluded}


def _branch(repo: str) -> str:
    return _run(repo, "rev-parse", "--abbrev-ref", "HEAD", check=False).stdout.strip() or "main"


def _parse_name_status(text: str) -> List[Dict]:
    out = []
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            code = parts[0][0]
            out.append({"status": {"A": "added", "D": "removed", "M": "changed"}.get(code, code), "path": parts[-1]})
    return out


def list_commits(repo: str, group: Optional[str] = None, limit: int = 50) -> List[Dict]:
    """Recent commits (optionally only those touching a group), newest first."""
    if not os.path.isdir(os.path.join(repo, ".git")):
        return []
    args = ["log", f"-{limit}", "--pretty=%H%x1f%cI%x1f%s"]
    if group:
        args += ["--", _slug(group)]
    out = _run(repo, *args, check=False).stdout
    commits = []
    for line in out.splitlines():
        sha, date, subject = (line.split("\x1f") + ["", "", ""])[:3]
        if sha:
            commits.append({"sha": sha, "short": sha[:10], "date": date, "subject": subject})
    return commits


def diff_runs(repo: str, ref_a: str, ref_b: str, group: Optional[str] = None) -> Dict:
    """Added / removed / changed detections between two commits (optionally within one group)."""
    if not os.path.isdir(os.path.join(repo, ".git")):
        return {"added": [], "removed": [], "changed": []}
    args = ["diff", "--name-status", "--no-renames", ref_a, ref_b]
    if group:
        args += ["--", _slug(group)]
    changes = _parse_name_status(_run(repo, *args, check=False).stdout)
    out = {"added": [], "removed": [], "changed": []}
    for c in changes:
        bucket = {"added": "added", "removed": "removed", "changed": "changed"}.get(c["status"])
        if bucket:
            out[bucket].append(c["path"])
    return out

"""
OSINT Technique Index

Builds and serves a prebuilt reverse index mapping MITRE ATT&CK technique IDs
to matching detection rules across every cloned OSINT repository (Elastic,
Splunk, Azure Sentinel, Google SecOps).

Without this index, osint_comparison.py searches live on every request: a
`grep -r` subprocess per technique per repo. Building the index walks each
repo exactly once, extracting every technique ID mentioned in every rule
file in a single pass, so query generation becomes a dict lookup instead.

Technique IDs are pulled directly from each file's raw text via a shared
regex rather than parsing each format's specific "this rule covers T1234"
field -- this mirrors exactly what the live `grep -r -l <technique_id>`
search already matches, so the index and the old live search agree on what
counts as a match.
"""

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import toml
import yaml as yaml_lib

from ..config import DATA_DIR
from .osint_repos import REPOS, search_paths

INDEX_PATH = Path(DATA_DIR) / "cache" / "osint_technique_index.json"
TECHNIQUE_ID_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

_GITHUB_BASE = {
    "elastic": ("https://github.com/elastic/detection-rules/blob", "main"),
    "splunk": ("https://github.com/splunk/security_content/blob", "develop"),
    "azure_sentinel": ("https://github.com/Azure/Azure-Sentinel/blob", "master"),
    "chronicle": ("https://github.com/chronicle/detection-rules/blob", "main"),
}


def _github_url(repo_name: str, repo_path: Path, file_path: Path) -> str:
    base, branch = _GITHUB_BASE[repo_name]
    rel = str(file_path.relative_to(repo_path)).replace("\\", "/")
    return f"{base}/{branch}/{rel}"


# Known false positives, the way LoFP (br0k3nlab.com/LoFP) collects them: from each rule's
# own false_positives (Elastic) or known_false_positives (Splunk). Boilerplate that says
# nothing ("None identified", "Unknown") is dropped.
_FP_BOILERPLATE = re.compile(
    r"^\s*(none|n/?a|unknown|tbd)\b|\bno (known )?false positives?\b|false positives? (are|is|should be) "
    r"(very |highly |extremely )?(un(known|likely)|not (known|expected|likely))|\bnone (are )?(known|identified|expected)",
    re.I)


def _false_positives(value) -> List[str]:
    items = value if isinstance(value, list) else [value] if value else []
    out = []
    for item in items:
        text = " ".join(str(item).split())
        if len(text) >= 25 and not (len(text) < 160 and _FP_BOILERPLATE.search(text)) and text not in out:
            out.append(text[:600])
    return out[:4]


def _index_elastic(repo_path: Path) -> Dict[str, List[Dict]]:
    index: Dict[str, List[Dict]] = {}
    search_dir = repo_path / REPOS["elastic"]["search_dir"]
    if not search_dir.exists():
        return index

    for file_path in search_dir.rglob("*.toml"):
        try:
            raw = file_path.read_text(errors="ignore")
        except Exception:
            continue
        technique_ids = set(TECHNIQUE_ID_RE.findall(raw))
        if not technique_ids:
            continue
        try:
            rule_data = toml.loads(raw)
        except Exception:
            continue
        rule_section = rule_data.get("rule", {})
        query = rule_section.get("query", "")
        if not query:
            continue
        entry = {
            "name": rule_section.get("name", file_path.name),
            "source_url": _github_url("elastic", repo_path, file_path),
            "query_snippet": query[:500],
        }
        fps = _false_positives(rule_section.get("false_positives"))
        if fps:
            entry["false_positives"] = fps
        for tid in technique_ids:
            index.setdefault(tid, []).append(entry)
    return index


def _index_splunk(repo_path: Path) -> Dict[str, List[Dict]]:
    index: Dict[str, List[Dict]] = {}
    search_dir = repo_path / REPOS["splunk"]["search_dir"]
    if not search_dir.exists():
        return index

    for file_path in search_dir.rglob("*.yml"):
        try:
            raw = file_path.read_text(errors="ignore")
        except Exception:
            continue
        technique_ids = set(TECHNIQUE_ID_RE.findall(raw))
        if not technique_ids:
            continue
        try:
            detection_data = yaml_lib.safe_load(raw)
        except Exception:
            continue
        if not isinstance(detection_data, dict):
            continue
        search_query = detection_data.get("search", "")
        if not search_query:
            continue
        entry = {
            "name": detection_data.get("name", file_path.name),
            "source_url": _github_url("splunk", repo_path, file_path),
            "query_snippet": search_query[:500],
        }
        fps = _false_positives(detection_data.get("known_false_positives"))
        if fps:
            entry["false_positives"] = fps
        for tid in technique_ids:
            index.setdefault(tid, []).append(entry)
    return index


def _index_azure_sentinel(repo_path: Path) -> Dict[str, List[Dict]]:
    index: Dict[str, List[Dict]] = {}
    files = [f for d in search_paths("azure_sentinel") for pattern in ("*.yaml", "*.yml", "*.json")
             for f in d.rglob(pattern)]
    for file_path in files:
        try:
            raw = file_path.read_text(errors="ignore")
        except Exception:
            continue
        technique_ids = set(TECHNIQUE_ID_RE.findall(raw))
        if not technique_ids:
            continue
        try:
            rule_data = yaml_lib.safe_load(raw)
        except Exception:
            try:
                rule_data = json.loads(raw)
            except Exception:
                continue
        if not isinstance(rule_data, dict):
            continue
        query = rule_data.get("query", rule_data.get("Query", ""))
        if not query:
            continue
        entry = {
            "name": rule_data.get("name", rule_data.get("displayName", file_path.name)),
            "source_url": _github_url("azure_sentinel", repo_path, file_path),
            "query_snippet": query[:500],
        }
        for tid in technique_ids:
            index.setdefault(tid, []).append(entry)
    return index


_YARAL_RULE_RE = re.compile(r'^\s*rule\s+(\w+)\s*\{', re.M)
_YARAL_SECTION_RE = re.compile(r'^\s*(meta|events|match|outcome|condition|options)\s*:', re.M)
_YARAL_DESC_RE = re.compile(r'^\s*description\s*=\s*"([^"]*)"', re.M)


def _index_chronicle(repo_path: Path) -> Dict[str, List[Dict]]:
    """YARA-L rules: technique IDs from each rule's meta block (technique = "T1098",
    mitre_attack_technique = ...), the events section onwards as the snippet."""
    index: Dict[str, List[Dict]] = {}
    for search_dir in search_paths("chronicle"):
        for file_path in search_dir.rglob("*.yaral"):
            try:
                raw = file_path.read_text(errors="ignore")
            except Exception:
                continue
            sections = list(_YARAL_SECTION_RE.finditer(raw))
            meta = next((m for m in sections if m.group(1) == "meta"), None)
            events = next((m for m in sections if m.group(1) == "events"), None)
            if not meta or not events:
                continue
            technique_ids = set(TECHNIQUE_ID_RE.findall(raw[meta.end():events.start()]))
            if not technique_ids:
                continue
            name = _YARAL_RULE_RE.search(raw)
            desc = _YARAL_DESC_RE.search(raw[meta.end():events.start()])
            entry = {
                "name": name.group(1) if name else file_path.stem,
                "source_url": _github_url("chronicle", repo_path, file_path),
                "query_snippet": raw[events.start():].strip()[:500],
            }
            if desc:
                entry["description"] = desc.group(1)[:300]
            for tid in technique_ids:
                index.setdefault(tid, []).append(entry)
    return index


_BUILDERS = {
    "elastic": _index_elastic,
    "splunk": _index_splunk,
    "azure_sentinel": _index_azure_sentinel,
    "chronicle": _index_chronicle,
}


def build_full_index() -> Dict:
    """Walk every cloned OSINT repo once and write the technique -> rules index to disk."""
    techniques: Dict[str, Dict[str, List[Dict]]] = {}
    stats = {}

    for repo_name, builder in _BUILDERS.items():
        repo_path = Path(REPOS[repo_name]["path"])
        if not repo_path.exists():
            print(f"⚠️  {repo_name} not cloned locally, skipping (run ensure_repos_ready() first)")
            stats[repo_name] = {"status": "not_cloned", "entries": 0}
            continue

        start = time.time()
        per_repo_index = builder(repo_path)
        elapsed = time.time() - start

        entry_count = sum(len(v) for v in per_repo_index.values())
        stats[repo_name] = {
            "status": "indexed",
            "techniques": len(per_repo_index),
            "entries": entry_count,
            "seconds": round(elapsed, 1),
        }
        print(f"✓ {repo_name}: {len(per_repo_index)} techniques, {entry_count} rules ({elapsed:.1f}s)")

        for tid, entries in per_repo_index.items():
            techniques.setdefault(tid, {}).setdefault(repo_name, []).extend(entries)

    index = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "stats": stats,
        "techniques": techniques,
    }

    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(INDEX_PATH, "w") as f:
        json.dump(index, f)

    global _index_cache
    _index_cache = index

    print(f"\n✓ Index written to {INDEX_PATH} ({len(techniques)} techniques total)")
    return index


_index_cache: Optional[Dict] = None


def load_index() -> Optional[Dict]:
    """
    Load the prebuilt index from disk, cached in memory for the life of the process.

    Returns None if the index has never been built (or is corrupt) -- callers
    should treat that as "fall back to the old live search", not "nothing found".
    """
    global _index_cache
    if _index_cache is not None:
        return _index_cache

    if not INDEX_PATH.exists():
        return None

    try:
        with open(INDEX_PATH) as f:
            _index_cache = json.load(f)
    except Exception:
        return None

    return _index_cache


def lookup(technique_id: str, source: str) -> List[Dict]:
    """Look up prebuilt entries for a technique/source pair. Returns [] if none found."""
    index = load_index()
    if not index:
        return []
    return index.get("techniques", {}).get(technique_id, {}).get(source, [])


def get_index_age_hours() -> Optional[float]:
    """Age of the on-disk index in hours, or None if it doesn't exist."""
    index = load_index()
    if not index:
        return None
    try:
        generated_at = datetime.fromisoformat(index["generated_at"].rstrip("Z"))
        return (datetime.utcnow() - generated_at).total_seconds() / 3600
    except Exception:
        return None


def known_false_positives(technique_id: str, limit: int = 8, terms: Optional[List[str]] = None) -> List[Dict]:
    """Known false positives for a technique (its sub-techniques' too, and the parent's),
    across the Elastic and Splunk rules that cover it: [{source, rule, url, text}]. Given
    `terms` (the detection's own binaries and tools), only rules whose name, query or false
    positives mention one count: a technique's other rules are often about another product
    entirely (Google Drive downloads under a certutil T1105 detection)."""
    words = {w for t in terms or [] for w in [os.path.splitext(os.path.basename(str(t).lower()))[0]] if len(w) >= 4}
    index = load_index()
    if not index or not technique_id:
        return []
    techniques = index.get("techniques", {})
    family = technique_id.split(".")[0]
    tids = [t for t in techniques if t == technique_id or t == family or t.startswith(technique_id + ".")]
    # Exact technique first, then its family; alternate Elastic and Splunk so neither fills the list
    queues = {"elastic": [], "splunk": []}
    seen = set()
    for tid in sorted(tids, key=lambda t: (t != technique_id, t)):
        for repo, queue in queues.items():
            entries = [e for e in techniques[tid].get(repo, []) if e.get("false_positives")]
            if words:
                entries = [e for e in entries if any(
                    w in " ".join([e.get("name", ""), e.get("query_snippet", "")] + e["false_positives"]).lower()
                    for w in words)]
            for entry in entries:
                for text in entry["false_positives"]:
                    key = text.lower()[:120]
                    if key not in seen:
                        seen.add(key)
                        queue.append({"source": {"elastic": "Elastic", "splunk": "Splunk"}[repo],
                                      "rule": entry.get("name"), "url": entry.get("source_url"), "text": text})
    out = []
    while len(out) < limit and any(queues.values()):
        for queue in queues.values():
            if queue and len(out) < limit:
                out.append(queue.pop(0))
    return out

if __name__ == "__main__":
    build_full_index()

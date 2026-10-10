"""Query-level gate for legacy Archer YAML (the pre-contract wrapper in data/generate and data/groups).

The contract validator needs the full metadata envelope; legacy files have none. This module runs
the query-level subset (the checks that only need the query text) so that every write through
yaml.write_yaml and detections._write_bespoke_yamls is linted today, and so the committed corpus
can be measured.

ARCHER_CONTRACT_STRICT=1 turns findings into a refusal to write. Default is warn-only.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import yaml

from .validator import Report, lint_query


def strict_mode() -> bool:
    return os.getenv("ARCHER_CONTRACT_STRICT", "0").strip().lower() in ("1", "true", "yes", "on")


def gate_query(query: str, siem: Optional[str] = None, label: str = "") -> Tuple[bool, Report]:
    """Lint a query. Returns (allowed_to_write, report). Allowed is False only in strict mode with findings."""
    rep = lint_query(query, siem)
    rep.path = label or rep.path
    if rep.fails:
        mode = "BLOCKED" if strict_mode() else "WARN"
        print(f"  [contract {mode}] {label or 'query'} ({rep.siem}): {len(rep.fails)} finding(s)")
        for f in rep.fails:
            print(f"      {f}")
    return (not rep.fails) if strict_mode() else True, rep


def extract_query(doc: dict) -> Optional[str]:
    """Pull the query text out of either legacy wrapper shape."""
    if not isinstance(doc, dict): return None
    if isinstance(doc.get("query"), str): return doc["query"]
    qs = doc.get("queries")
    if isinstance(qs, list) and qs and isinstance(qs[0], dict) and isinstance(qs[0].get("query"), str):
        return qs[0]["query"]
    return None


def lint_legacy_file(path) -> Report:
    p = Path(path)
    try:
        doc = yaml.safe_load(p.read_text())
    except yaml.YAMLError as e:
        rep = Report(str(p)); rep.siem = None; rep.fail("YAML", str(e).splitlines()[0]); return rep
    q = extract_query(doc)
    if q is None:
        rep = Report(str(p)); rep.siem = None; rep.fail("LEGACY-0", "no query field found"); return rep
    rep = lint_query(q)
    rep.path = str(p)
    return rep


def iter_yaml_files(targets: Iterable[str]) -> List[Path]:
    out: List[Path] = []
    for t in targets:
        p = Path(t)
        if p.is_dir(): out.extend(sorted(p.rglob("*.yaml")) + sorted(p.rglob("*.yml")))
        elif p.exists(): out.append(p)
    return out

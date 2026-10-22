"""
One YAML file per correlation, written once a run's correlations are final (scored,
filtered and grouped): data/correlate/<group>/<A>_and_<B>_<Vendor>.yaml.

The group's JSON (data/correlate/<group>.json) stays as the index: relevance, parts and
the file each correlation lives in. The file holds the query, ready to paste into the
SIEM, with the same stamp as a detection (archer.build.yaml): a file edited by hand is
kept on the next run and its query wins; files a run no longer produces are removed
unless edited.

    python -m archer.build.correlation_files [GROUP ...]   # files for correlations already on disk
"""

import hashlib
import json
import os
import re
import sys
import uuid
from typing import Dict, List, Optional

from archer.build.yaml import GENERATOR_VERSION, _STAMP, _query_block
from archer.config import CORRELATE_DIR

CONNECTOR = {"googlesecops": "GoogleSecOps", "mde": "MicrosoftThreatProtection", "splunk": "Splunk",
             "elastic": "Elastic"}
SUFFIX = {"googlesecops": "GoogleSecOps", "mde": "DefenderXDR", "splunk": "Splunk", "elastic": "Elastic"}
_NAMESPACE = uuid.UUID("8f5c1d2e-6a0b-4c7e-9a41-2f3b5d6e7c80")


def group_dir(group_name: str) -> str:
    return os.path.join(CORRELATE_DIR, group_name)


def _camel(name: str) -> str:
    return "".join(w[:1].upper() + w[1:] for w in re.split(r"[^A-Za-z0-9]+", str(name)) if w)


def _label(path: Optional[str]) -> str:
    """Technique name from a detection filename: AccessTokenManipulation_GoogleSecOps.yaml -> Access Token Manipulation."""
    stem = os.path.basename(str(path or "")).rsplit(".", 1)[0].split("_")[0]
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", stem).strip()


def _techniques(corr: Dict) -> List[str]:
    names = [str(n) for n in corr.get("techniques_involved") or [] if n]
    if not names:
        names = [n for n in (_label(corr.get("a")), _label(corr.get("b"))) if n]
    return list(dict.fromkeys(names))


def title(corr: Dict) -> str:
    names = _techniques(corr)
    return " and ".join(names[:2]) + (f" (+{len(names) - 2} more)" if len(names) > 2 else "") or "Correlation"


def filename(corr: Dict) -> str:
    names = _techniques(corr) or ["Correlation"]
    stem = "_and_".join(_camel(n) for n in names[:2]) + (f"_plus{len(names) - 2}" if len(names) > 2 else "")
    return f"{stem[:150]}_{SUFFIX.get(corr.get('vendor', ''), _camel(corr.get('vendor', 'Unknown')))}.yaml"


def _parts(corr: Dict) -> List[str]:
    b = corr.get("b")
    return [os.path.basename(p) for p in [corr.get("a")] + (b if isinstance(b, list) else [b]) if p]


def _technique_ids(query: str) -> List[str]:
    m = re.search(r"ATT&CK ((?:T\d{4}(?:\.\d{3})?(?:, )?)+)", query or "")
    return [t.strip() for t in m.group(1).split(",")] if m else []


def _window(query: str) -> Optional[str]:
    """The correlation window: a join's match window, SPL maxspan, or KQL's between-events bin."""
    for pattern in (r"^\s*\$[\w, $]+\s+over\s+(\d+[smhd])\b", r"maxspan=(\d+[smhd])\b",
                    r"\bbin\(\s*Timestamp\s*,\s*(\d+[smhd])\)", r"ago\((\d+[smhd])\)"):
        m = re.search(pattern, query or "", re.M)
        if m:
            return m.group(1)
    return None


def render(corr: Dict, group_name: str) -> str:
    """The file's text, stamped. YAML written by hand so the query stays a literal block."""
    query = (corr.get("combined_query") or "").rstrip()
    lines = [f"id: {uuid.uuid5(_NAMESPACE, group_name + '/' + filename(corr))}",
             f"name: {json.dumps(title(corr))}",
             "kind: correlation",
             f"group: {json.dumps(group_name)}",
             f"vendor: {corr.get('vendor', '')}",
             "requiredDataConnectors:",
             f"  - connectorId: {CONNECTOR.get(corr.get('vendor', ''), corr.get('vendor', ''))}",
             "severity: High",
             f"relevance_score: {corr.get('relevance_score', 0)}"]
    window = _window(query)
    if window:
        lines.append(f"time_window: {window}")
    for key, values in (("tactics", corr.get("tactics") or []), ("technique_ids", _technique_ids(query)),
                        ("techniques", _techniques(corr)), ("parts", _parts(corr))):
        if values:
            lines.append(f"{key}:")
            lines += [f"  - {json.dumps(str(v))}" for v in values]
    lines.append("query: |")
    lines += ["  " + l if l else "" for l in query.split("\n")]
    lines.append("version: 1.0.0")
    body = "\n".join(lines) + "\n"
    digest = hashlib.sha256(_query_block(body).encode()).hexdigest()
    return f"# archer-generator: {GENERATOR_VERSION} query-sha256: {digest}\n{body}"


def read_query(path: str) -> Optional[str]:
    """The query in a correlation file, or None."""
    try:
        with open(path, encoding="utf-8") as fh:
            block = _query_block(fh.read())
    except OSError:
        return None
    return "\n".join(l[2:] if l.startswith("  ") else l for l in block.split("\n")) or None


def _edited(path: str) -> bool:
    try:
        with open(path, encoding="utf-8") as fh:
            first, _, body = fh.read().partition("\n")
    except OSError:
        return False
    m = _STAMP.match(first)
    return bool(m) and hashlib.sha256(_query_block(body).encode()).hexdigest() != m.group(2)


def errors(corr: Dict) -> List[str]:
    """What stops a correlation's query being pasted into its SIEM: static-check errors."""
    from archer.validation.static_check import check_query

    query = corr.get("combined_query") or ""
    if not query.strip():
        return ["no query"]
    result = check_query(query, corr.get("vendor"))
    return [f"{f['check']}: {f['message']}" for f in result["findings"] if f["severity"] == "error"]


def write(group_name: str, correlations: List[Dict]) -> Dict[str, List[str]]:
    """
    Write each correlation's file and record it on the correlation ("file", relative to
    CORRELATE_DIR). A hand-edited file is kept and its query becomes the correlation's.
    Returns {"written", "kept_edited", "removed"} (file names).
    """
    out_dir = group_dir(group_name)
    os.makedirs(out_dir, exist_ok=True)
    report = {"written": [], "kept_edited": [], "removed": []}
    used = set()
    for corr in correlations:
        if not (corr.get("combined_query") or "").strip():
            continue
        name = filename(corr)
        stem, n = name[:-5], 2
        while name in used:  # two correlations of the same pair: number the second
            name, n = f"{stem}_{n}.yaml", n + 1
        used.add(name)
        path = os.path.join(out_dir, name)
        corr["file"] = os.path.join(group_name, name)
        if os.path.exists(path) and _edited(path):
            corr["combined_query"] = read_query(path) or corr["combined_query"]
            corr["edited"] = True
            report["kept_edited"].append(name)
            continue
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(render(corr, group_name))
        os.replace(tmp, path)
        report["written"].append(name)
    for name in os.listdir(out_dir):
        path = os.path.join(out_dir, name)
        if name.endswith(".yaml") and name not in used and not _edited(path):
            os.remove(path)
            report["removed"].append(name)
    return report


def backfill(group_name: str) -> Optional[Dict[str, List[str]]]:
    """Files for a group's correlations already on disk; the index gains each file."""
    index = os.path.join(CORRELATE_DIR, f"{group_name}.json")
    if not os.path.isfile(index):
        return None
    with open(index, encoding="utf-8") as fh:
        data = json.load(fh)
    report = write(group_name, data.get("vendor_correlations") or [])
    tmp = index + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, index)
    return report


def main(argv=None) -> int:
    groups = (argv if argv is not None else sys.argv[1:]) or sorted(
        n[:-5] for n in os.listdir(CORRELATE_DIR) if n.endswith(".json") and not n.startswith("."))
    for group in groups:
        report = backfill(group)
        if report is None:
            print(f"{group}: no correlations")
            continue
        print(f"{group}: {len(report['written'])} files written, {len(report['kept_edited'])} kept (edited), "
              f"{len(report['removed'])} removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

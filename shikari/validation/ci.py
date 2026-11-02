"""
Gate detections in CI/CD (#34): every check Shikari runs, on detection files, with an exit code.

    python -m shikari.validation.ci detections/ [--min-grade C] [--max-fp-risk medium] [--max-cost medium]
                                              [--fail-on-warnings] [--format text|github|json] [--changed-only REF]

For each detection YAML: the static checks (it parses, known tables and fields, no placeholders)
and precision checks, the quality grade, the false-positive risk and the run cost. A static error
always fails; the thresholds fail the rest. Exit 0 when everything passes, 1 when anything fails,
2 when there was nothing to check.

--format github writes workflow annotations (::error file=...::), so failures show on the pull
request's diff. --changed-only origin/main checks only the files that differ from that ref.
No AI and no network: it runs on a CI runner with nothing but Shikari's Python dependencies.

--server https://shikari.example.com sends the files to an Shikari server to check instead
(POST /api/validate/assess, with SHIKARI_TOKEN as the API token), so a detections repository's CI
needs only Python, requests and PyYAML and a copy of this file, not an Shikari checkout. The
thresholds are applied here either way.
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Dict, List

import yaml

GRADES = "ABCDF"
LEVELS = ["low", "medium", "high"]


def detection_files(paths: List[str]) -> List[str]:
    found = []
    for path in paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                found += [os.path.join(root, f) for f in files if f.endswith((".yaml", ".yml"))]
        elif path.endswith((".yaml", ".yml")) and os.path.isfile(path):
            found.append(path)
    return sorted(found)


def changed_since(ref: str) -> set:
    out = subprocess.run(["git", "diff", "--name-only", "--diff-filter=AMR", ref, "--"],
                         capture_output=True, text=True, check=True).stdout
    return {os.path.normpath(p) for p in out.splitlines() if p}


def assess_document(doc: Dict) -> Dict:
    """What the server's /api/validate/assess returns for one parsed detection:
    {findings: [{level, check, message}], quality, fp_risk, cost}."""
    from shikari.validation.quality import assess
    from shikari.validation.static_check import check_query

    checked = check_query(doc["query"], None)
    return {"findings": [{"level": f["severity"], "check": f["check"], "message": f["message"]}
                         for f in checked["findings"]], **assess(doc)}


def _remote_assess(server: str, doc: Dict) -> Dict:
    import requests

    r = requests.post(server.rstrip("/") + "/api/validate/assess", json={"detection": doc}, timeout=60,
                      headers={"Authorization": f"Bearer {os.environ.get('SHIKARI_TOKEN', '')}"})
    if r.status_code != 200:
        raise RuntimeError(f"{server} answered {r.status_code}: {r.text[:200]}")
    return r.json()


def check_file(path: str, args) -> Dict:
    """{file, ok, problems: [{level, check, message}], quality, fp_risk, cost} for one file."""
    result = {"file": path, "problems": []}
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as e:
        result.update(ok=False, problems=[{"level": "error", "check": "YAML", "message": f"not valid YAML: {e}"}])
        return result
    if not isinstance(doc, dict) or not doc.get("query"):
        result.update(ok=True, skipped="no query")
        return result

    assessed = _remote_assess(args.server, doc) if getattr(args, "server", None) else assess_document(doc)
    result["problems"] += assessed.pop("findings")
    result.update(assessed)
    q, r, c = assessed["quality"], assessed["fp_risk"], assessed["cost"]
    if GRADES.index(q["grade"]) > GRADES.index(args.min_grade):
        result["problems"].append({"level": "error", "check": "QUALITY",
                                   "message": f"quality {q['grade']} ({q['score']}/100) is below {args.min_grade}: " + "; ".join(
                                       n for f in q["factors"] if f["points"] < f["max"] for n in f["notes"])})
    if LEVELS.index(r["level"]) > LEVELS.index(args.max_fp_risk):
        result["problems"].append({"level": "error", "check": "FP-RISK",
                                   "message": f"false-positive risk {r['level']}: " + "; ".join(r["reasons"])})
    if LEVELS.index(c["level"]) > LEVELS.index(args.max_cost):
        result["problems"].append({"level": "error", "check": "COST", "message": f"run cost {c['level']}: " + "; ".join(
            f"{f['message']} (fix: {f['fix']})" for f in c["findings"])})
    failing = {"error"} | ({"warning"} if args.fail_on_warnings else set())
    result["ok"] = not any(p["level"] in failing for p in result["problems"])
    return result


def _escape(text: str) -> str:
    """GitHub workflow commands: %, CR and LF must be encoded in the message."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def report(results: List[Dict], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(results, indent=2, default=str)
    lines = []
    for r in results:
        if r.get("skipped"):
            continue
        if fmt == "github":
            for p in r["problems"]:
                kind = "error" if p["level"] == "error" else "warning"
                lines.append(f"::{kind} file={r['file']},title={p['check']}::{_escape(p['message'])}")
            continue
        summary = ""
        if "quality" in r:
            summary = (f"quality {r['quality']['grade']}, FP risk {r['fp_risk']['level']}, "
                       f"cost {r['cost']['level']}")
        lines.append(f"{'PASS' if r['ok'] else 'FAIL'}  {r['file']}  {summary}")
        lines += [f"      {p['level']:<7} {p['check']}: {p['message']}" for p in r["problems"]]
    checked = [r for r in results if not r.get("skipped")]
    failed = sum(not r["ok"] for r in checked)
    lines.append(f"{len(checked)} detection{'s' if len(checked) != 1 else ''} checked, {failed} failed")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="+", help="detection YAML files or folders")
    parser.add_argument("--min-grade", choices=list(GRADES), default="D", help="fail below this quality grade (default D)")
    parser.add_argument("--max-fp-risk", choices=LEVELS, default="high", help="fail above this false-positive risk")
    parser.add_argument("--max-cost", choices=LEVELS, default="high", help="fail above this run cost")
    parser.add_argument("--fail-on-warnings", action="store_true", help="static and precision warnings fail too")
    parser.add_argument("--format", choices=["text", "github", "json"], default="text")
    parser.add_argument("--changed-only", metavar="REF", help="only files that differ from this git ref")
    parser.add_argument("--server", metavar="URL", help="check on this Shikari server (API token in SHIKARI_TOKEN)")
    args = parser.parse_args(argv)

    files = detection_files(args.paths)
    if args.changed_only:
        changed = changed_since(args.changed_only)
        files = [f for f in files if os.path.normpath(os.path.relpath(f)) in changed]
    if not files:
        print("No detection files to check")
        return 2
    results = [check_file(f, args) for f in files]
    print(report(results, args.format))
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())

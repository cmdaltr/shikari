"""
Files named for a product (At_GoogleSecOps.yaml, ..._DefenderXDR.yaml) renamed for the
query language (At_UDM.yaml, ..._KQL.yaml): detections in data/groups, correlation files
in data/correlate/<group>/, and the names the correlation indexes and run manifests hold.
Contents are unchanged, so a hand-edited file stays edited. A rename whose new name is
already taken is left alone and reported.

    python -m archer.build.migrate_names [--dry-run]
"""

import glob
import os
import re
import sys
from typing import Dict, List

from archer.build.yaml import LANGUAGE_SUFFIX
from archer.config import DATA_DIR, GENERATE_DIR

CORRELATE_DIR = os.path.join(DATA_DIR, "correlate")
RUNS_DIR = os.path.join(DATA_DIR, "runs")

# Detection suffixes were connector ids; correlation suffixes were product names
_OLD = {**LANGUAGE_SUFFIX, "DefenderXDR": "KQL"}
_DETECTION = re.compile(r"_(GoogleSecOps|MicrosoftThreatProtection|Elastic)\.yaml$")
_CORRELATION = re.compile(r"_(GoogleSecOps|DefenderXDR|Splunk|Elastic)((?:_\d+)?)\.yaml$")
# A file name inside an index or manifest: either kind
_IN_TEXT = re.compile(r"(?<=[A-Za-z0-9])_(GoogleSecOps|MicrosoftThreatProtection|DefenderXDR|Splunk|Elastic)((?:_\d+)?)\.yaml\b")


def _rename(paths: List[str], pattern: re.Pattern, dry_run: bool, report: Dict[str, List[str]]) -> None:
    for path in paths:
        new = pattern.sub(lambda m: f"_{_OLD[m.group(1)]}{m.group(2) if m.lastindex > 1 else ''}.yaml",
                          os.path.basename(path))
        target = os.path.join(os.path.dirname(path), new)
        if new == os.path.basename(path):
            continue
        if os.path.exists(target):
            report["conflicts"].append(os.path.relpath(path, DATA_DIR))
            continue
        if not dry_run:
            os.replace(path, target)
        report["renamed"].append(os.path.relpath(path, DATA_DIR))


def _rewrite(paths: List[str], dry_run: bool, report: Dict[str, List[str]]) -> None:
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        new = _IN_TEXT.sub(lambda m: f"_{_OLD[m.group(1)]}{m.group(2)}.yaml", text)
        if new == text:
            continue
        if not dry_run:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(new)
            os.replace(tmp, path)
        report["rewritten"].append(os.path.relpath(path, DATA_DIR))


def migrate(dry_run: bool = False) -> Dict[str, List[str]]:
    report = {"renamed": [], "rewritten": [], "conflicts": []}
    _rename([p for p in glob.glob(os.path.join(GENERATE_DIR, "*.yaml")) if _DETECTION.search(p)],
            _DETECTION, dry_run, report)
    _rename([p for p in glob.glob(os.path.join(CORRELATE_DIR, "*", "*.yaml")) if _CORRELATION.search(p)],
            _CORRELATION, dry_run, report)
    # Indexes and manifests name both kinds; a correlation file's parts: names detections
    _rewrite(glob.glob(os.path.join(CORRELATE_DIR, "*.json")) + glob.glob(os.path.join(RUNS_DIR, "*.json"))
             + glob.glob(os.path.join(CORRELATE_DIR, "*", "*.yaml")), dry_run, report)
    return report


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    report = migrate(dry_run="--dry-run" in argv)
    print(f"{len(report['renamed'])} files renamed, {len(report['rewritten'])} indexes/manifests/files rewritten")
    for path in report["conflicts"]:
        print(f"  ⚠️  left as is, its new name is taken: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

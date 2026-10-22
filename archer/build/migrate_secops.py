"""
Turn the Google SecOps YARA-L rules already on disk into UDM searches (archer.build.udm)
without a run: detections in GENERATE_DIR and the correlations in data/correlate.

The conversion is mechanical: a single-event rule's events become one search expression,
a multi-event rule a two-event join. Generated files get a fresh query hash, so they don't
count as hand-edited. A hand-edited file is converted too, with its edit, and keeps its old
hash: it still counts as edited, so a run won't overwrite it.

    python -m archer.build.migrate_secops [--dry-run] [DIR]
"""

import argparse
import hashlib
import json
import os
import sys

from archer.build.udm import from_yaral, is_yaral, normalise_join
from archer.build.yaml import _STAMP, _query_block
from archer.config import DATA_DIR, GENERATE_DIR

CORRELATE_DIR = os.path.join(DATA_DIR, "correlate")


def migrate_file(path: str, dry_run: bool = False) -> str:
    """'migrated', 'migrated-edited', 'unchanged' or 'skipped' (not a SecOps detection)."""
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    first, _, body = content.partition("\n")
    stamp = _STAMP.match(first)
    if not stamp:
        first, body = "", content
    if "GoogleSecOps" not in body:
        return "skipped"
    block = _query_block(body)
    query = "\n".join(l[2:] if l.startswith("  ") else l for l in block.split("\n"))
    if not is_yaral(query):
        return "unchanged"
    new = from_yaral(query)
    if not new:
        return "skipped"
    edited = bool(stamp) and hashlib.sha256(block.encode()).hexdigest() != stamp.group(2)
    body = body.replace(block, "\n".join("  " + l if l else l for l in new.split("\n")), 1)
    if stamp and not edited:
        first = f"# archer-generator: {stamp.group(1)} query-sha256: {hashlib.sha256(_query_block(body).encode()).hexdigest()}"
    if not dry_run:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(f"{first}\n{body}" if first else body)
        os.replace(tmp, path)
    return "migrated-edited" if edited else "migrated"


def migrate_correlations(path: str, dry_run: bool = False) -> int:
    """Convert a correlation file's SecOps queries; returns how many changed."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    changed = 0

    def convert(q):
        nonlocal changed
        if isinstance(q, str) and "\nUNION\n" in q:
            parts = [convert(p) for p in q.split("\nUNION\n")]
            return "\nUNION\n".join(parts)
        if isinstance(q, str) and is_yaral(q):
            changed += 1
            return from_yaral(q) or q
        if isinstance(q, str) and normalise_join(q) != q:
            changed += 1
            return normalise_join(q)
        return q

    for corr in data.get("vendor_correlations", []) if isinstance(data, dict) else []:
        for key in ("combined_query", "query_a", "query_b"):
            if key in corr:
                corr[key] = convert(corr[key])
    if changed and not dry_run:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
    return changed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("dir", nargs="?", default=GENERATE_DIR)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    counts = {}
    edited = []
    for name in sorted(os.listdir(args.dir)):
        if name.endswith((".yaml", ".yml")):
            result = migrate_file(os.path.join(args.dir, name), args.dry_run)
            counts[result] = counts.get(result, 0) + 1
            if result == "migrated-edited":
                edited.append(name)
    queries = 0
    if os.path.isdir(CORRELATE_DIR):
        for name in sorted(os.listdir(CORRELATE_DIR)):
            if name.endswith(".json") and not name.startswith("."):  # .*_example.json are samples
                queries += migrate_correlations(os.path.join(CORRELATE_DIR, name), args.dry_run)
    verb = "Would convert" if args.dry_run else "Converted"
    print(verb, counts.get("migrated", 0) + counts.get("migrated-edited", 0), "SecOps detections to UDM;",
          ", ".join(f"{v} {k}" for k, v in sorted(counts.items()) if not k.startswith("migrated")))
    print(verb, queries, "correlation queries")
    for name in edited:
        print(f"  ✋ converted, still marked edited by hand: {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

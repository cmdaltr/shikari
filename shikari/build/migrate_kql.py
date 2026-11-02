"""
Bring MDE detections already on disk up to generator 3's KQL without a run: aggregate per
finding instead of "summarize by Timestamp, ..." (every raw event alerted), verbatim
literals for paths, and bracketed and/or. The meaning of each where clause is unchanged.

Files edited by hand are left alone. Migrated files keep their old generator number and
get a fresh query hash, so they don't count as hand-edited and the next run that reaches
them still rewrites them from scratch with generator 3.

    python -m shikari.build.migrate_kql [--dry-run] [DIR]
"""

import argparse
import hashlib
import os
import re
import sys

from shikari.build.yaml import _STAMP, _query_block
from shikari.config import GENERATE_DIR
from shikari.validation.mde_field_validator import (
    EXCLUDED_MDE_FIELDS,
    _aggregate_summarize,
    normalise_where_logic,
    verbatim_backslash_literals,
)

_PER_EVENT = re.compile(r"^\|\s*summarize\s+by\s+Timestamp\s*,")


def migrate_query(query: str) -> str:
    query = normalise_where_logic(verbatim_backslash_literals(query))
    lines = query.split("\n")
    for i, line in enumerate(lines):
        if _PER_EVENT.match(line.strip()):
            # The field list runs on over continuation lines, to the next pipe
            end = i + 1
            while end < len(lines) and lines[end].strip() and not lines[end].lstrip().startswith("|"):
                end += 1
            text = " ".join(l.strip() for l in lines[i:end])
            fields = [f.strip() for f in text.split("by", 1)[1].split(",") if f.strip()]
            fields = [f for f in fields if f not in EXCLUDED_MDE_FIELDS]
            return "\n".join(lines[:i] + _aggregate_summarize(fields) + lines[end:])
    return query


def migrate_file(path: str, dry_run: bool = False) -> str:
    """'migrated', 'unchanged', 'edited' (left alone) or 'skipped' (not a stamped MDE file)."""
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    first, _, body = content.partition("\n")
    stamp = _STAMP.match(first)
    if not stamp or "MicrosoftThreatProtection" not in body:
        return "skipped"
    block = _query_block(body)
    if hashlib.sha256(block.encode()).hexdigest() != stamp.group(2):
        return "edited"
    query = "\n".join(l[2:] if l.startswith("  ") else l for l in block.split("\n"))
    new = migrate_query(query)
    if new == query:
        return "unchanged"
    new_block = "\n".join("  " + l if l else l for l in new.split("\n"))
    body = body.replace(block, new_block, 1)
    digest = hashlib.sha256(_query_block(body).encode()).hexdigest()
    if not dry_run:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(f"# shikari-generator: {stamp.group(1)} query-sha256: {digest}\n{body}")
        os.replace(tmp, path)
    return "migrated"


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
            if result == "edited":
                edited.append(name)
    print(("Would migrate" if args.dry_run else "Migrated"), counts.get("migrated", 0), "files;",
          ", ".join(f"{v} {k}" for k, v in sorted(counts.items()) if k != "migrated"))
    for name in edited:
        print(f"  ✋ left alone (edited by hand): {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

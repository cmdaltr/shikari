#!/usr/bin/env python3
"""
build_osint_index.py - Build the MITRE ATT&CK technique -> OSINT rule index

Walks the locally-cloned OSINT repos (Elastic, Splunk, Azure Sentinel) once and writes a reverse index (data/cache/osint_technique_index.json)
mapping technique IDs to matching rules in each repo. Once this exists,
shikari/build/osint_comparison.py looks up techniques in it instead of
grepping each repo on every single OSINT comparison call.

Run this after updating the OSINT repos (update_osint.py), or on a schedule
(cron/launchd) alongside it -- the index doesn't update itself.

Usage:
    python3 scripts/data/build_osint_index.py               # clone/update repos, then build
    python3 scripts/data/build_osint_index.py --skip-clone  # build from whatever's on disk now
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shikari.build.osint_repos import ensure_repos_ready
from shikari.build.osint_index import build_full_index, get_index_age_hours


def main():
    parser = argparse.ArgumentParser(description="Build the OSINT technique index")
    parser.add_argument(
        "--skip-clone",
        action="store_true",
        help="Don't clone/update the OSINT repos first, just index whatever's already on disk",
    )
    args = parser.parse_args()

    age = get_index_age_hours()
    if age is not None:
        print(f"Existing index is {age:.1f} hours old.")

    if not args.skip_clone:
        print("Ensuring OSINT repos are cloned and up to date...")
        ensure_repos_ready()
        print()

    print("Building technique index...")
    build_full_index()


if __name__ == "__main__":
    main()

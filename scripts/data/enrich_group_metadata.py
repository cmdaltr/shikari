#!/usr/bin/env python3
"""
Rebuild data/cache/group_metadata.json from the MITRE ATT&CK STIX bundle.

Extracts structured metadata for every MITRE ATT&CK group using regex-based
heuristics applied to the STIX description field and relationship objects:
  - Nexus (country attribution)
  - Sponsor / Affiliation
  - Activity since (year)
  - Primary objectives
  - Target regions
  - Target sectors
  - Attribution confidence
  - Notable tools / malware
  - Notable campaigns / ops

Usage:
    python scripts/data/enrich_group_metadata.py
    python scripts/data/enrich_group_metadata.py --force   # re-enrich even if cache exists
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from archer.mitre.group_metadata import build_group_metadata_cache, load_group_metadata

STIX_CACHE   = PROJECT_ROOT / "data" / "cache" / "enterprise-attack.json"
OUTPUT_PATH  = PROJECT_ROOT / "data" / "cache" / "group_metadata.json"


def main() -> None:
    ap = argparse.ArgumentParser(description="Enrich MITRE group metadata cache")
    ap.add_argument("--force", action="store_true", help="Rebuild even if cache already exists")
    ap.add_argument("--output", default=str(OUTPUT_PATH), help="Output JSON path")
    args = ap.parse_args()

    out = Path(args.output)

    if out.exists() and not args.force:
        existing = load_group_metadata(out)
        group_count = sum(1 for k in existing if k.startswith("G"))
        print(f"Cache already exists with {group_count} groups. Use --force to rebuild.")
        return

    if not STIX_CACHE.exists():
        print(f"STIX bundle cache not found at {STIX_CACHE}")
        print("Run Archer once first so it downloads the STIX bundle, then re-run this script.")
        sys.exit(1)

    print(f"Loading STIX bundle from {STIX_CACHE}…")
    with open(STIX_CACHE, encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])
    print(f"Processing {len(objects):,} STIX objects…")

    metadata = build_group_metadata_cache(objects, out)
    group_count = sum(1 for k in metadata if k.startswith("G"))
    print(f"Done. Enriched {group_count} groups → {out}")

    # Show a few sample results
    samples = [(k, v) for k, v in metadata.items() if k.startswith("G")][:3]
    for att_id, m in samples:
        print(f"\n  {att_id} {m['group_name']}")
        print(f"    Nexus:      {m['nexus'] or '—'}")
        print(f"    Sponsor:    {m['sponsor'] or '—'}")
        print(f"    Since:      {m['activity_since'] or '—'}")
        print(f"    Objectives: {m['primary_objectives'] or '—'}")
        print(f"    Regions:    {m['target_regions'] or '—'}")
        print(f"    Sectors:    {m['target_sectors'] or '—'}")
        print(f"    Confidence: {m['attribution_confidence'] or '—'}")
        print(f"    Tools:      {(m['tools_malware'] or '—')[:80]}")
        print(f"    Campaigns:  {m['campaigns'] or '—'}")


if __name__ == "__main__":
    main()

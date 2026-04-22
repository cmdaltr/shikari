"""Preview detection queries for a threat group without writing files.

Usage:
    archer-preview APT29
    archer-preview "Scattered Spider"
    archer-preview APT29 --limit 5
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="archer-preview",
        description="Preview detection queries for a threat group (no files written)",
    )
    parser.add_argument("group", help="Threat group name (e.g. APT29, 'Scattered Spider')")
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        metavar="N",
        help="Stop after N techniques (0 = all)",
    )
    args = parser.parse_args()

    # Patch tactic lookups for speed
    from archer.build import yaml_patch  # noqa: F401

    from archer.build.orchestrator import process_group

    if args.limit > 0:
        # Monkey-patch process_group to honour --limit by wrapping compile_query
        from archer.build import detections as _det

        _original = _det.compile_query
        _count = [0]

        def _limited(*a, **kw):
            if _count[0] >= args.limit:
                return
            kw["dry_run"] = True
            _original(*a, **kw)
            _count[0] += 1

        _det.compile_query = _limited

    process_group(group_name=args.group, dry_run=True)

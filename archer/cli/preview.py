"""Preview detection queries for a threat group without writing files.

Usage:
    archer-preview APT29
    archer-preview "Scattered Spider" --limit 5
    archer-preview APT29 --siem splunk,mde
    archer-preview APT29 --siem elastic,secops --limit 3
"""

import argparse

VALID_SIEMS = {"mde", "splunk", "elastic", "secops"}


def _parse_siem(value: str) -> set:
    """Parse a comma-separated SIEM list into a normalised set."""
    items = {s.strip().lower() for s in value.split(",") if s.strip()}
    unknown = items - VALID_SIEMS
    if unknown:
        raise argparse.ArgumentTypeError(
            f"Unknown SIEM(s): {', '.join(sorted(unknown))}. "
            f"Valid options: {', '.join(sorted(VALID_SIEMS))}"
        )
    return items


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
    parser.add_argument(
        "--siem",
        type=_parse_siem,
        default=None,
        metavar="SIEM[,SIEM...]",
        help=f"SIEMs to include: {', '.join(sorted(VALID_SIEMS))} (default: all)",
    )
    args = parser.parse_args()

    siem_filter = args.siem  # None means all

    # Patch tactic lookups for speed
    from archer.build import yaml_patch  # noqa: F401
    from archer.build.orchestrator import process_group

    if args.limit > 0:
        from archer.build import detections as _det
        _original = _det.compile_query
        _count = [0]

        def _limited(*a, **kw):
            if _count[0] >= args.limit:
                return
            kw["dry_run"] = True
            kw.setdefault("siem_filter", siem_filter)
            _original(*a, **kw)
            _count[0] += 1

        _det.compile_query = _limited
        process_group(group_name=args.group, dry_run=True, siem_filter=siem_filter)
    else:
        process_group(group_name=args.group, dry_run=True, siem_filter=siem_filter)

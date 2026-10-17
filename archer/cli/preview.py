"""Preview detection queries for a threat group without writing files.

Usage:
    archer-cli preview APT29
    archer-cli preview "Scattered Spider" --limit 5
    archer-cli preview APT29 --siem splunk,mde
    archer-cli preview APT29 --siem elastic,secops --limit 3
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
        prog="archer-cli preview",
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
    parser.add_argument(
        "--index", "-i",
        default=None,
        metavar="NAME[,NAME...]",
        help="Only show queries whose index/table name contains one of these strings "
             "(e.g. edr_events,DeviceProcessEvents)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        metavar="FILE",
        help="Write full output to FILE instead of (or in addition to) stdout",
    )
    args = parser.parse_args()

    siem_filter = args.siem  # None means all
    index_filter = {s.strip() for s in args.index.split(",") if s.strip()} if args.index else None

    # Patch tactic lookups for speed
    from archer.build import yaml_patch  # noqa: F401
    from archer.build.orchestrator import process_group
    import sys

    # If --output specified, tee stdout to a file
    if args.output:
        import io

        class _Tee:
            def __init__(self, *streams):
                self._streams = streams

            def write(self, data):
                for s in self._streams:
                    s.write(data)

            def flush(self):
                for s in self._streams:
                    s.flush()

            # Delegate other attribute lookups to the first stream
            def __getattr__(self, name):
                return getattr(self._streams[0], name)

        out_file = open(args.output, "w", encoding="utf-8")
        sys.stdout = _Tee(sys.__stdout__, out_file)
        print(f"[preview] Writing output to: {args.output}\n")

    try:
        if args.limit > 0:
            from archer.build import detections as _det
            _original = _det.compile_query
            _count = [0]

            def _limited(*a, **kw):
                if _count[0] >= args.limit:
                    return
                kw["dry_run"] = True
                kw.setdefault("siem_filter", siem_filter)
                kw.setdefault("index_filter", index_filter)
                _original(*a, **kw)
                _count[0] += 1

            _det.compile_query = _limited
            process_group(group_name=args.group, dry_run=True, siem_filter=siem_filter, index_filter=index_filter)
        else:
            process_group(group_name=args.group, dry_run=True, siem_filter=siem_filter, index_filter=index_filter)
    finally:
        if args.output:
            sys.stdout = sys.__stdout__
            out_file.close()
            print(f"\n[preview] Output saved to: {args.output}")

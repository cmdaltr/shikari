"""
shikari export siem: a SIEM export pack (#41) from the command line.

    shikari export siem --siem elastic --group "Sandworm Team"
    shikari export siem --siem splunk --all --telemetry caldera-shikari-sbx-20261108-103915 -o pack.zip
    shikari export runs        the lab runs --telemetry can take

The same pack the Detections as code page downloads: see shikari.export.siem_pack.
"""

import argparse
import contextlib
import os
import sys

ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def _bundle():
    """The ATT&CK bundle for the rules' tactic mapping: the cached copy whatever its age, so an export
    works offline. Its loading messages go to stderr, keeping stdout for the result."""
    from shikari.mitre.enterprise import get_stix_data

    try:
        with contextlib.redirect_stdout(sys.stderr):
            return get_stix_data(ATTACK_URL, cache_days=3650)
    except Exception as e:
        print(f"ATT&CK bundle not loaded ({e}): rules are exported without their tactics", file=sys.stderr)
        return None


def lab_runs():
    """{run name: folder} for every recorded lab run."""
    from shikari.telemetry import lab

    return {name: os.path.join(lab.LAB_DIR, name) for name, _manifest in lab.runs()}


def _siem(args) -> int:
    from shikari.build.group_files import group_yaml_files
    from shikari.config import GENERATE_DIR
    from shikari.export import siem_pack
    from shikari.security.validation import sanitize_group_name

    group = None if args.all else sanitize_group_name(args.group)
    if group and not group_yaml_files(group, GENERATE_DIR):
        print(f"error: no detections for {args.group}. Hunt it first.", file=sys.stderr)
        return 1
    run_dir = None
    if args.telemetry:
        runs = lab_runs()
        if args.telemetry not in runs:
            print(f"error: no lab run called {args.telemetry}" + (f": choose from {', '.join(runs)}" if runs else
                  ": record one first (scripts/telemetry)"), file=sys.stderr)
            return 1
        run_dir = runs[args.telemetry]
    data, manifest = siem_pack.build(args.siem, group, GENERATE_DIR, group_yaml_files, bundle=_bundle(),
                                     exclude_unavailable=not args.include_unavailable,
                                     telemetry_run=run_dir, rebase=not args.no_rebase)
    out = args.output or siem_pack.filename(args.siem, group)
    with open(out, "wb") as fh:
        fh.write(data)
    what = f"{manifest['rules']} rules from {manifest['detections']} detections" if "rules" in manifest \
        else f"{manifest['detections']} detections"
    print(f"{out}: {siem_pack.SIEMS[args.siem]['label']}, {manifest['group']}, {what}")
    if manifest["excluded"]:
        print(f"  {len(manifest['excluded'])} left out (see manifest.json)")
    if manifest.get("telemetry"):
        print(f"  lab telemetry: {manifest['telemetry']['events']} events from {manifest['telemetry']['run']}")
    return 0


def _runs(_args) -> int:
    runs = lab_runs()
    if not runs:
        print("No lab runs recorded yet (scripts/telemetry: record-atomics.ps1, record-custom.ps1, a CALDERA capture)")
    for name in runs:
        print(name)
    return 0


def main(argv=None):
    from shikari.export.siem_pack import SIEMS

    p = argparse.ArgumentParser(prog="shikari export", description="Export detections for use elsewhere.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("siem", help="a pack to import into your own Elastic, Splunk or Wazuh")
    s.add_argument("--siem", required=True, choices=list(SIEMS))
    which = s.add_mutually_exclusive_group(required=True)
    which.add_argument("--group", help="a hunted group, CVE or report run")
    which.add_argument("--all", action="store_true", help="every detection")
    s.add_argument("--telemetry", metavar="RUN", help="add a lab run's events (shikari export runs lists them)")
    s.add_argument("--no-rebase", action="store_true", help="keep the events' recorded times")
    s.add_argument("--include-unavailable", action="store_true",
                   help="keep detections whose data source the estate doesn't ingest")
    s.add_argument("-o", "--output", help="the zip to write (default shikari-<siem>-<group>.zip here)")
    sub.add_parser("runs", help="list the recorded lab runs")
    args = p.parse_args(argv)
    return {"siem": _siem, "runs": _runs}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

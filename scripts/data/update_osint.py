#!/usr/bin/env python3
"""
Clone or update the OSINT detection repositories Archer searches per technique, then
rebuild the technique index. The repositories, their URLs and sparse checkouts are
defined once, in archer/build/osint_repos.py (REPOS); Archer's start-up uses the same.

Usage:
    python3 scripts/data/update_osint.py                  # every repository, if due
    python3 scripts/data/update_osint.py --force          # every repository, now
    python3 scripts/data/update_osint.py --chronicle --splunk
    python3 scripts/data/update_osint.py --no-index       # skip the index rebuild

Air-gapped use: run it on a connected machine, then copy data/repos/ (and
data/cache/osint_technique_index.json) to the same place in the other installation.
"""

import argparse
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# Standard library only, so it runs on a machine without Archer's dependencies (the
# air-gapped workflow): register archer and archer.build as bare packages, so importing
# osint_repos (and the config it reads) doesn't run their __init__s, which pull in
# everything else
for _pkg, _dir in (("archer", ROOT / "archer"), ("archer.build", ROOT / "archer" / "build")):
    if _pkg not in sys.modules:
        _mod = types.ModuleType(_pkg)
        _mod.__path__ = [str(_dir)]
        sys.modules[_pkg] = _mod

from archer.build.osint_repos import REPOS, clone_or_update_repo  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="update even if updated within the hour")
    parser.add_argument("--no-index", action="store_true", help="don't rebuild the technique index")
    for name in REPOS:
        parser.add_argument(f"--{name.replace('_', '-')}", action="store_true", dest=name,
                            help=f"update only {REPOS[name]['url'].split('github.com/')[-1].removesuffix('.git')}")
    args = parser.parse_args()

    chosen = [name for name in REPOS if getattr(args, name)] or list(REPOS)
    failed = [name for name in chosen if not clone_or_update_repo(name, force=args.force)]
    print(f"\n{len(chosen) - len(failed)} of {len(chosen)} repositories up to date"
          + (f"; failed: {', '.join(failed)}" if failed else ""))

    if not args.no_index:
        try:
            from archer.build.osint_index import build_full_index
        except ImportError as e:   # toml/yaml missing: fine for a fetch-only machine
            print(f"Index not rebuilt ({e}); run scripts/data/build_osint_index.py where Archer is installed")
        else:
            build_full_index()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

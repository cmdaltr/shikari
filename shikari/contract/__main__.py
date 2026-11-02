"""CLI: python -m shikari.contract <command> ...

  validate <file.yaml> [...]       full contract validation; exit 1 on any finding
  lint <file|dir> [...]            query-level lint of legacy Shikari YAML; exit 1 on any finding
  report <file|dir> [...]          lint legacy YAML and print a per-gate summary (never exits 1)
  prompt [--siem yara_l|kql]       print the contract prompt block
"""
import argparse
import sys
from collections import Counter

from .legacy import iter_yaml_files, lint_legacy_file
from .prompt import contract_prompt_block
from .validator import validate_file


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m shikari.contract")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate"); v.add_argument("files", nargs="+")
    l = sub.add_parser("lint"); l.add_argument("targets", nargs="+")
    r = sub.add_parser("report"); r.add_argument("targets", nargs="+"); r.add_argument("--top", type=int, default=25)
    p = sub.add_parser("prompt"); p.add_argument("--siem", default="yara_l"); p.add_argument("--type", default="scheduled_detection")
    a = ap.parse_args(argv)

    if a.cmd == "validate":
        bad = 0
        for f in a.files:
            rep = validate_file(f)
            print(f"{'PASS' if rep.ok() else 'FAIL'}  {f}")
            for x in rep.fails: print(f"       {x}"); bad += 1
        return 1 if bad else 0

    files = iter_yaml_files(a.targets) if a.cmd in ("lint", "report") else []
    if a.cmd == "lint":
        bad = 0
        for f in files:
            rep = lint_legacy_file(f)
            if rep.fails:
                bad += 1; print(f"FAIL  {f} ({rep.siem})")
                for x in rep.fails: print(f"       {x}")
        print(f"\n{len(files)} files, {bad} with findings")
        return 1 if bad else 0

    if a.cmd == "report":
        gates, by_siem, examples = Counter(), Counter(), {}
        parse_failed = linted = with_findings = skipped = 0
        for f in files:
            rep = lint_legacy_file(f)
            if any(g in ("YAML", "LEGACY-0") for g in rep.gates()):
                parse_failed += 1
            elif rep.siem in (None, "spl"):
                skipped += 1
            else:
                linted += 1
                if rep.fails: with_findings += 1
            by_siem[rep.siem or "unparsed"] += 1
            for g in set(rep.gates()):
                gates[g] += 1; examples.setdefault(g, f)
        print(f"files: {len(files)}  by syntax: {dict(by_siem)}")
        print(f"linted (kql/yara_l): {linted}, with findings: {with_findings}; skipped (spl/unknown): {skipped}; failed to parse: {parse_failed}\n")
        print(f"{'gate':14s} {'files':>6s}  example")
        for g, n in gates.most_common(a.top):
            print(f"{g:14s} {n:6d}  {examples[g]}")
        return 0

    if a.cmd == "prompt":
        print(contract_prompt_block(a.siem, a.type)); return 0


if __name__ == "__main__":
    sys.exit(main())

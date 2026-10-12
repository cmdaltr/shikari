"""
Which techniques can't produce a detection, known before a run spends time or tokens on them.

Two lists:

- No indicators (static, from ATT&CK): the technique's description and every group's
  procedure example for it (and, for a parent, its sub-techniques') name no command, file, registry key, API, port or service, so
  the standard pipeline has nothing to build a query from (T1190, T1566.001). Only AI or
  OSINT can produce something. Built from the ATT&CK bundle and rebuilt when the ATT&CK
  version changes (archer/data/technique_yield.json, committed).

- AI comes back empty (learnt): techniques the LLM has returned no queries for on
  LLM_EMPTY_LIMIT runs in a row. Further runs skip the LLM call for them and use the
  standard pipeline only; one successful call clears the count (data/technique_yield_llm.json).

    python -m archer.build.technique_yield            # print both lists
    python -m archer.build.technique_yield --rebuild  # rebuild the ATT&CK list
"""

import json
import os
import threading
import time
from typing import Dict, Iterable, Optional

from archer.config import DATA_DIR

STATIC_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "technique_yield.json")
LEDGER_PATH = os.path.join(DATA_DIR, "technique_yield_llm.json")
LLM_EMPTY_LIMIT = 3

REASONS = {
    "no_indicators": "ATT&CK names no command, file, registry key or other indicator for it; "
                     "only AI or OSINT can build a query",
    "llm_empty": "AI returned no queries for it on {n} runs in a row; the AI call was skipped",
    "no_source": "its indicators fit none of the configured data sources",
    "osint_empty": "no indicators from ATT&CK and nothing usable from OSINT",
    "ai_none": "neither ATT&CK nor the AI produced a query for it",
    "ai_failed": "the AI call failed; see the server log",
    "pre_compromise": "pre-compromise activity (Reconnaissance or Resource Development) "
                      "that no log source sees",
}

_lock = threading.Lock()
_static: Optional[dict] = None
_building = False


def attack_version(bundle) -> str:
    for obj in getattr(bundle, "objects", None) or bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return f"{obj.get('x_mitre_version', '')} {obj.get('modified', '')}".strip()
    return ""


def build(bundle) -> dict:
    """Run every technique's ATT&CK text through the standard pipeline's indicator extraction."""
    from archer.build.detections import filter_generic_indicators, load_indicator_mappings
    from archer.mitre.retrieve import retrieve_procedures

    usable = {k for k in load_indicator_mappings() if not k.startswith("_")}
    techniques = {}
    objects = getattr(bundle, "objects", None) or bundle.get("objects", [])
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = next((r.get("external_id") for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        try:
            procs = retrieve_procedures(bundle, [(obj.get("description", ""), obj["id"])])
        except Exception:
            continue
        found = {}
        for proc in procs if procs else []:
            if proc[0] != tid and not proc[0].startswith(tid + "."):
                continue
            op = proc[4] if isinstance(proc[4], dict) else {}
            red = proc[5] if isinstance(proc[5], dict) else {}
            found.update({k: v for k, v in {**op, **red}.items() if k != "description" and v})
        found, _ = filter_generic_indicators(found)
        if not any(k in usable for k in found):
            tactics = [p.get("phase_name", "").replace("-", " ").title() for p in obj.get("kill_chain_phases", [])]
            techniques[tid] = {"name": obj.get("name", tid), "tactics": tactics, "reason": "no_indicators"}
    return {"attack_version": attack_version(bundle), "generated": time.strftime("%Y-%m-%d"),
            "checked": sum(1 for o in objects if o.get("type") == "attack-pattern"
                           and not o.get("revoked") and not o.get("x_mitre_deprecated")),
            "techniques": dict(sorted(techniques.items()))}


def _write_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    os.replace(tmp, path)


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def static_list() -> dict:
    global _static
    if _static is None:
        _static = _read_json(STATIC_PATH)
    return _static.get("techniques", {})


def ensure(bundle, background: bool = True) -> None:
    """Rebuild the ATT&CK list when the bundle's version differs from the saved one (~1 min)."""
    global _static, _building
    if _read_json(STATIC_PATH).get("attack_version") == attack_version(bundle):
        return

    def _run():
        global _static, _building
        try:
            data = build(bundle)
            _write_json(STATIC_PATH, data)
            _static = data
            print(f"Technique yield list rebuilt for ATT&CK {data['attack_version']}: "
                  f"{len(data['techniques'])} of {data['checked']} techniques have no indicators")
        except Exception as e:
            print(f"Technique yield list not rebuilt: {e}")
        finally:
            _building = False

    with _lock:
        if _building:
            return
        _building = True
    if background:
        threading.Thread(target=_run, daemon=True).start()
    else:
        _run()


def no_indicators(tid: str) -> bool:
    return tid in static_list()


def llm_exhausted(tid: str) -> int:
    """Consecutive empty LLM runs for the technique, when at or over the limit; else 0."""
    n = _read_json(LEDGER_PATH).get(tid, {}).get("empty", 0)
    return n if n >= LLM_EMPTY_LIMIT else 0


def record_llm(tid: str, produced: bool) -> None:
    if not tid:
        return
    with _lock:
        ledger = _read_json(LEDGER_PATH)
        if produced:
            if tid not in ledger:
                return
            ledger.pop(tid)
        else:
            entry = ledger.setdefault(tid, {"empty": 0})
            entry["empty"] += 1
            entry["last"] = time.strftime("%Y-%m-%d")
        _write_json(LEDGER_PATH, ledger)


def reset_llm(tids: Optional[Iterable[str]] = None) -> int:
    """Forget the learnt list (all, or the given techniques). Returns how many were removed."""
    with _lock:
        ledger = _read_json(LEDGER_PATH)
        drop = set(ledger) if tids is None else {t.upper() for t in tids} & set(ledger)
        for t in drop:
            ledger.pop(t)
        _write_json(LEDGER_PATH, ledger)
    return len(drop)


def describe(reason: str, tid: str = "") -> str:
    n = _read_json(LEDGER_PATH).get(tid, {}).get("empty", LLM_EMPTY_LIMIT) if reason == "llm_empty" else 0
    return REASONS.get(reason, reason).format(n=n)


def preflight(tids: Iterable[str], ai: bool = False, osint: bool = False) -> Dict[str, dict]:
    """
    Techniques of a planned run that will produce nothing, with why. Without AI or OSINT,
    the no-indicator ones; with AI, those the AI has repeatedly come back empty for.
    """
    out = {}
    listed = static_list()
    for tid in tids:
        tid = tid.strip().upper()
        if tid in listed and not ai and not osint:
            out[tid] = {"name": listed[tid]["name"], "reason": "no_indicators", "text": describe("no_indicators")}
        elif ai and not osint and llm_exhausted(tid):
            out[tid] = {"name": listed.get(tid, {}).get("name", tid), "reason": "llm_empty",
                        "text": describe("llm_empty", tid)}
    return out


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m archer.build.technique_yield", description=__doc__.split("\n\n")[0])
    ap.add_argument("--rebuild", action="store_true", help="rebuild the ATT&CK list now")
    ap.add_argument("--reset-llm", nargs="*", metavar="TID", help="forget the learnt AI list (all, or these)")
    args = ap.parse_args(argv)

    if args.reset_llm is not None:
        print(f"Removed {reset_llm(args.reset_llm or None)} technique(s) from the learnt AI list")
        return 0
    if args.rebuild or not os.path.exists(STATIC_PATH):
        from archer.mitre.enterprise import get_stix_data

        global _static
        _static = None
        if os.path.exists(STATIC_PATH):
            os.remove(STATIC_PATH)
        ensure(get_stix_data("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
                             "enterprise-attack/enterprise-attack.json"), background=False)
        _static = None

    data = _read_json(STATIC_PATH)
    listed = data.get("techniques", {})
    print(f"No indicators in ATT&CK (ATT&CK {data.get('attack_version', '?')}): "
          f"{len(listed)} of {data.get('checked', '?')} techniques\n")
    for tid, t in listed.items():
        print(f"  {tid:<10} {t['name'][:50]:<50} {', '.join(t.get('tactics', []))}")
    ledger = _read_json(LEDGER_PATH)
    print(f"\nAI returned nothing ({LLM_EMPTY_LIMIT}+ runs in a row = skipped): "
          f"{sum(1 for v in ledger.values() if v.get('empty', 0) >= LLM_EMPTY_LIMIT)}")
    for tid, v in sorted(ledger.items()):
        mark = "skipped" if v.get("empty", 0) >= LLM_EMPTY_LIMIT else "counting"
        print(f"  {tid:<10} {v.get('empty')} empty, last {v.get('last', '?')}  {mark}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
archer.mitre.procedures
=======================

Adapter module that delegates MITRE ATT&CK data extraction to MITRESaw
(included as a git submodule at ./MITRESaw/) and provides the interface
that Archer internals expect.

Data generation (CSV / XLSX):
    Runs MITRESaw CLI:  python MITRESaw.py -f Enterprise -D -E -q -A -S
    on Archer's ATT&CK bundle, one run at a time, then checks the CSV against
    Archer's own walk of that bundle (check_procedures): Archer is the reference.
    Output: mitre_procedures.csv + mitre_procedures.xlsx

Real-time STIX operations (used by app.py hunter/export routes):
    _build_indexes, _resolve_group, _walk_path1/2/3, _attack_id, _clean
    These work on the in-memory STIX bundle (app.state.bundle) and are
    retained here because MITRESaw's architecture uses MitreAttackData
    rather than raw STIX dicts.
"""

from __future__ import annotations

import atexit
import csv
import fcntl
import json
import glob as _glob
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Source URLs (kept for fetch_stix which is used by app.py at startup)
# ---------------------------------------------------------------------------

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)

XLSX_URL = (
    "https://attack.mitre.org/docs/attack-excel-files/v18.1"
    "/enterprise-attack/enterprise-attack-v18.1-relationships.xlsx"
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).parent.parent.parent
_DEFAULT_CSV = _PROJECT_ROOT / "data" / "mitre_procedures.csv"
_DEFAULT_XLSX = _PROJECT_ROOT / "data" / "mitre_procedures.xlsx"


def _find_mitresaw() -> Path:
    """MITRESaw: $MITRESAW_DIR, else the submodule (./MITRESaw), else a checkout beside
    Archer (../MITRESaw). The first that has MITRESaw.py wins."""
    candidates = [Path(os.environ["MITRESAW_DIR"])] if os.environ.get("MITRESAW_DIR") else []
    candidates += [_PROJECT_ROOT / "MITRESaw", _PROJECT_ROOT.parent / "MITRESaw"]
    return next((c for c in candidates if (c / "MITRESaw.py").exists()), candidates[0])


_MITRESAW_DIR = _find_mitresaw()
_MITRESAW_VENV = Path.home() / ".venvs" / "mitresaw"


def _mitresaw_python() -> str:
    """An interpreter that can import MITRESaw's dependencies. MITRESaw pins different
    pandas/stix2 versions from Archer, so it runs in its own environment:
    $MITRESAW_PYTHON, ~/.venvs/mitresaw (outside OneDrive, which breaks a venv's
    symlinks), MITRESaw/.venv, then Archer's own interpreter."""
    candidates = [os.environ.get("MITRESAW_PYTHON") or "", str(_MITRESAW_VENV / "bin" / "python"),
                  str(_MITRESAW_DIR / ".venv" / "bin" / "python"), sys.executable]
    for python in filter(None, candidates):
        try:
            if subprocess.run([python, "-c", "import mitreattack"], capture_output=True, timeout=60).returncode == 0:
                return python
        except (OSError, subprocess.TimeoutExpired):
            continue
    raise RuntimeError(
        "No Python environment can run MITRESaw (needs mitreattack-python). Create one outside "
        f"OneDrive: python3 -m venv {_MITRESAW_VENV} && {_MITRESAW_VENV}/bin/pip install "
        f"-r {_MITRESAW_DIR}/requirements.txt (or set MITRESAW_PYTHON)")

# ---------------------------------------------------------------------------
# MITRESaw CSV column order (12 columns)
# ---------------------------------------------------------------------------

FIELDNAMES: List[str] = [
    "group_sw_id",
    "group_sw_name",
    "group_sw_description",
    "technique_id",
    "technique_name",
    "technique_description",
    "tactic",
    "platforms",
    "framework",
    "procedure_example",
    "evidence",
    "detectable_via",
]

# Mapping from MITRESaw column names to Archer's legacy names (for callers
# that reference the old schema). Used by get_group_coverage().
_LEGACY_MAP = {
    "group_sw_id": "group_id",
    "group_sw_name": "group_name",
}


# ---------------------------------------------------------------------------
# Internal helpers (used by app.py for real-time STIX operations)
# ---------------------------------------------------------------------------

def _attack_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _clean(text: Optional[str]) -> str:
    if not text:
        return ""
    return text.replace("\n", " ").replace("\r", " ").strip()


def _tactics(obj: dict) -> List[str]:
    out = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            name = phase.get("phase_name", "").replace("-", " ").title()
            if name:
                out.append(name)
    return out


def _build_indexes(
    objects: List[dict],
) -> Tuple[Dict, Dict, Dict, Dict]:
    """Return (groups, techniques, software, campaigns) dicts keyed by STIX id."""
    groups: Dict[str, dict] = {}
    techniques: Dict[str, dict] = {}
    software: Dict[str, dict] = {}
    campaigns: Dict[str, dict] = {}

    for obj in objects:
        oid = obj.get("id", "")
        t = obj.get("type", "")
        if t == "intrusion-set" and _attack_id(obj).startswith("G"):
            groups[oid] = obj
        elif t == "attack-pattern":
            techniques[oid] = obj
        elif t in ("tool", "malware"):
            software[oid] = obj
        elif t == "campaign":
            campaigns[oid] = obj

    return groups, techniques, software, campaigns


def _resolve_group(groups: Dict[str, dict], identifier: str) -> Optional[str]:
    """Resolve an ATT&CK ID (G1015) or name to a STIX object ID."""
    ident_lower = identifier.lower()
    for stix_id, obj in groups.items():
        if _attack_id(obj).lower() == ident_lower:
            return stix_id
        if obj.get("name", "").lower() == ident_lower:
            return stix_id
        aliases = obj.get("aliases", [])
        if any(a.lower() == ident_lower for a in aliases):
            return stix_id
    return None


def _emit(
    rows: List[dict],
    seen: Set[Tuple],
    group_obj: dict,
    tech_obj: dict,
    attribution_type: str,
    description: str,
) -> None:
    group_id = _attack_id(group_obj)
    tech_id = _attack_id(tech_obj)
    if not group_id or not tech_id:
        return

    tactic_list = _tactics(tech_obj) or [""]
    for tactic in tactic_list:
        key = (tech_id, tactic, group_id, attribution_type)
        if key in seen:
            continue
        seen.add(key)
        group_name = group_obj.get("name", "")
        group_desc = _clean(group_obj.get("description", ""))
        platforms = ", ".join(tech_obj.get("x_mitre_platforms", []))
        rows.append({
            # MITRESaw column names (FIELDNAMES order)
            "group_sw_id": group_id,
            "group_sw_name": group_name,
            "group_sw_description": group_desc,
            "technique_id": tech_id,
            "technique_name": tech_obj.get("name", ""),
            "technique_description": _clean(tech_obj.get("description", "")),
            "tactic": tactic,
            "platforms": platforms,
            "framework": "Enterprise",
            "procedure_example": _clean(description),
            "evidence": "{}",
            "detectable_via": "",
            # Extra fields for in-memory callers
            "attribution_type": attribution_type,
            # Legacy aliases
            "group_id": group_id,
            "group_name": group_name,
            "group_description": group_desc,
        })


def _walk_path1(objects, groups, techniques, rows, seen):
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
        if src in groups and tgt in techniques:
            _emit(rows, seen, groups[src], techniques[tgt], "direct",
                  obj.get("description", ""))


def _walk_path2(objects, groups, techniques, software, rows, seen):
    sw_to_techs: Dict[str, List[Tuple[str, str]]] = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
        if src in software and tgt in techniques:
            sw_to_techs.setdefault(src, []).append((tgt, obj.get("description", "")))

    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
        if src in groups and tgt in software:
            sw_name = software[tgt].get("name", tgt)
            grp_desc = obj.get("description", "")
            for tech_ref, tech_desc in sw_to_techs.get(tgt, []):
                combined = " ".join(filter(None, [grp_desc, tech_desc]))
                _emit(rows, seen, groups[src], techniques[tech_ref],
                      f"via_software:{sw_name}", combined)


def _walk_path3(objects, groups, techniques, campaigns, rows, seen):
    camp_to_groups: Dict[str, Set[str]] = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "attributed-to":
            continue
        src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
        if src in campaigns and tgt in groups:
            camp_to_groups.setdefault(src, set()).add(tgt)

    camp_to_techs: Dict[str, List[Tuple[str, str]]] = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
        if src in campaigns and tgt in techniques:
            camp_to_techs.setdefault(src, []).append((tgt, obj.get("description", "")))

    for camp_id, grp_ids in camp_to_groups.items():
        camp_name = campaigns[camp_id].get("name", camp_id)
        for tech_ref, desc in camp_to_techs.get(camp_id, []):
            for grp_id in grp_ids:
                _emit(rows, seen, groups[grp_id], techniques[tech_ref],
                      f"via_campaign:{camp_name}", desc)


# ---------------------------------------------------------------------------
# Public: fetch STIX (used by app.py at startup for in-memory bundle)
# ---------------------------------------------------------------------------

def fetch_stix(url: str = STIX_URL, timeout: int = 120) -> dict:
    """
    Download and return the raw STIX bundle JSON dict.
    Raises requests.HTTPError on non-200 responses.
    """
    logger.info("Downloading STIX bundle from %s", url)
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    version = next(
        (o.get("x_mitre_version") for o in data.get("objects", [])
         if o.get("type") == "x-mitre-collection"),
        "unknown",
    )
    logger.info("Downloaded ATT&CK v%s (%d objects)", version, len(data.get("objects", [])))
    return data


# ---------------------------------------------------------------------------
# Cache staleness helpers
# ---------------------------------------------------------------------------

CACHE_TTL_SECONDS: int = 7 * 24 * 3600  # 7 days


def is_cache_stale(csv_path: Optional[Path] = None) -> bool:
    """
    Return True if the MITRESaw CSV cache is missing or older than 7 days.

    The cache is the mitre_procedures.csv in Archer's data directory —
    the file written by run_mitresaw() / run_mitresaw_detection().
    """
    path = Path(csv_path) if csv_path is not None else _DEFAULT_CSV
    if not path.exists():
        return True
    age = time.time() - path.stat().st_mtime
    return age > CACHE_TTL_SECONDS


# ---------------------------------------------------------------------------
# Public: run MITRESaw with detection flags (used by detection generation)
# ---------------------------------------------------------------------------

# Enterprise only, the express CSV (-D) and evidence report (-E, which writes
# mitre_procedures.csv/.xlsx), quietly, without MITRESaw's "start?" prompt (-A), with
# techniques reached through a group's software as well as its own and its campaigns' (-S)
_MITRESAW_FLAGS = ["-f", "Enterprise", "-D", "-E", "-q", "-A", "-S"]
_ARCHER_BUNDLE = _PROJECT_ROOT / "archer" / "data" / "cache" / "enterprise-attack.json"
_LOCK = _PROJECT_ROOT / "data" / ".mitresaw.lock"

# The last check of MITRESaw's CSV against ATT&CK (check_procedures), for the server to report
LAST_CHECK: Optional[Dict] = None
# The last incremental plan: groups collected again ("run") and dropped; None for a full run
LAST_PLAN: Optional[Dict] = None


class MitresawBusy(RuntimeError):
    """Another rebuild holds the lock: two runs write the same files."""


@contextmanager
def _mitresaw_lock():
    _LOCK.parent.mkdir(parents=True, exist_ok=True)
    with open(_LOCK, "w") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MitresawBusy("MITRESaw is already rebuilding the procedures CSV") from None
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def _expected_techniques(bundle_path: Path) -> Dict[str, Set[str]]:
    """Archer's own walk of ATT&CK: each current group's techniques, its own, its
    campaigns' and its software's, leaving out anything revoked or deprecated."""
    with open(bundle_path, encoding="utf-8") as fh:
        objects = [o for o in json.load(fh).get("objects", [])
                   if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    groups, techniques, software, campaigns = _build_indexes(objects)
    rows: List[dict] = []
    seen: Set[Tuple] = set()
    _walk_path1(objects, groups, techniques, rows, seen)
    _walk_path2(objects, groups, techniques, software, rows, seen)
    _walk_path3(objects, groups, techniques, campaigns, rows, seen)
    expected: Dict[str, Set[str]] = {_attack_id(g): set() for g in groups.values()}
    for r in rows:
        expected.setdefault(r["group_sw_id"], set()).add(r["technique_id"])
    return expected


def check_procedures(csv_path: Path, bundle_path: Path) -> Dict:
    """Compare MITRESaw's CSV with Archer's own walk of the same ATT&CK bundle: which
    techniques each group has. Archer is the reference, so a difference is MITRESaw's."""
    expected = _expected_techniques(bundle_path)
    found: Dict[str, Set[str]] = {}
    csv.field_size_limit(sys.maxsize)
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            gid, tid = row.get("group_sw_id", ""), row.get("technique_id", "")
            if gid.startswith("G") and tid:
                found.setdefault(gid, set()).add(tid)
    missing = {g: sorted(t - found.get(g, set())) for g, t in expected.items() if t - found.get(g, set())}
    extra = {g: sorted(t - expected.get(g, set())) for g, t in found.items() if t - expected.get(g, set())}
    return {
        "ok": not missing and not extra,
        "groups": len([g for g, t in expected.items() if t]),
        "techniques": len(set().union(*expected.values())) if expected else 0,
        "missing": missing,
        "extra": extra,
    }


def describe_check(check: Dict) -> str:
    """One line for the log: matches, or what differs."""
    if check["ok"]:
        return (f"MITRESaw's procedures match ATT&CK: {check['groups']} groups, "
                f"{check['techniques']} techniques")
    def sample(d):
        return "; ".join(f"{g}: {', '.join(t[:3])}{'…' if len(t) > 3 else ''}" for g, t in list(d.items())[:3])
    parts = []
    if check["missing"]:
        n = sum(map(len, check["missing"].values()))
        parts.append(f"{n} group-technique links missing across {len(check['missing'])} groups ({sample(check['missing'])})")
    if check["extra"]:
        n = sum(map(len, check["extra"].values()))
        parts.append(f"{n} not in ATT&CK across {len(check['extra'])} groups ({sample(check['extra'])})")
    return "MITRESaw's procedures differ from ATT&CK: " + "; ".join(parts)


def _share_attack_bundle() -> bool:
    """Give MITRESaw the ATT&CK bundle Archer already fetched (attack-stix-data, the
    latest release, checked on every start), so both tools run on the same release and
    MITRESaw needn't download its own. A fresh mtime keeps MITRESaw from treating it as
    a stale cache. False when Archer has no bundle yet."""
    if not _ARCHER_BUNDLE.exists():
        return False
    target = _MITRESAW_DIR / "data" / "stix" / "enterprise-attack.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(_ARCHER_BUNDLE, target)
    logger.info("Shared Archer's ATT&CK bundle with MITRESaw: %s", target)
    return True


def _run_mitresaw(output_csv: Optional[Path], output_xlsx: Optional[Path],
                  force: bool, full: bool = False) -> Tuple[Path, Optional[Path]]:
    # One at a time: concurrent runs write the same dated folder and break each other
    with _mitresaw_lock():
        return _run_mitresaw_locked(output_csv, output_xlsx, force, full)


def _meta_path(output_csv: Path) -> Path:
    return output_csv.with_name(output_csv.stem + ".meta.json")


def _read_meta(output_csv: Path) -> Optional[Dict]:
    try:
        with open(_meta_path(output_csv), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_meta(output_csv: Path, version: str, index: Dict, flags: List[str], mode: str,
                plan_: Optional[Dict]) -> None:
    meta = {
        "attack_version": version,
        "built": datetime.now().isoformat(timespec="seconds"),
        "mode": mode,
        "flags": flags,
        "groups_collected": plan_["run"] if plan_ else "all",
        "groups_dropped": plan_["drop"] if plan_ else [],
        "objects": index,
    }
    path = _meta_path(output_csv)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, separators=(",", ":"))
    os.replace(tmp, path)


def _read_rows(path: Path) -> Tuple[List[str], List[dict]]:
    csv.field_size_limit(sys.maxsize)
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader.fieldnames or []), list(reader)


# MITRESaw processes this Archer process started, stopped if Archer exits first (a server
# reload, a stopped job) so none run on unattended beside the next collection
_CHILDREN: Set[subprocess.Popen] = set()


@atexit.register
def _stop_children() -> None:
    for proc in list(_CHILDREN):
        if proc.poll() is None:
            proc.terminate()


def _run_command(cmd: List[str], cwd: str, timeout: int) -> subprocess.CompletedProcess:
    with subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          stdin=subprocess.DEVNULL, text=True) as proc:
        _CHILDREN.add(proc)
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise
        finally:
            _CHILDREN.discard(proc)
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def _groups_in_csv(path: Path) -> Set[str]:
    return {r.get("group_sw_id", "") for r in _read_rows(path)[1]}


def _invoke_mitresaw(flags: List[str]) -> Optional[Path]:
    """Run MITRESaw and return the procedures CSV this run wrote (None when it found no
    procedures for the groups asked for)."""
    mitresaw_script = _MITRESAW_DIR / "MITRESaw.py"
    if not mitresaw_script.exists():
        raise FileNotFoundError(
            f"MITRESaw not found at {mitresaw_script}. Clone it beside Archer, or set MITRESAW_DIR")
    logger.info("Running MITRESaw: %s %s", mitresaw_script, " ".join(flags))
    started = time.time()
    result = _run_command(
        [_mitresaw_python(), str(mitresaw_script)] + flags,
        cwd=str(_MITRESAW_DIR),
        # A batch of groups takes minutes; an unbatched full run (no bundle to batch by) hours
        timeout=(3600 if "-g" in flags else 6 * 3600),
    )
    if result.returncode != 0:
        logger.error("MITRESaw failed (exit %d):\n%s", result.returncode, result.stderr)
        raise RuntimeError(f"MITRESaw exited with code {result.returncode}: {result.stderr[-2000:]}")
    logger.info("MITRESaw output:\n%s", result.stdout[-500:] if result.stdout else "(empty)")

    # MITRESaw writes data/YYYY-MM-DD/ (a subfolder of it when filtered by group; older
    # versions: YYYY-MM-DD/) under its own directory. Only output from this run counts:
    # an older CSV would pass for a rebuild. The evidence report's CSV sits beside its
    # XLSX; a filtered run also writes the express CSV elsewhere.
    fresh = lambda p: p.stat().st_mtime >= started - 1
    candidates = [p for pattern in ("data/*/mitre_procedures.csv", "data/*/*/mitre_procedures.csv",
                                    "data/mitre_procedures.csv", "*/mitre_procedures.csv")
                  for p in _MITRESAW_DIR.glob(pattern) if fresh(p)]
    if not candidates:
        if "No evidence could be found" in (result.stdout or ""):
            return None
        raise FileNotFoundError(
            f"MITRESaw finished but wrote no new mitre_procedures.csv under {_MITRESAW_DIR}. "
            f"stdout: {result.stdout[-300:]}")
    if "-g" in flags:
        # Another MITRESaw run may have written beside this one: only a CSV of exactly
        # these groups is this run's
        asked = set(flags[flags.index("-g") + 1].split(","))
        candidates = [p for p in candidates if _groups_in_csv(p) and _groups_in_csv(p) <= asked]
        if not candidates:
            raise FileNotFoundError(f"MITRESaw wrote no CSV of the groups asked for ({len(asked)} groups)")
    beside_xlsx = [p for p in candidates
                   if (p.parent / "mitre_procedures.xlsx").exists() and fresh(p.parent / "mitre_procedures.xlsx")]
    return max(beside_xlsx or candidates, key=lambda p: p.stat().st_mtime)


# Groups per MITRESaw run. All 176 in one run take hours; batches keep each run short and
# are saved as they finish, so an interrupted collection carries on where it stopped.
_BATCH_SIZE = 20


def _collect(groups: List[str], flags: List[str], output_csv: Path, key: str) -> Tuple[List[str], List[dict]]:
    """Collect these groups' rows from MITRESaw in batches. Finished batches are kept in
    <csv>.building.csv / .building.json until the whole job is done; a later call with
    the same key (same flags, groups and ATT&CK) resumes from them."""
    staging = output_csv.with_name(output_csv.stem + ".building.csv")
    progress = output_csv.with_name(output_csv.stem + ".building.json")
    state: Dict = {}
    try:
        state = json.loads(progress.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    if state.get("key") != key or not staging.exists():
        state = {"key": key, "done": [], "fieldnames": []}
        staging.unlink(missing_ok=True)
    done = set(state["done"])
    fieldnames: List[str] = state["fieldnames"]
    rows = _read_rows(staging)[1] if staging.exists() else []
    if done:
        logger.info("Resuming: %d of %d groups already collected", len(done), len(groups))

    todo = [g for g in groups if g not in done]
    batches = [todo[i:i + _BATCH_SIZE] for i in range(0, len(todo), _BATCH_SIZE)]
    for n, batch in enumerate(batches, 1):
        logger.info("MITRESaw batch %d of %d: %d groups (%d of %d collected)",
                    n, len(batches), len(batch), len(done), len(groups))
        src = _invoke_mitresaw(flags + ["-g", ",".join(batch)])
        new: List[dict] = []
        if src is not None:
            names, out = _read_rows(src)
            fieldnames = fieldnames or names
            new = [r for r in out if r.get("group_sw_id") in set(batch)]
        if new:
            first = not staging.exists()
            with open(staging, "a", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
                if first:
                    writer.writeheader()
                writer.writerows(new)
        rows.extend(new)
        done.update(batch)
        state.update(done=sorted(done), fieldnames=fieldnames)
        tmp = progress.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, progress)
    return fieldnames, rows


def _finish_collect(output_csv: Path) -> None:
    for suffix in (".building.csv", ".building.json"):
        output_csv.with_name(output_csv.stem + suffix).unlink(missing_ok=True)


def _job_key(flags: List[str], groups: List[str], index: Dict) -> str:
    import hashlib
    body = json.dumps([flags, groups, sorted(v[2] for v in index.values())])
    return hashlib.sha1(body.encode("utf-8")).hexdigest()


def _write_rows(output_csv: Path, fieldnames: List[str], rows: List[dict]) -> None:
    # MITRESaw lists groups by name: keep each group's rows together in that order
    rows = sorted(rows, key=lambda r: r.get("group_sw_name", "").casefold())
    tmp = output_csv.with_suffix(".tmp")
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp, output_csv)


def _run_mitresaw_locked(output_csv: Optional[Path], output_xlsx: Optional[Path],
                         force: bool, full: bool) -> Tuple[Path, Optional[Path]]:
    global LAST_CHECK, LAST_PLAN
    from archer.mitre import attack_delta

    output_csv = Path(output_csv or _DEFAULT_CSV)
    output_xlsx = Path(output_xlsx or _DEFAULT_XLSX)
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    flags = list(_MITRESAW_FLAGS)
    shared = _share_attack_bundle()
    # With Archer's bundle shared there's nothing for MITRESaw to fetch
    if not shared and force:
        flags.append("-F")

    # Collect only the groups ATT&CK changed since the last build, unless asked for a
    # full collection or there's nothing to compare with (no bundle, no index, other flags)
    index, version = None, ""
    LAST_PLAN = None
    if shared:
        with open(_ARCHER_BUNDLE, encoding="utf-8") as fh:
            objects = json.load(fh).get("objects", [])
        index = attack_delta.build_index(objects)
        version = next((o.get("x_mitre_version", "") for o in objects if o.get("type") == "x-mitre-collection"), "")
    meta = _read_meta(output_csv)
    if index is not None and not full and meta and meta.get("flags") == flags and output_csv.exists():
        fieldnames, rows = _read_rows(output_csv)
        links: Dict[str, Set[str]] = {}
        for r in rows:
            links.setdefault(r.get("group_sw_id", ""), set()).add(r.get("technique_id", ""))
        LAST_PLAN = attack_delta.plan(meta.get("objects"), index, links)

    xlsx_result: Optional[Path] = None
    all_groups = sorted(set(attack_delta.groups_in(index))) if index else []
    if LAST_PLAN is None and not all_groups:
        # Nothing to batch by (no bundle to share): one run over every group
        src_csv = _invoke_mitresaw(flags)
        if src_csv is None:
            raise FileNotFoundError("MITRESaw found no procedures at all")
        shutil.copy2(str(src_csv), str(output_csv))
        logger.info("Copied MITRESaw CSV to %s", output_csv)
        src_xlsx = src_csv.parent / "mitre_procedures.xlsx"
        if src_xlsx.exists():
            shutil.copy2(str(src_xlsx), str(output_xlsx))
            logger.info("Copied MITRESaw XLSX to %s", output_xlsx)
            xlsx_result = output_xlsx
        mode = "full"
    elif LAST_PLAN is None:
        # Every group, in batches; the evidence XLSX is per batch, so it isn't kept
        # (nothing in Archer reads it)
        logger.info("Full collection: %d groups in batches of %d", len(all_groups), _BATCH_SIZE)
        fieldnames, rows = _collect(all_groups, flags, output_csv, _job_key(flags, all_groups, index))
        _write_rows(output_csv, fieldnames, rows)
        _finish_collect(output_csv)
        mode = "full"
    else:
        run, drop = LAST_PLAN["run"], LAST_PLAN["drop"]
        logger.info("ATT&CK changes touch %d groups (%d gone)", len(run), len(drop))
        if run or drop:
            fresh: List[dict] = []
            if run:
                names, fresh = _collect(run, flags, output_csv, _job_key(flags, run, index))
                fieldnames = fieldnames or names
            replaced = set(run) | set(drop)
            _write_rows(output_csv, fieldnames, [r for r in rows if r.get("group_sw_id") not in replaced] + fresh)
            _finish_collect(output_csv)
            logger.info("Updated %s: %d groups collected again, %d dropped", output_csv, len(run), len(drop))
        # The evidence XLSX stays from the last full collection (nothing in Archer reads it)
        mode = "incremental"

    if index is not None:
        _write_meta(output_csv, version, index, flags, mode, LAST_PLAN)
    if _ARCHER_BUNDLE.exists():
        try:
            LAST_CHECK = check_procedures(output_csv, _ARCHER_BUNDLE)
            (logger.info if LAST_CHECK["ok"] else logger.warning)(describe_check(LAST_CHECK))
        except Exception as e:  # the check never costs the rebuild
            logger.warning("Couldn't check MITRESaw's procedures against ATT&CK: %s", e)
    return output_csv, xlsx_result


def run_mitresaw_detection(
    output_csv: Optional[Path] = None,
    output_xlsx: Optional[Path] = None,
    force: bool = False,
    full: bool = False,
) -> Tuple[Path, Optional[Path]]:
    """
    Run MITRESaw for the procedures CSV and evidence XLSX, on Archer's ATT&CK bundle.
    Only the groups ATT&CK changed since the last build are collected again (see
    archer.mitre.attack_delta); full=True collects every group.
    force fetches ATT&CK in MITRESaw (-F) only when Archer has no bundle to share.
    Returns (csv_path, xlsx_path); xlsx_path is None unless the XLSX was rebuilt.
    """
    return _run_mitresaw(output_csv, output_xlsx, force, full)


def run_mitresaw(
    output_csv: Optional[Path] = None,
    output_xlsx: Optional[Path] = None,
    full: bool = False,
) -> Tuple[Path, Optional[Path]]:
    """Run MITRESaw and update mitre_procedures.csv (and the XLSX on a full run) in
    Archer's data directory: only the groups ATT&CK changed, unless full."""
    return _run_mitresaw(output_csv, output_xlsx, force=False, full=full)


def build_procedures_csv(
    output_path: Optional[Path] = None,
    stix_url: str = STIX_URL,
    xlsx_url: str = XLSX_URL,
    validate: bool = True,
) -> Path:
    """
    Generate mitre_procedures.csv by running MITRESaw.

    This replaces the previous implementation that duplicated MITRESaw's
    STIX extraction logic. The stix_url, xlsx_url, and validate parameters
    are accepted for backward compatibility but are not used — MITRESaw
    handles its own STIX fetching and validation.

    Args:
        output_path: Where to write the CSV. Defaults to data/mitre_procedures.csv.
        stix_url:    Ignored (kept for API compatibility).
        xlsx_url:    Ignored (kept for API compatibility).
        validate:    Ignored (kept for API compatibility).

    Returns:
        Path to the written CSV file.
    """
    csv_path, _ = run_mitresaw(output_csv=output_path)
    return csv_path


# ---------------------------------------------------------------------------
# Public: coverage check (reads MITRESaw's CSV output)
# ---------------------------------------------------------------------------

_TECHNIQUE_LINE = re.compile(r"^(?:technique_id:|\s*-)\s*['\"]?(T\d{4}(?:\.\d{3})?)\b", re.M)


def _detected_technique_ids(generate_path: Path) -> set:
    ids = set()
    for path in _glob.glob(str(generate_path / "*.yaml")):
        try:
            with open(path, encoding="utf-8") as fh:
                head = fh.read(4000)  # technique_id/techniques sit near the top
        except OSError:
            continue
        ids.update(_TECHNIQUE_LINE.findall(head))
    return ids


def get_group_coverage(group: str, generate_dir) -> Optional[Dict]:
    """
    Load mitre_procedures.csv (generated by MITRESaw), filter by group name
    or ATT&CK ID, and check which techniques already have detection YAML
    files in generate_dir.

    Args:
        group: Group name (e.g. "Scattered Spider") or ATT&CK ID (e.g. "G1015")
        generate_dir: Path to the directory containing generated detection YAMLs

    Returns:
        Dict with keys: group_name, group_id, total, covered_count, gap_count,
        covered (list), gaps (list). Returns None if group not found in CSV.
    """
    csv_path = _DEFAULT_CSV
    if not csv_path.exists():
        return None

    rows = []
    group_lower = group.lower()
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # MITRESaw's 12-column CSV, or the older 9-column one (group_id/group_name)
            gid = (row.get("group_sw_id") or row.get("group_id") or "").upper()
            gname = (row.get("group_sw_name") or row.get("group_name") or "").lower()
            if gid == group.upper() or gname == group_lower:
                rows.append(row)

    group_found = bool(rows)
    # Reconnaissance and Resource Development are outside Archer's scope (archer.tactic_scope)
    from archer.tactic_scope import excluded
    rows = [r for r in rows if not excluded(r.get("tactic", ""))]

    if not group_found:
        return None
    if not rows:
        return {"group_name": group, "group_id": "", "total": 0, "covered_count": 0, "gap_count": 0,
                "covered": [], "gaps": []}

    group_name = rows[0].get("group_sw_name") or rows[0].get("group_name")
    group_id = rows[0].get("group_sw_id") or rows[0].get("group_id")

    # Deduplicate by technique_id — keep first occurrence per technique
    seen: Dict[str, dict] = {}
    for row in rows:
        tid = row["technique_id"]
        if tid not in seen:
            seen[tid] = {
                "technique_id": tid,
                "technique_name": row["technique_name"],
                "tactic": row["tactic"],
                # The 12-column CSV doesn't carry it; its rows are direct attributions
                "attribution_type": row.get("attribution_type") or "direct",
                "covered": False,
            }

    # Coverage: a detection file names the technique (technique_id, or the techniques
    # list of bespoke files). Files are named after the technique *name*, so the old
    # filename-prefix check never matched
    covered_ids = _detected_technique_ids(Path(str(generate_dir)))
    for tid, data in seen.items():
        data["covered"] = tid in covered_ids

    techniques = list(seen.values())
    covered = [t for t in techniques if t["covered"]]
    gaps = [t for t in techniques if not t["covered"]]

    return {
        "group_name": group_name,
        "group_id": group_id,
        "total": len(techniques),
        "covered_count": len(covered),
        "gap_count": len(gaps),
        "covered": covered,
        "gaps": gaps,
    }


# ---------------------------------------------------------------------------
# Kept for backward compatibility — these were part of the old public API
# but are no longer used for CSV generation. They use the in-memory STIX
# bundle for real-time lookups.
# ---------------------------------------------------------------------------

def get_group_techniques(
    bundle: dict,
    group_id_or_name: str,
) -> List[Dict]:
    """
    Return all technique records for a group, following all three attribution paths.
    Uses the in-memory STIX bundle (not MITRESaw CLI).
    """
    objects = bundle.get("objects", [])
    groups, techniques, software, campaigns = _build_indexes(objects)

    target_stix_id = _resolve_group(groups, group_id_or_name)
    if not target_stix_id:
        raise ValueError(f"Group not found in ATT&CK bundle: {group_id_or_name!r}")

    rows: List[dict] = []
    seen: Set[Tuple] = set()
    group_obj = groups[target_stix_id]

    _walk_path1(objects, {target_stix_id: group_obj}, techniques, rows, seen)
    _walk_path2(objects, {target_stix_id: group_obj}, techniques, software, rows, seen)
    _walk_path3(objects, {target_stix_id: group_obj}, techniques, campaigns, rows, seen)

    return rows


def get_all_procedures(bundle: dict) -> List[Dict]:
    """
    Return all group-technique rows for every group in the bundle.
    Kept for backward compatibility. Prefer run_mitresaw() for CSV generation.
    """
    objects = bundle.get("objects", [])
    groups, techniques, software, campaigns = _build_indexes(objects)

    rows: List[dict] = []
    seen: Set[Tuple] = set()

    _walk_path1(objects, groups, techniques, rows, seen)
    _walk_path2(objects, groups, techniques, software, rows, seen)
    _walk_path3(objects, groups, techniques, campaigns, rows, seen)

    return rows


# ---------------------------------------------------------------------------
# XLSX cross-reference (kept for backward compatibility)
# ---------------------------------------------------------------------------

def fetch_xlsx_relationships(
    url: str = XLSX_URL,
    timeout: int = 120,
) -> Optional[Set[Tuple[str, str]]]:
    """
    Download the ATT&CK relationships XLSX and return a set of
    (source_attack_id, target_attack_id) pairs for cross-validation.
    Returns None if openpyxl is not installed or download fails.
    """
    try:
        import io
        import openpyxl
    except ImportError:
        logger.info("openpyxl not installed — XLSX cross-reference skipped")
        return None

    logger.info("Downloading XLSX relationships from %s", url)
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("XLSX download failed (%s) — skipping cross-reference", exc)
        return None

    wb = openpyxl.load_workbook(io.BytesIO(resp.content), read_only=True, data_only=True)
    ws = next(
        (wb[n] for n in wb.sheetnames if "relation" in n.lower()),
        wb.active,
    )
    header = None
    pairs: Set[Tuple[str, str]] = set()
    for row in ws.iter_rows(values_only=True):
        if header is None:
            header = [str(c).lower().strip() if c else "" for c in row]
            continue
        rd = dict(zip(header, row))
        src = str(rd.get("source id", "") or "").strip()
        tgt = str(rd.get("target id", "") or "").strip()
        if src and tgt:
            pairs.add((src, tgt))

    logger.info("Loaded %d relationship pairs from XLSX", len(pairs))
    return pairs


def cross_reference(
    rows: List[dict],
    xlsx_pairs: Optional[Set[Tuple[str, str]]],
) -> List[Tuple[str, str]]:
    """
    Compare extracted rows against XLSX pairs.
    Returns list of (group_id, technique_id) pairs found in XLSX but not in rows.
    """
    if xlsx_pairs is None:
        return []
    stix_pairs = {(r.get("group_sw_id", r.get("group_id", "")), r["technique_id"]) for r in rows}
    return sorted(
        (src, tgt)
        for src, tgt in xlsx_pairs
        if src.startswith("G") and tgt.startswith("T")
        and (src, tgt) not in stix_pairs
    )


# ---------------------------------------------------------------------------
# CLI entry point  (python -m archer.mitre.procedures)
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(
        description="Rebuild data/mitre_procedures.csv by running MITRESaw.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m archer.mitre.procedures            # only the groups ATT&CK changed
  python -m archer.mitre.procedures --full     # every group (about 90 minutes)
  python -m archer.mitre.procedures --output /tmp/procedures.csv
        """,
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Collect every group again, not just those ATT&CK changed since the last build",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help=f"Output CSV path (default: {_DEFAULT_CSV})",
    )
    args = parser.parse_args()

    csv_path, xlsx_path = run_mitresaw(output_csv=args.output, full=args.full)
    if LAST_PLAN is not None:
        print(f"\nATT&CK changes touched {len(LAST_PLAN['run'])} groups; {len(LAST_PLAN['drop'])} dropped")
    if LAST_CHECK:
        print(describe_check(LAST_CHECK))
    print(f"\n✓ CSV written to {csv_path}")
    if xlsx_path:
        print(f"✓ XLSX written to {xlsx_path}")


if __name__ == "__main__":
    _cli()

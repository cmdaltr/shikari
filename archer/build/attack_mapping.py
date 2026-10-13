"""
A detection's ATT&CK mapping, changed by hand. Archer maps each detection to the
technique and tactics ATT&CK gives it; an analyst can change either, with a comment
saying why, and restore the ATT&CK default later (also with a comment).

The detection's own technique_id, name, tactics and severity always hold the mapping in
force, so correlations, flows and severity follow a change without knowing about it.
attack_override records the ATT&CK default, the comment, who and when; it's absent when
the default applies. attack_mapping_history logs every change and restore.

A SecOps rule's meta (technique, description, severity, $risk_score) follows the
mapping too. Its rule name stays as generated: renaming would make SecOps treat it as a
new rule. The generator stamp's query hash is refreshed when the query was unedited
before, so a mapping change alone never marks the query as edited by hand.
"""

import hashlib
import re
from datetime import datetime
from typing import Dict, List, Optional

import yaml

from archer.build.severity import RISK_SCORE, rate

OVERRIDE_KEY = "attack_override"
HISTORY_KEY = "attack_mapping_history"
_STAMP = re.compile(r"^# archer-generator: (\d+) query-sha256: ([0-9a-f]{64})\s*$")


class MappingError(ValueError):
    pass


class Unchanged(MappingError):
    """The detection already has the mapping asked for."""


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _query_block(content: str) -> str:
    m = re.search(r"^query: \|\n(.*?)(?=^\S|\Z)", content, re.M | re.S)
    return m.group(1).rstrip() if m else ""


def _digest(content: str) -> str:
    return hashlib.sha256(_query_block(content).encode()).hexdigest()


def read(path: str) -> Dict:
    """The mapping in force, the override (or None) and the history of a detection."""
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    return {
        "technique_id": str(doc.get("technique_id") or ""),
        "name": str(doc.get("name") or ""),
        "tactics": list(doc.get("tactics") or []),
        "severity": doc.get("severity"),
        "override": doc.get(OVERRIDE_KEY) or None,
        "history": list(doc.get(HISTORY_KEY) or []),
    }


# Query lines the mapping owns; everything else must come through a rewrite untouched
_MAPPING_LINE = re.compile(r'mitre_attack_technique = |description = "Detects |^\s*severity = "|\$risk_score = ')


def _logic(query) -> List[str]:
    return [line for line in str(query or "").split("\n") if not _MAPPING_LINE.search(line)]


def _drop_block(text: str, key: str) -> str:
    """Remove a top-level key and its value, wherever it sits."""
    lines = text.split("\n")
    out, skipping = [], False
    for line in lines:
        if line.startswith(f"{key}:"):
            skipping = True
            continue
        if skipping and (not line.strip() or line.startswith((" ", "\t", "- "))):
            continue
        skipping = False
        out.append(line)
    return "\n".join(out)


def _dump(key: str, value) -> str:
    return yaml.safe_dump({key: value}, sort_keys=False, allow_unicode=True, width=10000)


def _rewrite(path: str, technique_id: str, name: str, tactics: List[str],
             override: Optional[Dict], history: List[Dict]) -> None:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    first, _, body = text.partition("\n")
    stamp = _STAMP.match(first)
    if not stamp:
        first, body = "", text
    was_unedited = bool(stamp) and _digest(body) == stamp.group(2)
    try:
        old = yaml.safe_load(body) or {}
    except yaml.YAMLError as err:
        raise MappingError(f"The detection isn't valid YAML: {err}")
    old_tid, old_name = str(old.get("technique_id") or ""), str(old.get("name") or "")

    severity = rate(tactics)
    body = re.sub(r"^technique_id: .*$", f"technique_id: {technique_id}", body, count=1, flags=re.M)
    body = re.sub(r"^name: .*$", lambda _: f"name: {name}", body, count=1, flags=re.M)
    body = re.sub(r"^severity: .*$", f"severity: {severity}", body, count=1, flags=re.M)
    tactic_block = "tactics:\n" + "".join(f"  - {t}\n" for t in tactics)
    body, n = re.subn(r"^tactics:\n(?:  - .*\n?)*", lambda _: tactic_block, body, count=1, flags=re.M)
    if not n:
        raise MappingError("The detection has no tactics field")

    # A YARA-L rule's meta and outcome carry the mapping too
    if old_tid:
        body = re.sub(r'(mitre_attack_technique = ")[^"]*(")', rf"\g<1>{technique_id}\g<2>", body)
        body = body.replace(f'"Detects {old_name} ({old_tid})"', f'"Detects {name} ({technique_id})"')
    body = re.sub(r'(^\s*severity = ")[A-Z]+(")', rf"\g<1>{severity.upper()}\g<2>", body, flags=re.M)
    body = re.sub(r"(\$risk_score = )\d+", rf"\g<1>{RISK_SCORE[severity]}", body)

    body = _drop_block(_drop_block(body, OVERRIDE_KEY), HISTORY_KEY).rstrip("\n") + "\n"
    if override:
        body += _dump(OVERRIDE_KEY, override)
    if history:
        body += _dump(HISTORY_KEY, history)

    check = yaml.safe_load(body) or {}
    if (str(check.get("technique_id")) != technique_id or list(check.get("tactics") or []) != tactics
            or _logic(check.get("query")) != _logic(old.get("query"))):
        raise MappingError("Couldn't rewrite the mapping safely; not saved")

    if stamp:
        digest = _digest(body) if was_unedited else stamp.group(2)
        first = f"# archer-generator: {stamp.group(1)} query-sha256: {digest}"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write((first + "\n" if first else "") + body)


def _clean_tactics(tactics, allowed: Optional[List[str]]) -> List[str]:
    picked = [str(t).strip() for t in tactics or [] if str(t).strip()]
    if allowed:
        unknown = [t for t in picked if t not in allowed]
        if unknown:
            raise MappingError(f"Not an ATT&CK tactic: {', '.join(unknown)}")
        picked = [t for t in allowed if t in picked]
    if not picked:
        raise MappingError("Choose at least one tactic")
    return picked


def change(path: str, technique_id: str, tactics, comment: str, by: str,
           index: Optional[Dict[str, Dict]] = None, tactic_order: Optional[List[str]] = None) -> Dict:
    """Map the detection to technique_id and tactics. comment is required. Setting the
    ATT&CK default back counts as a restore."""
    comment = (comment or "").strip()
    if not comment:
        raise MappingError("A comment is required to change the mapping")
    technique_id = (technique_id or "").strip().upper()
    if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique_id):
        raise MappingError(f"Not a technique ID: {technique_id or '(empty)'}")
    if index is not None and technique_id not in index:
        raise MappingError(f"{technique_id} isn't a current ATT&CK technique")
    tactics = _clean_tactics(tactics, tactic_order)

    state = read(path)
    default = (state["override"] or {}).get("default") or {
        "technique_id": state["technique_id"], "name": state["name"], "tactics": state["tactics"]}
    if technique_id == default["technique_id"] and tactics == list(default["tactics"]):
        if not state["override"]:
            raise Unchanged("That's already the ATT&CK mapping")
        return restore(path, comment, by)
    name = (index or {}).get(technique_id, {}).get("name") or (
        default["name"] if technique_id == default["technique_id"] else technique_id)
    if technique_id == state["technique_id"] and tactics == state["tactics"]:
        raise Unchanged("The mapping is unchanged")

    at = _now()
    history = state["history"] + [{
        "action": "changed", "at": at, "by": by, "comment": comment,
        "from": {"technique_id": state["technique_id"], "tactics": state["tactics"]},
        "to": {"technique_id": technique_id, "tactics": tactics},
    }]
    override = {"technique_id": technique_id, "name": name, "tactics": tactics,
                "comment": comment, "by": by, "at": at, "default": default}
    _rewrite(path, technique_id, name, tactics, override, history)
    return read(path)


def restore(path: str, comment: str, by: str) -> Dict:
    """Put the ATT&CK default mapping back. comment is required."""
    comment = (comment or "").strip()
    if not comment:
        raise MappingError("A comment is required to restore the mapping")
    state = read(path)
    if not state["override"]:
        raise Unchanged("The detection already has the ATT&CK mapping")
    default = state["override"]["default"]
    history = state["history"] + [{
        "action": "restored", "at": _now(), "by": by, "comment": comment,
        "from": {"technique_id": state["technique_id"], "tactics": state["tactics"]},
        "to": {"technique_id": default["technique_id"], "tactics": list(default["tactics"])},
    }]
    _rewrite(path, default["technique_id"], default["name"], list(default["tactics"]), None, history)
    return read(path)


def reapply(path: str, override: Optional[Dict], history: Optional[List[Dict]]) -> None:
    """After the generator rewrites a detection: its fresh ATT&CK mapping becomes the
    default, and a hand-made mapping goes back on top, with its history."""
    if not override and not history:
        return
    state = read(path)
    fresh = {"technique_id": state["technique_id"], "name": state["name"], "tactics": state["tactics"]}
    if override and (override["technique_id"], list(override["tactics"])) != (
            fresh["technique_id"], fresh["tactics"]):
        override = {**override, "default": fresh}
        _rewrite(path, override["technique_id"], override["name"], list(override["tactics"]),
                 override, list(history or []))
    else:
        _rewrite(path, fresh["technique_id"], fresh["name"], fresh["tactics"], None, list(history or []))

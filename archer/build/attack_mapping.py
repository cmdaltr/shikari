"""
A detection's ATT&CK mapping, changed by hand. Archer maps each detection to the
technique and tactics ATT&CK gives it; an analyst can change either, with a comment
saying why, and restore the ATT&CK default later (also with a comment).

The detection's own technique_id, name, tactics and severity always hold the mapping in
force, so correlations, flows and severity follow a change without knowing about it.
attack_override records the ATT&CK default, the comment, who and when; it's absent when
the default applies. attack_mapping_history logs every change and restore.

A SecOps rule's meta (technique, description, severity, $risk_score) follows the
mapping too. Its rule name stays as generated unless the change asks for a rename:
SecOps treats a renamed rule as a new rule. Restore puts the generated name back.
The generator stamp's query hash is refreshed when the query was unedited before, so a
mapping change alone never marks the query as edited by hand.

Detection files on disk and Library copies (JSON content) share the same rules: plan_*
decides, and each side applies the plan to its own format.
"""

import copy
import hashlib
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import yaml

from archer.build.severity import RISK_SCORE, rate

OVERRIDE_KEY = "attack_override"
HISTORY_KEY = "attack_mapping_history"
_STAMP = re.compile(r"^# archer-generator: (\d+) query-sha256: ([0-9a-f]{64})\s*$")
_RULE = re.compile(r"^(\s*rule )(\w+)(\s*\{)", re.M)
# Query lines the mapping owns; everything else must come through a rewrite untouched
_MAPPING_LINE = re.compile(
    r'mitre_attack_technique = |description = "Detects |^\s*severity = "|\$risk_score = |^\s*rule \w+\s*\{')


class MappingError(ValueError):
    pass


class Unchanged(MappingError):
    """The detection already has the mapping asked for."""


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def yaral_rule_name(technique_id: str) -> str:
    """Same naming as archer.build.secops.yaral_rule_name (not imported: secops imports this side)."""
    return "archer_" + re.sub(r"\W+", "_", technique_id).strip("_").lower()


def rule_name(query) -> Optional[str]:
    m = _RULE.search(str(query or ""))
    return m.group(2) if m else None


def _logic(query) -> List[str]:
    return [line for line in str(query or "").split("\n") if not _MAPPING_LINE.search(line)]


def _retarget(text: str, old: Dict, new: Dict, severity: str) -> str:
    """Carry a mapping into a YARA-L rule's meta, outcome and (when asked) its name.
    Harmless on KQL/SPL: none of these patterns occur there."""
    if old.get("technique_id"):
        text = re.sub(r'(mitre_attack_technique = ")[^"]*(")', rf"\g<1>{new['technique_id']}\g<2>", text)
        text = text.replace(f'"Detects {old["name"]} ({old["technique_id"]})"',
                            f'"Detects {new["name"]} ({new["technique_id"]})"')
    text = re.sub(r'(^\s*severity = ")[A-Z]+(")', rf"\g<1>{severity.upper()}\g<2>", text, flags=re.M)
    text = re.sub(r"(\$risk_score = )\d+", rf"\g<1>{RISK_SCORE[severity]}", text)
    if new.get("rule_name"):
        text = _RULE.sub(lambda m: m.group(1) + new["rule_name"] + m.group(3), text, count=1)
    return text


def _clean_tactics(tactics, allowed: Optional[List[str]]) -> List[str]:
    picked = [str(t).strip() for t in tactics or [] if str(t).strip()]
    if allowed:
        unknown = [t for t in picked if t not in allowed]
        if unknown:
            raise MappingError(f"Not an ATT&CK tactic Archer detects: {', '.join(unknown)}")
        picked = [t for t in allowed if t in picked]
    if not picked:
        raise MappingError("Choose at least one tactic")
    return picked


# ── Deciding a change or restore (format-free) ───────────────────────────────
# state: {"mapping": {technique_id, name, tactics, rule_name}, "override", "history"}

def _present(mapping: Dict) -> Dict:
    return {k: v for k, v in mapping.items() if v or k != "rule_name"}


def _default(state: Dict) -> Dict:
    return (state["override"] or {}).get("default") or _present(state["mapping"])


def plan_restore(state: Dict, comment: str, by: str) -> Tuple[Dict, None, List[Dict]]:
    comment = (comment or "").strip()
    if not comment:
        raise MappingError("A comment is required to restore the mapping")
    if not state["override"]:
        raise Unchanged("The detection already has the ATT&CK mapping")
    default = dict(state["override"]["default"])
    cur = state["mapping"]
    history = state["history"] + [{
        "action": "restored", "at": _now(), "by": by, "comment": comment,
        "from": {"technique_id": cur["technique_id"], "tactics": cur["tactics"]},
        "to": {"technique_id": default["technique_id"], "tactics": list(default["tactics"])},
    }]
    if default.get("rule_name") and cur.get("rule_name") and default["rule_name"] != cur["rule_name"]:
        history[-1]["rule_renamed"] = {"from": cur["rule_name"], "to": default["rule_name"]}
    return default, None, history


def plan_change(state: Dict, technique_id: str, tactics, comment: str, by: str,
                index: Optional[Dict[str, Dict]] = None, tactic_order: Optional[List[str]] = None,
                rename_rule: bool = False) -> Tuple[Dict, Optional[Dict], List[Dict]]:
    """(mapping to apply, override or None, history). Choosing the ATT&CK default again
    is a restore."""
    comment = (comment or "").strip()
    if not comment:
        raise MappingError("A comment is required to change the mapping")
    technique_id = (technique_id or "").strip().upper()
    if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique_id):
        raise MappingError(f"Not a technique ID: {technique_id or '(empty)'}")
    if index is not None and technique_id not in index:
        raise MappingError(f"{technique_id} isn't a current ATT&CK technique")
    tactics = _clean_tactics(tactics, tactic_order)

    cur, default = state["mapping"], _default(state)
    if technique_id == default["technique_id"] and tactics == list(default["tactics"]):
        if not state["override"]:
            raise Unchanged("That's already the ATT&CK mapping")
        return plan_restore(state, comment, by)
    name = (index or {}).get(technique_id, {}).get("name") or (
        default["name"] if technique_id == default["technique_id"] else technique_id)
    rule = cur.get("rule_name")
    if rule and rename_rule:
        rule = yaral_rule_name(technique_id)
    if technique_id == cur["technique_id"] and tactics == cur["tactics"] and rule == cur.get("rule_name"):
        raise Unchanged("The mapping is unchanged")

    at = _now()
    history = state["history"] + [{
        "action": "changed", "at": at, "by": by, "comment": comment,
        "from": {"technique_id": cur["technique_id"], "tactics": cur["tactics"]},
        "to": {"technique_id": technique_id, "tactics": tactics},
    }]
    if rule and rule != cur.get("rule_name"):
        history[-1]["rule_renamed"] = {"from": cur["rule_name"], "to": rule}
    mapping = {"technique_id": technique_id, "name": name, "tactics": tactics}
    override = {**mapping, "comment": comment, "by": by, "at": at, "default": default}
    if rule:
        mapping["rule_name"] = rule
        if rule != default.get("rule_name"):
            override["rule_name"] = rule
    return mapping, override, history


# ── Detection files ──────────────────────────────────────────────────────────

def _query_block(content: str) -> str:
    m = re.search(r"^query: \|\n(.*?)(?=^\S|\Z)", content, re.M | re.S)
    return m.group(1).rstrip() if m else ""


def _digest(content: str) -> str:
    return hashlib.sha256(_query_block(content).encode()).hexdigest()


def read(path: str) -> Dict:
    """The mapping in force, the override (or None) and the history of a detection."""
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    mapping = {"technique_id": str(doc.get("technique_id") or ""), "name": str(doc.get("name") or ""),
               "tactics": list(doc.get("tactics") or []), "rule_name": rule_name(doc.get("query"))}
    return {
        **mapping, "mapping": mapping, "severity": doc.get("severity"),
        "override": doc.get(OVERRIDE_KEY) or None,
        "history": list(doc.get(HISTORY_KEY) or []),
    }


def _drop_block(text: str, key: str) -> str:
    """Remove a top-level key and its value, wherever it sits."""
    out, skipping = [], False
    for line in text.split("\n"):
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


def _rewrite(path: str, mapping: Dict, override: Optional[Dict], history: List[Dict]) -> None:
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
    old_map = {"technique_id": str(old.get("technique_id") or ""), "name": str(old.get("name") or "")}
    technique_id, name, tactics = mapping["technique_id"], mapping["name"], list(mapping["tactics"])

    severity = rate(tactics)
    body = re.sub(r"^technique_id: .*$", f"technique_id: {technique_id}", body, count=1, flags=re.M)
    body = re.sub(r"^name: .*$", lambda _: f"name: {name}", body, count=1, flags=re.M)
    body = re.sub(r"^severity: .*$", f"severity: {severity}", body, count=1, flags=re.M)
    tactic_block = "tactics:\n" + "".join(f"  - {t}\n" for t in tactics)
    body, n = re.subn(r"^tactics:\n(?:  - .*\n?)*", lambda _: tactic_block, body, count=1, flags=re.M)
    if not n:
        raise MappingError("The detection has no tactics field")
    body = _retarget(body, old_map, mapping, severity)

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


def change(path: str, technique_id: str, tactics, comment: str, by: str,
           index: Optional[Dict[str, Dict]] = None, tactic_order: Optional[List[str]] = None,
           rename_rule: bool = False) -> Dict:
    """Map the detection file to technique_id and tactics. comment is required."""
    _rewrite(path, *plan_change(read(path), technique_id, tactics, comment, by, index, tactic_order,
                                rename_rule))
    return read(path)


def restore(path: str, comment: str, by: str) -> Dict:
    """Put the ATT&CK default mapping back. comment is required."""
    _rewrite(path, *plan_restore(read(path), comment, by))
    return read(path)


def reapply(path: str, override: Optional[Dict], history: Optional[List[Dict]]) -> None:
    """After the generator rewrites a detection: its fresh ATT&CK mapping becomes the
    default, and a hand-made mapping goes back on top, with its history."""
    if not override and not history:
        return
    fresh = _present(read(path)["mapping"])
    history = list(history or [])
    if override and ((override["technique_id"], list(override["tactics"]))
                     != (fresh["technique_id"], fresh["tactics"]) or override.get("rule_name")):
        override = {**override, "default": fresh}
        mapping = {k: override[k] for k in ("technique_id", "name", "tactics")}
        if override.get("rule_name"):
            mapping["rule_name"] = override["rule_name"]
        _rewrite(path, mapping, override, history)
    else:
        _rewrite(path, fresh, None, history)


# ── Library copies (JSON content saved from the results page or imported YAML) ─

def _content_keys(content: Dict) -> Dict[str, str]:
    """Where a Library copy keeps each part of its mapping."""
    if "requiredDataConnectors" in content or "technique_id" in content:
        return {"technique_id": "technique_id", "name": "name"}
    return {"technique_id": "attack_id", "name": "technique_display"}


def content_state(content: Dict, index: Optional[Dict[str, Dict]] = None) -> Dict:
    keys = _content_keys(content)
    query = content.get("query") or ""
    tid = str(content.get(keys["technique_id"]) or "")
    if not tid:
        # Saved before Library copies carried the ID: a YARA-L rule names it, else the
        # technique name does when only one technique has it
        m = re.search(r'mitre_attack_technique = "([^"]+)"', query)
        name = str(content.get(keys["name"]) or "").lower()
        hits = [t for t, v in (index or {}).items() if v["name"].lower() == name]
        tid = m.group(1) if m else (hits[0] if len(hits) == 1 else "")
    tactics = content.get("tactics") or (
        [content["tactic"]] if content.get("tactic") not in (None, "", "Unknown") else [])
    mapping = {"technique_id": tid, "name": str(content.get(keys["name"]) or ""),
               "tactics": list(tactics), "rule_name": rule_name(query)}
    return {"mapping": mapping, "override": content.get(OVERRIDE_KEY) or None,
            "history": list(content.get(HISTORY_KEY) or [])}


def apply_content(content: Dict, mapping: Dict, override: Optional[Dict], history: List[Dict],
                  index: Optional[Dict[str, Dict]] = None) -> Dict:
    """A new copy of the Library content with the mapping applied."""
    out = copy.deepcopy(content)
    keys = _content_keys(content)
    old = content_state(content, index)["mapping"]
    severity = rate(mapping["tactics"])
    out[keys["technique_id"]] = mapping["technique_id"]
    out[keys["name"]] = mapping["name"]
    out["tactics"] = list(mapping["tactics"])
    if "tactic" in out or keys["name"] == "technique_display":
        out["tactic"] = mapping["tactics"][0]
    if "severity" in out:
        out["severity"] = severity
    if out.get("query"):
        out["query"] = _retarget(out["query"], old, mapping, severity)
        if _logic(out["query"]) != _logic(content.get("query")):
            raise MappingError("Couldn't rewrite the mapping safely; not saved")
    out.pop(OVERRIDE_KEY, None)
    if override:
        out[OVERRIDE_KEY] = override
    if history:
        out[HISTORY_KEY] = history
    return out

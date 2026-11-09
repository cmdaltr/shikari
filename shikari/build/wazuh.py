"""
Wazuh rules (#41): a technique's extracted indicators as a custom rules file.

Wazuh isn't one of the SIEMs the hunt generates queries for, so its rules are built at export time
from the `indicators` the other SIEMs' detections already carry: every detection for a technique
pools its indicators, and each indicator kind becomes one rule per Windows event field it can
appear in. Windows only for now (Sysmon and the Security log), as Wazuh decodes them: `win.system.*`
and `win.eventdata.<lowerCamel>`. No AI.

Rule IDs sit in Wazuh's custom range and are remembered in a map file keyed by technique, event and
field, so a rule keeps its ID from one export to the next and Wazuh's alerts stay comparable.

Checked against Wazuh 4.14 in the #41 spike: the parent groups exist as named, and pcre2 fields
refuse any `(?<` construct (one bad rule stops analysisd loading every rule), so no lookbehinds.
"""

import json
import os
import re
from typing import Dict, Iterable, List, Optional, Tuple
from xml.sax.saxutils import escape

from shikari.build.indicator_hygiene import too_generic

FIRST_ID, LAST_ID = 100100, 119999
LEVEL = {"informational": 3, "low": 5, "medium": 8, "high": 10, "critical": 12}
MAX_ALTERNATIVES = 40  # per rule; more indicators split over several rules
MIN_LENGTH = 3  # a shorter substring matches nearly everything

# (event key) -> the built-in rule group it chains from, and the event it must be
SOURCES = {
    "sysmon1": {"parent": "sysmon_event1", "provider": "Microsoft-Windows-Sysmon", "event_id": "1",
                "label": "process creation (Sysmon 1)"},
    "sysmon3": {"parent": "sysmon_event3", "provider": "Microsoft-Windows-Sysmon", "event_id": "3",
                "label": "network connection (Sysmon 3)"},
    "sysmon11": {"parent": "sysmon_event_11", "provider": "Microsoft-Windows-Sysmon", "event_id": "11",
                 "label": "file created (Sysmon 11)"},
    "sysmon13": {"parent": "sysmon_event_13", "provider": "Microsoft-Windows-Sysmon", "event_id": "1[234]",
                 "label": "registry (Sysmon 12-14)"},
    "sysmon22": {"parent": "sysmon_event_22", "provider": "Microsoft-Windows-Sysmon", "event_id": "22",
                 "label": "DNS query (Sysmon 22)"},
    "security4688": {"parent": "windows", "provider": "Microsoft-Windows-Security-Auditing", "event_id": "4688",
                     "label": "process creation (Security 4688)"},
}

# indicator kind -> [(event key, win.eventdata field, exact match)]
KIND_FIELDS: Dict[str, List[Tuple[str, str, bool]]] = {
    "cmd": [("sysmon1", "commandLine", False), ("sysmon1", "parentCommandLine", False),
            ("security4688", "commandLine", False)],
    "sw": [("sysmon1", "image", False), ("sysmon1", "originalFileName", False),
           ("security4688", "newProcessName", False)],
    "reg": [("sysmon13", "targetObject", False)],
    "domain": [("sysmon22", "queryName", False), ("sysmon3", "destinationHostname", False)],
    "ip": [("sysmon3", "destinationIp", True)],
    "hash": [("sysmon1", "hashes", False)],
}
# The extracted kinds folded into the ones above
KIND_ALIASES = {"network": "domain", "sha256": "hash", "sha1": "hash", "md5": "hash"}

# Wazuh's eventchannel decoder keeps a Windows backslash escaped in the field (two in the value a
# rule sees), but the json decoder the practice events go through keeps one: match either
BACKSLASH = r"\\{1,2}"

_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


def _clean(kind: str, value) -> Optional[str]:
    """The indicator as a match value, or None when it can't make a sound Wazuh match."""
    v = str(value or "").strip().strip("*")
    # A rule raises an alert each time it fires: no lone extension, stopword or always-running process
    if len(v) < MIN_LENGTH or "<" in v or ">" in v or too_generic(v):
        return None
    if kind == "domain":
        v = v.lower().rstrip(".")
        return v if _DOMAIN.match(v) else None
    if kind == "ip":
        return v if _IPV4.match(v) and all(int(p) < 256 for p in v.split(".")) else None
    if kind == "hash":
        return v.upper() if _HASH.match(v) else None
    return v


def pool(docs: Iterable[Dict]) -> Dict[str, Dict]:
    """{technique: {name, severity, indicators: {kind: [values]}}} across every detection for it.

    The highest severity any of its detections has wins; values are deduplicated without case."""
    rank = list(LEVEL)
    out: Dict[str, Dict] = {}
    for doc in docs:
        tid = str(doc.get("technique_id") or "")
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
            continue
        entry = out.setdefault(tid, {"name": doc.get("name") or tid, "severity": "low", "indicators": {}})
        sev = str(doc.get("severity") or "medium").lower()
        if sev in rank and rank.index(sev) > rank.index(entry["severity"]):
            entry["severity"] = sev
        for raw_kind, values in (doc.get("indicators") or {}).items():
            kind = KIND_ALIASES.get(raw_kind, raw_kind)
            if kind not in KIND_FIELDS:
                continue
            bucket = entry["indicators"].setdefault(kind, [])
            seen = {v.lower() for v in bucket}
            for value in values or []:
                v = _clean(kind, value)
                if v and v.lower() not in seen:
                    bucket.append(v)
                    seen.add(v.lower())
    return {t: e for t, e in out.items() if any(e["indicators"].values())}


def _pcre(value: str) -> str:
    """A literal for Wazuh's pcre2: regex metacharacters escaped, backslashes as the decoder keeps them."""
    out = []
    for ch in value:
        if ch == "\\":
            out.append(BACKSLASH)
        elif ch in ".^$|?*+()[]{}/":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _bounded(value: str) -> str:
    """The literal, not inside a longer word: `dir` matches `cmd /c dir` but not `mkdir`, and
    `.wll` still matches `addin.wll`, as a side that starts or ends on punctuation is left open."""
    lit = _pcre(value)
    if value[:1].isalnum():
        lit = r"(?:^|[^A-Za-z0-9_])" + lit
    if value[-1:].isalnum():
        lit += r"(?![A-Za-z0-9_])"
    return lit


def _pattern(values: List[str], exact: bool) -> str:
    if exact:
        return "(?i)^(?:" + "|".join(_pcre(v) for v in values) + ")$"
    return "(?i)(?:" + "|".join(_bounded(v) for v in values) + ")"


def _chunks(values: List[str], size: int = MAX_ALTERNATIVES) -> List[List[str]]:
    return [values[i:i + size] for i in range(0, len(values), size)]


class RuleIds:
    """Stable rule IDs: one per technique/event/field/chunk key, remembered in a JSON file."""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.ids: Dict[str, int] = {}
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    self.ids = {k: int(v) for k, v in json.load(fh).items()}
            except (OSError, ValueError):
                self.ids = {}
        self._next = max([FIRST_ID - 1, *self.ids.values()]) + 1

    def get(self, key: str) -> int:
        if key not in self.ids:
            used = set(self.ids.values())
            while self._next in used:
                self._next += 1
            if self._next > LAST_ID:
                raise RuntimeError(f"Wazuh's custom rule range is full ({FIRST_ID}-{LAST_ID})")
            self.ids[key] = self._next
            self._next += 1
        return self.ids[key]

    def save(self) -> None:
        if not self.path:
            return
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(dict(sorted(self.ids.items())), fh, indent=1)
        os.replace(tmp, self.path)


def rules(pooled: Dict[str, Dict], ids: RuleIds, attack_names: Optional[Dict[str, str]] = None) -> List[Dict]:
    """[{id, level, technique, source, field, pattern, description}] in technique order."""
    names = attack_names or {}
    out = []
    for tid in sorted(pooled):
        entry = pooled[tid]
        title = names.get(tid) or entry["name"]
        for kind, values in sorted(entry["indicators"].items()):
            for source, field, exact in KIND_FIELDS[kind]:
                for n, chunk in enumerate(_chunks(values), 1):
                    key = f"{tid}|{source}|{field}|{n}"
                    out.append({
                        "id": ids.get(key),
                        "level": LEVEL.get(entry["severity"], 8),
                        "technique": tid,
                        "source": source,
                        "field": f"win.eventdata.{field}",
                        "pattern": _pattern(chunk, exact),
                        "count": len(chunk),
                        "description": f"Shikari: {tid} {title}: {field} in {SOURCES[source]['label']}",
                    })
    return out


PRACTICE_FIRST_ID = 100000  # below FIRST_ID: the practice parents, never in shikari_rules.xml


def practice_xml() -> str:
    """Parent rules for the lab events alone. A manager decodes a file of them with its json decoder,
    not windows_eventchannel, so the built-in Sysmon and Security rules never fire and Shikari's rules
    have nothing to chain from. These give json-decoded events the same groups; an agent's real
    eventchannel events never pass through them."""
    lines = ['<group name="shikari_practice,">']
    for n, (key, src) in enumerate(SOURCES.items()):
        lines += [
            f'  <rule id="{PRACTICE_FIRST_ID + n}" level="0">',
            "    <decoded_as>json</decoded_as>",
            f'    <field name="win.system.providerName" type="pcre2">^{escape(src["provider"])}$</field>',
            f'    <field name="win.system.eventID" type="pcre2">^(?:{src["event_id"]})$</field>',
            f'    <description>Shikari practice: a lab {escape(src["label"])} event</description>',
            f'    <group>{src["parent"]},</group>',
            "  </rule>",
        ]
    lines.append("</group>")
    return "\n".join(lines) + "\n"


def to_xml(rule_list: List[Dict], header: str = "") -> str:
    """The rules file, for /var/ossec/etc/rules/ on the manager."""
    lines = []
    if header:
        lines.append("<!-- " + escape(header).replace("--", "- -") + " -->")
    lines.append('<group name="shikari,attack,">')
    for r in rule_list:
        src = SOURCES[r["source"]]
        lines += [
            f'  <rule id="{r["id"]}" level="{r["level"]}">',
            f'    <if_group>{src["parent"]}</if_group>',
            f'    <field name="win.system.providerName" type="pcre2">^{escape(src["provider"])}$</field>',
            f'    <field name="win.system.eventID" type="pcre2">^(?:{src["event_id"]})$</field>',
            f'    <field name="{r["field"]}" type="pcre2">{escape(r["pattern"])}</field>',
            f'    <description>{escape(r["description"])}</description>',
            f'    <mitre><id>{r["technique"]}</id></mitre>',
            "  </rule>",
        ]
    lines.append("</group>")
    return "\n".join(lines) + "\n"

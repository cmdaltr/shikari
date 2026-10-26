"""
Cross-vendor correlation playbooks (#8).

A same-vendor correlation is one runnable query. Across SIEMs that can't work — YARA-L, KQL, SPL
and ES|QL don't splice — so a cross-vendor correlation is a **playbook**: the chain's stages in
order, each with the per-SIEM query that detects it, the entity fields to join the stages on, and a
time window. An analyst or SOAR runs each stage wherever that telemetry lives and joins on the keys.

Built from the chains the vendor correlator already found (archer.ai.genai.engine), so no new
scoring and no AI. ATT&CK isn't linear, so stage order follows the correlation's own chain, never a
fixed tactic order.
"""

import hashlib
import re
from typing import Dict, List

# Engine's vendor keys, SecOps first (the primary platform).
VENDOR_ORDER = ["googlesecops", "mde", "splunk", "elastic"]
VENDOR_LABELS = {"googlesecops": "Google SecOps", "mde": "Microsoft Defender XDR",
                 "splunk": "Splunk", "elastic": "Elastic"}

# The field each SIEM joins on, per normalised entity. This is what the playbook tells the analyst.
JOIN_FIELDS = {
    "host": {"googlesecops": "principal.hostname", "mde": "DeviceName", "splunk": "host", "elastic": "host.name"},
    "user": {"googlesecops": "principal.user.userid", "mde": "AccountName", "splunk": "user", "elastic": "user.name"},
    "ip": {"googlesecops": "principal.ip", "mde": "RemoteIP", "splunk": "src_ip", "elastic": "source.ip"},
    "process_hash": {"googlesecops": "target.process.file.sha256", "mde": "SHA256", "splunk": "file_hash", "elastic": "process.hash.sha256"},
}

# How to spot each entity in a query's text (any SIEM), case-insensitive.
_ENTITY_HINTS = {
    "host": re.compile(r"devicename|hostname|host\.name|principal\.hostname|\bhost\b", re.I),
    "user": re.compile(r"accountname|user\.name|userid|principal\.user|\buser\b|\baccount\b", re.I),
    "ip": re.compile(r"remoteip|localip|source\.ip|destination\.ip|principal\.ip|\bsrc_ip\b|\bdest_ip\b|\bip\b", re.I),
    "process_hash": re.compile(r"sha256|sha1|md5|\bhash\b", re.I),
}


def _tech_index(file_info: Dict) -> Dict[str, Dict[str, Dict]]:
    """technique name -> {vendor -> {query, file, tactics, technique_id}}.

    The engine's chains list techniques by *name* (e.g. "Valid Accounts"), so that's the key; the
    ATT&CK ID is carried inside for display."""
    index: Dict[str, Dict[str, Dict]] = {}
    for rec in file_info.values():
        name, vendor = rec.get("name"), rec.get("vendor")
        if not name or not vendor:
            continue
        index.setdefault(name, {}).setdefault(vendor, {
            "query": rec.get("query") or "", "file": rec.get("path"),
            "tactics": rec.get("tactics") or [], "technique_id": rec.get("technique_id") or ""})
    return index


def _join_keys(stages: List[Dict]) -> List[Dict]:
    """Entities seen in at least two stages' queries, with the field to join on per SIEM."""
    hits = {e: 0 for e in _ENTITY_HINTS}
    for st in stages:
        text = " ".join(v.get("query", "") for v in st["vendors"].values())
        for entity, pat in _ENTITY_HINTS.items():
            if pat.search(text):
                hits[entity] += 1
    keys = [e for e, n in hits.items() if n >= 2]
    if not keys:
        keys = ["host"]  # endpoint chains always share a host
    return [{"entity": e, "fields": JOIN_FIELDS[e]} for e in keys if e in JOIN_FIELDS]


def _ordered_unique(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def build_cross_vendor_playbooks(vendor_correlations: List[Dict], file_info: Dict,
                                 max_playbooks: int = 40) -> List[Dict]:
    """Cross-vendor playbooks from the vendor correlator's chains.

    A chain qualifies when its techniques are collectively covered by two or more SIEMs, so its
    stages really could be followed across platforms. Deduplicated by technique set, newest/strongest
    first. No AI, no external calls."""
    index = _tech_index(file_info)
    playbooks: Dict[frozenset, Dict] = {}

    for corr in vendor_correlations:
        if not corr.get("chain"):
            continue
        techs = _ordered_unique(corr.get("techniques_involved") or [])
        if len(techs) < 2:
            continue
        sig = frozenset(techs)

        stages = []
        for name in techs:
            vendors = index.get(name, {})
            if not vendors:
                continue
            tactic = next((t for v in vendors.values() for t in v["tactics"]), "")
            tid = next((v["technique_id"] for v in vendors.values() if v["technique_id"]), "")
            stages.append({
                "technique_id": tid, "technique_name": name, "tactic": tactic,
                "vendors": {v: {"query": vendors[v]["query"], "file": vendors[v]["file"],
                                "label": VENDOR_LABELS.get(v, v)}
                            for v in VENDOR_ORDER if v in vendors},
            })
        if len(stages) < 2:
            continue

        covering = sorted({v for st in stages for v in st["vendors"]},
                          key=lambda v: VENDOR_ORDER.index(v) if v in VENDOR_ORDER else 99)
        if len(covering) < 2:
            continue  # a single-SIEM chain is an ordinary vendor correlation, not cross-vendor

        score = float(corr.get("relevance_score", 0.0))
        existing = playbooks.get(sig)
        if existing and existing["relevance_score"] >= score:
            continue
        playbooks[sig] = {
            "correlation_id": "xv_" + hashlib.sha1("|".join(techs).encode()).hexdigest()[:10],
            "type": "cross_vendor",
            "techniques_involved": techs,
            "tactics": _ordered_unique(t for st in stages for t in [st["tactic"]]),
            "vendors": covering,
            "vendor_labels": [VENDOR_LABELS.get(v, v) for v in covering],
            "attack_chain_length": len(stages),
            "relevance_score": round(score, 3),
            "time_window": corr.get("time_window", "1h"),
            "join_keys": _join_keys(stages),
            "stages": stages,
        }

    ranked = sorted(playbooks.values(),
                    key=lambda p: (-p["relevance_score"], -p["attack_chain_length"]))
    return ranked[:max_playbooks]

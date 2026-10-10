"""LLM pipeline hook: accept, validate and persist contract documents produced by the model.

Called from archer.build.llm_queries.generate_llm_queries when the response is a contract
document (root key archer_output). A rule that passes validation is written to
data/groups/contract/<name>.yaml and also returned in the legacy query-dict shape so the
existing writers still receive it. A rejection is written to data/groups/contract/rejections/.
A document that fails validation is written to data/groups/contract/failed/ with its findings
and nothing is returned: the contract fails closed.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List

from .validator import Report, validate_text

CONTRACT_DIR = Path(os.getenv("GENERATE_DIR", "data/groups")) / "contract"


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120]


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _legacy_platform(siem: str, source: str) -> str:
    if siem == "yara_l": return "GoogleSecOps"
    return "MDE"


def handle_contract_response(response_text: str, technique_id: str = "", group_name: str = "") -> List[Dict]:
    """Validate a contract document and persist it. Returns legacy query dicts (possibly empty)."""
    rep: Report = validate_text(response_text, f"llm:{technique_id}")
    if not rep.ok():
        tag = _safe(f"{technique_id or 'unknown'}_{group_name or 'nogroup'}")
        _write(CONTRACT_DIR / "failed" / f"{tag}.yaml", response_text)
        _write(CONTRACT_DIR / "failed" / f"{tag}.findings.txt", "\n".join(rep.fails) + "\n")
        print(f"  [contract FAILED] {technique_id}: {len(rep.fails)} finding(s); nothing written to generate dir")
        for f in rep.fails: print(f"      {f}")
        return []
    top = rep.document["archer_output"]
    if top["kind"] == "rejection":
        rej = top["rejection"]
        tag = _safe(f"{top['request_ref']}_{rej['reason_code']}")
        _write(CONTRACT_DIR / "rejections" / f"{tag}.yaml", response_text)
        print(f"  [contract REJECTION] {technique_id}: {rej['reason_code']} (see {CONTRACT_DIR / 'rejections' / tag}.yaml)")
        return []
    rule = top["rule"]
    _write(CONTRACT_DIR / f"{_safe(rule['name'])}.yaml", response_text)
    print(f"  [contract OK] {rule['name']} -> {CONTRACT_DIR / (_safe(rule['name']) + '.yaml')}")
    source = rule["log_sources"][0]["siem_source"]
    return [{
        "platform": _legacy_platform(rule["siem"], source),
        "data_source": source,
        "query": rule["query"],
        "technique_id": rule["attack"]["technique_ids"][0],
        "technique_name": rule["name"],
        "reason": rule["attack"]["mapping_rationale"],
        "source": "llm-contract",
        "contract_rule_id": rule["rule_id"],
        "detection_type": rule["detection_type"],
        "status": rule["status"],
    }]

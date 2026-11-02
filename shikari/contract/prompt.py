"""Prompt material for contract-mode generation: the checklist, the schema summary and the exemplars.

Appended to the LLM prompt by shikari.build.llm_queries.build_llm_prompt when SHIKARI_CONTRACT_MODE=1.
Exemplars are the few-shot anchors; the default selection is one of each kind (detection, hunt,
sweep, rejection) in the requested syntax, with YARA-L as the default.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent
DOCS = HERE / "docs"
EXEMPLARS = HERE / "exemplars"

DEFAULT_SET = {
    "yara_l": ["EX-01", "EX-04", "EX-03", "EX-08"],
    "kql": ["EX-06", "EX-07", "EX-04", "EX-09"],
}


def contract_mode() -> bool:
    return os.getenv("SHIKARI_CONTRACT_MODE", "0").strip().lower() in ("1", "true", "yes", "on")


def _read(name: str) -> str:
    p = DOCS / name
    return p.read_text() if p.exists() else ""


def exemplar_files(siem: str = "yara_l", ids: Optional[List[str]] = None) -> List[Path]:
    wanted = ids or DEFAULT_SET.get(siem, DEFAULT_SET["yara_l"])
    out = []
    for w in wanted:
        out.extend(sorted(EXEMPLARS.glob(f"{w}-*.yaml")))
    return out


def contract_prompt_block(siem: str = "yara_l", detection_type: str = "scheduled_detection",
                          exemplar_ids: Optional[List[str]] = None, include_checklist: bool = True) -> str:
    parts = [
        "---",
        "## OUTPUT CONTRACT (mandatory)",
        f"Emit exactly one YAML document with root key `shikari_output`, contract_version \"1.0\", kind `rule` or `rejection`. "
        f"Requested syntax: {siem}. Requested detection_type: {detection_type}. status is always `draft`. "
        "`query` is the last key of `rule` and is a literal block scalar (`query: |`). Keys appear in the fixed order of the schema. "
        "No flow-style collections except `[]`, no anchors, no tags, no tabs. "
        "Output the raw YAML only: no ``` fences, no `---` markers and no prose before or after it. "
        "If any rejection condition holds, emit the rejection shape with a reason code and no query.",
        "",
    ]
    if include_checklist:
        parts += ["## PRE-OUTPUT CHECKLIST (run every gate before emitting)", "", _read("04-checklist.md"), ""]
    parts += ["## SCHEMA", "", _read("03-schema.md"), ""]
    parts += ["## EXEMPLARS (few-shot anchors; match their structure exactly)", ""]
    for f in exemplar_files(siem, exemplar_ids):
        parts += [f"### {f.stem}", "```yaml", f.read_text().rstrip(), "```", ""]
    parts.append("---")
    return "\n".join(parts)

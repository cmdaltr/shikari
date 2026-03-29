"""
Mode 1 — LLM-powered query generation.

Assembles prompt from bespoke templates + MITRESaw technique data,
sends to an LLM (cloud or local), and parses the structured response
back into Archer's query format.
"""

import json
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional


_BESPOKE_DIR = Path(__file__).resolve().parent.parent.parent / "bespoke"
_PROMPTS_DIR = _BESPOKE_DIR / "prompts"
_TEMPLATES_DIR = _BESPOKE_DIR / "query_templates"


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------

def _load_prompt_template(use_local: bool = False) -> str:
    """Load the master LLM prompt template.

    Args:
        use_local: If True, use the LocalLLM prompt (smaller context).
                   If False, use the CloudLLM prompt (full context).
    """
    filename = "LocalLLM_Master.md" if use_local else "CloudLLM_Master.md"
    path = _PROMPTS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Prompt template not found: {path}")
    return path.read_text()


def _load_detection_templates() -> str:
    """Load the unified detection generation templates."""
    path = _TEMPLATES_DIR / "DetectionGeneration_Templates.md"
    if not path.exists():
        return ""
    return path.read_text()


def build_llm_prompt(
    technique_id: str,
    technique_name: str,
    tactic: str,
    procedure_example: str,
    evidence_json: str,
    platforms: List[str],
    detectable_via: str = "",
    group_name: str = "",
    output_format: str = "JSON",
    use_local: bool = False,
) -> str:
    """Assemble a complete LLM prompt for detection query generation.

    Combines the master prompt template + detection templates + technique
    context from MITRESaw data.

    Args:
        technique_id: ATT&CK technique ID.
        technique_name: Technique name.
        tactic: ATT&CK tactic.
        procedure_example: MITRE procedure text.
        evidence_json: MITRESaw evidence column JSON.
        platforms: List of platforms.
        detectable_via: MITRESaw log sources.
        group_name: Threat group name.
        output_format: "JSON" or "YAML".
        use_local: Use local LLM prompt (smaller).

    Returns:
        Complete prompt string ready to send to an LLM.
    """
    master_prompt = _load_prompt_template(use_local)
    detection_templates = _load_detection_templates()

    # Build the technique context block
    context_lines = [
        "---",
        "## TECHNIQUE CONTEXT (from MITRESaw)",
        f"- Technique name: {technique_name}",
        f"- Technique ID: {technique_id}",
        f"- Tactic: {tactic}",
        f"- Platforms: {', '.join(platforms)}",
        f"- Threat Group: {group_name}" if group_name else "",
        f"- Output: {output_format}",
        "",
        "### Procedure Example (MITRE ATT&CK)",
        procedure_example[:2000] if procedure_example else "(none)",
        "",
    ]

    # Add evidence indicators
    if evidence_json and evidence_json != "{}":
        try:
            evidence = json.loads(evidence_json) if isinstance(evidence_json, str) else evidence_json
            if evidence:
                context_lines.append("### Extracted Indicators (from MITRESaw)")
                for ev_type, values in evidence.items():
                    if values:
                        formatted = []
                        for v in values[:10]:
                            if isinstance(v, dict):
                                formatted.extend(v.keys())
                            else:
                                formatted.append(str(v))
                        context_lines.append(f"- {ev_type}: {', '.join(formatted)}")
                context_lines.append("")
        except (json.JSONDecodeError, TypeError):
            pass

    # Add log sources
    if detectable_via:
        context_lines.append(f"### MITRESaw Log Sources")
        context_lines.append(detectable_via)
        context_lines.append("")

    context_lines.append("---")

    # Replace the placeholder in the master prompt
    filled_prompt = master_prompt.replace("<TECHNIQUE_NAME>", technique_name)

    # Assemble: master prompt + technique context + detection templates
    full_prompt = "\n".join([
        filled_prompt,
        "",
        "\n".join(context_lines),
        "",
        "## DETECTION TEMPLATES (use as source of truth for query structure)",
        "",
        detection_templates,
    ])

    return full_prompt


# ---------------------------------------------------------------------------
# LLM response parsing
# ---------------------------------------------------------------------------

def parse_llm_response(response_text: str) -> List[Dict]:
    """Parse an LLM response into structured query dicts.

    The LLM should return JSON with the schema:
    {
        "technique_id": "T1059.001",
        "technique_name": "...",
        "queries": [
            {"source_index": "...", "reason": "...", "query": "..."},
            ...
        ]
    }

    Args:
        response_text: Raw text from the LLM.

    Returns:
        List of query dicts with keys: platform, data_source, query,
        technique_id, technique_name, reason.
    """
    # Try to extract JSON from the response
    json_match = re.search(r"\{[\s\S]*\}", response_text)
    if not json_match:
        return []

    try:
        data = json.loads(json_match.group(0))
    except json.JSONDecodeError:
        # Try fixing common JSON issues
        cleaned = json_match.group(0)
        cleaned = re.sub(r",\s*}", "}", cleaned)
        cleaned = re.sub(r",\s*]", "]", cleaned)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            return []

    technique_id = data.get("technique_id", "")
    technique_name = data.get("full_technique_name", data.get("technique_name", ""))
    raw_queries = data.get("queries", [])

    results = []
    for q in raw_queries:
        source = q.get("source_index", "")
        query_text = q.get("query", "")
        reason = q.get("reason", "")

        if not query_text:
            continue

        # Determine platform from source index
        if source.startswith("Device") or source.startswith("AAD") or source.startswith("Cloud") or source.startswith("Identity"):
            platform = "MDE"
        else:
            platform = "Splunk"

        results.append({
            "platform": platform,
            "data_source": source,
            "query": query_text,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "reason": reason,
            "source": "llm",
        })

    return results


# ---------------------------------------------------------------------------
# LLM call wrapper
# ---------------------------------------------------------------------------

def call_llm(prompt: str, config: Optional[Dict] = None) -> str:
    """Send a prompt to the configured LLM and return the response.

    Supports multiple backends:
    - Anthropic Claude API (ANTHROPIC_API_KEY)
    - OpenAI API (OPENAI_API_KEY)
    - Local LLM via HTTP endpoint (LLM_ENDPOINT)

    Args:
        prompt: The assembled prompt string.
        config: Optional config dict with model settings.

    Returns:
        Raw response text from the LLM.
    """
    config = config or {}

    # Try Anthropic Claude first
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        return _call_anthropic(prompt, api_key, config)

    # Try OpenAI
    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key:
        return _call_openai(prompt, api_key, config)

    # Try local endpoint
    endpoint = os.environ.get("LLM_ENDPOINT")
    if endpoint:
        return _call_local(prompt, endpoint, config)

    raise RuntimeError(
        "No LLM configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or LLM_ENDPOINT."
    )


def _call_anthropic(prompt: str, api_key: str, config: dict) -> str:
    """Call Anthropic Claude API."""
    import requests

    model = config.get("model", "claude-sonnet-4-20250514")
    max_tokens = config.get("max_tokens", 4096)

    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["content"][0]["text"]


def _call_openai(prompt: str, api_key: str, config: dict) -> str:
    """Call OpenAI API."""
    import requests

    model = config.get("model", "gpt-4o")
    max_tokens = config.get("max_tokens", 4096)

    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def _call_local(prompt: str, endpoint: str, config: dict) -> str:
    """Call a local LLM via HTTP endpoint (OpenAI-compatible)."""
    import requests

    model = config.get("model", "default")
    max_tokens = config.get("max_tokens", 4096)

    resp = requests.post(
        f"{endpoint}/v1/chat/completions",
        json={
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=300,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# Main Mode 1 entry point
# ---------------------------------------------------------------------------

def generate_llm_queries(
    technique_id: str,
    technique_name: str,
    tactic: str,
    procedure_example: str,
    evidence_json: str,
    platforms: List[str],
    detectable_via: str = "",
    group_name: str = "",
    use_local: bool = False,
    config: Optional[Dict] = None,
) -> List[Dict]:
    """Generate detection queries using an LLM.

    This is Mode 1. Assembles a prompt from bespoke templates + MITRESaw
    technique data, sends to the LLM, and parses the structured response.

    Args:
        technique_id: ATT&CK technique ID.
        technique_name: Technique name.
        tactic: ATT&CK tactic.
        procedure_example: MITRE procedure text.
        evidence_json: MITRESaw evidence column JSON.
        platforms: List of platforms.
        detectable_via: MITRESaw log sources.
        group_name: Threat group name.
        use_local: Use local LLM prompt template.
        config: Optional LLM config dict.

    Returns:
        List of query dicts (same format as bespoke_queries.generate_fallback_queries).
    """
    # Build the prompt
    prompt = build_llm_prompt(
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        procedure_example=procedure_example,
        evidence_json=evidence_json,
        platforms=platforms,
        detectable_via=detectable_via,
        group_name=group_name,
        use_local=use_local,
    )

    # Call the LLM
    try:
        response = call_llm(prompt, config)
    except Exception as e:
        print(f"  LLM call failed for {technique_id}: {e}")
        return []

    # Parse the response
    queries = parse_llm_response(response)

    # Add tactic to each query
    for q in queries:
        q["tactic"] = tactic
        q["source"] = "llm"

    return queries

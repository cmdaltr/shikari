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

    # Contract mode (ARCHER_CONTRACT_MODE=1): append the output contract, checklist and
    # few-shot exemplars so the model emits an archer_output document instead of raw JSON.
    try:
        from archer.contract import contract_mode, contract_prompt_block
        if contract_mode():
            siem = os.getenv("ARCHER_CONTRACT_SIEM", "yara_l")
            dtype = os.getenv("ARCHER_CONTRACT_TYPE", "scheduled_detection")
            full_prompt = full_prompt + "\n\n" + contract_prompt_block(siem, dtype)
    except Exception as e:
        print(f"  [contract] prompt block unavailable: {e}")

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
    # Reasoning models (qwen3, deepseek-r1) can put their thinking first
    response_text = re.sub(r"<think>[\s\S]*?</think>", "", response_text or "")
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

def _load_llm_config() -> Dict:
    """Load LLM configuration from bespoke/config.yaml if present."""
    config_path = _BESPOKE_DIR / "config.yaml"
    if not config_path.exists():
        return {}
    try:
        import yaml
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        return data.get("llm", {})
    except Exception:
        return {}


def call_llm(prompt: str, config: Optional[Dict] = None) -> str:
    """Send a prompt to the configured LLM and return the response.

    Resolution order (first match wins):
    1. Config dict passed directly (from adfconsole or API)
    2. bespoke/config.yaml → llm section
    3. Environment variables

    Supported providers:
    - Anthropic Claude     (ANTHROPIC_API_KEY)
    - OpenAI / ChatGPT     (OPENAI_API_KEY)
    - Azure OpenAI         (AZURE_OPENAI_KEY + AZURE_OPENAI_ENDPOINT)
    - Microsoft Copilot    (same as Azure OpenAI)
    - OpenAI-compatible    (LLM_ENDPOINT — covers local LLMs, LiteLLM, vLLM, etc.)

    Args:
        prompt: The assembled prompt string.
        config: Optional config dict with provider/model/key overrides.

    Returns:
        Raw response text from the LLM.
    """
    # Merge: explicit config > config.yaml > env vars
    file_config = _load_llm_config()
    merged = {**file_config, **(config or {})}

    # Answers run to 3-5k tokens (contract exemplars are 11-20KB, a T1190 query set ~11KB);
    # 4096 cuts the JSON mid-string and the parser finds nothing
    if "max_tokens" not in merged:
        merged["max_tokens"] = int(os.getenv("ARCHER_LLM_MAX_TOKENS")
                                   or os.getenv("ARCHER_CONTRACT_MAX_TOKENS", "16000"))

    provider = merged.get("provider", "").lower()

    # A provider chosen in the profile (archer.ai.assignment): the same factory Ask
    # Archer uses, so every cloud provider and local endpoint works the same way
    if merged.get("via_factory"):
        return _call_via_factory(prompt, merged)

    # Explicit provider selection from config
    if provider == "anthropic":
        key = merged.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")
        if key:
            return _call_anthropic(prompt, key, merged)

    if provider == "openai":
        key = merged.get("api_key") or os.environ.get("OPENAI_API_KEY")
        if key:
            return _call_openai(prompt, key, merged)

    if provider in ("azure", "azure_openai", "copilot"):
        key = merged.get("api_key") or os.environ.get("AZURE_OPENAI_KEY")
        endpoint = merged.get("endpoint") or os.environ.get("AZURE_OPENAI_ENDPOINT")
        deployment = merged.get("deployment") or os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        api_version = merged.get("api_version") or os.environ.get("AZURE_OPENAI_API_VERSION", "2024-06-01")
        if key and endpoint:
            return _call_azure_openai(prompt, key, endpoint, deployment, api_version, merged)

    if provider == "local":
        endpoint = merged.get("endpoint") or os.environ.get("LLM_ENDPOINT")
        if endpoint:
            return _call_local(prompt, endpoint, merged)

    # Auto-detect from environment variables (no explicit provider)
    if os.environ.get("ANTHROPIC_API_KEY"):
        return _call_anthropic(prompt, os.environ["ANTHROPIC_API_KEY"], merged)

    if os.environ.get("AZURE_OPENAI_KEY") and os.environ.get("AZURE_OPENAI_ENDPOINT"):
        return _call_azure_openai(
            prompt,
            os.environ["AZURE_OPENAI_KEY"],
            os.environ["AZURE_OPENAI_ENDPOINT"],
            os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
            os.environ.get("AZURE_OPENAI_API_VERSION", "2024-06-01"),
            merged,
        )

    if os.environ.get("OPENAI_API_KEY"):
        return _call_openai(prompt, os.environ["OPENAI_API_KEY"], merged)

    if os.environ.get("LLM_ENDPOINT"):
        return _call_local(prompt, os.environ["LLM_ENDPOINT"], merged)

    raise RuntimeError(
        "No LLM configured. Set provider in bespoke/config.yaml or use environment variables:\n"
        "  Anthropic:    ANTHROPIC_API_KEY\n"
        "  OpenAI:       OPENAI_API_KEY\n"
        "  Azure OpenAI: AZURE_OPENAI_KEY + AZURE_OPENAI_ENDPOINT\n"
        "  Local:        LLM_ENDPOINT"
    )


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------

def _call_anthropic(prompt: str, api_key: str, config: dict) -> str:
    """Call Anthropic Claude API."""
    import requests

    model = config.get("model", "claude-sonnet-4-20250514")
    max_tokens = config.get("max_tokens", 4096)
    base_url = config.get("base_url", "https://api.anthropic.com")

    resp = requests.post(
        f"{base_url}/v1/messages",
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
        timeout=180,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["content"][0]["text"]


def _call_openai(prompt: str, api_key: str, config: dict) -> str:
    """Call OpenAI API (including ChatGPT Enterprise with custom base_url)."""
    import requests

    model = config.get("model", "gpt-4o")
    max_tokens = config.get("max_tokens", 4096)
    base_url = config.get("base_url", "https://api.openai.com")

    resp = requests.post(
        f"{base_url}/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=180,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def _call_azure_openai(
    prompt: str,
    api_key: str,
    endpoint: str,
    deployment: str,
    api_version: str,
    config: dict,
) -> str:
    """Call Azure OpenAI (ChatGPT Enterprise / Microsoft Copilot).

    Azure OpenAI uses a different URL pattern and auth header than standard OpenAI.
    """
    import requests

    max_tokens = config.get("max_tokens", 4096)

    # Azure OpenAI URL: https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=<version>
    url = f"{endpoint.rstrip('/')}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"

    resp = requests.post(
        url,
        headers={
            "api-key": api_key,
            "Content-Type": "application/json",
        },
        json={
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=180,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def _is_ollama(endpoint: str) -> bool:
    import requests

    try:
        return requests.get(f"{endpoint}/api/version", timeout=3).ok
    except Exception:
        return False


def _call_ollama(prompt: str, endpoint: str, config: dict) -> str:
    """
    Ollama's native chat API, with a context sized to the prompt.

    Its OpenAI-compatible endpoint runs every model at Ollama's default context
    (4096 tokens) and silently cuts the prompt to fit: the ~29k-token detection prompt
    arrived as its last 2k tokens, and qwen3 answered an LSASS request with a WAF
    query repeated until max_tokens.
    """
    import requests

    max_tokens = config.get("max_tokens", 4096)
    # ~3.5 characters a token for this English/query mix, plus room for the answer
    needed = int(len(prompt) / 3.5) + max_tokens + 1024
    num_ctx = int(config.get("num_ctx") or min(max(8192, -(-needed // 4096) * 4096), 131072))
    resp = requests.post(
        f"{endpoint}/api/chat",
        json={
            "model": config.get("model", "default"),
            "stream": False,
            "think": False,  # qwen3 and other reasoning models: the answer, not the reasoning
            "options": {"num_ctx": num_ctx, "num_predict": max_tokens},
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=int(config.get("timeout", 1800)),  # a 30k-token prompt on CPU takes minutes
    )
    resp.raise_for_status()
    data = resp.json()
    estimated = int(len(prompt) / 3.5)
    if data.get("prompt_eval_count") and data["prompt_eval_count"] < estimated // 2:
        print(f"  ⚠️  Ollama read {data['prompt_eval_count']} of ~{estimated} prompt tokens: the prompt was cut")
    return data.get("message", {}).get("content", "")


def _call_via_factory(prompt: str, config: dict) -> str:
    from archer.ai.assignment import LOCAL, create_llm

    if config["provider"] == LOCAL and config.get("endpoint"):
        # Ollama's OpenAI endpoint cuts long prompts to 4096 tokens; size the context
        return _call_local(prompt, config["endpoint"], config)
    llm = create_llm(config)
    return llm.generate(prompt, temperature=0.2, max_tokens=config.get("max_tokens", 4096)).content


def _call_local(prompt: str, endpoint: str, config: dict) -> str:
    """Call any OpenAI-compatible endpoint (local LLMs, LiteLLM, vLLM, Ollama, etc.)."""
    import requests

    model = config.get("model", "default")
    max_tokens = config.get("max_tokens", 4096)

    if _is_ollama(endpoint):
        return _call_ollama(prompt, endpoint, config)

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

def _keep_unusable_response(technique_id: str, response: str) -> None:
    """An answer that produced no queries is kept (data/llm_responses/) and named in the log,
    instead of only "No bespoke queries generated"."""
    from datetime import datetime

    out_dir = Path("data/llm_responses")
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{technique_id}_{datetime.now():%Y%m%d-%H%M%S}.txt"
        path.write_text(response or "")
        head = " ".join((response or "").split())[:160]
        print(f"  ⚠️  LLM answer for {technique_id} gave no usable queries ({len(response or '')} chars, saved to {path}): {head}")
    except OSError as e:
        print(f"  ⚠️  LLM answer for {technique_id} gave no usable queries (not saved: {e})")


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

    # Contract documents (root key archer_output) are validated and persisted by the
    # contract pipeline; a failing or rejected document returns nothing (fail closed).
    try:
        from archer.contract import is_contract_document, handle_contract_response
        if is_contract_document(response):
            queries = handle_contract_response(response, technique_id=technique_id, group_name=group_name)
            if not queries:
                _keep_unusable_response(technique_id, response)
            for q in queries:
                q["tactic"] = tactic
            return queries
    except Exception as e:
        print(f"  [contract] response handling failed for {technique_id}: {e}")
        return []

    # Parse the response (legacy JSON shape)
    queries = parse_llm_response(response)
    if not queries:
        _keep_unusable_response(technique_id, response)

    # Add tactic to each query
    for q in queries:
        q["tactic"] = tactic
        q["source"] = "llm"

    return queries

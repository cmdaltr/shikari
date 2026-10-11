"""
Ask Archer – conversational Q&A endpoint.

POST /api/ask
    { "question": "...", "context": { "group": "Scattered Spider" } }

Answers questions about ATT&CK techniques, threat groups, SIEM query languages
and Archer-generated detections using the user's configured LLM.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Cookie, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from archer.database.db import get_db
from archer.database.models import APIKey
from archer.auth import decrypt_api_key, get_user_from_session_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["ask"])

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class AskRequest(BaseModel):
    question: str
    context: Optional[Dict[str, Any]] = None


class AskResponse(BaseModel):
    answer: str
    provider: str


class BriefingRequest(BaseModel):
    group: str
    top_n: int = 5


class TechniquePriority(BaseModel):
    priority_rank: int
    technique_id: str
    technique_name: str
    tactic: str
    attribution_type: str
    covered: bool
    priority_reason: str
    detection_approach: str


class BriefingResponse(BaseModel):
    group_name: str
    group_id: str
    total_techniques: int
    covered_count: int
    gap_count: int
    top_techniques: List[TechniquePriority]
    attack_chain: List[str]
    briefing_summary: str
    provider: str


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_BRIEFING_SYSTEM_PROMPT = """You are Archer, an expert threat detection engineer.
You are given the REAL techniques attributed to a specific threat group, extracted from
MITRE ATT&CK STIX data across all three attribution paths (direct, via_software, via_campaign).

For each technique you are told:
- technique_id (ATT&CK ID, e.g. T1078.004)
- technique_name
- tactic (kill chain stage, e.g. Initial Access)
- attribution_type (direct / via_software:ToolName / via_campaign:CampaignName)
- covered (true = Archer already has a detection YAML for this; false = gap)

Your task: Return the top {n} most critical techniques to prioritize for detection.

Ranking criteria (in order of weight):
1. Uncovered gaps — prefer techniques with no existing detection
2. Kill chain position — Initial Access and Execution enable everything downstream
3. Attribution confidence — direct > via_software > via_campaign
4. Detection opportunity — prefer techniques with rich, available telemetry (process, network, auth logs)
5. Chaining potential — techniques that bridge multiple kill-chain stages

Return a JSON object with EXACTLY this structure (no markdown, no preamble):
{{
  "top_techniques": [
    {{
      "priority_rank": 1,
      "technique_id": "T1078.004",
      "technique_name": "Cloud Accounts",
      "tactic": "Initial Access",
      "attribution_type": "direct",
      "covered": false,
      "priority_reason": "Two to three sentences explaining why this is critical to detect now.",
      "detection_approach": "Specific data source and field names and detection logic to implement."
    }}
  ],
  "attack_chain": ["Initial Access", "Persistence", "Lateral Movement"],
  "briefing_summary": "Two to three sentence executive summary for a SOC team."
}}"""


_SYSTEM_PROMPT = """You are Archer, an expert threat-detection engineer and ATT&CK specialist.
You have deep knowledge of:
- MITRE ATT&CK techniques, tactics, threat groups and their TTPs
- Detection engineering for Splunk (SPL), Microsoft Defender for Endpoint (KQL),
  Elastic (EQL/ES|QL), Google SecOps (YARA-L2)
- SIEM correlation logic, data sources, and log field naming conventions
- The Archer detection-generation platform which produces YAML-based detection rules

Guidelines:
- Give clear, concise, technically accurate answers.
- When asked for queries, always produce complete, runnable examples with realistic field names.
- For Splunk use `index=`, `| stats`, `| transaction`, `| eval`, `| where` etc.
- For MDE/Sentinel use KQL with `DeviceEvents`, `DeviceProcessEvents`, etc.
- Reference ATT&CK technique IDs (e.g. T1078.004) where relevant.
- If asked about a specific threat group, mention their known TTPs first then give detection examples.
- Keep answers focused. If a topic is outside threat detection, politely redirect.
"""


# ---------------------------------------------------------------------------
# LLM helper – try providers in priority order using stored API keys
# ---------------------------------------------------------------------------

# Cloud priority order: (provider_id, stored-key name(s), env var name(s), display label).
# Anthropic/OpenAI stay first (existing behaviour preserved); the newer providers
# are tried after, in the same order the Hunt-page AI prompt offers them.
_CLOUD_PROVIDER_CHAIN = [
    ("anthropic", ["anthropic"], ["ANTHROPIC_API_KEY"], "Claude (Anthropic)"),
    ("openai", ["openai"], ["OPENAI_API_KEY"], "GPT-4o (OpenAI)"),
    ("google", ["google"], ["GOOGLE_API_KEY"], "Gemini (Google)"),
    ("deepseek", ["deepseek"], ["DEEPSEEK_API_KEY"], "DeepSeek"),
    ("qwen", ["qwen"], ["QWEN_API_KEY", "DASHSCOPE_API_KEY"], "Qwen"),
    ("grok", ["grok"], ["XAI_API_KEY", "GROK_API_KEY"], "Grok (xAI)"),
]


def _try_cloud_providers(keys: Dict[str, str]):
    """Try each configured cloud provider in priority order. keys is a
    stored-key-name -> value map (may be empty for anonymous callers)."""
    from archer.ai.llm.providers import LLMFactory

    for provider_id, key_names, env_names, label in _CLOUD_PROVIDER_CHAIN:
        api_key = next((keys[k] for k in key_names if keys.get(k)), None)
        if not api_key:
            api_key = next((os.getenv(e) for e in env_names if os.getenv(e)), None)
        if not api_key:
            continue
        try:
            return LLMFactory.create(provider_id, api_key=api_key), label
        except Exception as e:
            logger.warning("%s provider failed: %s", label, e)
    return None, None


def _try_local_providers(local_llm_endpoints: List[dict]):
    """Try each detected local endpoint (Ollama, Osaurus) in detection order."""
    from archer.ai.llm.providers import LLMFactory

    for endpoint in local_llm_endpoints or []:
        if not endpoint.get("available"):
            continue
        provider_id = endpoint.get("provider")
        if provider_id not in ("ollama", "osaurus"):
            continue
        try:
            base_url = endpoint.get("base_url") or endpoint.get("url", "").split("/api/")[0]
            model = endpoint.get("model") or ("llama2" if provider_id == "ollama" else "default")
            return LLMFactory.create(provider_id, base_url=base_url, model=model), f"Local LLM ({endpoint.get('name')}/{model})"
        except Exception as e:
            logger.warning("%s provider failed: %s", provider_id, e)
    return None, None


def _get_llm_provider(user_id: int, db, local_llm_endpoints: Optional[List[dict]] = None):
    """
    Return an (LLMProvider, provider_name) tuple for Ask Archer.

    The provider assigned to Ask Archer in the profile wins (GitHub #10); an assigned
    provider that fails raises rather than quietly answering with a different one.
    With nothing assigned: the user's stored keys, then server keys, in priority
    order Anthropic → OpenAI → DeepSeek → Qwen → Grok → local (Ollama/Osaurus).
    Returns (None, None) if no provider is available.
    """
    from archer.ai.assignment import create_llm, resolve

    assigned = resolve(db, user_id, "ask")
    if assigned:
        model = assigned["model"] or "default model"
        print(f"🤖 Ask Archer: {assigned['label']} / {model} (assigned in profile)", flush=True)
        return create_llm(assigned), f"{assigned['label']} / {model}"

    # Build platform → decrypted_value map for this user
    keys: Dict[str, str] = {}
    try:
        rows = db.query(APIKey).filter(APIKey.user_id == user_id).all()
        for row in rows:
            try:
                keys[row.platform] = decrypt_api_key(row.encrypted_key)
            except Exception:
                pass
    except Exception as e:
        logger.warning("Could not read API keys from DB: %s", e)

    llm, label = _try_cloud_providers(keys)
    if llm:
        return llm, label

    return _try_local_providers(local_llm_endpoints)


def _get_llm_provider_anonymous(local_llm_endpoints: Optional[List[dict]] = None):
    """LLM provider lookup using only environment variables — no DB, no user."""
    llm, label = _try_cloud_providers({})
    if llm:
        return llm, label

    return _try_local_providers(local_llm_endpoints)


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.post("/ask", response_model=AskResponse)
async def ask_archer(
    payload: AskRequest,
    request: Request,
    archer_session: Optional[str] = Cookie(None),
):
    """Answer a natural-language question using the configured LLM.
    Works for authenticated users (uses their stored API keys) and
    unauthenticated users (falls back to environment-variable API keys).
    """
    local_llm_endpoints = getattr(request.app.state, "local_llm_endpoints", None)
    if local_llm_endpoints is None:
        single = getattr(request.app.state, "local_llm_detected", {})
        local_llm_endpoints = [single] if single.get("available") else []
    db = None
    try:
        # Try to resolve user for their stored API keys; fall back gracefully.
        user_id = None
        if archer_session:
            db = next(get_db())
            try:
                user = get_user_from_session_id(archer_session, db)
                if user:
                    user_id = user.id
            except Exception:
                pass

        if user_id is not None and db is None:
            db = next(get_db())

        def resolve(endpoints):
            if user_id is not None:
                return _get_llm_provider(user_id, db, endpoints)
            # Unauthenticated – env-var keys only (no DB lookup)
            return _get_llm_provider_anonymous(endpoints)

        llm, provider_name = resolve(local_llm_endpoints)
        redetect = getattr(request.app.state, "redetect_local_llm", None)
        if llm is None and not local_llm_endpoints and redetect:
            # Local LLMs are probed at startup; one started since would otherwise
            # stay invisible until Archer restarts
            await redetect()
            llm, provider_name = resolve(getattr(request.app.state, "local_llm_endpoints", []))

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "No LLM provider is configured. "
                    "Add an API key under Profile → API Keys, or start a local Ollama instance."
                ),
            )

        # Build context-enriched prompt
        question = payload.question.strip()
        context = payload.context or {}
        if context.get("group"):
            question = f"[Threat group context: {context['group']}]\n\n{question}"

        response = llm.generate(
            prompt=question,
            system_prompt=_SYSTEM_PROMPT,
            temperature=0.4,
            max_tokens=2048,
        )

        return AskResponse(answer=response.content, provider=provider_name)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Ask Archer error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if db:
            db.close()


# ---------------------------------------------------------------------------
# Threat Briefing route
# ---------------------------------------------------------------------------

@router.post("/threat-briefing", response_model=BriefingResponse)
async def threat_briefing(
    payload: BriefingRequest,
    request: Request,
    archer_session: Optional[str] = Cookie(None),
):
    """
    Generate a grounded threat briefing for a specific ATT&CK group.
    Reads real technique data from mitre_procedures.csv and checks
    existing detection coverage before calling the LLM.
    """
    import json
    import re as _re

    if not archer_session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = next(get_db())
    try:
        user = get_user_from_session_id(archer_session, db)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")

        # Load coverage data grounded in mitre_procedures.csv
        from archer.mitre.procedures import get_group_coverage
        from archer.config import GENERATE_DIR

        coverage = get_group_coverage(payload.group, GENERATE_DIR)
        if not coverage:
            raise HTTPException(
                status_code=404,
                detail=f"Group '{payload.group}' not found in ATT&CK data. "
                       "Try the full group name (e.g. 'Scattered Spider') or ATT&CK ID (e.g. 'G1015').",
            )

        # Build grounded prompt — caps gaps at 80 to stay within token limits
        covered_lines = "\n".join(
            f"  - {t['technique_id']} {t['technique_name']} [{t['tactic']}]"
            for t in coverage["covered"]
        )
        gap_lines = "\n".join(
            f"  - {t['technique_id']} {t['technique_name']} [{t['tactic']}] ({t['attribution_type']})"
            for t in coverage["gaps"][:80]
        )

        prompt = (
            f"Group: {coverage['group_name']} ({coverage['group_id']})\n"
            f"Total techniques: {coverage['total']}\n\n"
            f"Already covered by existing detections ({coverage['covered_count']}):\n"
            f"{covered_lines or '  (none)'}\n\n"
            f"Detection GAPS — no detection exists yet ({coverage['gap_count']} techniques):\n"
            f"{gap_lines}\n\n"
            f"Identify the TOP {payload.top_n} techniques to prioritize for detection."
        )

        local_llm_endpoints = getattr(request.app.state, "local_llm_endpoints", None)
        if local_llm_endpoints is None:
            single = getattr(request.app.state, "local_llm_detected", {})
            local_llm_endpoints = [single] if single.get("available") else []
        llm, provider_name = _get_llm_provider(user.id, db, local_llm_endpoints)

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "No LLM provider configured. "
                    "Add an API key under Profile → API Keys, or start a local Ollama instance."
                ),
            )

        system = _BRIEFING_SYSTEM_PROMPT.format(n=payload.top_n)
        raw = llm.generate(
            prompt=prompt,
            system_prompt=system,
            temperature=0.3,
            max_tokens=3000,
        )

        # Parse LLM JSON response
        try:
            data = json.loads(raw.content if hasattr(raw, "content") else raw)
        except Exception:
            # Fallback: extract first JSON object from response
            match = _re.search(r"\{.*\}", raw.content if hasattr(raw, "content") else raw, _re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group())
                except Exception:
                    data = {}
            else:
                data = {}

        return BriefingResponse(
            group_name=coverage["group_name"],
            group_id=coverage["group_id"],
            total_techniques=coverage["total"],
            covered_count=coverage["covered_count"],
            gap_count=coverage["gap_count"],
            top_techniques=data.get("top_techniques", []),
            attack_chain=data.get("attack_chain", []),
            briefing_summary=data.get("briefing_summary", ""),
            provider=provider_name,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Threat briefing error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

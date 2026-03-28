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
  Elastic (EQL/ES|QL), Google SecOps (YARA-L2) and Chronicle
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

def _get_llm_provider(user_id: int, db, local_llm_state: Optional[dict] = None):
    """
    Return an (LLMProvider, provider_name) tuple using the user's stored API keys.
    Priority: Anthropic → OpenAI → local Ollama.
    Returns (None, None) if no provider is available.
    """
    from archer.ai.llm.providers import LLMFactory

    # Build key_name → decrypted_value map for this user
    keys: Dict[str, str] = {}
    try:
        rows = db.query(APIKey).filter(APIKey.user_id == user_id).all()
        for row in rows:
            try:
                keys[row.key_name] = decrypt_api_key(row.encrypted_key)
            except Exception:
                pass
    except Exception as e:
        logger.warning("Could not read API keys from DB: %s", e)

    # Anthropic
    anthropic_key = keys.get("anthropic") or os.getenv("ANTHROPIC_API_KEY")
    if anthropic_key:
        try:
            return LLMFactory.create("anthropic", api_key=anthropic_key), "Claude (Anthropic)"
        except Exception as e:
            logger.warning("Anthropic provider failed: %s", e)

    # OpenAI
    openai_key = keys.get("openai") or os.getenv("OPENAI_API_KEY")
    if openai_key:
        try:
            return LLMFactory.create("openai", api_key=openai_key), "GPT-4o (OpenAI)"
        except Exception as e:
            logger.warning("OpenAI provider failed: %s", e)

    # Local Ollama
    local_available = (
        local_llm_state.get("available", False) if local_llm_state else False
    )
    if local_available:
        try:
            base_url = local_llm_state.get("url", "http://localhost:11434")
            return LLMFactory.create("ollama", base_url=base_url), "Local LLM (Ollama)"
        except Exception as e:
            logger.warning("Ollama provider failed: %s", e)

    return None, None


def _get_llm_provider_anonymous(local_llm_state: Optional[dict] = None):
    """LLM provider lookup using only environment variables — no DB, no user."""
    from archer.ai.llm.providers import LLMFactory

    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if anthropic_key:
        try:
            return LLMFactory.create("anthropic", api_key=anthropic_key), "Claude (Anthropic)"
        except Exception as e:
            logger.warning("Anthropic provider failed: %s", e)

    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        try:
            return LLMFactory.create("openai", api_key=openai_key), "GPT-4o (OpenAI)"
        except Exception as e:
            logger.warning("OpenAI provider failed: %s", e)

    local_available = (
        local_llm_state.get("available", False) if local_llm_state else False
    )
    if local_available:
        try:
            base_url = local_llm_state.get("url", "http://localhost:11434")
            return LLMFactory.create("ollama", base_url=base_url), "Local LLM (Ollama)"
        except Exception as e:
            logger.warning("Ollama provider failed: %s", e)

    return None, None


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
    local_llm_state = getattr(request.app.state, "local_llm_detected", {})
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

        if user_id is not None:
            if db is None:
                db = next(get_db())
            llm, provider_name = _get_llm_provider(user_id, db, local_llm_state)
        else:
            # Unauthenticated – env-var keys only (no DB lookup)
            llm, provider_name = _get_llm_provider_anonymous(local_llm_state)

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

        local_llm_state = getattr(request.app.state, "local_llm_detected", {})
        llm, provider_name = _get_llm_provider(user.id, db, local_llm_state)

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

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
from typing import Any, Callable, Dict, List, Optional, Tuple

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
- tactic (ATT&CK tactic, e.g. Initial Access)
- attribution_type (direct / via_software:ToolName / via_campaign:CampaignName)
- covered (true = Archer already has a detection YAML for this; false = gap)

Your task: Return the top {n} most critical techniques to prioritize for detection.

Ranking criteria (in order of weight):
1. Uncovered gaps — prefer techniques with no existing detection
2. Enabling position — entry points and techniques the group's other techniques depend on.
   ATT&CK is not linear: tactics are goals, not steps, and a group can reach them in any order,
   so don't rank by a tactic's column position
3. Attribution confidence — direct > via_software > via_campaign
4. Detection opportunity — prefer techniques with rich, available telemetry (process, network, auth logs)
5. Chaining potential — techniques that bridge several tactics

attack_chain is the order this group is reported to use its tactics in, not ATT&CK's column order.

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
  Elastic (EQL/ES|QL), Google SecOps (UDM Search)
- SIEM correlation logic, data sources, and log field naming conventions
- The Archer detection-generation platform which produces YAML-based detection rules

Guidelines:
- Give clear, concise, technically accurate answers.
- When asked for queries, always produce complete, runnable examples with realistic field names.
- For Splunk use `index=`, `| stats`, `| transaction`, `| eval`, `| where` etc.
- For Defender XDR/Sentinel use KQL with `DeviceEvents`, `DeviceProcessEvents`, etc.
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


def _cloud_candidates(keys: Dict[str, str]) -> List[Tuple[str, Callable]]:
    """(label, make_llm) for each cloud provider with a key: the user's, else the server's."""
    from archer.ai.llm.providers import LLMFactory

    out = []
    for provider_id, key_names, env_names, label in _CLOUD_PROVIDER_CHAIN:
        api_key = next((keys[k] for k in key_names if keys.get(k)), None)
        if not api_key:
            api_key = next((os.getenv(e) for e in env_names if os.getenv(e)), None)
        if api_key:
            out.append((label, lambda p=provider_id, k=api_key: LLMFactory.create(p, api_key=k)))
    return out


def _local_candidates(local_llm_endpoints: List[dict]) -> List[Tuple[str, Callable]]:
    """(label, make_llm) for each detected local endpoint (Ollama, Osaurus)."""
    from archer.ai.llm.providers import LLMFactory

    out = []
    for endpoint in local_llm_endpoints or []:
        provider_id = endpoint.get("provider")
        if not endpoint.get("available") or provider_id not in ("ollama", "osaurus"):
            continue
        base_url = endpoint.get("base_url") or endpoint.get("url", "").split("/api/")[0]
        model = endpoint.get("model") or ("llama2" if provider_id == "ollama" else "default")
        out.append((f"Local LLM ({endpoint.get('name')}/{model})",
                    lambda p=provider_id, b=base_url, m=model: LLMFactory.create(p, base_url=b, model=m)))
    return out


def _provider_candidates(user_id: Optional[int], db, local_llm_endpoints: Optional[List[dict]] = None):
    """
    The providers to try for Ask Archer (and the threat briefing), in order, and
    whether they come from an assignment.

    The provider assigned to Ask Archer in the profile is the only candidate (GitHub
    #10): if it fails, the error is shown rather than an answer from another provider.
    With nothing assigned: the user's keys (then the server's) in priority order
    Anthropic → OpenAI → Gemini → DeepSeek → Qwen → Grok, then the profile's local
    model, then local LLMs detected on this machine.
    """
    from archer.ai.assignment import LOCAL, create_llm, resolve

    keys: Dict[str, str] = {}
    if user_id is not None:
        assigned = resolve(db, user_id, "ask")
        if assigned:
            model = assigned["model"] or "default model"
            return [(f"{assigned['label']} / {model}", lambda: create_llm(assigned))], True
        try:
            for row in db.query(APIKey).filter(APIKey.user_id == user_id).all():
                try:
                    keys[row.platform] = decrypt_api_key(row.encrypted_key)
                except Exception:
                    pass
        except Exception as e:
            logger.warning("Could not read API keys from DB: %s", e)

    candidates = _cloud_candidates(keys)
    if user_id is not None:
        profile_local = resolve(db, user_id, "ask", LOCAL)
        if profile_local:
            model = profile_local["model"] or "default model"
            candidates.append((f"{profile_local['label']} / {model}", lambda: create_llm(profile_local)))
    return candidates + _local_candidates(local_llm_endpoints), False


def _generate(candidates, assigned: bool, purpose: str, **kwargs):
    """
    Generate with the first provider that answers; returns (LLMResponse, label).

    Unassigned, a provider that errors (no credit, bad key, unreachable) is skipped
    for the next one, so Ask Archer still answers from Ollama when the first cloud key
    is out of credit. Assigned, its error is the answer. Raises HTTPException(502)
    listing each failure when none answers.
    """
    failures = []
    for label, make in candidates:
        try:
            response = make().generate(**kwargs)
        except Exception as e:
            reason = str(e).split(" - {")[0][:200] if " - {" in str(e) else str(e)[:200]
            if "credit balance is too low" in str(e):
                reason = "credit balance too low"
            print(f"⚠️  {purpose}: {label} failed ({reason})"
                  f"{'' if assigned else '; trying the next provider'}", flush=True)
            failures.append(f"{label}: {reason}")
            if assigned:
                break
            continue
        print(f"🤖 {purpose}: {label}{' (assigned in profile)' if assigned else ''}"
              f"{' after ' + str(len(failures)) + ' failed' if failures else ''}", flush=True)
        return response, label
    raise HTTPException(status_code=502, detail="; ".join(failures) or "No LLM provider answered")


def _get_llm_provider(user_id: int, db, local_llm_endpoints: Optional[List[dict]] = None):
    """The first provider that can be created, as (LLMProvider, label); (None, None) if none."""
    candidates, _ = _provider_candidates(user_id, db, local_llm_endpoints)
    for label, make in candidates:
        try:
            return make(), label
        except Exception as e:
            logger.warning("%s provider failed: %s", label, e)
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

        candidates, assigned = _provider_candidates(user_id, db, local_llm_endpoints)
        redetect = getattr(request.app.state, "redetect_local_llm", None)
        if not candidates and not local_llm_endpoints and redetect:
            # Local LLMs are probed at startup; one started since would otherwise
            # stay invisible until Archer restarts
            await redetect()
            candidates, assigned = _provider_candidates(
                user_id, db, getattr(request.app.state, "local_llm_endpoints", []))

        if not candidates:
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

        response, provider_name = _generate(
            candidates, assigned, "Ask Archer",
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
        candidates, assigned = _provider_candidates(user.id, db, local_llm_endpoints)

        if not candidates:
            raise HTTPException(
                status_code=503,
                detail=(
                    "No LLM provider configured. "
                    "Add an API key under Profile → API Keys, or start a local Ollama instance."
                ),
            )

        system = _BRIEFING_SYSTEM_PROMPT.format(n=payload.top_n)
        raw, provider_name = _generate(
            candidates, assigned, "Threat briefing",
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

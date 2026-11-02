"""
Push exported detections to a SIEM's rule store (#20).

Pushing is outward-facing and can't be exercised without live tenant credentials, so it is a
**dry run by default**: ``plan_push`` builds the rule payloads and the API calls that would be made and
returns them for review, writing nothing. An actual push happens only when ``execute=True`` and the
caller supplies credentials — kept off in the UI until a tenant is wired up. No AI.

Supported today: Microsoft Defender XDR (custom detection rules, Graph security API) and
Google SecOps (rules, Chronicle Detection Engine). Each detection becomes one rule in that SIEM's
native language (KQL / YARA-L), which is already what Shikari generated.
"""

from typing import Dict, List, Optional

# SIEM key -> (label, the rule endpoint a real push would POST to, created disabled)
TARGETS = {
    "mde": {
        "label": "Microsoft Defender XDR",
        "endpoint": "https://graph.microsoft.com/beta/security/rules/detectionRules",
        "language": "KQL",
    },
    "secops": {
        "label": "Google SecOps",
        "endpoint": "https://{region}-chronicle.googleapis.com/v1alpha/.../rules",
        "language": "YARA-L",
    },
}

SEVERITY_MDE = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "informational": "informational"}


def _mde_rule(det: Dict) -> Dict:
    """A Defender XDR custom detection rule payload, created disabled (isEnabled false)."""
    sev = SEVERITY_MDE.get(str(det.get("severity", "medium")).lower(), "medium")
    return {
        "displayName": f"[Shikari] {det.get('name') or det.get('technique_id')}",
        "isEnabled": False,
        "queryCondition": {"queryText": det.get("query", "")},
        "detectionAction": {
            "alertTemplate": {
                "title": det.get("name") or det.get("technique_id"),
                "severity": sev,
                "category": "Execution",
                "mitreTechniques": [det["technique_id"]] if det.get("technique_id") else [],
            }
        },
        "schedule": {"period": "24H"},
    }


def _secops_rule(det: Dict) -> Dict:
    """A SecOps rule payload, created in the disabled (no live deployment) state."""
    return {
        "rule": {"text": det.get("query", "")},
        "metadata": {"technique": det.get("technique_id"), "name": det.get("name")},
        "deploymentState": {"enabled": False, "alerting": False},
    }


_BUILDERS = {"mde": _mde_rule, "secops": _secops_rule}


def plan_push(siem: str, detections: List[Dict], execute: bool = False,
              credentials: Optional[Dict] = None) -> Dict:
    """Build the rule payloads and the calls a push would make.

    detections: [{name, technique_id, query, severity, siem}]. Returns the plan; with execute=False
    (the default) nothing is sent. execute=True without credentials is refused rather than silently
    dry-running, so a caller can't believe it pushed when it didn't."""
    target = TARGETS.get(siem)
    if not target:
        return {"success": False, "error": f"Push to {siem} is not supported"}

    builder = _BUILDERS[siem]
    chosen = [d for d in detections if d.get("query") and (d.get("siem") in (siem, None))]
    calls = [{"method": "POST", "url": target["endpoint"], "body": builder(d)} for d in chosen]
    plan = {
        "success": True,
        "siem": siem,
        "label": target["label"],
        "language": target["language"],
        "rule_count": len(calls),
        "created_disabled": True,
        "dry_run": not execute,
        "calls": calls,
    }
    if not execute:
        plan["note"] = ("Dry run: no rules were sent. Pushing is disabled until a tenant and "
                        "credentials are configured; every rule is created disabled when it is.")
        return plan
    if not credentials:
        return {"success": False, "error": "Push requires tenant credentials; none supplied (still a dry run only)"}
    # A real push would authenticate and POST each call here. Deliberately not implemented:
    # outward-facing, untestable without a live tenant, and out of scope for single-machine use.
    return {"success": False, "error": "Live push is not enabled in this build", "planned": plan}

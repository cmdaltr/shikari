"""
Coverage of ATT&CK's cloud techniques by provider (#36): for each technique on a cloud platform,
whether the detection library has a detection over AWS, Azure, GCP or identity/SaaS logs, and in
which SIEMs.

A technique applies to a provider by its ATT&CK platforms: IaaS techniques to AWS, Azure and GCP
(control-plane logs: CloudTrail, the Activity Log, Cloud Audit Logs); Identity Provider, SaaS and
Office Suite techniques to identity (Entra ID, Okta, Defender's identity tables, sign-in logs).
A detection covers a provider when its file or query names that provider's logs: Splunk's
per-provider indexes, SecOps log types (AWS_CLOUDTRAIL, AZURE_AD, GCP_AUDIT), Elastic's data
streams (logs-aws.*), or Defender's CloudAppEvents (which carries every connected cloud through
Defender for Cloud Apps, so it counts for all three unless the query names one).
"""

import os
import re
from typing import Dict, Iterable, List, Set

PROVIDERS = ("aws", "azure", "gcp", "identity")
LABELS = {"aws": "AWS", "azure": "Azure", "gcp": "GCP", "identity": "Identity & SaaS"}
IAAS = {"IaaS"}
IDENTITY = {"Identity Provider", "SaaS", "Office Suite", "Office 365", "Azure AD", "Google Workspace"}

# Markers in a detection's text, lower-cased
MARKERS = {
    "aws": ("aws_cloudtrail", "logs-aws", "index=aws", "amazon web services", "cloudtrail", "aws.cloudtrail"),
    "azure": ("logs-azure.activitylogs", "index=azure", "microsoft azure", "azureactivity", "azure.activitylogs",
              "microsoft.compute/", "microsoft.authorization/"),
    "gcp": ("gcp_audit", "logs-gcp", "index=gcp", "google cloud", "gcp.audit", "cloudaudit"),
    "identity": ("azure_ad", "index=identity", "identitylogonevents", "identitydirectoryevents", "signinlogs",
                 "okta", "logs-azure.signinlogs", "logs-azure.auditlogs", "entra"),
}
SIEMS = {"MicrosoftThreatProtection": "Defender XDR", "GoogleSecOps": "SecOps", "Splunk": "Splunk", "Elastic": "Elastic"}
_TID = re.compile(r"^technique_id:\s*['\"]?(T\d{4}(?:\.\d{3})?)", re.M)
_CONNECTOR = re.compile(r"connectorId:\s*(\w+)")


def applies(platforms: Iterable[str]) -> List[str]:
    platforms = set(platforms or [])
    return ([p for p in ("aws", "azure", "gcp")] if platforms & IAAS else []) + (["identity"] if platforms & IDENTITY else [])


def providers_of(filename: str, text: str) -> Set[str]:
    """The cloud providers a detection file's logs belong to."""
    lower = text.lower()
    found = {p for p in PROVIDERS if os.path.splitext(filename)[0].lower().endswith("_" + p)}
    found |= {p for p, marks in MARKERS.items() if any(m in lower for m in marks)}
    if "cloudappevents" in lower and not found & {"aws", "azure", "gcp"}:
        found |= {"aws", "azure", "gcp"}
    return found


def siem_of(filename: str, text: str) -> str:
    m = _CONNECTOR.search(text)
    if m and m.group(1) in SIEMS:
        return SIEMS[m.group(1)]
    stem = os.path.splitext(filename)[0].lower()
    if stem.endswith(("_udm", "_yaral")):
        return "SecOps"
    if stem.endswith("_esql"):
        return "Elastic"
    if stem.endswith("_kql") or "cloudappevents" in stem or stem.startswith("device"):
        return "Defender XDR"
    return "Splunk"


def library_index(generate_dir: str) -> Dict[str, Dict[str, Set[str]]]:
    """{technique ID: {provider: {SIEMs}}} from the detection files, by reading their text
    (a regex per file, not a YAML parse: libraries run to thousands of files)."""
    index: Dict[str, Dict[str, Set[str]]] = {}
    if not os.path.isdir(generate_dir):
        return index
    for name in os.listdir(generate_dir):
        if not name.endswith((".yaml", ".yml")):
            continue
        try:
            with open(os.path.join(generate_dir, name), encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        m = _TID.search(text)
        providers = providers_of(name, text)
        if not m or not providers:
            continue
        siem = siem_of(name, text)
        for tid in {m.group(1).upper(), m.group(1).upper().split(".")[0]}:
            for p in providers:
                index.setdefault(tid, {}).setdefault(p, set()).add(siem)
    return index


def cloud_coverage(generate_dir: str, attack: Dict[str, Dict]) -> Dict:
    """{providers, labels, summary: {provider: {applicable, covered}}, techniques: [...]}."""
    index = library_index(generate_dir)
    rows = []
    for tid, obj in sorted(attack.items()):
        providers = applies(obj.get("x_mitre_platforms") or [])
        if not providers:
            continue
        have = index.get(tid, {})
        rows.append({
            "technique_id": tid, "name": obj.get("name"),
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
            "platforms": obj.get("x_mitre_platforms") or [],
            "coverage": {p: (sorted(have.get(p, [])) if p in providers else None) for p in PROVIDERS},
        })
    summary = {p: {"applicable": sum(r["coverage"][p] is not None for r in rows),
                   "covered": sum(bool(r["coverage"][p]) for r in rows)} for p in PROVIDERS}
    return {"providers": list(PROVIDERS), "labels": LABELS, "summary": summary, "techniques": rows}

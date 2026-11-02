"""
Technology stack (Profile → Technology stack): the products an organisation runs, so a group
hunt leaves out what can't happen there. Any product works the same way; the catalogue is
data (shikari/mappings/tech_stack.json, extended or overridden by bespoke/mappings/tech_stack.json).

Two checks, both only when a stack is set (none chosen means everything applies):

- Platform: a technique whose ATT&CK platforms are all outside the stack's (an ESXi-only
  technique with no ESXi, an Office Suite one with neither Microsoft 365 nor Google Workspace).
  PRE (Reconnaissance, Resource Development) always applies.
- Product: a procedure example that names catalogue products, none of them in the stack
  ("APT29 used the SolarWinds Orion update" for a stack without SolarWinds). A procedure
  that names no product, or names one the stack has, applies. Products attackers also bring
  or host on (attacker_used: GitHub, Google Drive, AnyDesk) don't count: naming them says
  nothing about the victim.

Group hunts apply both. Explicit inputs (a technique or CVE hunt, a report) are the user's
choice: they warn instead.
"""

import json
import os
import re
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Sequence

CATALOGUE_FILES = (
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "mappings", "tech_stack.json"),
    os.path.join("bespoke", "mappings", "tech_stack.json"),
)
ALWAYS = {"PRE"}


@lru_cache(maxsize=1)
def catalogue() -> Dict:
    """{"categories": [...], "products": {id: product}}; a bespoke product replaces one with its id."""
    categories, products = [], {}
    for path in CATALOGUE_FILES:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        categories += [c for c in data.get("categories", []) if c not in categories]
        for p in data.get("products", []):
            if p.get("id") and p.get("label"):
                products[p["id"]] = {"platforms": [], "aliases": [], "cpe": [], "category": "Other", **p}
    if any(p["category"] == "Other" for p in products.values()) and "Other" not in categories:
        categories.append("Other")
    return {"categories": categories, "products": products}


def as_stack(ids: Iterable[str]) -> List[str]:
    """Known product ids, in catalogue order."""
    wanted = set(ids or [])
    return [pid for pid in catalogue()["products"] if pid in wanted]


def platforms(stack: Sequence[str]) -> set:
    products = catalogue()["products"]
    return {pl for pid in stack for pl in products.get(pid, {}).get("platforms", [])} | ALWAYS


def _alias_pattern(alias: str) -> re.Pattern:
    # Capitalised aliases are names ("Orion", "Zoom"): case-sensitive, so prose doesn't match
    flags = 0 if any(c.isupper() for c in alias) else re.IGNORECASE
    return re.compile(rf"(?<![\w-]){re.escape(alias)}(?![\w-])", flags)


@lru_cache(maxsize=1)
def _patterns() -> List[tuple]:
    return [(pid, _alias_pattern(a)) for pid, p in catalogue()["products"].items() for a in p["aliases"]]


# ATT&CK's "(Citation: Check Point Scattered Spider JUL 2025)" names the report's publisher, a
# campaign's name isn't its target ("During the [SolarWinds Compromise](…/campaigns/C0024), APT29
# cleared event logs" happened on the victims' Windows hosts), and a link's URL isn't prose
_NOT_PROSE = re.compile(r"\(Citation:[^)]*\)|\[[^\]]*\]\(https?://attack\.mitre\.org/campaigns/[^)]*\)"
                        r"|\]\([^)]*\)|https?://\S+")


def products_named(text: str) -> List[str]:
    """Catalogue products the text names, in catalogue order."""
    if not text:
        return []
    text = _NOT_PROSE.sub(" ", text)
    found = {pid for pid, pattern in _patterns() if pattern.search(text)}
    return [pid for pid in catalogue()["products"] if pid in found]


def platform_applies(technique_platforms: Optional[Sequence[str]], stack: Sequence[str]) -> bool:
    """No stack, or no platforms recorded: it applies."""
    if not stack or not technique_platforms:
        return True
    return bool(set(technique_platforms) & platforms(stack))


def targets_in(pids: Iterable[str]) -> List[str]:
    """
    The products that only a victim's estate explains: not the attacker_used ones (GitHub
    accounts to host malware, exfiltration to Google Drive, an AnyDesk they installed).
    """
    products = catalogue()["products"]
    return [pid for pid in pids if pid in products and not products[pid].get("attacker_used")]


def targets_named(text: str) -> List[str]:
    return targets_in(products_named(text))


def text_applies(text: str, stack: Sequence[str]) -> bool:
    """False when the text names targeted products and none of them is in the stack."""
    if not stack:
        return True
    named = targets_named(text)
    return not named or bool(set(named) & set(stack))


def off_stack(text: str, stack: Sequence[str]) -> List[str]:
    """Labels of the targeted products the text names that the stack doesn't have (for warnings)."""
    if not stack:
        return []
    return [label(pid) for pid in targets_named(text) if pid not in stack]


def label(pid: str) -> str:
    return catalogue()["products"].get(pid, {}).get("label", pid)


# ------------------------------------------------------------------- CVEs (NVD CPE)

_CPE = re.compile(r"cpe:2\.3:[aho]:([^:]+):([^:]+)")


def cpe_products(cpes: Iterable[str]) -> List[str]:
    """Catalogue products for NVD CPE strings (cpe:2.3:a:solarwinds:orion_platform:...)."""
    pairs = {(m.group(1), m.group(2)) for c in cpes or [] if (m := _CPE.match(c or ""))}
    found = []
    for pid, p in catalogue()["products"].items():
        for rule in p["cpe"]:
            vendor, _, product = rule.partition(":")
            pattern = re.compile(re.escape(product).replace(r"\*", ".*") + "$") if product else None
            if any(v == vendor and (pattern is None or pattern.match(prod)) for v, prod in pairs):
                found.append(pid)
                break
    return found


# ---------------------------------------------------------------- company profiles

# The profiler's page detections that are observations: its AWS, Azure and Google Cloud ones
# match "amazon" or "google" anywhere in the page (a shop link, Google Analytics)
_OBSERVED = {"WordPress": "WordPress", "Apache": "Apache HTTP Server", "nginx": "nginx", "Microsoft-IIS": "IIS"}


def from_profile(profile: Dict) -> List[str]:
    """Products a company profile observed: web server banner, page technologies, MX-record email provider."""
    threat = (profile or {}).get("threat_profile") or {}
    tech = threat.get("tech_stack") or {}
    supply = threat.get("supply_chain") or {}
    seen = [] if tech.get("web_server_custom_banner") else [str(tech.get("web_server") or "")]
    seen += [_OBSERVED[t] for t in tech.get("technologies") or [] if t in _OBSERVED]
    seen += [str(t) for t in supply.get("email_providers") or []]
    return as_stack(pid for s in seen for pid in products_named(s))

"""
Search functionality for the ADF console.

Three search domains:
  bespoke  — prompts, templates, reference queries, mappings
  mitre    — ATT&CK techniques, groups, tactics, data sources
  library  — generated detection YAMLs and correlation files
"""

import json
import os
import re
from pathlib import Path
from typing import List, Tuple


_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_BESPOKE_DIR = _PROJECT_ROOT / "bespoke"
_DATA_DIR = _PROJECT_ROOT / "data"


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

_C_CYAN = "\033[36m"
_C_GREEN = "\033[32m"
_C_YELLOW = "\033[33m"
_C_WHITE = "\033[1;37m"
_C_GREY = "\033[90m"
_C_RESET = "\033[0m"


def _highlight(text: str, term: str) -> str:
    """Highlight search term occurrences in text."""
    if not term:
        return text
    pattern = re.compile(re.escape(term), re.IGNORECASE)
    return pattern.sub(f"{_C_YELLOW}\\g<0>{_C_RESET}", text)


def _truncate(text: str, length: int = 100) -> str:
    """Truncate text to length with ellipsis."""
    text = text.replace("\n", " ").strip()
    if len(text) <= length:
        return text
    return text[:length] + "..."


# ---------------------------------------------------------------------------
# BESPOKE search
# ---------------------------------------------------------------------------

def search_bespoke(term: str) -> List[dict]:
    """Search bespoke prompts, templates, references, and mappings."""
    results = []
    term_lower = term.lower()

    if not _BESPOKE_DIR.exists():
        return results

    # Search markdown files (prompts, templates)
    for md_file in _BESPOKE_DIR.rglob("*.md"):
        if md_file.name.startswith("."):
            continue
        try:
            content = md_file.read_text(errors="ignore")
            if term_lower in content.lower():
                # Find matching lines
                matches = []
                for i, line in enumerate(content.splitlines(), 1):
                    if term_lower in line.lower():
                        matches.append((i, line.strip()))
                rel_path = md_file.relative_to(_PROJECT_ROOT)
                results.append({
                    "domain": "bespoke",
                    "type": _classify_bespoke(md_file),
                    "file": str(rel_path),
                    "matches": matches[:5],
                })
        except Exception:
            continue

    # Search YAML files (references, searches)
    for yaml_file in _BESPOKE_DIR.rglob("*.yaml"):
        if yaml_file.name.startswith(".") or yaml_file.name.endswith(".example"):
            continue
        try:
            content = yaml_file.read_text(errors="ignore")
            if term_lower in content.lower():
                # Try to extract name/technique_id
                name_match = re.search(r"^name:\s*(.+)$", content, re.MULTILINE)
                tid_match = re.search(r"^technique_id:\s*(.+)$", content, re.MULTILINE)
                rel_path = yaml_file.relative_to(_PROJECT_ROOT)
                results.append({
                    "domain": "bespoke",
                    "type": "reference",
                    "file": str(rel_path),
                    "name": name_match.group(1).strip() if name_match else "",
                    "technique_id": tid_match.group(1).strip() if tid_match else "",
                })
        except Exception:
            continue

    # Search JSON mappings
    for json_file in (_BESPOKE_DIR / "mappings").glob("*.json"):
        try:
            content = json_file.read_text(errors="ignore")
            if term_lower in content.lower():
                rel_path = json_file.relative_to(_PROJECT_ROOT)
                results.append({
                    "domain": "bespoke",
                    "type": "mapping",
                    "file": str(rel_path),
                })
        except Exception:
            continue

    return results


def _classify_bespoke(path: Path) -> str:
    """Classify a bespoke file by its parent directory."""
    parts = path.parts
    if "prompts" in parts:
        return "prompt"
    if "query_templates" in parts:
        return "template"
    if "references" in parts:
        return "reference"
    if "mappings" in parts:
        return "mapping"
    return "config"


# ---------------------------------------------------------------------------
# MITRE search
# ---------------------------------------------------------------------------

def search_mitre(term: str) -> List[dict]:
    """Search MITRE ATT&CK techniques, groups, tactics."""
    results = []
    term_lower = term.lower()

    # Try to load cached STIX data
    cache_path = _DATA_DIR / "cache" / "enterprise-attack.json"
    if not cache_path.exists():
        # Try alternate locations
        for alt in [
            _PROJECT_ROOT / ".cache_enterprise_attack.json",
            _PROJECT_ROOT / "MITRESaw" / "toolbox" / "scripts" / ".cache_enterprise_attack.json",
        ]:
            if alt.exists():
                cache_path = alt
                break

    if not cache_path.exists():
        return [{"domain": "mitre", "type": "error",
                 "message": "No cached STIX data found. Run a generate first to fetch MITRE data."}]

    try:
        with open(cache_path) as f:
            bundle = json.load(f)
    except Exception:
        return [{"domain": "mitre", "type": "error", "message": "Failed to parse STIX cache."}]

    objects = bundle.get("objects", [])

    # Search techniques (attack-pattern)
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        name = obj.get("name", "")
        desc = obj.get("description", "")
        tid = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id", "")
                break

        tactics = [
            p["phase_name"].replace("-", " ").title()
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        platforms = obj.get("x_mitre_platforms", [])

        searchable = f"{tid} {name} {desc} {' '.join(tactics)} {' '.join(platforms)}".lower()
        if term_lower in searchable:
            results.append({
                "domain": "mitre",
                "type": "technique",
                "technique_id": tid,
                "name": name,
                "tactics": tactics,
                "platforms": platforms,
                "description": desc[:200],
            })

    # Search groups (intrusion-set)
    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        name = obj.get("name", "")
        desc = obj.get("description", "")
        aliases = obj.get("aliases", [])
        gid = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                gid = ref.get("external_id", "")
                break

        searchable = f"{gid} {name} {' '.join(aliases)} {desc}".lower()
        if term_lower in searchable:
            results.append({
                "domain": "mitre",
                "type": "group",
                "group_id": gid,
                "name": name,
                "aliases": [a for a in aliases if a != name],
                "description": desc[:200],
            })

    # Search software (tool/malware)
    for obj in objects:
        if obj.get("type") not in ("tool", "malware"):
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        name = obj.get("name", "")
        desc = obj.get("description", "")
        sid = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                sid = ref.get("external_id", "")
                break

        searchable = f"{sid} {name} {desc}".lower()
        if term_lower in searchable:
            results.append({
                "domain": "mitre",
                "type": "software",
                "software_id": sid,
                "name": name,
                "description": desc[:200],
            })

    return results


# ---------------------------------------------------------------------------
# LIBRARY search
# ---------------------------------------------------------------------------

def search_library(term: str) -> List[dict]:
    """Search generated detection YAMLs and correlations."""
    results = []
    term_lower = term.lower()

    # Search detection YAMLs
    groups_dir = _DATA_DIR / "groups"
    if groups_dir.exists():
        for yaml_file in groups_dir.glob("*.yaml"):
            try:
                content = yaml_file.read_text(errors="ignore")
                if term_lower in content.lower():
                    # Extract key fields
                    name_m = re.search(r"^name:\s*(.+)$", content, re.MULTILINE)
                    tid_m = re.search(r"^technique_id:\s*(.+)$", content, re.MULTILINE)
                    tactic_m = re.findall(r"^\s*-\s*([\w\s]+)$", content, re.MULTILINE)
                    tag_m = re.findall(r"^\s*-\s*(.+\(Group\))$", content, re.MULTILINE)

                    results.append({
                        "domain": "library",
                        "type": "detection",
                        "file": yaml_file.name,
                        "name": name_m.group(1).strip() if name_m else yaml_file.stem,
                        "technique_id": tid_m.group(1).strip() if tid_m else "",
                        "group": tag_m[0].replace(" (Group)", "") if tag_m else "",
                    })
            except Exception:
                continue

    # Search correlation files
    correlate_dir = _DATA_DIR / "correlate"
    if correlate_dir.exists():
        for json_file in correlate_dir.glob("*.json"):
            try:
                content = json_file.read_text(errors="ignore")
                if term_lower in content.lower():
                    data = json.loads(content)
                    corr_count = len(data.get("vendor_correlations", []))
                    results.append({
                        "domain": "library",
                        "type": "correlation",
                        "file": json_file.name,
                        "group": json_file.stem,
                        "correlation_count": corr_count,
                    })
            except Exception:
                continue

    return results


# ---------------------------------------------------------------------------
# Unified search + display
# ---------------------------------------------------------------------------

SEARCH_DOMAINS = {
    "bespoke": search_bespoke,
    "mitre": search_mitre,
    "library": search_library,
}


def run_search(term: str, domain: str = "all") -> None:
    """Execute a search and print formatted results.

    Args:
        term: Search string.
        domain: "bespoke", "mitre", "library", or "all".
    """
    if not term.strip():
        print("  Usage: search <domain> <term>")
        print("  Domains: bespoke | mitre | library | all")
        return

    if domain == "all":
        domains = ["mitre", "library", "bespoke"]
    elif domain in SEARCH_DOMAINS:
        domains = [domain]
    else:
        print(f"  Unknown domain: {domain}")
        print(f"  Available: {', '.join(SEARCH_DOMAINS.keys())}, all")
        return

    total = 0
    for d in domains:
        results = SEARCH_DOMAINS[d](term)
        if not results:
            continue

        print(f"\n  {_C_CYAN}{'=' * 60}{_C_RESET}")
        print(f"  {_C_WHITE}{d.upper()}{_C_RESET} ({len(results)} result{'s' if len(results) != 1 else ''})")
        print(f"  {_C_CYAN}{'=' * 60}{_C_RESET}")

        for r in results[:25]:  # Cap display at 25 per domain
            _print_result(r, term)
            total += 1

        if len(results) > 25:
            print(f"\n  {_C_GREY}... and {len(results) - 25} more results{_C_RESET}")
            total += len(results) - 25

    if total == 0:
        print(f"\n  No results found for '{term}'")
    else:
        print(f"\n  {_C_GREEN}{total} total result{'s' if total != 1 else ''}{_C_RESET}")


def _print_result(r: dict, term: str) -> None:
    """Print a single search result."""
    rtype = r.get("type", "")

    if rtype == "technique":
        tid = r.get("technique_id", "")
        name = r.get("name", "")
        tactics = ", ".join(r.get("tactics", []))
        platforms = ", ".join(r.get("platforms", []))
        print(f"\n  {_C_GREEN}{tid}{_C_RESET}  {_highlight(name, term)}")
        print(f"    Tactics:   {_C_YELLOW}{tactics}{_C_RESET}")
        print(f"    Platforms: {platforms}")
        desc = _truncate(r.get("description", ""), 120)
        if desc:
            print(f"    {_C_GREY}{_highlight(desc, term)}{_C_RESET}")

    elif rtype == "group":
        gid = r.get("group_id", "")
        name = r.get("name", "")
        aliases = r.get("aliases", [])
        print(f"\n  {_C_GREEN}{gid}{_C_RESET}  {_highlight(name, term)}")
        if aliases:
            print(f"    Aliases: {', '.join(aliases[:5])}")
        desc = _truncate(r.get("description", ""), 120)
        if desc:
            print(f"    {_C_GREY}{_highlight(desc, term)}{_C_RESET}")

    elif rtype == "software":
        sid = r.get("software_id", "")
        name = r.get("name", "")
        print(f"\n  {_C_GREEN}{sid}{_C_RESET}  {_highlight(name, term)}")
        desc = _truncate(r.get("description", ""), 120)
        if desc:
            print(f"    {_C_GREY}{_highlight(desc, term)}{_C_RESET}")

    elif rtype == "detection":
        name = r.get("name", "")
        tid = r.get("technique_id", "")
        group = r.get("group", "")
        fname = r.get("file", "")
        print(f"\n  {_C_GREEN}{tid}{_C_RESET}  {_highlight(name, term)}")
        if group:
            print(f"    Group: {group}")
        print(f"    {_C_GREY}{fname}{_C_RESET}")

    elif rtype == "correlation":
        group = r.get("group", "")
        count = r.get("correlation_count", 0)
        print(f"\n  {_C_CYAN}Correlation:{_C_RESET} {_highlight(group, term)}  ({count} queries)")
        print(f"    {_C_GREY}{r.get('file', '')}{_C_RESET}")

    elif rtype == "prompt" or rtype == "template":
        fname = r.get("file", "")
        print(f"\n  {_C_CYAN}{rtype.title()}:{_C_RESET} {fname}")
        for lineno, line in r.get("matches", [])[:3]:
            print(f"    L{lineno}: {_C_GREY}{_highlight(_truncate(line, 80), term)}{_C_RESET}")

    elif rtype == "reference":
        name = r.get("name", "")
        tid = r.get("technique_id", "")
        fname = r.get("file", "")
        label = f"{tid} — {name}" if tid and name else fname
        print(f"\n  {_C_GREEN}Ref:{_C_RESET} {_highlight(label, term)}")
        print(f"    {_C_GREY}{fname}{_C_RESET}")

    elif rtype == "mapping":
        fname = r.get("file", "")
        print(f"\n  {_C_CYAN}Mapping:{_C_RESET} {fname}")

    elif rtype == "error":
        print(f"\n  {r.get('message', 'Unknown error')}")

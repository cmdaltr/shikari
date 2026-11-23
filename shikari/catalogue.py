"""
What the Catalogue lists: the work done so far, one kind per tab.

  Hunts      every generation run (data/runs/<group>.json) for an ATT&CK group, a CVE or techniques,
             with the hunt_runs row of the latest /api/runs request for it (its Ostraka reference and
             the result counts, when it was executed)
  Analyses   every report read: a blog URL, an uploaded file, a STIX/TAXII or MISP import
             (data/blog_analysis and data/uploads, <name>_extraction.json)
  Companies  every organisation profiled (data/profiles/<domain>_profile.json)
  Campaigns  every campaign researched (shikari.intelligence.campaign)

All of it is read from the files the producers already write: nothing new is stored. A run whose
name has an extraction is an analysis; a run named Campaign_* is its campaign's; the rest are hunts.
`source_index` maps a group name, as the Library tags a detection with it, back to the entry that made it.
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

from shikari.config import BLOG_DIR, DATA_DIR, UPLOADS_DIR

RUNS_DIR = os.path.join(DATA_DIR, "runs")
PROFILES_DIR = os.path.join(DATA_DIR, "profiles")
CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_UPLOAD_HASH = re.compile(r"_[0-9a-f]{8}$")


def _key(name: str) -> str:
    """Run files, extractions and Library tags spell a group's name with spaces or underscores."""
    return re.sub(r"[\s_]+", "_", (name or "").strip()).lower()


def _read(path: str) -> Optional[dict]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _iso(when) -> str:
    """An epoch, a datetime or an ISO string, as a UTC ISO string ('' when unknown)."""
    if when is None or when == "":
        return ""
    if isinstance(when, (int, float)):
        return datetime.fromtimestamp(when, tz=timezone.utc).isoformat()
    if isinstance(when, datetime):
        return (when if when.tzinfo else when.replace(tzinfo=timezone.utc)).isoformat()
    return str(when)


def short_date(iso: str) -> str:
    """'12 Nov', or '12 Nov 2025' outside the current year."""
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return ""
    text = f"{when.day} {when:%b}"
    return text if when.year == datetime.now(timezone.utc).year else f"{text} {when.year}"


def results_href(name: str) -> str:
    return f"/results?group_name={quote(name)}&run=latest"


# ---------------------------------------------------------------------------------------------------
# Analyses


def _analysis_title(name: str, data: dict) -> str:
    if data.get("group_name"):
        return data["group_name"]
    title = re.sub(r"^(Report|Upload|BlogAnalysis)_", "", name)
    if name.startswith("Upload_"):
        title = _UPLOAD_HASH.sub("", title)
    return title.replace("_", " ").strip() or name


def _analysis_source(data: dict, uploaded: bool) -> Dict[str, str]:
    url = str(data.get("url") or "")
    label = str(data.get("filename") or "")
    if uploaded:
        return {"kind": "File", "text": label, "url": ""}
    if url.startswith(("http://", "https://")) and label == url:
        return {"kind": "Blog URL", "text": re.sub(r"^https?://(www\.)?", "", url).rstrip("/"), "url": url}
    # A STIX/TAXII or MISP import: filename is its source label, url the TAXII collection if any
    return {"kind": label or "Import", "text": url if url != label else "", "url": ""}


def analyses() -> List[Dict]:
    """Every report analysed, newest first."""
    out = []
    for folder, uploaded in ((BLOG_DIR, False), (UPLOADS_DIR, True)):
        if not os.path.isdir(folder):
            continue
        for entry in os.scandir(folder):
            if not entry.name.endswith("_extraction.json"):
                continue
            data = _read(entry.path)
            if data is None:
                continue
            name = data.get("synthetic_group_name") or entry.name[: -len("_extraction.json")]
            if name.startswith("Campaign_"):
                continue  # written for a campaign's detections; the campaign is in its own tab
            iocs = data.get("iocs") or {}
            run = _read(os.path.join(RUNS_DIR, name.replace("/", "_") + ".json"))
            out.append({
                "kind": "analysis", "name": name, "title": _analysis_title(name, data),
                "source": _analysis_source(data, uploaded),
                "actor": data.get("group_name") or "",
                "ttps": len(data.get("ttps") or []),
                "iocs": sum(len(v) for v in iocs.values() if isinstance(v, list)) if isinstance(iocs, dict) else 0,
                "procedures": len(data.get("procedures") or []),
                "ai": bool(data.get("ai_provider")),
                "when": _iso((run or {}).get("completed_at") or entry.stat().st_mtime),
                "generated": run is not None,
                "detections": len((run or {}).get("files") or []),
                "href": results_href(name) if run is not None else "",
            })
    out.sort(key=lambda a: a["when"], reverse=True)
    return out


# ---------------------------------------------------------------------------------------------------
# Hunts


def _hunt_kind(name: str) -> str:
    if CVE.match(name):
        return "cve"
    if name.startswith("Hunt_"):
        return "techniques"
    return "group"


def _hunt_title(name: str, kind: str) -> str:
    if kind != "techniques":
        return name.replace("_plus_", " + ") if kind == "cve" else name
    first, _, more = name[len("Hunt_"):].partition("_plus_")
    return f"{first} + {more} more" if more else first


def _api_runs(user=None) -> Dict[str, dict]:
    """The latest /api/runs request per group: an admin sees everyone's, anyone else their own."""
    try:
        from shikari.database.models import HuntRun, UserRole, at_least
        from shikari.hunt_runs import _db, describe
    except ImportError:
        return {}
    db = _db()
    try:
        query = db.query(HuntRun)
        if user is not None and not at_least(user, UserRole.ADMIN):
            query = query.filter(HuntRun.user_id == user.id)
        latest: Dict[str, dict] = {}
        for row in query.order_by(HuntRun.created_at.desc()).limit(500):
            latest.setdefault(_key(row.group_name), describe(row, full=False))
        return latest
    except Exception:
        return {}  # the table predates this install's migration: the files alone still list the hunts
    finally:
        db.close()


def hunts(user=None, analysed: Optional[set] = None) -> List[Dict]:
    """Every hunt run, newest first. `analysed`: analyses' names, which aren't hunts. Matched exactly:
    a report about Scattered Spider runs as Scattered_Spider, a hunt for the group as Scattered Spider."""
    if analysed is None:
        analysed = {a["name"] for a in analyses()}
    api = _api_runs(user)
    out, seen = [], set()
    if os.path.isdir(RUNS_DIR):
        for entry in os.scandir(RUNS_DIR):
            if not entry.name.endswith(".json") or entry.name.startswith("."):
                continue  # ".json": a run that was given no name
            data = _read(entry.path) or {}
            name = data.get("group") or entry.name[:-5]
            key = _key(name)
            if not name.strip() or name.startswith("Campaign_") or name in analysed or key in seen:
                continue
            seen.add(key)
            kind = _hunt_kind(name)
            run = api.get(key) or {}
            out.append({
                "kind": "hunt", "hunt_kind": kind, "name": name, "title": _hunt_title(name, kind),
                "when": _iso(data.get("completed_at") or data.get("started_at") or entry.stat().st_mtime),
                "detections": len(data.get("files") or []),
                "no_detection": len(data.get("no_detection") or []),
                "warnings": len(data.get("stack_warnings") or []),
                "status": run.get("status") or "complete",
                "external_ref": run.get("external_ref") or "",
                "executed": bool(run.get("executed_at")),
                "totals": run.get("totals") or {},
                "href": results_href(name),
            })
    # Requested through /api/runs but with no run file yet: queued, generating, or failed
    for key, run in api.items():
        name = run.get("group_name") or ""
        if not name.strip() or key in seen or name in analysed or name.startswith("Campaign_"):
            continue
        kind = run.get("kind") or _hunt_kind(run["group_name"])
        out.append({
            "kind": "hunt", "hunt_kind": kind, "name": run["group_name"],
            "title": _hunt_title(run["group_name"], kind), "when": run.get("created_at") or "",
            "detections": 0, "no_detection": 0, "warnings": 0, "status": run.get("status") or "queued",
            "external_ref": run.get("external_ref") or "", "executed": False, "totals": {},
            "error": run.get("error") or "", "href": "",
        })
    out.sort(key=lambda h: h["when"], reverse=True)
    return out


# ---------------------------------------------------------------------------------------------------
# Companies and campaigns


def companies(home_org: str = "") -> List[Dict]:
    """Every organisation profiled: the user's own first (starred), then newest first."""
    home_org = (home_org or "").strip().lower()
    out = []
    folder = Path(PROFILES_DIR)
    if folder.is_dir():
        for path in folder.glob("*_profile.json"):
            prof = _read(str(path))
            if prof is None:
                continue
            ci = prof.get("company_info") or {}
            osint = prof.get("osint") or {}
            net = ci.get("networks") or {}
            domain = prof.get("domain") or ci.get("domain")
            if not domain:
                continue
            out.append({
                "kind": "company", "domain": domain, "name": ci.get("company_name") or domain,
                "is_home": bool(home_org) and str(domain).strip().lower() == home_org,
                "country": ci.get("country"),
                "risk": prof.get("risk_score") or 0,
                "groups": len(prof.get("recommended_groups") or []),
                "timestamp": prof.get("timestamp"),
                "ips": len(ci.get("ip_addresses") or []),
                "subdomains": len(osint.get("subdomains") or []),
                "asns": len(net.get("asns") or []),
                "hosting": net.get("hosting_countries") or [],
                "breaches": (prof.get("breach_surface") or {}).get("count") or 0,
                "href": f"/review?domain={quote(str(domain))}",
            })
    out.sort(key=lambda c: (c["is_home"], c["timestamp"] or ""), reverse=True)
    return out


def campaigns() -> List[Dict]:
    from shikari.intelligence import campaign as campaign_mod

    rows = campaign_mod.all_campaigns()
    for r in rows:
        r["kind"] = "campaign"
        r["href"] = f"/campaigns/{r['slug']}"
    return rows


# ---------------------------------------------------------------------------------------------------
# For other pages


def everything(user=None) -> Dict[str, List[Dict]]:
    found = analyses()
    return {
        "hunts": hunts(user, {a["name"] for a in found}),
        "analyses": found,
        "companies": companies(getattr(user, "organisation", "") or ""),
        "campaigns": campaigns(),
    }


def recent(user=None, n: int = 3) -> Dict[str, List[Dict]]:
    """The newest few of each kind, as the home page's strips show them."""
    every = everything(user)
    every["companies"] = sorted(every["companies"], key=lambda c: c["timestamp"] or "", reverse=True)

    def row(label, meta, href):
        return {"label": label, "meta": meta, "href": href}

    return {
        "hunts": [row(h["title"], short_date(h["when"]), h["href"] or "/catalogue?tab=hunts")
                  for h in every["hunts"][:n]],
        "analyses": [row(a["title"], short_date(a["when"]), a["href"] or "/catalogue?tab=analyses")
                     for a in every["analyses"][:n]],
        "companies": [row(c["name"], short_date(_iso(c["timestamp"])), c["href"]) for c in every["companies"][:n]],
        "campaigns": [row(c["name"], short_date(_iso(c["researched"])), c["href"]) for c in every["campaigns"][:n]],
        "counts": {k: len(v) for k, v in every.items()},
    }


def source_index(user=None) -> Dict[str, Dict]:
    """Group name -> where its detections came from, for the Library's "from:" chip. Keyed by the exact
    name and by _key(name); look a group up with `source_for`, which tries the exact name first."""
    from shikari.intelligence import campaign as campaign_mod

    found = analyses()
    entries = []
    for h in hunts(user, {a["name"] for a in found}):
        if h["href"]:
            entries.append((h["name"], {"label": h["title"], "kind": "hunt", "date": short_date(h["when"]),
                                        "href": h["href"]}))
    for a in found:
        entries.append((a["name"], {"label": a["title"], "kind": "analysis", "date": short_date(a["when"]),
                                    "href": a["href"] or "/catalogue?tab=analyses"}))
    for c in campaigns():
        entries.append((campaign_mod.group_name(c["name"]), {"label": c["name"], "kind": "campaign",
                        "date": short_date(_iso(c["researched"])), "href": c["href"]}))
    index: Dict[str, Dict] = {}
    for name, entry in entries:
        index[name] = entry
    for name, entry in entries:
        index.setdefault("~" + _key(name), entry)  # the first of its spellings wins: hunts before analyses
    return index


def source_for(index: Dict[str, Dict], group: str) -> Optional[Dict]:
    if not group or group == "Unknown":
        return None
    return index.get(group) or index.get("~" + _key(group))

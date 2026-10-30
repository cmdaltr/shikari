"""
Public-incident feeds for the Ordered Adversary List (archer.intelligence.adversary_ranking).

Three reputable, structured sources are fetched and distilled to small local caches; the ranking
reads only those caches, so it stays offline and AI-free at render time. Fetching is a separate
step (refresh), not something a page render does.

  VCDB            VERIS Community Database (github.com/vz-risk/VCDB) — thousands of publicly
                  disclosed incidents: victim org, industry (NAICS), country, actor, year.
  CISA KEV        Known Exploited Vulnerabilities — CVEs confirmed exploited in the wild, with a
                  knownRansomwareCampaignUse flag. Cross-referenced against the org's exposed CVEs.
  ransomware.live Recent ransomware victims: group -> company -> sector -> date (attacker-claimed,
                  ransomware only), the most current named-actor signal.

Distilled caches (data/cache/incidents/<source>.json):
  kev.json             {"generated", "cves": {CVE: {"ransomware": bool, "vendor", "product"}}}
  vcdb.json            {"generated", "total", "groups": {name: {victims, sectors, last_seen}},
                        "sector_counts": {label: n}}
  ransomware_live.json {"generated", "groups": {name: {victims, sectors, last_seen}}}

Every fetch is wrapped so one source failing never blocks the others, and a missing cache simply
means that source contributes nothing to the ranking.
"""

from __future__ import annotations

import datetime
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple

from archer import paths

_DIR = paths.DATA / "cache" / "incidents"
_KEV = _DIR / "kev.json"
_VCDB = _DIR / "vcdb.json"
_RANSOMWARE = _DIR / "ransomware_live.json"

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_VCDB_ZIP = "https://github.com/vz-risk/VCDB/archive/refs/heads/master.zip"
_RANSOMWARE_URL = "https://api.ransomware.live/v2/recentvictims"
_TIMEOUT = 60

# NAICS 2-digit sector -> the ranking's controlled sector vocab (archer.intelligence.adversary_ranking)
_NAICS2 = {
    "21": "Energy / Utilities", "22": "Energy / Utilities",
    "31": "Manufacturing / Industrial", "32": "Manufacturing / Industrial", "33": "Manufacturing / Industrial",
    "42": "Retail / Hospitality", "44": "Retail / Hospitality", "45": "Retail / Hospitality",
    "48": "Transport / Logistics", "49": "Transport / Logistics",
    "51": "Technology", "52": "Finance / Banking", "54": "Technology",
    "61": "Education / Research", "62": "Healthcare / Pharma",
    "71": "Media / Entertainment", "72": "Retail / Hospitality", "92": "Government",
}

# In-process memo: (mtime, data) per cache so a refresh is picked up without a restart.
_memo: Dict[str, Tuple[float, dict]] = {}


def _today() -> str:
    return datetime.date.today().isoformat()


def _clean(s) -> str:
    return str(s or "").strip().lower()


def _year(text) -> Optional[int]:
    years = re.findall(r"\b((?:19|20)\d{2})\b", str(text or ""))
    return max(int(y) for y in years) if years else None


def _load(path: Path) -> dict:
    """Read a distilled cache, memoised by mtime. {} if absent or unreadable."""
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {}
    cached = _memo.get(str(path))
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    _memo[str(path)] = (mtime, data)
    return data


# ── Loaders used by the ranking (offline) ───────────────────────────────────────

def load_kev() -> dict:
    """{"generated", "cves": {CVE_UPPER: {...}}} from the KEV cache, or {}."""
    return _load(_KEV)


def load_vcdb() -> dict:
    """{"generated", "total", "groups": {...}, "sector_counts": {...}} from the VCDB cache, or {}."""
    return _load(_VCDB)


def load_ransomware() -> dict:
    """{"generated", "groups": {...}} from the ransomware.live cache, or {}."""
    return _load(_RANSOMWARE)


def status() -> dict:
    """What's cached and when, for the UI and the refresh endpoint."""
    def meta(path: Path, data: dict, count_key: str) -> dict:
        return {"present": bool(data), "generated": data.get("generated"),
                "count": len(data.get(count_key, {}) or {})}
    return {
        "kev": meta(_KEV, load_kev(), "cves"),
        "vcdb": meta(_VCDB, load_vcdb(), "groups"),
        "ransomware_live": meta(_RANSOMWARE, load_ransomware(), "groups"),
    }


# ── Fetch + distil (network; run by refresh, never at render time) ───────────────

def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    _memo.pop(str(path), None)


def refresh_kev(log=print) -> dict:
    import requests
    log("KEV: fetching CISA Known Exploited Vulnerabilities…")
    r = requests.get(_KEV_URL, timeout=_TIMEOUT)
    r.raise_for_status()
    cves = {}
    for v in r.json().get("vulnerabilities", []):
        cve = (v.get("cveID") or "").strip().upper()
        if cve:
            cves[cve] = {"ransomware": _clean(v.get("knownRansomwareCampaignUse")) == "known",
                         "vendor": v.get("vendorProject") or "", "product": v.get("product") or ""}
    out = {"generated": _today(), "cves": cves}
    _write(_KEV, out)
    log(f"KEV: {len(cves)} actively-exploited CVE(s) cached")
    return out


def _add(groups: dict, name: str, victim: str, sectors, year: Optional[int]) -> None:
    key = _clean(name)
    if not key:
        return
    g = groups.setdefault(key, {"victims": set(), "sectors": set(), "last_seen": None})
    if victim:
        g["victims"].add(_clean(victim))
    g["sectors"].update(s for s in sectors if s)
    if year and (g["last_seen"] is None or year > g["last_seen"]):
        g["last_seen"] = year


def _freeze(groups: dict) -> dict:
    return {k: {"victims": sorted(v["victims"]), "sectors": sorted(v["sectors"]),
                "last_seen": v["last_seen"]} for k, v in groups.items()}


def refresh_vcdb(log=print) -> dict:
    import requests
    from collections import Counter
    log("VCDB: downloading the VERIS Community Database…")
    r = requests.get(_VCDB_ZIP, timeout=_TIMEOUT * 4)
    r.raise_for_status()
    groups: dict = {}
    sector_counts: Counter = Counter()
    total = 0
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        members = [n for n in z.namelist() if "/data/json/validated/" in n and n.endswith(".json")]
        log(f"VCDB: parsing {len(members)} incident record(s)…")
        for name in members:
            try:
                inc = json.loads(z.read(name))
            except (ValueError, KeyError):
                continue
            total += 1
            victim = inc.get("victim") or {}
            # NAICS: VERIS stores it under victim.industry (string) — first two digits are the sector
            naics2 = str(victim.get("industry") or "")[:2]
            sectors = {_NAICS2[naics2]} if naics2 in _NAICS2 else set()
            for s in sectors:
                sector_counts[s] += 1
            org = victim.get("victim_id") or ""
            year = _year((inc.get("timeline") or {}).get("incident", {}).get("year")
                         or inc.get("plus", {}).get("created"))
            # Named external actors (often generic, sometimes an ATT&CK group name)
            ext = (inc.get("actor") or {}).get("external") or {}
            names = ext.get("name") or []
            names = names if isinstance(names, list) else [names]
            for actor_name in names:
                if actor_name and _clean(actor_name) not in ("unknown", "unaffiliated", "other"):
                    _add(groups, actor_name, org, sectors, year)
    out = {"generated": _today(), "total": total, "groups": _freeze(groups),
           "sector_counts": dict(sector_counts)}
    _write(_VCDB, out)
    log(f"VCDB: {total} incident(s), {len(groups)} named actor(s), "
        f"{len(sector_counts)} sector(s) cached")
    return out


def refresh_ransomware(log=print) -> dict:
    import requests
    from archer.intelligence.adversary_ranking import match_sectors
    log("ransomware.live: fetching recent victims…")
    r = requests.get(_RANSOMWARE_URL, timeout=_TIMEOUT, headers={"accept": "application/json"})
    r.raise_for_status()
    rows = r.json()
    rows = rows if isinstance(rows, list) else rows.get("victims") or []
    groups: dict = {}
    for row in rows:
        name = row.get("group_name") or row.get("group") or ""
        victim = row.get("post_title") or row.get("victim") or ""
        sectors = match_sectors(row.get("activity") or row.get("sector") or "")
        year = _year(row.get("discovered") or row.get("published") or row.get("attackdate"))
        _add(groups, name, victim, sectors, year)
    out = {"generated": _today(), "groups": _freeze(groups)}
    _write(_RANSOMWARE, out)
    log(f"ransomware.live: {len(rows)} victim(s), {len(groups)} group(s) cached")
    return out


def refresh(sources=("kev", "vcdb", "ransomware"), log=print) -> dict:
    """Refresh the named sources. Each is isolated: a failure is logged and the others continue."""
    fns = {"kev": refresh_kev, "vcdb": refresh_vcdb, "ransomware": refresh_ransomware}
    result = {}
    for s in sources:
        fn = fns.get(s)
        if not fn:
            continue
        try:
            fn(log=log)
            result[s] = "ok"
        except Exception as e:  # network, parse, schema drift — never fatal
            log(f"{s}: refresh failed — {e}")
            result[s] = f"failed: {e}"
    return result


if __name__ == "__main__":
    import sys
    picks = [a for a in sys.argv[1:] if a in ("kev", "vcdb", "ransomware")]
    print(json.dumps(refresh(tuple(picks) if picks else ("kev", "vcdb", "ransomware")), indent=2))

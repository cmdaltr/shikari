"""
Recent CVEs: the last WINDOW_DAYS days of NVD, marked from CISA's Known Exploited
Vulnerabilities (KEV), cached in data/feed/cves.json. A recent CVE is the one worth
hunting: the patch may not be out, or not applied yet.

- Kept: published in the window with an ID from the window's year (in January, December's
  too), or hunted (its results still point at it; the picker doesn't list it once it's
  older). An ID's year is when it was reserved: CVE-2013-10076, published this month, is a
  2013 Perl bug a backlog has only now reached. The rest is dropped, KEV or not.
- Refresh: the first fills the window by publication date; after that, what NVD modified
  since the last refresh, since NVD often adds a CVE's products (CPEs) days after it's
  published and the technology-stack match needs them. Runs when Archer starts and every
  REFRESH_EVERY.
- Pre-research: KEV CVEs and those naming a product in someone's technology stack are
  researched in advance (archer.intelligence.cve_hunter, its own cache), so hunting one
  starts at once. At most PRERESEARCH_MAX a refresh, paced for GitHub's search limit.
- A hunt reads the NVD record from here (record()) rather than asking NVD again.

    python -m archer.intelligence.cve_feed          # refresh now
"""

import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Iterable, List, Optional

import requests

from archer import filelock
from archer.config import DATA_DIR

WINDOW_DAYS = 30
REFRESH_EVERY = 24 * 3600
PRERESEARCH_MAX = 60
CACHE_PATH = os.path.join(DATA_DIR, "feed", "cves.json")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
PAGE = 200  # NVD allows 2000 but drops anything over a few hundred part-way (1000: every time)
TRIES = 4
SAVE_EVERY = 10  # pages: a first fill (about 17,000 CVEs) resumes from its last save
KEEP_REFERENCES, KEEP_CPES = 25, 50  # per CVE, to keep the file to a few tens of MB

_running = threading.Lock()  # one refresh at a time
_writing = threading.Lock()  # the file: a refresh's save and mark_hunted
_status = {"refreshing": False, "error": None, "last_refresh": None}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _nvd_date(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


_memo: Dict = {}  # the parsed file and its mtime: a hunt or the API reads it often


def _load() -> Dict:
    try:
        mtime = os.path.getmtime(CACHE_PATH)
        if _memo.get("path") != CACHE_PATH or _memo.get("mtime") != mtime:
            with open(CACHE_PATH, encoding="utf-8") as fh:
                _memo.update(path=CACHE_PATH, mtime=mtime, data=json.load(fh))
        return dict(_memo["data"])  # writers replace top-level keys, never edit them in place
    except (OSError, ValueError):
        return {"cves": {}, "hunted": [], "last_refresh": None}


def _save(data: Dict) -> None:
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    tmp = CACHE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, CACHE_PATH)


def products(cve: Dict) -> List[str]:
    """
    The technology-stack products a CVE affects: from its CPEs, or, while NVD hasn't analysed
    it yet (most CVEs of the last few weeks have no CPEs), the products its description names.
    """
    from archer.intelligence.tech_stack import cpe_products, products_named

    return cpe_products(cve.get("cpes") or []) or products_named(cve.get("description") or "")


def _trim(cve: Dict) -> Dict:
    """What Archer reads: no CVSS v2 (NVD stopped scoring it in 2022), capped references and CPEs."""
    kept = {**{k: v for k, v in cve.items() if k != "cvss_v2"},
            "references": (cve.get("references") or [])[:KEEP_REFERENCES],
            "cpes": (cve.get("cpes") or [])[:KEEP_CPES]}
    return {**kept, "products": products(kept)}  # stored: matching 17,000 per request takes seconds


def _score(cve: Dict) -> float:
    return float(((cve.get("cvss_v3") or {}).get("score")) or 0)


def _pace() -> float:
    """NVD allows 5 requests in 30s without a key, 50 with one."""
    return 0.7 if os.getenv("NVD_API_KEY") else 6.5


def _nvd(params: Dict, start: int = 0, on_page: Optional[Callable[[List[Dict], int], None]] = None) -> List[Dict]:
    """Every vulnerability NVD returns for params from start, page by page; on_page(page, next start)."""
    from archer.intelligence.cve_hunter import CVEHunter

    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {}
    out = []
    while True:
        for attempt in range(TRIES):
            try:
                r = requests.get(NVD_URL, params={**params, "resultsPerPage": PAGE, "startIndex": start},
                                 headers=headers, timeout=90)
                r.raise_for_status()
                body = r.json()
                break
            except (requests.RequestException, ValueError):
                if attempt == TRIES - 1:
                    raise
                time.sleep(_pace() * (attempt + 2))  # a dropped or refused page: wait longer each time
        page = [_trim(CVEHunter.parse_nvd(v["cve"])) for v in body.get("vulnerabilities") or [] if v.get("cve")]
        out += page
        start += PAGE
        if on_page:
            on_page(page, start)
        if start >= body.get("totalResults", 0):
            return out
        time.sleep(_pace())


def _kev() -> Dict[str, Dict]:
    r = requests.get(KEV_URL, timeout=60)
    r.raise_for_status()
    return {v["cveID"]: {"date_added": v.get("dateAdded"), "due": v.get("dueDate"),
                         "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                         "action": v.get("requiredAction")}
            for v in r.json().get("vulnerabilities") or [] if v.get("cveID")}


def _cutoff() -> str:
    return (_now() - timedelta(days=WINDOW_DAYS)).isoformat()[:19]


def _recent(cve: Dict, cutoff: str) -> bool:
    """Published since cutoff, with an ID reserved no earlier than cutoff's year."""
    year = (str(cve.get("cve_id") or "").split("-") + ["", ""])[1]
    return (cve.get("published") or "") >= cutoff and year >= cutoff[:4]


def _in_window(cve: Dict, cutoff: str, hunted: set) -> bool:
    return _recent(cve, cutoff) or cve.get("cve_id") in hunted


def refresh(stacks: Callable[[], Iterable[Iterable[str]]] = lambda: [], research: bool = True) -> Dict:
    """Bring the window up to date, drop what has left it, then pre-research. Returns counts."""
    if not _running.acquire(blocking=False):
        return {"skipped": "a refresh is running"}
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    held = open(CACHE_PATH + ".lock", "a")  # and none in another process (the CLI beside the server)
    try:
        filelock.lock(held, block=False)
    except OSError:
        held.close()
        _running.release()
        return {"skipped": "a refresh is running in another process"}
    _status.update(refreshing=True, error=None)
    try:
        data = _load()
        cves, hunted = dict(data.get("cves") or {}), set(data.get("hunted") or [])
        now = _now()
        start = now - timedelta(days=WINDOW_DAYS)
        last = data.get("last_refresh")
        # A fetch cut short carries on where it was saved; otherwise what changed since the last
        # refresh, or the whole window by publication date
        pending = data.get("pending")
        if pending:
            now = datetime.fromisoformat(pending["as_of"])
        elif last and datetime.fromisoformat(last) > start:
            pending = {"params": {"lastModStartDate": _nvd_date(datetime.fromisoformat(last) - timedelta(hours=1)),
                                  "lastModEndDate": _nvd_date(now)}, "index": 0, "as_of": now.isoformat()}
        else:
            pending = {"params": {"pubStartDate": _nvd_date(start), "pubEndDate": _nvd_date(now)},
                       "index": 0, "as_of": now.isoformat()}
        start = now - timedelta(days=WINDOW_DAYS)
        pages = {"n": 0}

        def keep(page, next_index):
            for cve in page:
                cves[cve["cve_id"]] = {**cves.get(cve["cve_id"], {}), **cve}
            pages["n"] += 1
            if pages["n"] % SAVE_EVERY == 0:
                _commit(cves, hunted, pending={**pending, "index": next_index})

        found = _nvd(pending["params"], start=pending["index"], on_page=keep)
        for cid, c in cves.items():  # cached before products were stored
            if "products" not in c:
                cves[cid] = {**c, "products": products(c)}

        kev = _kev()
        for cid, entry in kev.items():
            if cid in cves:
                cves[cid]["kev"] = entry

        cutoff = start.isoformat()[:19]
        cves = _commit(cves, hunted, last_refresh=now.isoformat(), cutoff=cutoff)
        _status["last_refresh"] = now.isoformat()
        counts = {"cves": len(cves), "kev": sum(bool(c.get("kev")) for c in cves.values()), "fetched": len(found)}
        if research:
            counts["preresearched"] = preresearch(cves, stacks())
        return counts
    except Exception as e:
        _status["error"] = str(e)
        raise
    finally:
        _status["refreshing"] = False
        held.close()
        _running.release()


def _commit(cves: Dict, hunted: set, pending: Optional[Dict] = None, last_refresh: Optional[str] = None,
            cutoff: Optional[str] = None) -> Dict:
    """Save the CVEs: mid-fetch with where to carry on, or finished (the window applied)."""
    with _writing:  # a hunt may have marked a CVE while NVD was being read
        data = _load()
        hunted = hunted | set(data.get("hunted") or [])
        if cutoff:
            cves = {cid: c for cid, c in cves.items() if _in_window(c, cutoff, hunted)}
        data.update(cves=cves, hunted=sorted(hunted), pending=pending)
        if last_refresh:
            data["last_refresh"] = last_refresh
        _save(data)
    return cves


def wanted(cves: Dict[str, Dict], stacks: Iterable[Iterable[str]]) -> List[str]:
    """
    The CVEs to research in advance: KEV, newest first; then those affecting a stack product,
    highest CVSS first (a stack with Linux has some 1,700 kernel CVEs a month, mostly unscored).
    """
    stack = {p for s in stacks for p in s}
    newest = sorted(cves.items(), key=lambda kv: kv[1].get("published") or "", reverse=True)
    kev = [cid for cid, c in newest if c.get("kev")]
    on_stack = [cid for cid, c in newest if not c.get("kev") and stack & set(c.get("products") or products(c))]
    return kev + sorted(on_stack, key=lambda cid: _score(cves[cid]), reverse=True)


def preresearch(cves: Dict[str, Dict], stacks: Iterable[Iterable[str]], limit: int = PRERESEARCH_MAX) -> int:
    """Research the wanted CVEs that aren't researched yet. GitHub's search allows 10 a minute without a token."""
    from archer.intelligence.cve_hunter import CVEHunter

    hunter = CVEHunter()
    done = 0
    for cid in wanted(cves, stacks):
        if done >= limit:
            break
        if hunter._get_cached_research(cid):
            continue
        try:
            hunter.research_cve(cid)
        except Exception as e:
            print(f"CVE pre-research skipped {cid}: {e}")
        done += 1
        time.sleep(2.5 if os.getenv("GITHUB_TOKEN") else 7)
    return done


def record(cve_id: str) -> Optional[Dict]:
    """The cached NVD record for a CVE in the window, or None."""
    return (_load().get("cves") or {}).get(cve_id.upper())


def mark_hunted(cve_ids: Iterable[str]) -> None:
    """A hunted CVE stays past the window: its results still refer to it."""
    with _writing:
        data = _load()
        data["hunted"] = sorted(set(data.get("hunted") or []) | {c.upper() for c in cve_ids})
        _save(data)


def recent(stack: Iterable[str] = (), q: str = "", kev_only: bool = False, stack_only: bool = False,
           min_score: float = 0, offset: int = 0, limit: int = 50) -> Dict:
    """
    The Hunt page's picker: the window's CVEs, newest first, filtered by text (ID, description,
    product), KEV, the user's stack and CVSS. Each says whether it's in the stack and whether
    it has been researched already (its hunt starts at once).
    """
    from archer.intelligence.cve_hunter import CVEHunter
    from archer.intelligence.tech_stack import label

    stack, words, cutoff = set(stack), [w for w in q.lower().split() if w], _cutoff()
    rows = []
    for c in (_load().get("cves") or {}).values():
        if not _recent(c, cutoff):  # a hunted CVE kept for its results
            continue
        hits = stack & set(c.get("products") or [])
        if (kev_only and not c.get("kev")) or (stack_only and not hits) or _score(c) < min_score:
            continue
        text = f"{c.get('cve_id', '')} {c.get('description', '')} {' '.join(c.get('products') or [])}".lower()
        if words and not all(w in text for w in words):
            continue
        rows.append((c, hits))
    rows.sort(key=lambda r: r[0].get("published") or "", reverse=True)
    cache_dir = CVEHunter.cache_location()
    page = [{k: c.get(k) for k in ("cve_id", "published", "description", "cvss_v3", "kev")}
            | {"products": [label(p) for p in c.get("products") or []][:4],
               "on_stack": [label(p) for p in hits],
               "researched": os.path.exists(os.path.join(cache_dir, f"{c.get('cve_id')}.json"))}
            for c, hits in rows[offset:offset + limit]]
    return {"cves": page, "total": len(rows), "offset": offset, "limit": limit}


def status() -> Dict:
    return dict(_status, last_refresh=_status["last_refresh"] or _load().get("last_refresh"))


def keep_current(stacks: Callable[[], Iterable[Iterable[str]]], poll: int = 3600) -> None:
    """Refresh at start and whenever the cache is a day old, in the background."""
    def loop():
        first = True
        while True:
            last = _load().get("last_refresh")
            try:
                if not last or time.time() - datetime.fromisoformat(last).timestamp() >= REFRESH_EVERY:
                    print(f"Recent CVEs refreshed: {refresh(stacks)}")
                elif first:  # a restart cut the last pre-research short: carry on (researched ones are skipped)
                    print(f"Recent CVEs pre-researched: {preresearch(_load().get('cves') or {}, stacks())}")
            except Exception as e:
                print(f"Recent CVEs not refreshed: {e}")
            first = False
            time.sleep(poll)

    threading.Thread(target=loop, daemon=True, name="cve-feed").start()


if __name__ == "__main__":
    print(refresh())

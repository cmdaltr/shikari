"""
Living-off-the-land datasets: LOLBAS, LOLRMM and LOLDrivers.

Fetched as each project's JSON (standard library only, at most daily) into data/repos/lol/,
then compacted into data/cache/lol_index.json. During OSINT Enhancement, enrich() adds
what a dataset documents about a binary, RMM tool or driver that the group's own
indicators or procedure already name, and only for the technique being built:

  LOLBAS      certutil.exe named for T1105 -> its documented T1105 switches ("certutil.exe -urlcache")
  LOLRMM      AnyDesk named -> its process names, domains and registry keys
  LOLDrivers  RTCore64.sys named -> the driver file name (hashes go to the references)

Nothing is added for tools the group isn't seen using, so a detection keeps the group's
tradecraft rather than every binary ATT&CK files under the technique.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from pathlib import Path

from ..config import DATA_DIR, OSINT_REPOS_DIR

SOURCES = {
    "lolbas": {"url": "https://lolbas-project.github.io/api/lolbas.json", "site": "https://lolbas-project.github.io",
               "name": "LOLBAS"},
    "lolrmm": {"url": "https://lolrmm.io/api/rmm_tools.json", "site": "https://lolrmm.io", "name": "LOLRMM"},
    "loldrivers": {"url": "https://www.loldrivers.io/api/drivers.json", "site": "https://www.loldrivers.io",
                   "name": "LOLDrivers"},
}
LOL_DIR = Path(OSINT_REPOS_DIR) / "lol"
INDEX_PATH = Path(DATA_DIR) / "cache" / "lol_index.json"
UPDATE_INTERVAL = 24 * 3600

# Bare names (no extension) that are ordinary words or too short to match safely in prose
_STOP = {"change", "cipher", "control", "expand", "explorer", "finger", "logger", "outlook", "pester",
         "remote", "replace", "squirrel", "tracker", "update",
         # LOLRMM tools named after words: "integrity level", "executed remotely"
         "level", "remotely", "roster", "synergy", "overlord", "centurion", "basecamp"}
_PLACEHOLDER = re.compile(r"\{[^}]*\}")
_SWITCH = re.compile(r"^[-/][A-Za-z][\w:-]{2,}$")


# ---------- fetch ----------

def _path(name: str) -> Path:
    return LOL_DIR / f"{name}.json"


def needs_update(name: str) -> bool:
    try:
        return time.time() - _path(name).stat().st_mtime > UPDATE_INTERVAL
    except OSError:
        return True


def update(force: bool = False, timeout: int = 120) -> dict:
    """Fetch each dataset that's due. Returns {name: "ready" | "failed: <why>"}."""
    LOL_DIR.mkdir(parents=True, exist_ok=True)
    status = {}
    for name, src in SOURCES.items():
        if not force and not needs_update(name):
            status[name] = "ready"
            continue
        try:
            req = urllib.request.Request(src["url"], headers={"User-Agent": "Shikari"})
            with urllib.request.urlopen(req, timeout=timeout) as res:
                data = res.read()
            json.loads(data)  # don't replace a good copy with a broken one
            tmp = _path(name).with_suffix(".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, _path(name))
            status[name] = "ready"
        except Exception as e:  # offline: keep the copy we have
            status[name] = "ready" if _path(name).exists() else f"failed: {e}"
    return status


def updated(name: str) -> str | None:
    try:
        return time.strftime("%Y-%m-%d", time.localtime(_path(name).stat().st_mtime))
    except OSError:
        return None


# ---------- index ----------

def _phrase(command: str, binary: str) -> str | None:
    """'C:\\...\\certutil.exe -urlcache -f {REMOTEURL} {PATH}' -> 'certutil.exe -urlcache'."""
    tokens = _PLACEHOLDER.sub(" ", command).split()
    switch = next((t for t in tokens[1:] if _SWITCH.match(t)), None)
    return f"{binary} {switch.rstrip(':')}" if switch else None


def _keys(filename: str) -> list[str]:
    name = filename.lower()
    stem = os.path.splitext(name)[0]
    return [name] + ([stem] if len(stem) >= 6 and stem not in _STOP else [])


def _load(name: str):
    try:
        return json.loads(_path(name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def build_index() -> dict:
    index = {"built": time.strftime("%Y-%m-%dT%H:%M:%S"), "lolbas": {}, "lolrmm": {}, "loldrivers": {},
             "updated": {n: updated(n) for n in SOURCES}}

    for entry in _load("lolbas"):
        binary = entry.get("Name", "")
        if not binary:
            continue
        techniques: dict[str, list[str]] = {}
        for cmd in entry.get("Commands") or []:
            tid, phrase = (cmd.get("MitreID") or "").strip(), _phrase(cmd.get("Command") or "", binary)
            if not tid:
                continue
            # A technique with no switch to quote (mshta.exe file.hta) still counts: the binary is the indicator
            phrases = techniques.setdefault(tid, [])
            if phrase and phrase not in phrases:
                phrases.append(phrase)
        record = {"name": binary, "url": entry.get("url") or SOURCES["lolbas"]["site"],
                  "paths": [p.get("Path") for p in entry.get("Full_Path") or [] if p.get("Path")][:6],
                  "techniques": techniques}
        for key in _keys(binary):
            index["lolbas"].setdefault(key, record)

    for tool in _load("lolrmm"):
        details, artifacts = tool.get("Details") or {}, tool.get("Artifacts") or {}
        pe = details.get("PEMetadata") or []
        pe = [pe] if isinstance(pe, dict) else pe
        processes = sorted({p.get("Filename") or p.get("OriginalFileName") for p in pe
                            if isinstance(p, dict) and (p.get("Filename") or p.get("OriginalFileName"))})
        domains = sorted({d for n in artifacts.get("Network") or [] for d in (n.get("Domains") or [])
                          if d and "*" not in d})[:15]
        # Only keys that name the tool, without wildcards: LOLRMM also lists shared keys
        # (Lsa\Authentication Packages, bare CLSIDs) that would match far more than the tool
        words = [w for w in re.split(r"[^a-z0-9]+", (tool.get("Name") or "").lower()) if len(w) >= 4]
        registry = sorted({r.get("Path") for r in artifacts.get("Registry") or []
                           if r.get("Path") and "*" not in r["Path"]
                           and any(w in r["Path"].lower() for w in words)})[:10]
        if not (processes or domains):
            continue
        slug = re.sub(r"[^a-z0-9]+", "_", tool.get("Name", "").lower()).strip("_")
        record = {"name": tool.get("Name"), "url": f"{SOURCES['lolrmm']['site']}/tools/{slug}",
                  "processes": processes, "domains": domains, "registry": registry}
        name = (tool.get("Name") or "").lower()
        for key in ([name] if len(name) >= 5 and name not in _STOP else []) + [p.lower() for p in processes]:
            index["lolrmm"].setdefault(key, record)

    for driver in _load("loldrivers"):
        samples = driver.get("KnownVulnerableSamples") or []
        files = {s.get("Filename") for s in samples if s.get("Filename")} | set(driver.get("Tags") or [])
        sha256 = sorted({s.get("SHA256") for s in samples if s.get("SHA256")})[:20]
        for filename in files:
            if not filename.lower().endswith(".sys"):
                continue
            index["loldrivers"].setdefault(filename.lower(), {
                "name": filename, "category": driver.get("Category"), "mitre": driver.get("MitreID"),
                "url": f"{SOURCES['loldrivers']['site']}/drivers/{driver.get('Id', '')}/", "sha256": sha256})

    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = INDEX_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(index, separators=(",", ":")), encoding="utf-8")
    os.replace(tmp, INDEX_PATH)
    _cache["mtime"] = None
    return index


_cache: dict = {"mtime": None, "index": None}


def load_index() -> dict | None:
    try:
        mtime = INDEX_PATH.stat().st_mtime
    except OSError:
        return None
    if _cache["mtime"] != mtime:
        try:
            _cache.update(index=json.loads(INDEX_PATH.read_text(encoding="utf-8")), mtime=mtime)
        except (OSError, ValueError):
            return None
    return _cache["index"]


# ---------- enrich ----------

def _same_technique(a: str, b: str) -> bool:
    """T1218 and T1218.011 are the same family; T1218 and T1105 aren't."""
    return a == b or a.split(".")[0] == b.split(".")[0]


def _named(key: str, text: str) -> bool:
    return re.search(r"(?<![\w.\\/-])" + re.escape(key) + r"(?![\w-])", text) is not None


def enrich(identifiers: dict, technique_id: str, procedure_text: str = "") -> tuple[dict, list[dict]]:
    """What the datasets document about the tools this technique's indicators and procedure
    name. Returns ({indicator type: [new values]}, [{source, name, url, detail}])."""
    index = load_index()
    if not index or not technique_id:
        return {}, []
    values = [str(v) for vs in identifiers.values() if isinstance(vs, list) for v in vs]
    text = " ".join(values + [procedure_text or ""]).lower()
    have = {str(v).lower() for v in values}
    added: dict[str, list[str]] = {}
    refs: list[dict] = []
    seen = set()

    def add(kind, items):
        for item in items:
            if item and item.lower() not in have:
                added.setdefault(kind, []).append(item)
                have.add(item.lower())

    for key, rec in index.get("lolbas", {}).items():
        if rec["name"] in seen or key in _STOP or not _named(key, text):
            continue
        matching = [tid for tid in rec["techniques"] if _same_technique(tid, technique_id)]
        if not matching:
            continue
        phrases = [p for tid in matching for p in rec["techniques"][tid]]
        seen.add(rec["name"])
        add("sw", [rec["name"]])
        add("cmd", phrases[:6])
        refs.append({"source": "LOLBAS", "name": rec["name"], "url": rec["url"],
                     "detail": f"documented for {', '.join(sorted(matching))}"})

    for key, rec in index.get("lolrmm", {}).items():
        # Checked here too: an index built before a word joined _STOP still has it
        if rec["name"] in seen or key in _STOP or not _named(key, text):
            continue
        seen.add(rec["name"])
        add("sw", rec["processes"])
        add("network", rec["domains"])
        add("reg", rec["registry"])
        refs.append({"source": "LOLRMM", "name": rec["name"], "url": rec["url"],
                     "detail": f"{len(rec['processes'])} process(es), {len(rec['domains'])} domain(s)"})

    for key, rec in index.get("loldrivers", {}).items():
        if rec["name"] in seen or not _named(key, text):
            continue
        seen.add(rec["name"])
        add("sw", [rec["name"]])
        refs.append({"source": "LOLDrivers", "name": rec["name"], "url": rec["url"],
                     "detail": f"{rec.get('category') or 'driver'}; SHA256: {', '.join(rec['sha256'][:3])}"
                               + (f" (+{len(rec['sha256']) - 3})" if len(rec["sha256"]) > 3 else "")})
    return added, refs

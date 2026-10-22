"""
IOC sweep: one detection per SIEM for a report's atomic indicators.

A threat report's domains, IPs and hashes aren't tied to a technique, so they are
swept for together rather than stamped onto every technique's detection.
"""

import ipaddress
import json
import os
import re
from datetime import date, timedelta
from functools import lru_cache
from typing import Dict, List, Optional

from archer.build.indicator_hygiene import clean_indicator
from archer.build.secops import _re_literal
from archer.build.udm import from_yaral
from archer.build.severity import RISK_SCORE

_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HASH_KIND = {64: "sha256", 40: "sha1", 32: "md5"}
_FANG = re.compile(r"\s*(?:\[\.\]|\(\.\)|\[dot\]|\(dot\))\s*", re.I)
# Reports write lookalike-domain patterns with a stand-in for the victim's name
# ("targetsname-sso[.]com"): a pattern to hunt, not a literal domain
_PLACEHOLDER_LABEL = re.compile(r"(?:target|victim|your|client|company|org)s?(?:name|company|org|domain)?", re.I)


# A path segment a report blanked out or generalised: c:\users\[redacted]\downloads\z.exe
_REDACTED_SEGMENT = re.compile(
    r"^(?:\[[^\]]*\]|<[^>]*>|\{[^}]*\}|%[a-z_]+%|\*|x{3,}|redacted|username|user)$", re.I)
# The operating system's own folders. A file named there is usually a system file that runs
# on every host, but malware lands there too (a copy of RedSun as System32\TieringEngineService.exe):
# these paths are swept for being written, not for running (kind "system_file")
_SYSTEM_DIR = re.compile(r"^(?:[a-z]:|%(?:windir|systemroot)%)\\windows\\(?:system32|syswow64|winsxs|servicing)\\|"
                         r"^%(?:windir|systemroot)%\\(?:system32|syswow64)\\|"
                         r"^/(?:system|usr/(?:s?bin|lib|libexec)|s?bin|lib|lib64|library/apple)/", re.I)
KNOWN_GOOD_FILES = (os.path.join(os.path.dirname(__file__), "..", "mappings", "known_good.json"),
                    os.path.join("bespoke", "mappings", "known_good.json"))
# Days an IP or domain stays in a sweep after Archer first saw it; hashes don't expire
IOC_EXPIRY_DAYS = {"ip": 90, "domain": 90, "domain_pattern": 90}
from archer.config import DATA_DIR  # noqa: E402

IOC_DATES_DIR = os.path.join(DATA_DIR, "ioc_dates")


@lru_cache(maxsize=1)
def known_good() -> Dict[str, set]:
    """Shipped known-good values, plus bespoke/mappings/known_good.json if it exists."""
    out: Dict[str, set] = {"first_party_domains": set(), "shared_hosting": set(), "ips": set(), "hashes": set()}
    for path in KNOWN_GOOD_FILES:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        for key in out:
            entry = data.get(key) or {}
            out[key] |= {str(v).lower() for v in (entry.get("values") if isinstance(entry, dict) else entry) or []}
    return out


def _known_good_domain(d: str) -> bool:
    kg = known_good()
    if d in kg["shared_hosting"]:
        return True
    labels = d.split(".")
    return any(".".join(labels[i:]) in kg["first_party_domains"] for i in range(len(labels) - 1))


def _bare_system_binary(name: str) -> bool:
    """A file name alone that LOLBAS lists (comsvcs.dll): it matches every host that loads it."""
    if "\\" in name or "/" in name:
        return False
    try:
        from archer.build.lol import load_index
        lolbas = (load_index() or {}).get("lolbas") or {}
    except Exception:
        return False
    return name.lower() in lolbas


def _file_pattern(path: str) -> Optional[str]:
    """A regex for a path with redacted segments (any one segment there), or None."""
    parts = re.split(r"[\\/]", path)
    if not any(_REDACTED_SEGMENT.match(p) for p in parts):
        return None
    sep = r"[\\/]"
    return "^" + sep.join(r"[^\\/]+" if _REDACTED_SEGMENT.match(p) else re.escape(p) for p in parts) + "$"


def _refang(value: str) -> str:
    v = _FANG.sub(".", str(value).strip())
    return re.sub(r"^hxxp", "http", v, flags=re.I).replace("[:]", ":")


def clean_report_iocs(iocs: Dict) -> Dict[str, List[str]]:
    """Refanged, validated atomic IOCs: domain, ip (public only), sha256/sha1/md5, file."""
    out: Dict[str, List[str]] = {"domain": [], "domain_pattern": [], "ip": [], "sha256": [], "sha1": [], "md5": [],
                                 "file": [], "file_pattern": [], "system_file": []}
    kg = known_good()

    def add(kind, value):
        if value and value not in out[kind]:
            out[kind].append(value)

    raw_domains = [str(d) for d in (iocs or {}).get("domain", []) or []]
    # When a report defangs its indicators, plain domains are its citations and links
    defanged = [d for d in raw_domains if _FANG.search(d)]
    out["domain_pattern"] = []
    for raw in defanged or raw_domains:
        d = _refang(raw).lower().strip(".")
        d = re.sub(r"^https?://", "", d).split("/")[0]
        if not _DOMAIN.match(d):
            continue
        labels = d.split(".")
        if any(_PLACEHOLDER_LABEL.fullmatch(part) for lab in labels[:-1] for part in lab.split("-")):
            pattern = r"\.".join(
                "-".join(r"[a-z0-9-]+" if _PLACEHOLDER_LABEL.fullmatch(part) else re.escape(part)
                         for part in lab.split("-"))
                for lab in labels)
            add("domain_pattern", pattern)
        elif not _known_good_domain(d):
            add("domain", d)
    for raw in (iocs or {}).get("ip", []) or []:
        try:
            ip = ipaddress.ip_address(_refang(raw))
        except ValueError:
            continue
        if ip.is_global and str(ip) not in kg["ips"]:
            add("ip", str(ip))
    for raw in (iocs or {}).get("hash", []) or []:
        h = str(raw).strip().lower()
        if re.fullmatch(r"[0-9a-f]+", h) and len(h) in _HASH_KIND and h not in kg["hashes"]:
            add(_HASH_KIND[len(h)], h)
    for raw in (iocs or {}).get("file", []) or []:
        # Before cleaning, which strips a <user> placeholder as markup
        pattern = _file_pattern(str(raw).strip())
        if pattern:
            add("file_pattern", pattern)
            continue
        f = clean_indicator(raw)
        # URL fragments picked up as files ("//www.example.com/page.html")
        if not f or f.startswith("//") or "://" in f or f.lower().startswith("www."):
            continue
        if _SYSTEM_DIR.match(f):
            add("system_file", f)
        elif not _bare_system_binary(f):
            add("file", f)
    return {k: v for k, v in out.items() if v}


def _kql_list(values: List[str]) -> str:
    return "dynamic([" + ", ".join('"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"' for v in values) + "])"


def mde_sweep(iocs: Dict[str, List[str]]) -> Optional[str]:
    lets, parts = [], []
    for kind in ("domain", "ip", "sha256", "sha1", "md5", "file", "system_file"):  # *_pattern kinds are inlined
        if iocs.get(kind):
            lets.append(f"let ioc_{kind} = {_kql_list(iocs[kind])};")
    network = []
    if iocs.get("domain"):
        network.append("RemoteUrl has_any (ioc_domain)")
    for pattern in iocs.get("domain_pattern", []):
        network.append(f'RemoteUrl matches regex @"(?i)(^|[./]){pattern}($|[/:])"')
    if iocs.get("ip"):
        network.append("RemoteIP in (ioc_ip)")
    if network:
        parts.append(f"(DeviceNetworkEvents | where {' or '.join(network)})")
    hashes = [f"{k.upper()} in (ioc_{k})" for k in ("sha256", "sha1", "md5") if iocs.get(k)]
    if iocs.get("file"):
        hashes.append("FileName in~ (ioc_file) or FolderPath has_any (ioc_file)")
    # FolderPath holds the file name too in DeviceFileEvents and DeviceProcessEvents
    hashes += [f'FolderPath matches regex @"(?i){p.replace(chr(34), chr(34) * 2)}"' for p in iocs.get("file_pattern", [])]
    if hashes:
        cond = " or ".join(hashes)
        parts.append(f"(DeviceFileEvents | where {cond})")
        parts.append(f"(DeviceProcessEvents | where {cond})")
    # A system file is in the sweep for being written: the genuine one runs everywhere
    if iocs.get("system_file"):
        parts.append('(DeviceFileEvents | where ActionType in ("FileCreated", "FileModified", "FileRenamed")'
                     ' and FolderPath in~ (ioc_system_file))')
    if not parts:
        return None
    union = parts[0] if len(parts) == 1 else "union\n    " + ",\n    ".join(parts)
    # Project only columns the queried tables have: a network-only sweep has no
    # FileName/FolderPath/SHA256 and MDE refuses the query ("Failed to resolve column")
    columns = ["Timestamp", "DeviceName", "ActionType"]
    if network:
        columns += ["RemoteUrl", "RemoteIP"]
    if hashes or iocs.get("system_file"):
        columns += ["FileName", "FolderPath", "SHA256"]
    columns.append("InitiatingProcessAccountName")
    return "\n".join(lets + [union, "| project " + ", ".join(columns)])


def secops_sweep(iocs: Dict[str, List[str]], label: str) -> Optional[str]:
    alts = []
    for d in iocs.get("domain", []):
        pat = r"(^|\.)" + _re_literal(d) + "$"
        alts.append(f"re.regex($e.network.dns.questions.name, `{pat}`) nocase")
        alts.append(f"re.regex($e.target.hostname, `{pat}`) nocase")
    for pattern in iocs.get("domain_pattern", []):
        alts.append(f"re.regex($e.network.dns.questions.name, `(^|\\.){pattern}$`) nocase")
        alts.append(f"re.regex($e.target.hostname, `(^|\\.){pattern}$`) nocase")
    alts += [f'$e.target.ip = "{ip}"' for ip in iocs.get("ip", [])]
    for kind in ("sha256", "sha1", "md5"):
        for h in iocs.get(kind, []):
            alts.append(f'$e.target.file.{kind} = "{h}" nocase')
            alts.append(f'$e.target.process.file.{kind} = "{h}" nocase')
    for f in iocs.get("file", []):
        lit = _re_literal(f)
        if lit:
            alts.append(f"re.regex($e.target.file.full_path, `{lit}`) nocase")
    for p in iocs.get("file_pattern", []):
        if "`" not in p:
            alts.append(f"re.regex($e.target.file.full_path, `{p}`) nocase")
            alts.append(f"re.regex($e.target.process.file.full_path, `{p}`) nocase")
    # Written, not run: the genuine system file runs everywhere
    for f in iocs.get("system_file", []):
        lit = _re_literal(f)
        if lit:
            alts.append(f'(($e.metadata.event_type = "FILE_CREATION" or $e.metadata.event_type = "FILE_MODIFICATION")'
                        f" and re.regex($e.target.file.full_path, `^{lit}$`) nocase)")
    if not alts:
        return None
    name = "archer_ioc_sweep_" + re.sub(r"\W+", "_", label).strip("_").lower()
    # Built as a single-event rule, written as the UDM search it amounts to (archer.build.udm)
    return from_yaral(f"""rule {name} {{
  meta:
    author = "Archer Detection Engineering"
    description = "IOC sweep for {label.replace('"', "'")}"
    severity = "HIGH"

  events:
    ({" or ".join(alts)})

  outcome:
    $risk_score = {RISK_SCORE["High"]}
    $hostname = $e.principal.hostname
    $user = $e.principal.user.userid
    $target_host = $e.target.hostname
    $file = $e.target.file.full_path
    $command_line = $e.target.process.command_line

  condition:
    $e
}}""")


def apply_expiry(group_name: str, clean: Dict[str, List[str]], regenerate: bool,
                 today: Optional[date] = None) -> Optional[date]:
    """
    Record when each IP and domain was first seen for this run (data/ioc_dates), and on
    Regenerate drop those past IOC_EXPIRY_DAYS. Changes clean in place; returns the
    earliest expiry left, or None.
    """
    today = today or date.today()
    path = os.path.join(IOC_DATES_DIR, re.sub(r"[^A-Za-z0-9]+", "", group_name) + ".json")
    try:
        with open(path, encoding="utf-8") as fh:
            first_seen = json.load(fh)
    except (OSError, ValueError):
        first_seen = {}
    earliest = None
    for kind, days in IOC_EXPIRY_DAYS.items():
        kept = []
        for v in clean.get(kind, []):
            seen = date.fromisoformat(first_seen.setdefault(f"{kind}:{v}", today.isoformat()))
            expires = seen + timedelta(days=days)
            if regenerate and expires < today:
                continue
            kept.append(v)
            earliest = min(earliest, expires) if earliest else expires
        if kind in clean:
            clean[kind] = kept
    for kind in [k for k, v in clean.items() if not v]:
        del clean[kind]
    os.makedirs(IOC_DATES_DIR, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(first_seen, fh, indent=1, sort_keys=True)
    return earliest


def write_ioc_sweeps(group_name: str, iocs: Dict, source: str, generate_dir: str,
                     siems=("secops", "mde"), excluded_vendors=None, mentions=None) -> List[str]:
    """
    Write one IOC-sweep detection YAML per SIEM; returns the paths written.

    mentions (ioc_flow.ioc_mentions over the report text) places each IOC in the
    IOC flow shown on the results page; without it the flow falls back to IOC type.
    """
    from archer.build import run_files
    from archer.build.ioc_flow import build_ioc_flow, save_ioc_flow
    from archer.build.yaml import LANGUAGE_SUFFIX, file_state, write_yaml

    clean = clean_report_iocs(iocs)
    expires = apply_expiry(group_name, clean, regenerate=run_files.regenerating(group_name)) if clean else None
    if not clean:
        return []
    save_ioc_flow(group_name, build_ioc_flow(clean, mentions, source))
    excluded = {v.lower() for v in excluded_vendors or []}
    safe = re.sub(r"[^A-Za-z0-9]+", "", group_name)
    desc = f"Atomic indicators from {source}: " + "; ".join(f"{len(v)} {k}" for k, v in clean.items())
    if expires:
        desc += (f". IPs and domains expire {IOC_EXPIRY_DAYS['ip']} days after Archer first saw them, the first on"
                 f" {expires.isoformat()}; Regenerate drops expired ones. Hashes and files don't expire")
    if clean.get("system_file"):
        desc += ". Files in system folders are swept for being written, not run"
    written = []
    builders = {
        "secops": ("GoogleSecOps", "NETWORK_DNS", "googlesecops", lambda: secops_sweep(clean, group_name)),
        "mde": ("MicrosoftThreatProtection", "DeviceNetworkEvents", "mde", lambda: mde_sweep(clean)),
    }
    for siem in siems:
        if siem not in builders:
            continue
        connector, datatype, vendor_key, build = builders[siem]
        if vendor_key in excluded:
            continue
        query = build()
        if not query:
            continue
        path = os.path.join(generate_dir, f"IOCSweep{safe}_{LANGUAGE_SUFFIX[connector]}.yaml")
        # A sweep is rewritten every run with the report's current IOCs, unless someone
        # edited it by hand (Regenerate replaces it anyway)
        if os.path.exists(path) and file_state(path)["edited"] and not run_files.regenerating(group_name):
            print(f"  ✋ Kept {os.path.basename(path)}: its query was edited by hand (Regenerate replaces it)")
            run_files.note(path, group_name)
            run_files.kept(path, group_name)
            written.append(path)
            continue
        # The name is substituted unquoted into the YAML template: no ": " allowed
        title = "IOC Sweep - " + re.sub(r"\s*:\s*", " - ", group_name)
        write_yaml(path, title, "IOC-SWEEP", desc, connector, ["IOC Sweep"],
                   group_name, query, datatype=datatype, indicators=clean)
        written.append(path)
    return written

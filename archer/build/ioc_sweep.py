"""
IOC sweep: one detection per SIEM for a report's atomic indicators.

A threat report's domains, IPs and hashes aren't tied to a technique, so they are
swept for together rather than stamped onto every technique's detection.
"""

import ipaddress
import os
import re
from typing import Dict, List, Optional

from archer.build.indicator_hygiene import clean_indicator
from archer.build.secops import _re_literal

_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HASH_KIND = {64: "sha256", 40: "sha1", 32: "md5"}
_FANG = re.compile(r"\s*(?:\[\.\]|\(\.\)|\[dot\]|\(dot\))\s*", re.I)
# Reports write lookalike-domain patterns with a stand-in for the victim's name
# ("targetsname-sso[.]com"): a pattern to hunt, not a literal domain
_PLACEHOLDER_LABEL = re.compile(r"(?:target|victim|your|client|company|org)s?(?:name|company|org|domain)?", re.I)


def _refang(value: str) -> str:
    v = _FANG.sub(".", str(value).strip())
    return re.sub(r"^hxxp", "http", v, flags=re.I).replace("[:]", ":")


def clean_report_iocs(iocs: Dict) -> Dict[str, List[str]]:
    """Refanged, validated atomic IOCs: domain, ip (public only), sha256/sha1/md5, file."""
    out: Dict[str, List[str]] = {"domain": [], "domain_pattern": [], "ip": [], "sha256": [], "sha1": [], "md5": [], "file": []}

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
        else:
            add("domain", d)
    for raw in (iocs or {}).get("ip", []) or []:
        try:
            ip = ipaddress.ip_address(_refang(raw))
        except ValueError:
            continue
        if ip.is_global:
            add("ip", str(ip))
    for raw in (iocs or {}).get("hash", []) or []:
        h = str(raw).strip().lower()
        if re.fullmatch(r"[0-9a-f]+", h) and len(h) in _HASH_KIND:
            add(_HASH_KIND[len(h)], h)
    for raw in (iocs or {}).get("file", []) or []:
        f = clean_indicator(raw)
        # URL fragments picked up as files ("//www.example.com/page.html")
        if f and not f.startswith("//") and "://" not in f and not f.lower().startswith("www."):
            add("file", f)
    return {k: v for k, v in out.items() if v}


def _kql_list(values: List[str]) -> str:
    return "dynamic([" + ", ".join('"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"' for v in values) + "])"


def mde_sweep(iocs: Dict[str, List[str]]) -> Optional[str]:
    lets, parts = [], []
    for kind in ("domain", "ip", "sha256", "sha1", "md5", "file"):  # domain_pattern is inlined as regex
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
    if hashes:
        cond = " or ".join(hashes)
        parts.append(f"(DeviceFileEvents | where {cond})")
        parts.append(f"(DeviceProcessEvents | where {cond})")
    if not parts:
        return None
    union = parts[0] if len(parts) == 1 else "union\n    " + ",\n    ".join(parts)
    return "\n".join(lets + [union,
        "| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, FileName, FolderPath, SHA256, InitiatingProcessAccountName"])


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
    if not alts:
        return None
    name = "archer_ioc_sweep_" + re.sub(r"\W+", "_", label).strip("_").lower()
    return f"""rule {name} {{
  meta:
    author = "Archer Detection Engineering"
    description = "IOC sweep for {label.replace('"', "'")}"
    severity = "HIGH"

  events:
    ({" or ".join(alts)})

  condition:
    $e
}}"""


def write_ioc_sweeps(group_name: str, iocs: Dict, source: str, generate_dir: str,
                     siems=("secops", "mde"), excluded_vendors=None, mentions=None) -> List[str]:
    """
    Write one IOC-sweep detection YAML per SIEM; returns the paths written.

    mentions (ioc_flow.ioc_mentions over the report text) places each IOC in the
    IOC flow shown on the results page; without it the flow falls back to IOC type.
    """
    from archer.build.ioc_flow import build_ioc_flow, save_ioc_flow
    from archer.build.yaml import write_yaml

    clean = clean_report_iocs(iocs)
    if not clean:
        return []
    save_ioc_flow(group_name, build_ioc_flow(clean, mentions, source))
    excluded = {v.lower() for v in excluded_vendors or []}
    safe = re.sub(r"[^A-Za-z0-9]+", "", group_name)
    desc = f"Atomic indicators from {source}: " + "; ".join(f"{len(v)} {k}" for k, v in clean.items())
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
        path = os.path.join(generate_dir, f"IOCSweep{safe}_{connector}.yaml")
        # The name is substituted unquoted into the YAML template: no ": " allowed
        title = "IOC Sweep - " + re.sub(r"\s*:\s*", " - ", group_name)
        write_yaml(path, title, "IOC-SWEEP", desc, connector, ["IOC Sweep"],
                   group_name, query, datatype=datatype, indicators=clean)
        written.append(path)
    return written

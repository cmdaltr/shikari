"""
Passive network enrichment for the organisation exposure map: from an org's resolved IPs and
its domain, work out the ASNs, announced prefixes (the IP ranges), hosting countries and mail
exchangers, plus any org-level breach metadata — all from public sources, no credentials.

ASN/prefix/country come from Team Cymru's IP-to-ASN DNS service (free, keyless, passive): a TXT
lookup of a reversed IP under origin.asn.cymru.com gives the origin ASN, BGP prefix, country and
registry; AS<n>.asn.cymru.com gives the AS name. Breach *metadata* (names, dates, counts) for the
domain comes from HIBP's public breaches endpoint — never account data.

Everything here is best-effort: offline, rate-limited or missing data yields empty results, never
an exception that stops a profile.
"""

import ipaddress
import os
from typing import Dict, List, Optional

import dns.resolver
import requests

_UA = "Archer-OSINT/1.0 (attack-surface profiling)"
_TIMEOUT = 3.0
_asn_name_cache: Dict[str, str] = {}


def _txt(name: str) -> List[str]:
    try:
        r = dns.resolver.resolve(name, "TXT", lifetime=_TIMEOUT)
        return [b"".join(rd.strings).decode("utf-8", "replace") if hasattr(rd, "strings")
                else str(rd).strip('"') for rd in r]
    except Exception:
        return []


def _cymru_name(asn: str) -> str:
    if asn in _asn_name_cache:
        return _asn_name_cache[asn]
    name = ""
    for rec in _txt(f"AS{asn}.asn.cymru.com"):
        # "15169 | US | arin | 2000-03-30 | GOOGLE, US"
        parts = [p.strip() for p in rec.split("|")]
        if len(parts) >= 5:
            name = parts[4]
            break
    _asn_name_cache[asn] = name
    return name


def _reverse_query(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def asn_lookup(ip: str) -> Optional[Dict[str, str]]:
    """ASN, announced prefix, country and AS name for one IP, via Team Cymru. None if unresolved."""
    query = _reverse_query(ip)
    if not query:
        return None
    for rec in _txt(query):
        # "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"  (ASN field may list several, space-separated)
        parts = [p.strip() for p in rec.split("|")]
        if len(parts) < 3 or not parts[0]:
            continue
        asn = parts[0].split()[0]
        return {"ip": ip, "asn": asn, "prefix": parts[1], "country": parts[2],
                "registry": parts[3] if len(parts) > 3 else "", "as_name": _cymru_name(asn)}
    return None


def enrich_ips(ips: List[str]) -> Dict[str, object]:
    """Per-IP ASN/prefix/country, plus de-duplicated ASNs, prefixes and hosting countries."""
    per_ip, asns, prefixes, countries = [], {}, set(), set()
    for ip in ips:
        info = asn_lookup(ip)
        if not info:
            continue
        per_ip.append(info)
        if info["prefix"]:
            prefixes.add(info["prefix"])
        if info["country"]:
            countries.add(info["country"])
        if info["asn"]:
            asns.setdefault(info["asn"], info["as_name"])
    return {
        "per_ip": per_ip,
        "asns": [{"asn": a, "as_name": n} for a, n in sorted(asns.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0)],
        "prefixes": sorted(prefixes),
        "hosting_countries": sorted(countries),
    }


def mx_records(domain: str) -> List[Dict[str, object]]:
    """Mail exchangers for the domain, lowest preference (highest priority) first."""
    out = []
    try:
        for rd in dns.resolver.resolve(domain, "MX", lifetime=_TIMEOUT):
            host = str(rd.exchange).rstrip(".").lower()
            if host:
                out.append({"host": host, "preference": int(rd.preference)})
    except Exception:
        return []
    return sorted(out, key=lambda m: m["preference"])


def mail_provider(mx: List[Dict[str, object]]) -> str:
    """Name the mail provider from the MX hosts, where it's an obvious one."""
    joined = " ".join(m["host"] for m in mx)
    for needle, name in (("google", "Google Workspace"), ("outlook", "Microsoft 365"),
                         ("microsoft", "Microsoft 365"), ("protonmail", "Proton"), ("proton.me", "Proton"),
                         ("proofpoint", "Proofpoint"), ("mimecast", "Mimecast"), ("barracuda", "Barracuda"),
                         ("zoho", "Zoho"), ("fastmail", "Fastmail"), ("amazonaws", "Amazon SES")):
        if needle in joined:
            return name
    return ""


def breach_metadata(domain: str) -> Dict[str, object]:
    """
    Org-level breach *metadata* from HIBP — breaches whose breached site is this domain. Names,
    dates and counts only, never accounts or credentials. Keyless; a key (HIBP_API_KEY) is sent
    if set. Always returns a link-out; breaches is empty when offline or none are recorded.
    """
    link = f"https://haveibeenpwned.com/DomainSearch?Domain={domain}"
    headers = {"User-Agent": _UA}
    key = os.environ.get("HIBP_API_KEY")
    if key:
        headers["hibp-api-key"] = key
    breaches = []
    try:
        resp = requests.get("https://haveibeenpwned.com/api/v3/breaches",
                            params={"Domain": domain}, headers=headers, timeout=_TIMEOUT)
        if resp.status_code == 200:
            for b in resp.json():
                breaches.append({"name": b.get("Name"), "title": b.get("Title") or b.get("Name"),
                                 "date": b.get("BreachDate"), "pwn_count": b.get("PwnCount"),
                                 "verified": bool(b.get("IsVerified"))})
            breaches.sort(key=lambda b: b.get("date") or "", reverse=True)
    except Exception:
        pass
    return {"lookup_url": link, "breaches": breaches, "count": len(breaches)}

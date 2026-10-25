"""
Organisation exposure map: what profiling a domain unearthed from public sources, and how each
piece links back to the domain — in the same card-and-link style as the attack anatomy.

Built purely from a stored company profile (archer.intelligence.company_profiler), no AI. The point
is to show what a threat actor can see before they act: the domain resolves to IPs, those sit in
ASNs and announced ranges hosted in some country, mail flows through MX, certificate transparency
and Shodan expose subdomains and services, and the email domain is a breach-lookup pivot.

Two hops keep the links clean: everything in column 1 comes straight off the domain; column 2 comes
off column 1 (networks off the IPs, certificates off the subdomains, breach surface off the mail).
"""

from typing import Dict, List, Optional

from archer.visualization.anatomy import _Chain, _finish


def _n(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


def _sec(title: str, items: List[str]) -> Optional[Dict]:
    items = [str(i) for i in items if i]
    return {"title": title, "items": items, "brief": True} if items else None


def _secs(*sections) -> List[Dict]:
    return [s for s in sections if s]


def _asset_label(a) -> str:
    if isinstance(a, dict):
        for k in ("value", "subdomain", "ip", "hostname", "domain"):
            if a.get(k):
                extra = a.get("type") or a.get("port") or a.get("product")
                return f"{a[k]} ({extra})" if extra else str(a[k])
        return next((str(v) for v in a.values() if v), "")
    return str(a)


def _cert_label(c) -> str:
    if isinstance(c, dict):
        return str(c.get("common_name") or c.get("name_value") or c.get("issuer") or c.get("name") or "").split("\n")[0]
    return str(c)


def build(profile: Dict) -> Optional[Dict]:
    """Nodes/edges for the exposure map, or None if there's nothing but the domain to show."""
    if not isinstance(profile, dict):
        return None
    ci = profile.get("company_info") or {}
    osint = profile.get("osint") or {}
    bs = profile.get("breach_surface") or {}
    domain = profile.get("domain") or ci.get("domain")
    if not domain:
        return None

    chain = _Chain()

    # Column 0 — the organisation itself
    org_title = ci.get("company_name") or domain
    hq = ci.get("country") or (ci.get("identity") or {}).get("country")
    org_sub = domain if org_title != domain else ""
    chain.card("org", "org", org_title, sub=org_sub, col=0,
               sections=_secs(_sec("Based in", [hq]) if hq else None))

    # Column 1 — straight off the domain
    ips = ci.get("ip_addresses") or []
    if ips:
        chain.card("ips", "ip", "IP addresses", sub=f"{len(ips)} resolved", col=1,
                   sections=_secs(_sec("", ips[:8])))
        chain.link("org", "ips", "resolves to")

    ns = [str(n).rstrip(".") for n in (ci.get("nameservers") or [])]
    if ns:
        chain.card("ns", "dns", "Nameservers", col=1, sections=_secs(_sec("", ns[:6])))
        chain.link("org", "ns", "delegated to")

    mx = ci.get("mx") or []
    if mx:
        chain.card("mx", "mail", "Mail (MX)", sub=ci.get("mail_provider") or "", col=1,
                   sections=_secs(_sec("", [m.get("host") if isinstance(m, dict) else str(m) for m in mx][:5])))
        chain.link("org", "mx", "mail via")

    subs = osint.get("subdomains") or []
    if subs:
        chain.card("subs", "web", "Subdomains", sub=f"{len(subs)} found", col=1,
                   sections=_secs(_sec("", subs[:8])))
        chain.link("org", "subs", "CT logs reveal")

    # Technology fingerprint (from the live site + OSINT): server, CDN, cloud, TLS, missing headers
    tech = ((profile.get("threat_profile") or {}).get("tech_stack")) or {}
    server = tech.get("web_server") if not tech.get("web_server_custom_banner") else None
    missing_headers = [h for h, present in (tech.get("security_headers") or {}).items() if not present]
    tech_sections = _secs(
        _sec("Server", [server] if server else []),
        _sec("CDN", [tech.get("cdn")] if tech.get("cdn") else []),
        _sec("Cloud", [tech.get("cloud_provider")] if tech.get("cloud_provider") else []),
        _sec("Tech", (tech.get("technologies") or [])[:5]),
        _sec("Missing headers", missing_headers[:5]))
    if tech_sections or tech.get("tls_grade"):
        chain.card("tech", "tech", "Technology", sub=(f"TLS {tech['tls_grade']}" if tech.get("tls_grade") else server or ""),
                   col=1, sections=tech_sections)
        chain.link("org", "tech", "runs")

    hist = osint.get("historical_data") or []
    if hist:
        chain.card("hist", "history", "Historical", sub=_n(len(hist), "snapshot"), col=1,
                   sections=_secs(_sec("Wayback", [str(h.get("timestamp") or h) if isinstance(h, dict) else str(h) for h in hist[:4]])))
        chain.link("org", "hist", "archived by")

    # Column 2 — off column 1
    networks = ci.get("networks") or {}
    asns = networks.get("asns") or []
    prefixes = networks.get("prefixes") or []
    hosting = networks.get("hosting_countries") or []
    if asns or prefixes:
        chain.card("net", "asn", "Networks", col=2, sections=_secs(
            _sec("ASN", [f"AS{a['asn']} {a.get('as_name', '')}".strip() for a in asns]),
            _sec("Ranges", prefixes),
            _sec("Hosted in", hosting)))
        chain.link("ips" if ips else "org", "net", "announced by")

    certs = osint.get("certificates") or []
    if certs:
        chain.card("certs", "cert", "Certificates", sub=f"{len(certs)} seen", col=2,
                   sections=_secs(_sec("", [c for c in (_cert_label(x) for x in certs[:6]) if c])))
        chain.link("subs" if subs else "org", "certs", "issued for")

    assets = osint.get("exposed_assets") or []
    if assets:
        chain.card("svc", "service", "Exposed services", sub=_n(len(assets), "host"), col=2,
                   sections=_secs(_sec("Shodan", [a for a in (_asset_label(x) for x in assets[:8]) if a])))
        chain.link("ips" if ips else "org", "svc", "exposes")

    leaks = osint.get("github_leaks") or []
    secrets = osint.get("exposed_secrets") or []
    if bs.get("count") or leaks or secrets:
        secs = _secs(
            _sec("Breaches", [f"{b.get('title')} ({b.get('date')})" for b in (bs.get("breaches") or [])[:5]]),
            _sec("GitHub", [str(x.get("repo") or x.get("name") or x) if isinstance(x, dict) else str(x) for x in leaks[:3]]),
            _sec("Secrets", [str(x.get("type") or x) if isinstance(x, dict) else str(x) for x in secrets[:3]]))
        card = chain.card("breach", "breach", "Breach & leak surface",
                          sub=bs.get("email_domain") or domain, col=2, sections=secs)
        card["link"] = bs.get("lookup_url")
        card["breaches"] = bs.get("breaches") or []
        chain.link("mx" if mx else "org", "breach", "email domain")

    if len(chain.cards) <= 1:
        return None
    return _finish(chain, "exposure")

"""Organisation exposure map builder: nodes and links from a stored profile."""

from archer.visualization import exposure


PROFILE = {
    "domain": "acme-corp.com",
    "company_info": {
        "domain": "acme-corp.com",
        "company_name": "Acme Corp",
        "country": "United Kingdom",
        "ip_addresses": ["203.0.113.10", "203.0.113.11"],
        "nameservers": ["ns1.acme-corp.com.", "ns2.acme-corp.com."],
        "mx": [{"host": "aspmx.l.google.com", "preference": 1}],
        "mail_provider": "Google Workspace",
        "networks": {
            "asns": [{"asn": "64500", "as_name": "ACME-AS, GB"}],
            "prefixes": ["203.0.113.0/24"],
            "hosting_countries": ["GB"],
        },
    },
    "osint": {
        "subdomains": ["vpn.acme-corp.com", "mail.acme-corp.com", "dev.acme-corp.com"],
        "certificates": [{"common_name": "*.acme-corp.com"}],
        "exposed_assets": [{"value": "203.0.113.10", "port": 443}],
        "github_leaks": [{"repo": "acme/config"}],
    },
    "breach_surface": {
        "email_domain": "acme-corp.com",
        "lookup_url": "https://haveibeenpwned.com/DomainSearch?Domain=acme-corp.com",
        "count": 1,
        "breaches": [{"title": "SomeService", "date": "2019-04-01", "pwn_count": 1000}],
    },
}


def test_build_produces_linked_graph():
    out = exposure.build(PROFILE)
    assert out and out["kind"] == "exposure"
    ids = {n["id"] for n in out["nodes"]}
    assert {"org", "ips", "ns", "mx", "subs", "net", "certs", "svc", "breach"} <= ids
    edges = {(e["source"], e["target"]) for e in out["edges"]}
    assert ("org", "ips") in edges         # first hop off the domain
    assert ("ips", "net") in edges         # networks come off the IPs
    assert ("subs", "certs") in edges      # certs off the subdomains
    assert ("mx", "breach") in edges       # breach surface off the mail
    assert out["width"] and out["height"]


def test_breach_node_carries_link_and_breaches():
    out = exposure.build(PROFILE)
    breach = next(n for n in out["nodes"] if n["id"] == "breach")
    assert breach["link"].endswith("acme-corp.com")
    assert breach["breaches"][0]["title"] == "SomeService"


def test_networks_fall_back_to_org_when_no_ips():
    p = {"domain": "x.io", "company_info": {"domain": "x.io",
         "networks": {"asns": [{"asn": "1", "as_name": "A"}], "prefixes": ["1.0.0.0/24"], "hosting_countries": ["US"]}}}
    out = exposure.build(p)
    edges = {(e["source"], e["target"]) for e in out["edges"]}
    assert ("org", "net") in edges


def test_tech_stack_becomes_a_node():
    import copy
    p = copy.deepcopy(PROFILE)
    p["threat_profile"] = {"tech_stack": {
        "web_server": "nginx", "web_server_custom_banner": False, "cdn": "Cloudflare",
        "cloud_provider": "AWS", "tls_grade": "A+", "technologies": ["React"],
        "security_headers": {"Strict-Transport-Security": True, "Content-Security-Policy": False}}}
    out = exposure.build(p)
    tech = next(n for n in out["nodes"] if n["id"] == "tech")
    assert tech["sub"] == "TLS A+"
    joined = " ".join(it for s in tech["sections"] for it in s["items"])
    assert "nginx" in joined and "Cloudflare" in joined and "Content-Security-Policy" in joined
    assert ("org", "tech") in {(e["source"], e["target"]) for e in out["edges"]}


def test_custom_server_banner_is_not_shown_as_a_product():
    import copy
    p = copy.deepcopy(PROFILE)
    p["threat_profile"] = {"tech_stack": {"web_server": "Acme Web Server", "web_server_custom_banner": True,
                                          "security_headers": {}}}
    out = exposure.build(p)
    tech = next((n for n in out["nodes"] if n["id"] == "tech"), None)
    # a vanity banner alone, no real product/headers/tls -> no tech node
    assert tech is None


def test_domain_only_profile_has_no_map():
    assert exposure.build({"domain": "x.io", "company_info": {"domain": "x.io"}}) is None
    assert exposure.build({}) is None
    assert exposure.build(None) is None

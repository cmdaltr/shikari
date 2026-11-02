"""Passive network enrichment: Team Cymru ASN/prefix/country, MX, and HIBP breach metadata."""

import types

import pytest

from shikari.intelligence import network_enrichment as net


class _TXT:
    def __init__(self, text):
        self.strings = [text.encode()]


@pytest.fixture(autouse=True)
def _clear_cache():
    net._asn_name_cache.clear()
    yield
    net._asn_name_cache.clear()


def _fake_resolver(mapping):
    """mapping: {(name, rtype): [records]} where records are strings (TXT) or MX objects."""
    def resolve(name, rtype, lifetime=None):
        key = (str(name), rtype)
        if key not in mapping:
            raise Exception("NXDOMAIN")
        recs = mapping[key]
        if rtype == "TXT":
            return [_TXT(r) for r in recs]
        return recs
    return resolve


def test_asn_lookup_parses_origin_and_name(monkeypatch):
    mapping = {
        ("8.8.8.8.origin.asn.cymru.com", "TXT"): ["15169 | 8.8.8.0/24 | US | arin | 1992-12-01"],
        ("AS15169.asn.cymru.com", "TXT"): ["15169 | US | arin | 2000-03-30 | GOOGLE, US"],
    }
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver(mapping))
    # note: query uses reversed octets -> 8.8.8.8 -> "8.8.8.8" reversed is same; use a clearer IP
    out = net.asn_lookup("8.8.8.8")
    assert out == {"ip": "8.8.8.8", "asn": "15169", "prefix": "8.8.8.0/24", "country": "US",
                   "registry": "arin", "as_name": "GOOGLE, US"}


def test_asn_lookup_reverses_octets(monkeypatch):
    # 1.2.3.4 -> query 4.3.2.1.origin.asn.cymru.com
    mapping = {
        ("4.3.2.1.origin.asn.cymru.com", "TXT"): ["64500 | 1.2.3.0/24 | GB | ripe | 2010-01-01"],
        ("AS64500.asn.cymru.com", "TXT"): ["64500 | GB | ripe | 2010-01-01 | EXAMPLE-AS, GB"],
    }
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver(mapping))
    out = net.asn_lookup("1.2.3.4")
    assert out["asn"] == "64500" and out["prefix"] == "1.2.3.0/24" and out["country"] == "GB"
    assert out["as_name"] == "EXAMPLE-AS, GB"


def test_asn_lookup_unresolved_is_none(monkeypatch):
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver({}))
    assert net.asn_lookup("203.0.113.9") is None
    assert net.asn_lookup("not-an-ip") is None


def test_enrich_ips_dedupes_asns_prefixes_countries(monkeypatch):
    mapping = {
        ("1.0.0.1.origin.asn.cymru.com", "TXT"): ["13335 | 1.1.1.0/24 | US | arin | 2018"],
        ("2.0.0.1.origin.asn.cymru.com", "TXT"): ["13335 | 1.1.1.0/24 | US | arin | 2018"],  # same AS/prefix
        ("1.2.3.4.origin.asn.cymru.com".replace("1.2.3.4", "9.9.9.9"), "TXT"): ["19281 | 9.9.9.0/24 | CH | ripe | 2016"],
        ("AS13335.asn.cymru.com", "TXT"): ["13335 | US | arin | 2010 | CLOUDFLARENET, US"],
        ("AS19281.asn.cymru.com", "TXT"): ["19281 | CH | ripe | 2016 | QUAD9, CH"],
    }
    # IPs chosen so reversed queries match the keys above
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver(mapping))
    out = net.enrich_ips(["1.0.0.1", "1.0.0.2", "9.9.9.9"])
    # 1.0.0.1 -> 1.0.0.1 reversed = 1.0.0.1 ; 1.0.0.2 reversed = 2.0.0.1 ; 9.9.9.9 reversed = 9.9.9.9
    assert len(out["per_ip"]) == 3
    assert {a["asn"] for a in out["asns"]} == {"13335", "19281"}
    assert out["prefixes"] == ["1.1.1.0/24", "9.9.9.0/24"]
    assert out["hosting_countries"] == ["CH", "US"]
    assert dict((a["asn"], a["as_name"]) for a in out["asns"])["13335"] == "CLOUDFLARENET, US"


def test_mx_records_sorted_by_preference(monkeypatch):
    mx = [types.SimpleNamespace(exchange="alt2.aspmx.l.google.com.", preference=5),
          types.SimpleNamespace(exchange="aspmx.l.google.com.", preference=1)]
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver({("x.io", "MX"): mx}))
    out = net.mx_records("x.io")
    assert [m["host"] for m in out] == ["aspmx.l.google.com", "alt2.aspmx.l.google.com"]
    assert net.mail_provider(out) == "Google Workspace"


def test_mx_records_empty_on_failure(monkeypatch):
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver({}))
    assert net.mx_records("x.io") == []
    assert net.mail_provider([]) == ""


def test_breach_metadata_parses_and_sorts(monkeypatch):
    class _Resp:
        status_code = 200
        def json(self):
            return [{"Name": "Old", "Title": "Old Breach", "BreachDate": "2015-01-01", "PwnCount": 10, "IsVerified": True},
                    {"Name": "New", "Title": "New Breach", "BreachDate": "2021-06-01", "PwnCount": 99, "IsVerified": True}]
    monkeypatch.setattr(net.requests, "get", lambda *a, **k: _Resp())
    out = net.breach_metadata("acme.com")
    assert out["count"] == 2
    assert out["breaches"][0]["name"] == "New"  # newest first
    assert out["email_domain"] if "email_domain" in out else True  # set by caller, not here
    assert out["lookup_url"].endswith("acme.com")


def test_breach_metadata_graceful_offline(monkeypatch):
    def boom(*a, **k):
        raise Exception("no network")
    monkeypatch.setattr(net.requests, "get", boom)
    out = net.breach_metadata("acme.com")
    assert out["breaches"] == [] and out["count"] == 0 and out["lookup_url"]


def test_internetdb_aggregates_cves_and_ports(monkeypatch):
    responses = {
        "1.1.1.1": {"ports": [443, 80], "cpes": ["cpe:/a:nginx:nginx"], "vulns": ["CVE-2021-1234"], "hostnames": ["a.x.io"]},
        "2.2.2.2": {"ports": [22, 443], "cpes": ["cpe:/a:openssh:openssh"], "vulns": ["CVE-2023-0001", "CVE-2021-1234"], "hostnames": []},
    }

    class _Resp:
        def __init__(self, ip):
            self._ip = ip
            self.status_code = 200 if ip in responses else 404
        def json(self):
            return responses[self._ip]

    monkeypatch.setattr(net.requests, "get", lambda url, **k: _Resp(url.rsplit("/", 1)[-1]))
    out = net.enrich_internetdb(["1.1.1.1", "2.2.2.2", "bogus"])
    assert out["ports"] == [22, 80, 443]
    assert out["vulns"][0] == "CVE-2023-0001"  # newest CVE first
    assert "CVE-2021-1234" in out["vulns"] and len(out["vulns"]) == 2  # de-duplicated
    assert len(out["per_ip"]) == 2


def test_internetdb_rejects_bad_ip(monkeypatch):
    monkeypatch.setattr(net.requests, "get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not fetch")))
    assert net.internetdb("not-an-ip") is None


def test_email_auth_enforced_not_spoofable(monkeypatch):
    mapping = {
        ("acme.com", "TXT"): ["v=spf1 include:_spf.google.com -all"],
        ("_dmarc.acme.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@acme.com"],
        ("google._domainkey.acme.com", "TXT"): ["v=DKIM1; k=rsa; p=MIIBI..."],
    }
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver(mapping))
    out = net.email_auth("acme.com")
    assert out["spf"] and out["dmarc"] and out["dmarc_policy"] == "reject"
    assert out["dkim_selectors"] == ["google"]
    assert out["spoofable"] is False


def test_email_auth_missing_records_spoofable(monkeypatch):
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver({}))
    out = net.email_auth("acme.com")
    assert out["spf"] is False and out["dmarc"] is False
    assert out["spoofable"] is True


def test_email_auth_softfail_no_dmarc_spoofable(monkeypatch):
    mapping = {("acme.com", "TXT"): ["v=spf1 include:x ~all"]}
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver(mapping))
    out = net.email_auth("acme.com")
    assert out["spf"] is True and out["dmarc"] is False
    assert out["spoofable"] is True  # SPF soft-fail but no enforced DMARC

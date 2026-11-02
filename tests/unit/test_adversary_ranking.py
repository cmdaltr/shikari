"""Ordered Adversary List ranking (shikari.intelligence.adversary_ranking).

The group-metadata cache (data/cache/group_metadata.json) is committed, so the industry, geography
and incidents dimensions are exercised for real. The procedures CSV and ATT&CK bundle are local-only
(gitignored), so the exposure-technique and product dimensions degrade to 0 when absent — the tests
assert the engine still ranks on what it has rather than requiring those files.
"""

import json

import pytest

from shikari.intelligence import adversary_ranking as ar


# ── Pure signal helpers ─────────────────────────────────────────────────────────

def test_org_sectors_maps_synonyms_to_metadata_labels():
    prof = {"threat_profile": {"industry": {"sector": "fintech", "other_sectors": ["healthcare"]}}}
    labels = set(ar._org_sectors(prof))
    assert "Finance / Banking" in labels
    assert "Healthcare / Pharma" in labels


def test_org_region_buckets_country():
    assert ar._org_region({"company_info": {"country": "United Kingdom"}}) == "Europe"
    assert ar._org_region({"threat_profile": {"geography": {"country": "United States"}}}) == "North America"
    assert ar._org_region({"company_info": {"country": "Atlantis"}}) == ""


def test_exposure_techniques_from_osint():
    prof = {
        "exposed_services": {"ports": [443, 3389], "vulns": ["CVE-1", "CVE-2"]},
        "osint": {"exposed_secrets": [{"type": "key"}]},
        "company_info": {"mx": [{"host": "mx"}], "email_auth": {"spoofable": True}},
    }
    exp = ar._exposure_techniques(prof)
    assert ar.T_PUBLIC_APP in exp   # CVEs on exposed services
    assert ar.T_REMOTE in exp       # port 3389
    assert ar.T_VALID_ACCT in exp   # exposed secret
    assert ar.T_PHISH in exp        # spoofable mail
    assert exp[ar.T_PHISH]["weight"] > 0.5  # spoofable weighted higher than a plain mail surface


def test_exposed_products_drops_generic_and_versions():
    prof = {"threat_profile": {"tech_stack": {"technologies": ["Microsoft Exchange 2019", "nginx"],
                                              "web_server": "Apache"}},
            "exposed_services": {"cpes": ["cpe:/a:fortinet:fortigate"]}}
    products = ar._exposed_products(prof)
    assert "microsoft exchange" in products
    assert "fortinet" in products
    assert "nginx" not in products   # generic
    assert "apache" not in products  # generic


# ── Ranking ─────────────────────────────────────────────────────────────────────

def test_empty_profile_returns_nothing():
    assert ar.rank_adversaries({}) == []
    assert ar.rank_adversaries({"threat_profile": {}}) == []


def test_ranks_by_industry_and_geography_from_committed_metadata():
    prof = {"domain": "x.co.uk",
            "threat_profile": {"industry": {"sector": "technology"},
                               "geography": {"country": "United Kingdom"}}}
    rows = ar.rank_adversaries(prof, limit=10)
    assert rows, "committed group metadata should yield matches for a UK technology org"
    assert len(rows) <= 10
    # Sorted by likelihood, ranks numbered 1..n
    assert [r["rank"] for r in rows] == list(range(1, len(rows) + 1))
    assert all(rows[i]["likelihood"] >= rows[i + 1]["likelihood"] for i in range(len(rows) - 1))
    top = rows[0]
    assert top["breakdown"]["industry"] > 0 or top["breakdown"]["geography"] > 0
    assert "industry" in top["sources"] or "geography" in top["sources"]
    # A sector+region match should out-band a one-signal match
    assert top["band"] in ("High", "Medium")


def test_incidents_file_promotes_a_named_victim(tmp_path, monkeypatch):
    # Pick a real group from the committed metadata to attribute an incident to
    meta = ar.load_group_metadata(ar._META_CACHE)
    name = next(g["group_name"] for k, g in meta.items() if k.startswith("G") and g.get("group_name"))

    incidents = tmp_path / "incidents.json"
    incidents.write_text(json.dumps([{"group": name, "victims": ["acme.co.uk"], "last_seen": 2099}]))
    monkeypatch.setattr(ar, "_INCIDENTS_FILE", incidents)
    monkeypatch.setattr(ar, "_incidents_cache", (0.0, {}))  # force a reload

    prof = {"domain": "acme.co.uk",
            "threat_profile": {"industry": {"sector": "technology"},
                               "geography": {"country": "United Kingdom"}}}
    rows = ar.rank_adversaries(prof, limit=20)
    hit = next((r for r in rows if r["name"] == name), None)
    assert hit is not None
    assert hit["breakdown"]["incidents"] >= ar.W_INCIDENT_DIRECT
    assert any("acme.co.uk" in why for why in hit["reasons"])


def test_malformed_incidents_file_is_ignored(tmp_path, monkeypatch):
    bad = tmp_path / "incidents.json"
    bad.write_text("{not json")
    monkeypatch.setattr(ar, "_INCIDENTS_FILE", bad)
    monkeypatch.setattr(ar, "_incidents_cache", (0.0, {}))
    # No bespoke file content, and feeds are stubbed empty below via incident_sources
    from shikari.intelligence import incident_sources
    monkeypatch.setattr(incident_sources, "load_vcdb", lambda: {})
    monkeypatch.setattr(incident_sources, "load_ransomware", lambda: {})
    assert ar._load_incidents() == {}


def test_feeds_merge_into_incident_map(monkeypatch):
    # VCDB and ransomware.live caches are merged, unioning victims/sectors and keeping newest year
    from shikari.intelligence import incident_sources
    monkeypatch.setattr(incident_sources, "load_vcdb", lambda: {
        "groups": {"apt28": {"victims": ["acme corp"], "sectors": ["Government"], "last_seen": 2019}}})
    monkeypatch.setattr(incident_sources, "load_ransomware", lambda: {
        "groups": {"apt28": {"victims": ["beta ltd"], "sectors": ["Energy / Utilities"], "last_seen": 2025}}})
    monkeypatch.setattr(ar, "_incidents_cache", (0.0, {}))
    monkeypatch.setattr(ar, "_INCIDENTS_FILE", ar._INCIDENTS_FILE.parent / "does-not-exist.json")
    merged = ar._load_incidents()
    assert "acme corp" in merged["apt28"]["victims"]
    assert "beta ltd" in merged["apt28"]["victims"]
    assert merged["apt28"]["sectors"] == {"Government", "Energy / Utilities"}
    assert merged["apt28"]["last_seen"] == 2025  # most recent wins


def test_kev_strengthens_exposed_cve_signal(monkeypatch):
    from shikari.intelligence import incident_sources
    prof = {"exposed_services": {"vulns": ["CVE-2021-26855", "CVE-2099-0001"]}}
    monkeypatch.setattr(incident_sources, "load_kev", lambda: {})
    base = ar._exposure_techniques(prof)[ar.T_PUBLIC_APP]["weight"]
    monkeypatch.setattr(incident_sources, "load_kev", lambda: {
        "cves": {"CVE-2021-26855": {"ransomware": True}}})
    with_kev = ar._exposure_techniques(prof)
    assert with_kev[ar.T_PUBLIC_APP]["weight"] > base
    assert "CISA KEV" in with_kev[ar.T_PUBLIC_APP]["reason"]
    assert "ransomware" in with_kev[ar.T_PUBLIC_APP]["reason"]

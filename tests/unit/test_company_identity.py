"""
Company identity for the profiler: who is behind the domain, not where it is hosted.

tesco.com was profiled as "Hesse, Germany" (an Akamai edge) with no sector,
because location came from IP geolocation and sector from the domain string.
"""
from unittest.mock import MagicMock, patch

from archer.intelligence import company_identity
from archer.intelligence.company_identity import resolve_identity, sector_from_labels

EMPTY_PAGE = {"name": None, "country": None, "country_basis": None, "text": ""}


def _sparql(rows):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"results": {"bindings": [
        {k: {"value": v} for k, v in row.items()} for row in rows
    ]}}
    return resp


# Shape of the real Wikidata answer for tesco.com after walking P749 to the parent
TESCO = {
    "org": "http://www.wikidata.org/entity/Q487494",
    "orgLabel": "Tesco",
    "links": "56",
    "countryLabel": "United Kingdom",
    "hqLabel": "Welwyn Garden City",
    "hqCountryLabel": "United Kingdom",
    "industries": "retail chain",
    "types": "business|brick and mortar|supermarket chain|public company|enterprise",
}


def setup_function():
    company_identity.lookup_wikidata.cache_clear()


def test_tesco_resolves_to_uk_supermarket():
    with patch.object(company_identity.requests, "get", return_value=_sparql([TESCO])), \
         patch.object(company_identity, "homepage_signals", return_value=EMPTY_PAGE):
        identity = resolve_identity("tesco.com")

    assert identity["company_name"] == "Tesco"
    assert identity["country"] == "United Kingdom"
    assert identity["headquarters"] == "Welwyn Garden City"
    assert identity["sector"] == "retail"
    assert identity["organisation_types"][0] == "supermarket chain"
    assert identity["confidence"] == "high"
    assert any("Q487494" in e for e in identity["evidence"])


def test_hq_country_beats_operating_country():
    # Multinationals carry P17 for wherever they operate; HQ is home
    row = dict(TESCO, countryLabel="Ireland")
    with patch.object(company_identity.requests, "get", return_value=_sparql([row])), \
         patch.object(company_identity, "homepage_signals", return_value=EMPTY_PAGE):
        assert resolve_identity("tesco.com")["country"] == "United Kingdom"


def test_unknown_company_falls_back_to_cctld_without_guessing_sector():
    with patch.object(company_identity.requests, "get", return_value=_sparql([])), \
         patch.object(company_identity, "homepage_signals", return_value=EMPTY_PAGE):
        identity = resolve_identity("acme-widgets.co.uk")

    assert identity["country"] == "United Kingdom"
    assert identity["sector"] is None
    assert identity["company_name"] == "Acme Widgets"
    assert identity["evidence"] == ["Country-code TLD .uk"]


def test_wikidata_failure_is_not_fatal():
    with patch.object(company_identity.requests, "get", side_effect=OSError("down")), \
         patch.object(company_identity, "homepage_signals", return_value=EMPTY_PAGE):
        identity = resolve_identity("example.com")

    assert identity["country"] is None
    assert identity["confidence"] == "none"


def test_sector_from_labels():
    assert sector_from_labels(["retail chain", "supermarket chain"]) == "retail"
    assert sector_from_labels(["bank", "public company"]) == "finance"
    assert sector_from_labels(["public company", "enterprise"]) is None


def test_hosting_geoip_never_sets_company_location():
    from archer.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()
    profiler.write_progress = None
    geoip = MagicMock(status_code=200)
    geoip.json.return_value = {"status": "success", "country": "Germany", "regionName": "Hesse"}

    with patch("archer.intelligence.company_profiler.requests.get", return_value=geoip):
        unknown = profiler._analyze_geography("example.com", {"ip_addresses": ["23.3.15.208"], "country": None}, {})
        known = profiler._analyze_geography(
            "tesco.com",
            {"ip_addresses": ["23.3.15.208"], "country": "United Kingdom", "headquarters": "Welwyn Garden City"},
            {},
        )

    assert unknown["country"] is None
    assert unknown["hosting_country"] == "Germany"
    assert known["country"] == "United Kingdom"
    assert known["region"] == "Welwyn Garden City"
    assert known["hosting_region"] == "Hesse"


def test_tech_stack_refuses_internal_domain():
    """domain is user input; the homepage fetch must not reach internal hosts."""
    from archer.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()
    profiler.write_progress = None
    with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("169.254.169.254", 0))]), \
         patch("archer.parsers.blog_analyzer.requests.get") as safe_http, \
         patch("archer.intelligence.company_profiler.requests.get") as direct_http:
        profiler._analyze_tech_stack("metadata.internal", {"tls_config": {}, "subdomains": []})

    safe_http.assert_not_called()
    assert not any("metadata.internal" in str(c) for c in direct_http.call_args_list)


def test_first_label_wins_a_tie():
    from archer.intelligence.company_identity import sectors_from_labels
    # Rolls-Royce on Wikidata: aerospace first, so defence, with energy behind it
    assert sectors_from_labels(["aerospace industry", "energy industry", "weapons industry",
                                "public company"]) == ["defense", "energy"]
    assert sectors_from_labels(["energy industry", "aerospace industry"]) == ["energy", "defense"]
    assert sector_from_labels(["public company"]) is None

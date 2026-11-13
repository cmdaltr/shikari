#!/usr/bin/env python3
"""
Unit Tests: Company Profiler

Tests the company profiling functionality:
1. Domain info gathering
2. Certificate transparency checks
3. Industry sector detection
4. Geographic threat mapping
5. Tech stack detection
6. Threat recommendations

Can be run directly: python test_company_profiler.py
Or via pytest: pytest test_company_profiler.py
"""

import os
import sys
from unittest.mock import MagicMock, patch

# Add shikari to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import pytest


@pytest.fixture(autouse=True)
def progress_dir(tmp_path, monkeypatch):
    """profile_domain imports write_progress itself, so its progress records land in tmp, not data/progress."""
    from shikari.build import progress

    monkeypatch.setattr(progress, "PROGRESS_DIR", str(tmp_path))


def test_profiler_initialization():
    """Test that CompanyProfiler initializes successfully."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()
    assert profiler is not None
    assert profiler.use_openai is False
    return True


def test_profiler_initialization_with_openai():
    """Test profiler initialization with OpenAI option."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    with patch.dict("os.environ", {"OPENAI_API_KEY": ""}, clear=False):
        profiler = CompanyProfiler(use_openai=True)
        # Should gracefully handle missing API key
        assert profiler.use_openai is False
    return True


def test_gather_domain_info():
    """Test basic domain info gathering."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()
    profiler.write_progress = None
    profiler.progress_group = None

    with patch("shikari.intelligence.company_profiler.socket.getaddrinfo") as mock_getaddr, \
         patch("shikari.intelligence.company_profiler.dns.resolver.resolve") as mock_dns, \
         patch("shikari.intelligence.company_identity.lookup_wikidata", return_value=None), \
         patch("shikari.intelligence.company_identity.homepage_signals",
               return_value={"name": None, "country": None, "country_basis": None, "text": ""}):
        mock_getaddr.return_value = [
            (2, 1, 6, '', ('93.184.216.34', 0))
        ]
        mock_dns.return_value = [MagicMock(__str__=lambda s: "ns1.example.com")]

        result = profiler._gather_domain_info("example.com")

        assert result["domain"] == "example.com"
        assert "ip_addresses" in result
        assert "nameservers" in result
    return True


def test_gather_domain_info_extracts_company_name():
    """Test that company name is extracted from domain."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()
    profiler.write_progress = None
    profiler.progress_group = None

    with patch("shikari.intelligence.company_profiler.socket.getaddrinfo") as mock_getaddr, \
         patch("shikari.intelligence.company_profiler.dns.resolver.resolve") as mock_dns, \
         patch("shikari.intelligence.company_identity.lookup_wikidata", return_value=None), \
         patch("shikari.intelligence.company_identity.homepage_signals",
               return_value={"name": None, "country": None, "country_basis": None, "text": ""}):
        mock_getaddr.return_value = []
        mock_dns.side_effect = Exception("DNS error")

        result = profiler._gather_domain_info("acme-corp.com")

        assert result["company_name"] == "Acme Corp"
    return True


def test_check_certificate_transparency():
    """Test certificate transparency check."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()

    mock_ct_response = [
        {"name_value": "www.example.com", "common_name": "example.com",
         "issuer_name": "Let's Encrypt", "not_before": "2024-01-01", "not_after": "2024-12-31"},
        {"name_value": "api.example.com", "common_name": "api.example.com",
         "issuer_name": "Let's Encrypt", "not_before": "2024-01-01", "not_after": "2024-12-31"}
    ]

    with patch("shikari.intelligence.company_profiler.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_ct_response
        mock_get.return_value = mock_response

        result = profiler._check_certificate_transparency("example.com")

        assert "certificates" in result
        assert "subdomains" in result
        assert len(result["subdomains"]) >= 1
    return True


def test_check_google_dorks_returns_patterns():
    """Test that Google dork patterns are returned."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()

    result = profiler._check_google_dorks("example.com")

    assert isinstance(result, list)
    assert len(result) > 0
    assert any("site:example.com" in item.get("pattern", "") for item in result)
    return True


def test_analyze_industry_detection():
    """Test industry sector detection from domain."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()
    profiler.write_progress = None
    profiler.progress_group = None

    company_info = {"company_name": "Bank of America"}

    result = profiler._analyze_industry("bankofamerica.com", company_info)

    assert result["sector"] == "finance"
    assert result["confidence"] in ["high", "medium", "low"]
    return True


def test_map_sector_to_threats_finance():
    """Test threat mapping for finance sector."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()

    with patch("shikari.mitre.get_stix_data") as mock_stix:
        # Simulate MITRE data not available
        mock_stix.side_effect = Exception("MITRE data unavailable")

        result = profiler._map_sector_to_threats("finance")

        assert "groups" in result
        assert len(result["groups"]) > 0
        # Finance should include FIN groups
        assert any("FIN" in g for g in result["groups"])
    return True


def test_map_country_to_threats():
    """Test country to threat actor mapping."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()

    result = profiler._map_country_to_threats("United States")

    assert isinstance(result, list)
    # US is targeted by multiple nation-state actors
    assert len(result) > 0
    return True


def test_assess_geopolitical_risks():
    """Test geopolitical risk assessment."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()

    result = profiler._assess_geopolitical_risks("United States")

    assert isinstance(result, list)
    assert len(result) > 0
    return True


def test_analyze_tech_stack_from_headers():
    """Test tech stack detection from HTTP headers."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()
    profiler.write_progress = None
    profiler.progress_group = None

    osint = {"tls_config": {"grade": "A"}, "subdomains": []}

    mock_response = MagicMock()
    mock_response.ok = True
    mock_response.headers = {"Server": "nginx/1.18.0"}
    mock_response.text = "<html>Powered by WordPress</html>"

    # The fetch goes through the SSRF-checked helper (domain is user input)
    with patch("shikari.parsers.blog_analyzer._fetch_public_url", return_value=mock_response) as mock_fetch:
        result = profiler._analyze_tech_stack("example.com", osint)

        mock_fetch.assert_called_once_with("https://example.com")
        assert result["web_server"] == "nginx/1.18.0"
        assert result["web_server_custom_banner"] is False
        assert "nginx" in result["technologies"]
    return True


def test_generate_threat_recommendations():
    """Test threat recommendation generation."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()
    profiler.write_progress = None
    profiler.progress_group = None

    profile = {
        "domain": "example.com",
        "company_info": {"company_name": "Example Corp"},
        "threat_profile": {
            "industry": {
                "sector": "finance",
                "threat_groups": ["FIN7", "Lazarus Group"]
            },
            "geography": {
                "country": "United States",
                "threat_actors": ["APT28", "APT29"]
            },
            "tech_stack": {
                "technologies": ["WordPress"],
                "security_headers": {"Strict-Transport-Security": False}
            }
        }
    }

    result = profiler._generate_threat_recommendations(profile)

    assert "recommended_groups" in result
    assert "recommended_techniques" in result
    assert "risk_score" in result
    assert len(result["recommended_groups"]) > 0
    return True


def test_risk_score_calculation():
    """Test that risk score is calculated correctly."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()
    profiler.write_progress = None
    profiler.progress_group = None

    profile = {
        "domain": "example.com",
        "company_info": {},
        "threat_profile": {
            "industry": {"threat_groups": ["APT1"]},
            "geography": {"threat_actors": ["APT28"]},
            "tech_stack": {}
        }
    }

    result = profiler._generate_threat_recommendations(profile)

    # Risk score should be between 0 and 100
    assert 0 <= result["risk_score"] <= 100
    return True


def test_profile_domain_full_workflow():
    """Test complete profile_domain workflow with mocks."""
    from shikari.intelligence.company_profiler import CompanyProfiler

    profiler = CompanyProfiler()

    with patch.object(profiler, "_gather_domain_info") as mock_info, \
         patch.object(profiler, "_gather_osint") as mock_osint, \
         patch.object(profiler, "_analyze_industry") as mock_industry, \
         patch.object(profiler, "_analyze_geography") as mock_geo, \
         patch.object(profiler, "_analyze_tech_stack") as mock_tech, \
         patch.object(profiler, "_generate_threat_recommendations") as mock_rec:

        mock_info.return_value = {"domain": "example.com", "ip_addresses": [], "company_name": "Example"}
        mock_osint.return_value = {"subdomains": [], "certificates": []}
        mock_industry.return_value = {"sector": "technology", "threat_groups": []}
        mock_geo.return_value = {"country": "US", "threat_actors": []}
        mock_tech.return_value = {"technologies": [], "security_headers": {}}
        mock_rec.return_value = {
            "domain": "example.com",
            "company_info": {},
            "threat_profile": {},
            "recommended_groups": ["APT28"],
            "recommended_techniques": ["T1566.001"],
            "risk_score": 50
        }

        result = profiler.profile_domain("example.com")

        # Verify all workflow steps were called
        mock_info.assert_called_once()
        mock_osint.assert_called_once()
        mock_industry.assert_called_once()
        mock_geo.assert_called_once()
        mock_tech.assert_called_once()
        mock_rec.assert_called_once()
    return True


def test_company_profiling_workflow():
    """Standalone test function for CLI execution."""
    print("Testing Company Profiling Workflow...")
    print("=" * 60)

    tests = [
        ("Profiler initialization", test_profiler_initialization),
        ("Profiler with OpenAI", test_profiler_initialization_with_openai),
        ("Gather domain info", test_gather_domain_info),
        ("Extract company name", test_gather_domain_info_extracts_company_name),
        ("Certificate transparency", test_check_certificate_transparency),
        ("Google dorks patterns", test_check_google_dorks_returns_patterns),
        ("Industry detection", test_analyze_industry_detection),
        ("Finance sector threats", test_map_sector_to_threats_finance),
        ("Country threat mapping", test_map_country_to_threats),
        ("Geopolitical risks", test_assess_geopolitical_risks),
        ("Tech stack detection", test_analyze_tech_stack_from_headers),
        ("Threat recommendations", test_generate_threat_recommendations),
        ("Risk score calculation", test_risk_score_calculation),
        ("Full workflow", test_profile_domain_full_workflow),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            print(f"PASS: {name}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {name}")
            print(f"      {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {name}")
            print(f"       {e}")
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")

    return failed == 0


if __name__ == "__main__":
    success = test_company_profiling_workflow()
    sys.exit(0 if success else 1)

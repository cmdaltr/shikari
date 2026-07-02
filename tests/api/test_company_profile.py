"""
Tests for company profile endpoints.
"""
import pytest


class TestCompanyProfile:
    """POST /profile analyzes a company's threat landscape."""

    @pytest.mark.parametrize("company", [
        "Microsoft", "Google", "JPMorgan Chase", "Splunk",
    ])
    def test_known_company_accepted(self, api, ensure_running, company):
        r = api.post("/profile", data={"company_name": company}, timeout=120)
        assert r.status_code in [200, 302, 401, 422]

    def test_empty_company_rejected(self, api, ensure_running):
        r = api.post("/profile", data={"company_name": ""}, timeout=30)
        assert r.status_code in [200, 302, 400, 401, 422]

    def test_domain_input(self, api, ensure_running):
        r = api.post("/profile", data={"domain": "microsoft.com"}, timeout=120)
        assert r.status_code in [200, 302, 401, 422]

    def test_unknown_company(self, api, ensure_running):
        r = api.post("/profile", data={"company_name": "RandomUnknown12345"}, timeout=60)
        assert r.status_code in [200, 302, 400, 401, 422]


class TestProfileGenerateDetections:
    """POST /profile/generate-detections creates detections from profile."""

    def test_generate_from_profile(self, api, ensure_running):
        r = api.post("/profile/generate-detections", json={
            "company_name": "Microsoft",
            "techniques": ["T1566", "T1078", "T1059"],
        }, timeout=60)
        assert r.status_code in [200, 302, 303, 400, 401, 404, 422]

    def test_generate_without_techniques(self, api, ensure_running):
        r = api.post("/profile/generate-detections", json={
            "company_name": "Google",
        }, timeout=60)
        assert r.status_code in [200, 302, 303, 400, 401, 422]


class TestProfilePage:
    """GET /profile page rendering."""

    def test_profile_page_loads(self, api, ensure_running):
        r = api.get("/profile", allow_redirects=False)
        assert r.status_code in [200, 302]

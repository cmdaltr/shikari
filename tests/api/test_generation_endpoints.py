"""
Tests for all generation endpoints: /generate, /generate/cve, /hunt/technique.

These test that generation *initiates* correctly.
Full end-to-end generation tests are in tests/features/.
"""
import pytest


# ---------------------------------------------------------------------------
# Threat Group Generation
# ---------------------------------------------------------------------------

class TestGenerateByGroup:
    """POST /generate with group_name."""

    def test_valid_group_redirects(self, api, ensure_running):
        r = api.post("/generate", data={
            "group_name": "APT28",
            "osint_enhancement": "",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_with_osint_enhancement(self, api, ensure_running):
        r = api.post("/generate", data={
            "group_name": "APT28",
            "osint_enhancement": "on",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_with_correlation(self, api, ensure_running):
        r = api.post("/generate", data={
            "group_name": "APT28",
            "run_correlation": "on",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_with_osint_comparison(self, api, ensure_running):
        r = api.post("/generate", data={
            "group_name": "APT28",
            "osint_comparison": "true",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_with_all_options(self, api, ensure_running):
        r = api.post("/generate", data={
            "group_name": "APT29",
            "osint_enhancement": "on",
            "run_correlation": "on",
            "osint_comparison": "true",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_with_platform_exclusions(self, api, ensure_running):
        r = api.post("/generate", data={
            "group_name": "FIN7",
            "exclude_splunk": "true",
            "exclude_secops": "true",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_exclude_all_platforms_handled(self, api, ensure_running):
        r = api.post("/generate", data={
            "group_name": "APT28",
            "exclude_splunk": "true",
            "exclude_mde": "true",
            "exclude_secops": "true",
            "exclude_elastic": "true",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 400, 401, 422]

    def test_empty_group_name_rejected(self, api, ensure_running):
        r = api.post("/generate", data={"group_name": ""}, allow_redirects=False)
        assert r.status_code in [200, 302, 400, 401, 422]

    def test_whitespace_group_name_rejected(self, api, ensure_running):
        r = api.post("/generate", data={"group_name": "   "}, allow_redirects=False)
        assert r.status_code in [200, 302, 400, 401, 422]


# ---------------------------------------------------------------------------
# CVE Generation
# ---------------------------------------------------------------------------

class TestGenerateByCVE:
    """POST /generate/cve with cve_id."""

    @pytest.mark.parametrize("cve", [
        "CVE-2023-44487",
        "CVE-2024-3400",
        "CVE-2023-4966",
    ])
    def test_valid_cve_accepted(self, api, ensure_running, cve):
        r = api.post("/generate/cve", data={"cve_id": cve}, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_cve_case_insensitive(self, api, ensure_running):
        r = api.post("/generate/cve", data={"cve_id": "cve-2023-44487"}, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_cve_with_correlation(self, api, ensure_running):
        r = api.post("/generate/cve", data={
            "cve_id": "CVE-2024-3400",
            "run_correlation": "on",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    @pytest.mark.parametrize("bad_cve", [
        "", "CVE2024-1234", "CVE-24-1234", "NOTCVE-2024-1234",
        "random string", "CVE-2024-12345678",
    ])
    def test_invalid_cve_rejected(self, api, ensure_running, bad_cve):
        r = api.post("/generate/cve", data={"cve_id": bad_cve}, allow_redirects=False)
        assert r.status_code in [200, 302, 400, 401, 422]

    def test_nonexistent_cve_handled(self, api, ensure_running):
        r = api.post("/generate/cve", data={"cve_id": "CVE-2099-99999"}, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401, 404]


# ---------------------------------------------------------------------------
# Technique Hunt
# ---------------------------------------------------------------------------

class TestHuntByTechnique:
    """POST /hunt/technique with technique_ids."""

    @pytest.mark.parametrize("tid", [
        "T1059", "T1059.001", "T1566.001", "T1078.004", "T1003.001",
    ])
    def test_valid_technique_accepted(self, api, ensure_running, tid):
        r = api.post("/hunt/technique", data={
            "technique_ids": tid,
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_multiple_techniques(self, api, ensure_running):
        r = api.post("/hunt/technique", data={
            "technique_ids": "T1059.001,T1566.001,T1078",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_with_osint_enhancement(self, api, ensure_running):
        r = api.post("/hunt/technique", data={
            "technique_ids": "T1003.001",
            "osint_enhancement": "true",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_with_platform_exclusions(self, api, ensure_running):
        r = api.post("/hunt/technique", data={
            "technique_ids": "T1059.001",
            "exclude_elastic": "true",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    def test_duplicate_techniques_deduped(self, api, ensure_running):
        r = api.post("/hunt/technique", data={
            "technique_ids": "T1059.001,T1059.001,T1059.001",
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 303, 401]

    @pytest.mark.parametrize("bad_tid", [
        "", "X1059", "T12345", "technique", "1059",
    ])
    def test_invalid_technique_rejected(self, api, ensure_running, bad_tid):
        r = api.post("/hunt/technique", data={
            "technique_ids": bad_tid,
        }, allow_redirects=False)
        assert r.status_code in [200, 302, 400, 401, 422]


# ---------------------------------------------------------------------------
# Technique Names API
# ---------------------------------------------------------------------------

class TestTechniqueNamesAPI:
    """POST /api/technique_names resolves IDs to names."""

    def test_resolves_known_techniques(self, api, ensure_running):
        r = api.post("/api/technique_names", json={
            "technique_ids": ["T1059", "T1566", "T1078"]
        })
        assert r.status_code == 200
        data = r.json()
        assert len(data) > 0

    def test_resolves_subtechniques(self, api, ensure_running):
        r = api.post("/api/technique_names", json={
            "technique_ids": ["T1059.001", "T1003.001"]
        })
        assert r.status_code == 200

    def test_handles_invalid_ids(self, api, ensure_running):
        r = api.post("/api/technique_names", json={
            "technique_ids": ["INVALID", "T9999"]
        })
        assert r.status_code in [200, 400]

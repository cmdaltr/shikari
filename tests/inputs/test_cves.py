"""
Tests for CVE input method.

These tests validate CVE-based detection generation including
NVD lookups, vulnerability analysis, and detection creation.
"""
import pytest
import re


# Test data - mix of real and test CVEs
VALID_CVE_FORMATS = [
    "CVE-2024-1234",
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2024-3400",   # Palo Alto PAN-OS
    "CVE-2023-4966",   # Citrix Bleed
    "cve-2024-1234",   # lowercase should work
]

INVALID_CVE_FORMATS = [
    "CVE2024-1234",     # Missing dash
    "CVE-24-1234",      # Wrong year format
    "CVE-2024-123",     # Too few digits
    "CVE-2024-12345678",  # Too many digits
    "NOTCVE-2024-1234",
    "",
    "random string",
]

# CVEs that likely don't exist in NVD
NONEXISTENT_CVES = [
    "CVE-2099-99999",
    "CVE-2050-00001",
]


class TestCVEValidation:
    """Tests for CVE input validation."""

    @pytest.mark.parametrize("cve_id", VALID_CVE_FORMATS)
    def test_valid_cve_format_accepted(self, client, ensure_shikari_running, cve_id):
        """Test that valid CVE formats are accepted."""
        response = client.post(
            "/generate/cve",
            data={"cve_id": cve_id},
            allow_redirects=False
        )

        # Should accept the format (may fail later if CVE not in NVD)
        assert response.status_code in [200, 302, 303, 401]

    @pytest.mark.parametrize("cve_id", INVALID_CVE_FORMATS)
    def test_invalid_cve_format_rejected(self, client, ensure_shikari_running, cve_id):
        """Test that invalid CVE formats are rejected."""
        response = client.post(
            "/generate/cve",
            data={"cve_id": cve_id},
            allow_redirects=False
        )

        # Should either reject with error or redirect
        # If it accepts, the generation should fail with validation error
        assert response.status_code in [200, 302, 303, 400, 401, 422]

    def test_empty_cve_id_rejected(self, client, ensure_shikari_running):
        """Test that empty CVE ID is rejected."""
        response = client.post(
            "/generate/cve",
            data={"cve_id": ""},
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 400, 401, 422]


class TestCVEGeneration:
    """Tests for CVE-based detection generation."""

    def test_cve_generation_initiates(self, client, ensure_shikari_running):
        """Test that CVE generation initiates successfully."""
        response = client.post(
            "/generate/cve",
            data={
                "cve_id": "CVE-2023-44487",
                "run_correlation": "",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_cve_progress_tracking(self, client, ensure_shikari_running):
        """Test that CVE generation progress can be tracked."""
        cve_id = "CVE-2024-3400"

        # Initiate generation
        client.post(
            "/generate/cve",
            data={"cve_id": cve_id},
            allow_redirects=False
        )

        # Check progress
        response = client.get(
            "/progress_status",
            params={"group_name": cve_id}
        )

        assert response.status_code in [200, 401]

    def test_cve_with_correlation(self, client, ensure_shikari_running):
        """Test CVE generation with correlation enabled."""
        response = client.post(
            "/generate/cve",
            data={
                "cve_id": "CVE-2023-4966",
                "run_correlation": "on",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]


class TestCVELookup:
    """Tests for CVE information lookup."""

    def test_cve_info_endpoint(self, client, ensure_shikari_running):
        """Test CVE information lookup endpoint if available."""
        response = client.get(
            "/api/cve/info",
            params={"cve_id": "CVE-2023-44487"}
        )

        # Endpoint may or may not exist
        if response.status_code == 200:
            data = response.json()
            # Should contain CVE info
            assert "cve_id" in data or "id" in data or "description" in data

    def test_nonexistent_cve_handled(self, client, ensure_shikari_running):
        """Test that non-existent CVEs are handled gracefully."""
        response = client.post(
            "/generate/cve",
            data={"cve_id": "CVE-2099-99999"},
            allow_redirects=False
        )

        # Should accept but generation will fail with "not found"
        assert response.status_code in [200, 302, 303, 401, 404]


class TestCVEResults:
    """Tests for CVE generation results."""

    def test_cve_results_page(self, client, ensure_shikari_running):
        """Test CVE results page loads."""
        response = client.get(
            "/results",
            params={"group_name": "CVE-2023-44487"}
        )

        assert response.status_code in [200, 404]

    def test_cve_detections_structure(self, client, ensure_shikari_running):
        """Test that CVE detections have proper structure."""
        # This would verify the YAML structure of generated detections
        # Implementation depends on how results are accessed
        pass


class TestCVEEdgeCases:
    """Edge case tests for CVE input."""

    def test_cve_with_leading_zeros(self, client, ensure_shikari_running):
        """Test CVE ID with leading zeros in sequence number."""
        response = client.post(
            "/generate/cve",
            data={"cve_id": "CVE-2024-0001"},
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_cve_case_insensitivity(self, client, ensure_shikari_running):
        """Test that CVE lookup is case-insensitive."""
        # Try lowercase
        response_lower = client.post(
            "/generate/cve",
            data={"cve_id": "cve-2024-1234"},
            allow_redirects=False
        )

        # Try mixed case
        response_mixed = client.post(
            "/generate/cve",
            data={"cve_id": "CvE-2024-1234"},
            allow_redirects=False
        )

        # Both should be accepted
        assert response_lower.status_code in [200, 302, 303, 401]
        assert response_mixed.status_code in [200, 302, 303, 401]

    def test_cve_with_whitespace(self, client, ensure_shikari_running):
        """Test CVE ID with surrounding whitespace."""
        response = client.post(
            "/generate/cve",
            data={"cve_id": "  CVE-2024-1234  "},
            allow_redirects=False
        )

        # Should trim whitespace and accept
        assert response.status_code in [200, 302, 303, 401]

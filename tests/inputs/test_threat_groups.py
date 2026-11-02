"""
Tests for Threat Group input method.

These tests validate the threat group detection generation functionality
including MITRE ATT&CK group lookups, OSINT enrichment, and detection creation.
"""
import pytest
import time


# Test data - real threat groups from MITRE ATT&CK
VALID_THREAT_GROUPS = [
    "APT28",
    "APT29",
    "Lazarus Group",
    "Scattered Spider",
    "Wizard Spider",
    "Salt Typhoon",
    "FIN7",
    "Sandworm Team",
]

INVALID_THREAT_GROUPS = [
    "NonExistentGroup12345",
    "FakeAPT999",
    "",
    "   ",
]


class TestThreatGroupValidation:
    """Tests for threat group input validation."""

    def test_threat_groups_api_returns_groups(self, client, ensure_shikari_running):
        """Test that the threat groups API returns a list of groups."""
        response = client.get("/threat_groups")

        assert response.status_code in [200, 401]
        data = response.json()
        assert "groups" in data
        assert len(data["groups"]) > 0, "Expected at least some threat groups"

    def test_threat_groups_api_contains_known_groups(self, client, ensure_shikari_running):
        """Test that known APT groups are in the list."""
        response = client.get("/threat_groups")
        data = response.json()

        groups = [g.get("name", g) if isinstance(g, dict) else g for g in data["groups"]]
        group_names_lower = [g.lower() for g in groups]

        # Check for some well-known groups
        known_groups = ["apt28", "apt29", "lazarus"]
        for known in known_groups:
            assert any(
                known in g for g in group_names_lower
            ), f"Expected to find {known} in threat groups"

    def test_generate_with_empty_group_name(self, client, ensure_shikari_running):
        """Test that empty group name is rejected."""
        response = client.post(
            "/generate",
            data={"group_name": ""},
            allow_redirects=False
        )

        # Should either return error or redirect back
        assert response.status_code in [200, 302, 400, 401, 422]

    def test_generate_with_whitespace_group_name(self, client, ensure_shikari_running):
        """Test that whitespace-only group name is handled."""
        response = client.post(
            "/generate",
            data={"group_name": "   "},
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 400, 401, 422]


class TestThreatGroupGeneration:
    """Tests for threat group detection generation."""

    def test_generate_initiates_for_valid_group(self, client, ensure_shikari_running):
        """Test that generation initiates for a valid threat group."""
        response = client.post(
            "/generate",
            data={
                "group_name": "APT28",
                "run_correlation": "",
                "osint_enhancement": "on",
            },
            allow_redirects=False
        )

        # Should accept and redirect to progress page
        assert response.status_code in [200, 302, 303, 401]

    def test_progress_endpoint_returns_status(self, client, ensure_shikari_running):
        """Test that progress endpoint returns status for a group."""
        # First initiate a generation
        client.post(
            "/generate",
            data={"group_name": "APT29", "osint_enhancement": ""},
            allow_redirects=False
        )

        # Give it a moment to start
        time.sleep(2)

        # Check progress
        response = client.get(
            "/progress_status",
            params={"group_name": "APT29"}
        )

        assert response.status_code in [200, 401]
        data = response.json()

        # Should have progress info or indicate not found
        assert "progress" in data or "status" in data or "ok" in data

    @pytest.mark.parametrize("group_name", ["FIN7", "Sandworm Team"])
    def test_generate_with_various_groups(self, client, ensure_shikari_running, group_name):
        """Test generation initiation for various threat groups."""
        response = client.post(
            "/generate",
            data={
                "group_name": group_name,
                "osint_enhancement": "",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]


class TestThreatGroupOptions:
    """Tests for threat group generation options."""

    def test_generate_with_osint_enhancement(self, client, ensure_shikari_running):
        """Test generation with OSINT enhancement enabled."""
        response = client.post(
            "/generate",
            data={
                "group_name": "APT28",
                "osint_enhancement": "on",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_generate_with_correlation(self, client, ensure_shikari_running):
        """Test generation with correlation enabled."""
        response = client.post(
            "/generate",
            data={
                "group_name": "APT28",
                "run_correlation": "on",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_generate_with_all_options(self, client, ensure_shikari_running):
        """Test generation with all options enabled."""
        response = client.post(
            "/generate",
            data={
                "group_name": "APT29",
                "osint_enhancement": "on",
                "run_correlation": "on",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]


class TestThreatGroupResults:
    """Tests for threat group generation results."""

    def test_results_page_loads(self, client, ensure_shikari_running):
        """Test that results page loads for a group."""
        response = client.get(
            "/results",
            params={"group_name": "APT28"}
        )

        # Should either show results or indicate no results
        assert response.status_code in [200, 404]

    def test_results_api_returns_data(self, client, ensure_shikari_running):
        """Test results API endpoint."""
        response = client.get(
            "/api/results",
            params={"group_name": "APT28"}
        )

        # API should return JSON response
        assert response.status_code in [200, 404]
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, (dict, list))

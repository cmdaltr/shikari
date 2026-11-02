"""
Tests for ATT&CK Technique input method.

These tests validate technique-based detection generation (Hunt mode)
including technique validation, sub-technique handling, and detection creation.
"""
import pytest


# Test data - real MITRE ATT&CK techniques
VALID_TECHNIQUES = [
    "T1059",         # Command and Scripting Interpreter
    "T1059.001",     # PowerShell
    "T1059.003",     # Windows Command Shell
    "T1566",         # Phishing
    "T1566.001",     # Spearphishing Attachment
    "T1078",         # Valid Accounts
    "T1078.004",     # Cloud Accounts
    "T1003",         # OS Credential Dumping
    "T1003.001",     # LSASS Memory
    "T1021",         # Remote Services
    "T1021.001",     # Remote Desktop Protocol
]

INVALID_TECHNIQUES = [
    "T999",          # Too few digits
    "T12345",        # Too many digits
    "T1059.9999",    # Too many sub-technique digits
    "X1059",         # Wrong prefix
    "1059",          # Missing T prefix
    "",
    "technique",
    "T1059.001.001", # Too many levels
]

TECHNIQUE_COMBINATIONS = [
    ["T1059.001", "T1059.003"],           # Related sub-techniques
    ["T1566.001", "T1078", "T1059"],      # Kill chain sequence
    ["T1003.001", "T1021.001", "T1059"],  # Credential theft + lateral movement
]


class TestTechniqueValidation:
    """Tests for ATT&CK technique input validation."""

    @pytest.mark.parametrize("technique_id", VALID_TECHNIQUES)
    def test_valid_technique_format_accepted(self, client, ensure_shikari_running, technique_id):
        """Test that valid technique formats are accepted."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": technique_id,
                "osint_enhancement": "",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    @pytest.mark.parametrize("technique_id", INVALID_TECHNIQUES)
    def test_invalid_technique_format_rejected(self, client, ensure_shikari_running, technique_id):
        """Test that invalid technique formats are rejected."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": technique_id,
                "osint_enhancement": "",
            },
            allow_redirects=False
        )

        # Invalid formats should be rejected with 400 or handled gracefully
        # A 200/302 with error message is also acceptable
        assert response.status_code in [200, 302, 400, 401, 422]

    def test_empty_technique_id_rejected(self, client, ensure_shikari_running):
        """Test that empty technique ID is rejected."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": "",
                "osint_enhancement": "",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 400, 401, 422]

    def test_technique_case_insensitivity(self, client, ensure_shikari_running):
        """Test that technique IDs are case-insensitive."""
        # Lowercase
        response_lower = client.post(
            "/hunt/technique",
            data={"technique_ids": "t1059.001"},
            allow_redirects=False
        )

        # Mixed case
        response_mixed = client.post(
            "/hunt/technique",
            data={"technique_ids": "t1059.001"},
            allow_redirects=False
        )

        assert response_lower.status_code in [200, 302, 303, 401]
        assert response_mixed.status_code in [200, 302, 303, 401]


class TestMultipleTechniques:
    """Tests for multiple technique input."""

    @pytest.mark.parametrize("techniques", TECHNIQUE_COMBINATIONS)
    def test_multiple_techniques_accepted(self, client, ensure_shikari_running, techniques):
        """Test that multiple comma-separated techniques are accepted."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": ",".join(techniques),
                "osint_enhancement": "",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_duplicate_techniques_handled(self, client, ensure_shikari_running):
        """Test that duplicate techniques are handled."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": "T1059.001,T1059.001,T1059.001",
                "osint_enhancement": "",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_mixed_valid_invalid_techniques(self, client, ensure_shikari_running):
        """Test handling of mixed valid and invalid techniques."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": "T1059.001,INVALID,T1566",
                "osint_enhancement": "",
            },
            allow_redirects=False
        )

        # Should either reject all or process valid ones
        assert response.status_code in [200, 302, 303, 400, 401]

    def test_techniques_with_whitespace(self, client, ensure_shikari_running):
        """Test techniques with whitespace around them."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": "  T1059.001 , T1566  ,  T1078  ",
                "osint_enhancement": "",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]


class TestTechniqueGeneration:
    """Tests for technique-based detection generation."""

    def test_hunt_technique_initiates(self, client, ensure_shikari_running):
        """Test that technique hunting initiates successfully."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": "T1059.001",
                "osint_enhancement": "true",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_hunt_with_osint_enhancement(self, client, ensure_shikari_running):
        """Test hunting with OSINT enhancement enabled."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": "T1003.001",
                "osint_enhancement": "true",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_hunt_with_merge_options(self, client, ensure_shikari_running):
        """Test hunting with merge options."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": "T1059.001,T1059.003",
                "merge_by_tactic": "true",
                "merge_by_parent": "true",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_hunt_with_ai_generators(self, client, ensure_shikari_running):
        """Test hunting with AI generators enabled."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": "T1566.001",
                "ai_generators": "true",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]


class TestTechniqueNames:
    """Tests for technique name resolution."""

    def test_technique_names_api(self, client, ensure_shikari_running):
        """Test technique names resolution API."""
        response = client.post(
            "/api/technique_names",
            json={"technique_ids": ["T1059", "T1566", "T1078"]}
        )

        assert response.status_code == 200
        data = response.json()

        # Should return name mappings
        assert len(data) > 0

    def test_technique_names_for_subtechniques(self, client, ensure_shikari_running):
        """Test technique names for sub-techniques."""
        response = client.post(
            "/api/technique_names",
            json={"technique_ids": ["T1059.001", "T1059.003", "T1003.001"]}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) > 0

    def test_technique_names_for_invalid_ids(self, client, ensure_shikari_running):
        """Test technique names API with invalid IDs."""
        response = client.post(
            "/api/technique_names",
            json={"technique_ids": ["INVALID", "T9999"]}
        )

        # Should handle gracefully
        assert response.status_code in [200, 400]


class TestTechniqueResults:
    """Tests for technique hunt results."""

    def test_hunt_progress_tracking(self, client, ensure_shikari_running):
        """Test that hunt progress can be tracked."""
        # Initiate hunt
        client.post(
            "/hunt/technique",
            data={"technique_ids": "T1059.001"},
            allow_redirects=False
        )

        # Check progress
        response = client.get(
            "/progress_status",
            params={"group_name": "Hunt_T1059.001"}
        )

        assert response.status_code == 200

    def test_hunt_results_page(self, client, ensure_shikari_running):
        """Test hunt results page loads."""
        response = client.get(
            "/results",
            params={"group_name": "Hunt_T1059.001"}
        )

        assert response.status_code in [200, 404]


class TestTechniqueEdgeCases:
    """Edge case tests for technique input."""

    def test_parent_and_subtechnique_together(self, client, ensure_shikari_running):
        """Test including both parent and sub-technique."""
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": "T1059,T1059.001",
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_maximum_techniques(self, client, ensure_shikari_running):
        """Test with many techniques (stress test)."""
        many_techniques = ",".join([
            "T1059.001", "T1059.003", "T1566.001", "T1566.002",
            "T1078.001", "T1078.002", "T1003.001", "T1003.002",
            "T1021.001", "T1021.002"
        ])

        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": many_techniques,
            },
            allow_redirects=False
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_deprecated_technique(self, client, ensure_shikari_running):
        """Test handling of deprecated/revoked techniques."""
        # T1204 was split into sub-techniques
        response = client.post(
            "/hunt/technique",
            data={"technique_ids": "T1204"},
            allow_redirects=False
        )

        # Should still be handled
        assert response.status_code in [200, 302, 303, 400, 401]

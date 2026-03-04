"""
Integration Tests for Archer Web API.

Tests the FastAPI web endpoints, verifying response structure,
content, and error handling following the rivendell testing pattern.
"""
import pytest
import json
from pathlib import Path
from unittest.mock import MagicMock, patch


@pytest.mark.web
@pytest.mark.integration
class TestHealthEndpoints:
    """Test health and status endpoints."""

    def test_health_check(self, client):
        """Test health check endpoint returns correct status."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    def test_health_check_response_time(self, client):
        """Test health check responds quickly."""
        import time

        start = time.time()
        response = client.get("/health")
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 1.0  # Should respond in < 1 second


@pytest.mark.web
@pytest.mark.integration
class TestThreatGroupsAPI:
    """Test threat group lookup API."""

    def test_threat_groups_returns_groups(self, client, mock_mitre_bundle):
        """Test threat groups endpoint returns group data."""
        # Set the bundle directly on app.state
        client.app.state.bundle = mock_mitre_bundle
        try:
            response = client.get("/threat_groups?query=APT")

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert isinstance(data["groups"], list)
        finally:
            delattr(client.app.state, "bundle")

    def test_threat_groups_finds_by_name(self, client, mock_mitre_bundle):
        """Test finding groups by exact name."""
        client.app.state.bundle = mock_mitre_bundle
        try:
            response = client.get("/threat_groups?query=APT29")

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert any(g["name"] == "APT29" for g in data["groups"])
        finally:
            delattr(client.app.state, "bundle")

    def test_threat_groups_finds_by_alias(self, client, mock_mitre_bundle):
        """Test finding groups by alias."""
        client.app.state.bundle = mock_mitre_bundle
        try:
            response = client.get("/threat_groups?query=Cozy")

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            # Should find Cozy Bear alias
            assert any("Cozy" in g["name"] for g in data["groups"])
        finally:
            delattr(client.app.state, "bundle")

    def test_threat_groups_empty_query(self, client, mock_mitre_bundle):
        """Test threat groups with empty query."""
        client.app.state.bundle = mock_mitre_bundle
        try:
            response = client.get("/threat_groups?query=")

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            # Empty query returns all groups (limited to 10)
            assert isinstance(data["groups"], list)
        finally:
            delattr(client.app.state, "bundle")

    def test_threat_groups_no_results(self, client, mock_mitre_bundle):
        """Test threat groups with no matching results."""
        client.app.state.bundle = mock_mitre_bundle
        try:
            response = client.get("/threat_groups?query=NonExistentGroup12345")

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert data["groups"] == []
        finally:
            delattr(client.app.state, "bundle")

    def test_threat_groups_no_bundle(self, client):
        """Test threat groups when MITRE bundle not loaded."""
        # Ensure bundle is not set
        if hasattr(client.app.state, "bundle"):
            original_bundle = client.app.state.bundle
            client.app.state.bundle = None
        else:
            original_bundle = None
            client.app.state.bundle = None

        try:
            response = client.get("/threat_groups?query=APT")

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is False
            assert data["groups"] == []
        finally:
            if original_bundle is not None:
                client.app.state.bundle = original_bundle
            else:
                delattr(client.app.state, "bundle")


@pytest.mark.web
@pytest.mark.integration
class TestProgressStatusAPI:
    """Test progress tracking API."""

    def test_progress_status_returns_data(self, client, mock_dirs, sample_progress_data):
        """Test progress status returns progress data."""
        # Create progress file
        progress_file = mock_dirs["progress"] / "TestGroup.json"
        with open(progress_file, "w") as f:
            json.dump(sample_progress_data, f)

        with patch("archer.app.read_progress") as mock_read:
            mock_read.return_value = sample_progress_data

            response = client.get("/progress_status?group_name=TestGroup")

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert "progress" in data
            assert data["progress"]["status"] == "processing"

    def test_progress_status_missing_group_name(self, client):
        """Test progress status requires group_name parameter."""
        response = client.get("/progress_status")

        assert response.status_code == 400
        data = response.json()
        assert data["ok"] is False
        assert "group_name required" in data["error"]

    def test_progress_status_nonexistent_group(self, client):
        """Test progress status for non-existent group."""
        with patch("archer.app.read_progress") as mock_read:
            mock_read.return_value = {}

            response = client.get("/progress_status?group_name=NonExistent")

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert data["progress"] == {}


@pytest.mark.web
@pytest.mark.integration
class TestCorrelationsAPI:
    """Test correlation results API."""

    def test_correlations_returns_data(self, client, mock_dirs, sample_correlation_data):
        """Test correlations endpoint returns correlation data."""
        # Create correlation file
        corr_file = mock_dirs["correlate"] / "TestGroup.json"
        with open(corr_file, "w") as f:
            json.dump(sample_correlation_data, f)

        with patch("archer.app.CORRELATE_DIR", str(mock_dirs["correlate"])):
            response = client.get("/correlations/TestGroup.json")

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True
            assert "results" in data

    def test_correlations_not_found(self, client, mock_dirs):
        """Test correlations for non-existent group returns 404."""
        with patch("archer.app.CORRELATE_DIR", str(mock_dirs["correlate"])):
            response = client.get("/correlations/NonExistent.json")

            assert response.status_code == 404
            data = response.json()
            assert data["ok"] is False
            assert data["error"] == "not_found"


@pytest.mark.web
@pytest.mark.integration
class TestDraftsAPI:
    """Test draft save/load API."""

    def test_save_draft_success(self, client, mock_dirs, sample_draft_data):
        """Test saving a draft successfully."""
        with patch("archer.app.DRAFTS_DIR", str(mock_dirs["drafts"])):
            response = client.post(
                "/save_draft",
                json=sample_draft_data,
            )

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True

            # Verify file was created
            draft_file = mock_dirs["drafts"] / "test-draft-001.json"
            assert draft_file.exists()

    def test_save_draft_missing_draft_id(self, client, mock_dirs):
        """Test saving draft without draft_id fails."""
        with patch("archer.app.DRAFTS_DIR", str(mock_dirs["drafts"])):
            response = client.post(
                "/save_draft",
                json={"group_name": "APT29"},  # Missing draft_id
            )

            assert response.status_code == 400
            data = response.json()
            assert data["ok"] is False

    def test_save_draft_user_scoped(self, client, mock_dirs, sample_draft_data):
        """Test saving user-scoped draft."""
        user_draft = {**sample_draft_data, "user_id": "user123"}

        with patch("archer.app.DRAFTS_DIR", str(mock_dirs["drafts"])):
            response = client.post(
                "/save_draft",
                json=user_draft,
                headers={"X-USER-ID": "user123"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True

            # Verify file in user directory
            user_draft_file = mock_dirs["drafts"] / "users" / "user123" / "test-draft-001.json"
            assert user_draft_file.exists()

    def test_save_draft_user_id_mismatch(self, client, mock_dirs, sample_draft_data):
        """Test saving draft with mismatched user_id header."""
        user_draft = {**sample_draft_data, "user_id": "user123"}

        with patch("archer.app.DRAFTS_DIR", str(mock_dirs["drafts"])):
            response = client.post(
                "/save_draft",
                json=user_draft,
                headers={"X-USER-ID": "different_user"},  # Mismatch
            )

            assert response.status_code == 403
            data = response.json()
            assert data["ok"] is False
            assert "mismatch" in data["error"]

    def test_load_draft_success(self, client, mock_dirs, sample_draft_data):
        """Test loading an existing draft."""
        # Create draft file
        draft_file = mock_dirs["drafts"] / "test-draft-001.json"
        with open(draft_file, "w") as f:
            json.dump(sample_draft_data, f)

        with patch("archer.app.DRAFTS_DIR", str(mock_dirs["drafts"])):
            response = client.get("/load_draft?draft_id=test-draft-001")

            assert response.status_code == 200
            data = response.json()
            assert data["ok"] is True

    def test_load_draft_missing_draft_id(self, client):
        """Test loading draft without draft_id fails."""
        response = client.get("/load_draft")

        assert response.status_code == 400
        data = response.json()
        assert data["ok"] is False


@pytest.mark.web
@pytest.mark.integration
class TestBlogAnalysisAPI:
    """Test blog analysis API."""

    def test_analyze_blog_success(self, client, mock_dirs, sample_blog_analysis):
        """Test successful blog analysis."""
        with patch("archer.parsers.blog_analyzer.analyze_blog_post") as mock_analyze, \
             patch("archer.app.BLOG_DIR", str(mock_dirs["blog"])):

            mock_analyze.return_value = sample_blog_analysis

            response = client.post(
                "/analyze_blog",
                data={"url": "https://example.com/threat-report"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["show_extraction"] is True
            assert "ttps" in data
            assert "T1566.001" in data["ttps"]
            assert data["ttps_count"] == 3

    def test_analyze_blog_empty_url(self, client):
        """Test blog analysis with empty URL."""
        response = client.post(
            "/analyze_blog",
            data={"url": ""},
        )

        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
        assert "No URL" in data["message"]

    def test_analyze_blog_invalid_scheme(self, client, mock_dirs):
        """Test blog analysis rejects invalid URL schemes."""
        with patch("archer.parsers.blog_analyzer.analyze_blog_post") as mock_analyze, \
             patch("archer.app.BLOG_DIR", str(mock_dirs["blog"])):

            mock_analyze.return_value = {
                "success": False,
                "error": "Invalid URL scheme: ftp"
            }

            response = client.post(
                "/analyze_blog",
                data={"url": "ftp://example.com/file"},
            )

            assert response.status_code == 400
            data = response.json()
            assert data["success"] is False

    def test_analyze_blog_ssrf_blocked(self, client, mock_dirs):
        """Test blog analysis blocks SSRF attempts."""
        with patch("archer.parsers.blog_analyzer.analyze_blog_post") as mock_analyze, \
             patch("archer.app.BLOG_DIR", str(mock_dirs["blog"])):

            mock_analyze.return_value = {
                "success": False,
                "error": "localhost not allowed"
            }

            response = client.post(
                "/analyze_blog",
                data={"url": "http://localhost/admin"},
            )

            assert response.status_code == 403
            data = response.json()
            assert data["success"] is False

    def test_analyze_blog_private_ip_blocked(self, client, mock_dirs):
        """Test blog analysis blocks private IPs."""
        with patch("archer.parsers.blog_analyzer.analyze_blog_post") as mock_analyze, \
             patch("archer.app.BLOG_DIR", str(mock_dirs["blog"])):

            mock_analyze.return_value = {
                "success": False,
                "error": "Private IP addresses not allowed"
            }

            response = client.post(
                "/analyze_blog",
                data={"url": "http://192.168.1.1/admin"},
            )

            assert response.status_code == 403
            data = response.json()
            assert data["success"] is False

    def test_analyze_blog_extracts_iocs(self, client, mock_dirs, sample_blog_analysis):
        """Test blog analysis extracts IOCs."""
        with patch("archer.parsers.blog_analyzer.analyze_blog_post") as mock_analyze, \
             patch("archer.app.BLOG_DIR", str(mock_dirs["blog"])):

            mock_analyze.return_value = sample_blog_analysis

            response = client.post(
                "/analyze_blog",
                data={"url": "https://example.com/threat-report"},
            )

            assert response.status_code == 200
            data = response.json()
            assert "iocs" in data
            assert data["iocs_count"] == 2  # 1 domain + 1 IP


@pytest.mark.web
@pytest.mark.integration
class TestListDraftsAPI:
    """Test draft listing API."""

    def test_list_drafts_returns_drafts_key(self, client):
        """Test listing drafts returns proper structure with drafts key."""
        response = client.get("/list_drafts")

        assert response.status_code == 200
        data = response.json()
        # Response is {"ok": True, "drafts": []} or just a list
        if isinstance(data, dict):
            assert "ok" in data or "drafts" in data
            if "drafts" in data:
                assert isinstance(data["drafts"], list)
        else:
            assert isinstance(data, list)

    def test_list_drafts_with_user_id(self, client):
        """Test listing drafts with user_id parameter."""
        response = client.get("/list_drafts?user_id=testuser")

        assert response.status_code == 200
        data = response.json()
        # Response structure varies
        if isinstance(data, dict):
            assert "ok" in data or "drafts" in data
        else:
            assert isinstance(data, list)

    def test_list_drafts_success(self, client):
        """Test that list_drafts succeeds without error."""
        response = client.get("/list_drafts")

        assert response.status_code == 200
        data = response.json()
        # Just verify we got a valid response
        assert data is not None


@pytest.mark.web
@pytest.mark.integration
class TestAPIErrorHandling:
    """Test API error handling."""

    def test_invalid_json_body(self, client):
        """Test handling of invalid JSON in request body."""
        response = client.post(
            "/save_draft",
            content="{ invalid json }",
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 400

    def test_missing_required_form_field(self, client):
        """Test handling of missing required form fields."""
        response = client.post("/analyze_blog", data={})

        assert response.status_code == 422  # FastAPI validation error


@pytest.mark.web
@pytest.mark.integration
class TestAPIPerformance:
    """Test API performance benchmarks."""

    def test_threat_groups_performance(self, client, mock_mitre_bundle):
        """Test threat groups query responds quickly."""
        import time

        client.app.state.bundle = mock_mitre_bundle
        try:
            start = time.time()
            response = client.get("/threat_groups?query=APT")
            duration = time.time() - start

            assert response.status_code == 200
            assert duration < 2.0  # Should respond in < 2 seconds
        finally:
            delattr(client.app.state, "bundle")

    def test_progress_status_performance(self, client):
        """Test progress status responds quickly."""
        import time

        with patch("archer.app.read_progress") as mock_read:
            mock_read.return_value = {}

            start = time.time()
            response = client.get("/progress_status?group_name=Test")
            duration = time.time() - start

            assert response.status_code == 200
            assert duration < 1.0  # Should respond in < 1 second

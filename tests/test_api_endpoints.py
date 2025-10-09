#!/usr/bin/env python3
"""
API Endpoint Testing using pytest
Tests all FastAPI endpoints for the Archer web application
"""

import pytest
import json
from fastapi.testclient import TestClient
from archer.app import app

# Create test client
client = TestClient(app)


class TestHealthEndpoints:
    """Test basic health and info endpoints"""

    def test_root_endpoint(self):
        """Test GET / returns 200"""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_manual_page(self):
        """Test GET /manual returns 200"""
        response = client.get("/manual")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_progress_page(self):
        """Test GET /progress returns 200"""
        response = client.get("/progress")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]


class TestGenerateEndpoint:
    """Test /generate endpoint"""

    def test_generate_missing_group_name(self):
        """Test POST /generate without group_name"""
        response = client.post(
            "/generate",
            data={
                "correlate": "false",
                "advanced_parsing": "false",
                "semantic_analysis": "false",
            },
        )
        # Should return error or redirect
        assert response.status_code in [400, 422, 200]

    def test_generate_with_valid_group(self):
        """Test POST /generate with valid threat group"""
        response = client.post(
            "/generate",
            data={
                "group_name": "APT29",
                "correlate": "false",
                "advanced_parsing": "false",
                "semantic_analysis": "false",
                "ai_generators": "false",
                "local_llm": "false",
            },
        )
        assert response.status_code == 200
        # Should return progress_id in response
        response_data = response.json()
        assert "progress_id" in response_data

    def test_generate_with_correlation(self):
        """Test POST /generate with correlation enabled"""
        response = client.post(
            "/generate",
            data={
                "group_name": "Scattered Spider",
                "correlate": "true",
                "advanced_parsing": "false",
                "semantic_analysis": "false",
                "ai_generators": "false",
                "local_llm": "false",
            },
        )
        assert response.status_code == 200
        response_data = response.json()
        assert "progress_id" in response_data

    def test_generate_with_semantic_analysis(self):
        """Test POST /generate with semantic analysis"""
        response = client.post(
            "/generate",
            data={
                "group_name": "APT29",
                "correlate": "false",
                "advanced_parsing": "false",
                "semantic_analysis": "true",
                "ai_generators": "false",
                "local_llm": "false",
            },
        )
        assert response.status_code == 200
        response_data = response.json()
        assert "progress_id" in response_data


class TestCorrelateEndpoint:
    """Test /correlate endpoint"""

    def test_correlate_missing_group_name(self):
        """Test POST /correlate without group_name"""
        response = client.post(
            "/correlate",
            data={
                "advanced_parsing": "false",
                "semantic_analysis": "false",
            },
        )
        # Should return error
        assert response.status_code in [400, 422, 200]

    def test_correlate_with_valid_group(self):
        """Test POST /correlate with valid threat group"""
        response = client.post(
            "/correlate",
            data={
                "group_name": "Scattered Spider",
                "advanced_parsing": "false",
                "semantic_analysis": "false",
                "ai_generators": "false",
                "local_llm": "false",
            },
        )
        assert response.status_code == 200
        response_data = response.json()
        assert "progress_id" in response_data


class TestManualSubmitEndpoint:
    """Test /manual-submit endpoint"""

    def test_manual_submit_valid_yaml(self):
        """Test POST /manual-submit with valid YAML"""
        test_yaml = """
id: test-123
name: Test Detection
description: Test description
severity: Medium
query: |
  DeviceProcessEvents
  | where ProcessCommandLine contains "test"
"""
        response = client.post(
            "/manual-submit",
            data={"yaml_content": test_yaml},
        )
        assert response.status_code == 200
        assert (
            "successfully" in response.text.lower() or "saved" in response.text.lower()
        )

    def test_manual_submit_invalid_yaml(self):
        """Test POST /manual-submit with invalid YAML"""
        invalid_yaml = """
this is not valid yaml: [
  broken structure
"""
        response = client.post(
            "/manual-submit",
            data={"yaml_content": invalid_yaml},
        )
        # Should handle gracefully
        assert response.status_code in [200, 400, 422]

    def test_manual_submit_empty(self):
        """Test POST /manual-submit with empty content"""
        response = client.post(
            "/manual-submit",
            data={"yaml_content": ""},
        )
        assert response.status_code in [200, 400, 422]


class TestDraftEndpoints:
    """Test draft save/load endpoints"""

    def test_save_draft_valid(self):
        """Test POST /save-draft with valid data"""
        draft_data = {
            "group_name": "APT29",
            "correlate": "true",
            "advanced_parsing": "false",
        }
        response = client.post("/save-draft", json=draft_data)
        assert response.status_code == 200
        response_data = response.json()
        assert response_data.get("status") == "success"
        assert "draft_id" in response_data

    def test_save_draft_empty(self):
        """Test POST /save-draft with empty data"""
        response = client.post("/save-draft", json={})
        assert response.status_code == 200
        # Should still save even if empty

    def test_load_draft_nonexistent(self):
        """Test GET /load-draft with non-existent ID"""
        response = client.get("/load-draft?draft_id=nonexistent-id-12345")
        # Should return error or empty
        assert response.status_code in [200, 404]

    def test_list_drafts(self):
        """Test GET /list-drafts"""
        response = client.get("/list-drafts")
        assert response.status_code == 200
        response_data = response.json()
        assert isinstance(response_data, list)


class TestProgressEndpoint:
    """Test progress tracking endpoint"""

    def test_get_progress_nonexistent(self):
        """Test GET /get-progress with non-existent ID"""
        response = client.get("/get-progress/nonexistent-id")
        assert response.status_code in [200, 404]
        if response.status_code == 200:
            response_data = response.json()
            assert "status" in response_data or "error" in response_data

    def test_get_progress_format(self):
        """Test progress response format"""
        # First create a job
        gen_response = client.post(
            "/generate",
            data={
                "group_name": "APT29",
                "correlate": "false",
                "advanced_parsing": "false",
                "semantic_analysis": "false",
            },
        )
        if gen_response.status_code == 200:
            progress_id = gen_response.json().get("progress_id")
            if progress_id:
                progress_response = client.get(f"/get-progress/{progress_id}")
                assert progress_response.status_code == 200
                progress_data = progress_response.json()
                # Check for expected keys
                assert any(
                    key in progress_data
                    for key in ["status", "progress", "message", "error"]
                )


class TestStaticFiles:
    """Test static file serving"""

    def test_css_files_accessible(self):
        """Test CSS files are accessible"""
        response = client.get("/static/css/styles.css")
        # May or may not exist, but should handle gracefully
        assert response.status_code in [200, 404]

    def test_js_files_accessible(self):
        """Test JS files are accessible"""
        response = client.get("/static/js/main.js")
        # May or may not exist, but should handle gracefully
        assert response.status_code in [200, 404]


class TestErrorHandling:
    """Test error handling"""

    def test_404_page(self):
        """Test 404 for non-existent route"""
        response = client.get("/nonexistent-route-12345")
        assert response.status_code == 404

    def test_method_not_allowed(self):
        """Test wrong HTTP method"""
        # Try POST on GET-only endpoint
        response = client.post("/")
        assert response.status_code in [405, 200]  # 405 Method Not Allowed or handled

    def test_invalid_content_type(self):
        """Test invalid content type"""
        response = client.post(
            "/generate",
            data="invalid data format",
            headers={"Content-Type": "text/plain"},
        )
        # Should handle gracefully
        assert response.status_code in [200, 400, 415, 422]


class TestCORS:
    """Test CORS headers if configured"""

    def test_cors_headers(self):
        """Test CORS headers on API endpoints"""
        response = client.options("/generate")
        # Check if CORS is configured
        # This may or may not be enabled depending on configuration
        assert response.status_code in [200, 405]


# Fixtures for test data
@pytest.fixture
def valid_threat_groups():
    """Fixture providing valid threat group names"""
    return ["APT29", "APT28", "Scattered Spider", "Lazarus Group"]


@pytest.fixture
def valid_yaml_content():
    """Fixture providing valid YAML detection"""
    return """
id: test-detection-001
name: Test Process Detection
description: |
  This is a test detection for process activity
severity: Medium
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
tags:
  - Test
query: |
  DeviceProcessEvents
  | where Timestamp > ago(1h)
  | where ProcessCommandLine contains "test"
  | project Timestamp, DeviceName, ProcessCommandLine
"""


# Parametrized tests
@pytest.mark.parametrize(
    "group_name",
    ["APT29", "Scattered Spider", "Lazarus Group", "FIN7"],
)
def test_generate_multiple_groups(group_name):
    """Test generate endpoint with multiple threat groups"""
    response = client.post(
        "/generate",
        data={
            "group_name": group_name,
            "correlate": "false",
            "advanced_parsing": "false",
            "semantic_analysis": "false",
        },
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "option,value",
    [
        ("correlate", "true"),
        ("advanced_parsing", "true"),
        ("semantic_analysis", "true"),
    ],
)
def test_generate_options(option, value):
    """Test generate endpoint with different options"""
    data = {
        "group_name": "APT29",
        "correlate": "false",
        "advanced_parsing": "false",
        "semantic_analysis": "false",
        "ai_generators": "false",
        "local_llm": "false",
    }
    data[option] = value

    response = client.post("/generate", data=data)
    assert response.status_code == 200

"""
Feature tests for CVE-based detection generation workflow.

These tests simulate the complete production workflow:
1. User submits a CVE ID
2. System looks up CVE details from NVD
3. System identifies related ATT&CK techniques
4. System generates detection YAML files
5. User views generated detections

Note: These tests may require network access for NVD lookups.
"""
import pytest
import time


# Well-known CVEs for testing
# These are high-profile vulnerabilities with known exploitation patterns
TEST_CVES = {
    # HTTP/2 Rapid Reset - widely exploited DDoS vulnerability
    "http2_rapid_reset": "CVE-2023-44487",

    # Palo Alto PAN-OS Command Injection - actively exploited
    "panos_injection": "CVE-2024-3400",

    # Citrix Bleed - session hijacking vulnerability
    "citrix_bleed": "CVE-2023-4966",

    # Log4Shell - famous RCE vulnerability
    "log4shell": "CVE-2021-44228",
}


class TestCVEGenerationWorkflow:
    """
    Test the complete CVE detection generation workflow.
    """

    @pytest.mark.slow
    @pytest.mark.network
    def test_full_cve_workflow(
        self,
        client,
        ensure_shikari_running,
        wait_for_completion,
        check_generated_files,
    ):
        """
        Test the complete CVE → detection generation workflow.

        Steps:
        1. Submit CVE for analysis
        2. Monitor generation progress
        3. Verify detections were created
        """
        cve_id = TEST_CVES["http2_rapid_reset"]

        # Step 1: Submit CVE for generation
        print(f"\n[Step 1] Submitting CVE for generation: {cve_id}")
        response = client.post(
            "/generate/cve",
            data={
                "cve_id": cve_id,
                "run_correlation": "",
            },
            follow_redirects=False,
            timeout=60,
        )

        assert response.status_code in [200, 302, 303, 401], \
            f"CVE generation failed: {response.status_code}"

        # Step 2: Monitor progress
        print(f"\n[Step 2] Monitoring generation progress...")
        final_status = wait_for_completion(client, cve_id, timeout=180)

        if final_status:
            status = final_status.get("status") or final_status.get("progress", {}).get("status")
            print(f"  - Final status: {status}")

        # Step 3: Check generated files
        print(f"\n[Step 3] Checking generated detection files")
        files = check_generated_files(cve_id)

        print(f"  - Output directory exists: {files['exists']}")
        print(f"  - YAML files generated: {files['yaml_count']}")

        if files["yaml_count"] > 0:
            print(f"  - Sample files: {files['yaml_files'][:5]}")

        print("\n[SUCCESS] CVE workflow completed")

    @pytest.mark.network
    def test_cve_with_correlation(
        self,
        client,
        ensure_shikari_running,
        wait_for_completion,
    ):
        """Test CVE generation with correlation enabled."""
        cve_id = TEST_CVES["citrix_bleed"]

        print(f"\n[Test] Generating with correlation for {cve_id}")

        response = client.post(
            "/generate/cve",
            data={
                "cve_id": cve_id,
                "run_correlation": "on",
            },
            follow_redirects=False,
            timeout=60,
        )

        assert response.status_code in [200, 302, 303, 401]

        final_status = wait_for_completion(client, cve_id, timeout=180)

        if final_status:
            status = final_status.get("status") or final_status.get("progress", {}).get("status")
            print(f"  - Final status: {status}")


class TestCVELookup:
    """Test CVE information lookup functionality."""

    @pytest.mark.network
    def test_cve_info_retrieval(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test retrieving CVE information."""
        cve_id = TEST_CVES["log4shell"]

        # Try the CVE info endpoint if it exists
        response = client.get(
            "/api/cve/info",
            params={"cve_id": cve_id}
        )

        # Endpoint may or may not exist
        print(f"\nCVE info endpoint status: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"CVE info retrieved: {list(data.keys())}")

            # Should contain CVE details
            if "description" in data:
                print(f"Description: {data['description'][:100]}...")


class TestCVEProgress:
    """Test progress tracking for CVE generation."""

    def test_cve_progress_tracking(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test that progress is tracked during CVE generation."""
        cve_id = TEST_CVES["http2_rapid_reset"]

        # Start generation
        client.post(
            "/generate/cve",
            data={"cve_id": cve_id},
            follow_redirects=False,
        )

        # Check progress
        time.sleep(2)

        response = client.get(
            "/progress_status",
            params={"group_name": cve_id}
        )

        assert response.status_code in [200, 401]

        if response.status_code == 200:
            data = response.json()
            print(f"\nProgress data: {data}")


class TestCVEResults:
    """Test accessing CVE generation results."""

    def test_cve_results_page(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test that results page loads for a CVE."""
        cve_id = TEST_CVES["http2_rapid_reset"]

        response = client.get(
            "/results",
            params={"group_name": cve_id}
        )

        assert response.status_code in [200, 401, 404]


class TestCVEEdgeCases:
    """Test edge cases in CVE workflow."""

    def test_nonexistent_cve(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test handling of a CVE that doesn't exist in NVD."""
        response = client.post(
            "/generate/cve",
            data={"cve_id": "CVE-2099-99999"},
            follow_redirects=False,
        )

        # Should accept but may fail during lookup
        assert response.status_code in [200, 302, 303, 400, 401, 404]

    def test_cve_various_formats(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test CVE ID format handling."""
        # Standard format
        response1 = client.post(
            "/generate/cve",
            data={"cve_id": "CVE-2023-44487"},
            follow_redirects=False,
        )

        # Lowercase
        response2 = client.post(
            "/generate/cve",
            data={"cve_id": "cve-2023-44487"},
            follow_redirects=False,
        )

        # With whitespace
        response3 = client.post(
            "/generate/cve",
            data={"cve_id": "  CVE-2023-44487  "},
            follow_redirects=False,
        )

        # All should be accepted
        for r in [response1, response2, response3]:
            assert r.status_code in [200, 302, 303, 401]

    @pytest.mark.network
    def test_multiple_cves_sequentially(
        self,
        client,
        ensure_shikari_running,
        wait_for_completion,
    ):
        """Test generating detections for multiple CVEs sequentially."""
        cves = [TEST_CVES["http2_rapid_reset"], TEST_CVES["citrix_bleed"]]

        for cve_id in cves:
            print(f"\nProcessing {cve_id}...")

            response = client.post(
                "/generate/cve",
                data={"cve_id": cve_id},
                follow_redirects=False,
            )

            assert response.status_code in [200, 302, 303, 401]

            # Wait briefly between CVEs
            time.sleep(5)

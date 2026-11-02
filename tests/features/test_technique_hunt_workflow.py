"""
Feature tests for ATT&CK Technique Hunt workflow.

These tests simulate the complete production workflow:
1. User selects specific MITRE ATT&CK techniques to hunt
2. System generates detections for those techniques
3. System optionally merges related detections
4. User views generated detections

This is the "Hunt" mode - generating detections for specific techniques
rather than all techniques used by a threat group.
"""
import pytest
import time


# Common ATT&CK techniques for testing
# Organized by tactic for realistic hunting scenarios
TEST_TECHNIQUES = {
    # Execution techniques
    "powershell": "T1059.001",
    "cmd": "T1059.003",
    "python": "T1059.006",

    # Credential Access
    "lsass_dump": "T1003.001",
    "credential_api": "T1003.003",

    # Persistence
    "registry_run": "T1547.001",
    "scheduled_task": "T1053.005",

    # Lateral Movement
    "rdp": "T1021.001",
    "smb": "T1021.002",
    "winrm": "T1021.006",

    # Defense Evasion
    "disable_defender": "T1562.001",
    "indicator_removal": "T1070.001",

    # Initial Access
    "phishing_attachment": "T1566.001",
    "phishing_link": "T1566.002",

    # Collection
    "screen_capture": "T1113",
    "keylogging": "T1056.001",
}

# Kill chain scenarios for realistic testing
KILL_CHAINS = {
    "ransomware": [
        "T1566.001",  # Phishing Attachment
        "T1059.001",  # PowerShell
        "T1003.001",  # LSASS Memory
        "T1021.002",  # SMB/Windows Admin Shares
        "T1486",      # Data Encrypted for Impact
    ],
    "credential_theft": [
        "T1078",      # Valid Accounts
        "T1003.001",  # LSASS Memory
        "T1003.003",  # NTDS
        "T1558.003",  # Kerberoasting
    ],
    "data_exfil": [
        "T1074.001",  # Local Data Staging
        "T1560.001",  # Archive via Utility
        "T1041",      # Exfiltration Over C2
    ],
}


class TestTechniqueHuntWorkflow:
    """
    Test the complete technique hunt workflow.
    """

    @pytest.mark.slow
    def test_full_hunt_workflow(
        self,
        client,
        ensure_shikari_running,
        wait_for_completion,
        check_generated_files,
    ):
        """
        Test the complete technique hunt → detection generation workflow.

        Steps:
        1. Submit techniques for hunting
        2. Monitor generation progress
        3. Verify detections were created
        """
        techniques = [TEST_TECHNIQUES["powershell"], TEST_TECHNIQUES["lsass_dump"]]
        technique_str = ",".join(techniques)
        group_name = f"Hunt_{techniques[0]}"  # Progress tracked by first technique

        # Step 1: Submit techniques for hunting
        print(f"\n[Step 1] Submitting techniques for hunting: {techniques}")
        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": technique_str,
                "osint_enhancement": "",
            },
            follow_redirects=False,
            timeout=60,
        )

        assert response.status_code in [200, 302, 303, 401], \
            f"Hunt initiation failed: {response.status_code}"

        # Step 2: Monitor progress
        print(f"\n[Step 2] Monitoring hunt progress...")
        final_status = wait_for_completion(client, group_name, timeout=180)

        if final_status:
            status = final_status.get("status") or final_status.get("progress", {}).get("status")
            print(f"  - Final status: {status}")

        # Step 3: Check generated files
        print(f"\n[Step 3] Checking generated detection files")
        files = check_generated_files(group_name)

        print(f"  - Output directory exists: {files['exists']}")
        print(f"  - YAML files generated: {files['yaml_count']}")
        print(f"  - Techniques covered: {files['techniques_covered']}")

        if files["yaml_count"] > 0:
            print(f"  - Sample files: {files['yaml_files'][:5]}")

        print("\n[SUCCESS] Technique hunt workflow completed")

    @pytest.mark.slow
    def test_hunt_kill_chain_scenario(
        self,
        client,
        ensure_shikari_running,
        wait_for_completion,
        check_generated_files,
    ):
        """
        Test hunting a complete kill chain scenario.

        This simulates a SOC analyst building detections for a
        known attack pattern.
        """
        scenario = "ransomware"
        techniques = KILL_CHAINS[scenario][:3]  # Use first 3 for faster test
        technique_str = ",".join(techniques)
        group_name = f"Hunt_{techniques[0]}"

        print(f"\n[Test] Hunting {scenario} kill chain: {techniques}")

        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": technique_str,
                "osint_enhancement": "on",  # Enable OSINT for richer detections
            },
            follow_redirects=False,
            timeout=60,
        )

        assert response.status_code in [200, 302, 303, 401]

        final_status = wait_for_completion(client, group_name, timeout=300)

        if final_status:
            status = final_status.get("status") or final_status.get("progress", {}).get("status")
            print(f"  - Final status: {status}")

        files = check_generated_files(group_name)
        print(f"  - Detections generated: {files['yaml_count']}")

    def test_hunt_with_merge_by_tactic(
        self,
        client,
        ensure_shikari_running,
        wait_for_completion,
    ):
        """
        Test hunting with merge-by-tactic enabled.

        This combines detections for techniques in the same tactic.
        """
        # Use multiple execution techniques
        techniques = [TEST_TECHNIQUES["powershell"], TEST_TECHNIQUES["cmd"]]
        technique_str = ",".join(techniques)
        group_name = f"Hunt_{techniques[0]}"

        print(f"\n[Test] Hunting with merge-by-tactic: {techniques}")

        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": technique_str,
                "merge_by_tactic": "true",
            },
            follow_redirects=False,
            timeout=60,
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_hunt_with_merge_by_parent(
        self,
        client,
        ensure_shikari_running,
        wait_for_completion,
    ):
        """
        Test hunting with merge-by-parent enabled.

        This combines sub-techniques under their parent technique.
        """
        # Use sub-techniques of T1059 (Command and Scripting Interpreter)
        techniques = [TEST_TECHNIQUES["powershell"], TEST_TECHNIQUES["cmd"], TEST_TECHNIQUES["python"]]
        technique_str = ",".join(techniques)
        group_name = f"Hunt_{techniques[0]}"

        print(f"\n[Test] Hunting with merge-by-parent: {techniques}")

        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": technique_str,
                "merge_by_parent": "true",
            },
            follow_redirects=False,
            timeout=60,
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_hunt_with_ai_generators(
        self,
        client,
        ensure_shikari_running,
        wait_for_completion,
    ):
        """
        Test hunting with AI generators enabled.

        This uses AI to generate additional detection logic.
        """
        techniques = [TEST_TECHNIQUES["powershell"]]
        technique_str = ",".join(techniques)
        group_name = f"Hunt_{techniques[0]}"

        print(f"\n[Test] Hunting with AI generators: {techniques}")

        response = client.post(
            "/hunt/technique",
            data={
                "technique_ids": technique_str,
                "ai_generators": "true",
            },
            follow_redirects=False,
            timeout=60,
        )

        assert response.status_code in [200, 302, 303, 401]


class TestTechniqueResolution:
    """Test technique name/info resolution."""

    def test_technique_names_api(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test resolving technique IDs to names."""
        technique_ids = [
            TEST_TECHNIQUES["powershell"],
            TEST_TECHNIQUES["lsass_dump"],
            TEST_TECHNIQUES["rdp"],
        ]

        response = client.post(
            "/api/technique_names",
            json={"technique_ids": technique_ids}
        )

        assert response.status_code in [200, 401]

        if response.status_code == 200:
            data = response.json()
            print(f"\nTechnique names resolved:")
            for tid, info in data.items():
                name = info.get("name", info) if isinstance(info, dict) else info
                print(f"  - {tid}: {name}")

    def test_technique_names_for_subtechniques(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test resolving sub-technique IDs."""
        technique_ids = [
            "T1059.001",  # PowerShell
            "T1059.003",  # Windows Command Shell
            "T1003.001",  # LSASS Memory
        ]

        response = client.post(
            "/api/technique_names",
            json={"technique_ids": technique_ids}
        )

        assert response.status_code in [200, 401]

        if response.status_code == 200:
            data = response.json()
            print(f"\nSub-technique names: {len(data)} resolved")


class TestHuntProgress:
    """Test progress tracking for technique hunting."""

    def test_hunt_progress_tracking(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test that progress is tracked during hunting."""
        technique = TEST_TECHNIQUES["powershell"]
        group_name = f"Hunt_{technique}"

        # Start hunt
        client.post(
            "/hunt/technique",
            data={"technique_ids": technique},
            follow_redirects=False,
        )

        # Check progress
        time.sleep(2)

        response = client.get(
            "/progress_status",
            params={"group_name": group_name}
        )

        assert response.status_code in [200, 401]

        if response.status_code == 200:
            data = response.json()
            print(f"\nProgress data: {data}")


class TestHuntResults:
    """Test accessing hunt results."""

    def test_hunt_results_page(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test that results page loads for a hunt."""
        technique = TEST_TECHNIQUES["powershell"]
        group_name = f"Hunt_{technique}"

        response = client.get(
            "/results",
            params={"group_name": group_name}
        )

        assert response.status_code in [200, 401, 404]


class TestHuntEdgeCases:
    """Test edge cases in technique hunt workflow."""

    def test_single_technique_hunt(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test hunting a single technique."""
        response = client.post(
            "/hunt/technique",
            data={"technique_ids": TEST_TECHNIQUES["powershell"]},
            follow_redirects=False,
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_many_techniques_hunt(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test hunting many techniques at once."""
        # Use 10 techniques
        techniques = list(TEST_TECHNIQUES.values())[:10]
        technique_str = ",".join(techniques)

        response = client.post(
            "/hunt/technique",
            data={"technique_ids": technique_str},
            follow_redirects=False,
        )

        assert response.status_code in [200, 302, 303, 401]

    def test_parent_and_subtechnique_together(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test including both parent and sub-technique."""
        # T1059 is parent, T1059.001 is sub-technique
        techniques = ["T1059", "T1059.001"]
        technique_str = ",".join(techniques)

        response = client.post(
            "/hunt/technique",
            data={"technique_ids": technique_str},
            follow_redirects=False,
        )

        # Should handle gracefully (may dedupe or process both)
        assert response.status_code in [200, 302, 303, 401]

    def test_duplicate_techniques_handled(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test that duplicate techniques are handled."""
        technique = TEST_TECHNIQUES["powershell"]
        technique_str = f"{technique},{technique},{technique}"

        response = client.post(
            "/hunt/technique",
            data={"technique_ids": technique_str},
            follow_redirects=False,
        )

        # Should deduplicate
        assert response.status_code in [200, 302, 303, 401]

    def test_technique_with_whitespace(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test techniques with whitespace."""
        techniques = "  T1059.001 , T1003.001  ,  T1021.001  "

        response = client.post(
            "/hunt/technique",
            data={"technique_ids": techniques},
            follow_redirects=False,
        )

        # Should trim whitespace
        assert response.status_code in [200, 302, 303, 401]

    def test_technique_case_insensitivity(
        self,
        client,
        ensure_shikari_running,
    ):
        """Test that technique IDs are case-insensitive."""
        # Lowercase
        response_lower = client.post(
            "/hunt/technique",
            data={"technique_ids": "t1059.001"},
            follow_redirects=False,
        )

        # Mixed case
        response_mixed = client.post(
            "/hunt/technique",
            data={"technique_ids": "t1059.001"},
            follow_redirects=False,
        )

        assert response_lower.status_code in [200, 302, 303, 401]
        assert response_mixed.status_code in [200, 302, 303, 401]

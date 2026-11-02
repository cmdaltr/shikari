"""
VECTR Test Case Management

Maps Shikari detections to VECTR test cases for tracking and validation.
"""

import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
from .client import VECTRClient


class TestCaseManager:
    """Manages VECTR test cases for detection validation."""

    def __init__(self, client: Optional[VECTRClient] = None):
        """
        Initialize test case manager.

        Args:
            client: VECTR API client (creates new if not provided)
        """
        self.client = client or VECTRClient()

    def create_detection_test_case(
        self,
        campaign_id: str,
        detection_yaml: str,
        environment: Optional[str] = None,
        operator_guidance: Optional[str] = None,
        red_tools: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a VECTR test case from an Shikari detection YAML.

        Args:
            campaign_id: Parent campaign ID
            detection_yaml: Path to detection YAML file
            environment: Test environment name
            operator_guidance: Additional guidance for operators
            red_tools: Red team tools to use for testing

        Returns:
            Created test case object
        """
        # Load detection YAML
        with open(detection_yaml, "r", encoding="utf-8") as f:
            detection = yaml.safe_load(f)

        # Extract detection details
        name = detection.get("name", "Unknown Detection")
        description = detection.get("description", "")
        techniques = detection.get("relevantTechniques", [])
        tactics = detection.get("relevantTactics", [])
        platforms = detection.get("platforms", [])
        query = detection.get("query", "")

        # Build test case
        testcase_data = {
            "name": f"Validate: {name}",
            "description": description,
            "technique_ids": techniques,
            "tactics": tactics,
            "platforms": platforms,
            "test_type": "detection_validation",
            "status": "pending",
            "environment": environment,
            "created_date": datetime.utcnow().isoformat(),
            "detection_query": query,
            "detection_platform": detection.get("platform", "Unknown"),
            "detection_file": str(detection_yaml),
        }

        # Add operator guidance
        if operator_guidance:
            testcase_data["operator_guidance"] = operator_guidance
        elif detection.get("emulation_evidence"):
            # Use emulation evidence as operator guidance
            evidence = detection["emulation_evidence"]
            guidance = []
            if evidence.get("sample_commands"):
                guidance.append("**Sample Commands:**")
                for cmd in evidence["sample_commands"][:3]:
                    guidance.append(f"- `{cmd}`")
            if evidence.get("processes"):
                guidance.append("\n**Expected Processes:**")
                for proc in evidence["processes"]:
                    guidance.append(f"- {proc}")
            testcase_data["operator_guidance"] = "\n".join(guidance)

        # Add red team tools
        if red_tools:
            testcase_data["red_tools"] = red_tools
        elif detection.get("emulation_evidence", {}).get("source") == "Atomic Red Team":
            testcase_data["red_tools"] = ["Atomic Red Team"]

        # Create test case in VECTR
        test_case = self.client.create_test_case(campaign_id, testcase_data)

        print(
            f"✅ Created test case: {test_case.get('name')} (ID: {test_case.get('id')})"
        )

        return test_case

    def update_test_result(
        self,
        campaign_id: str,
        testcase_id: str,
        result: str,
        notes: Optional[str] = None,
        detected: bool = False,
        false_positives: int = 0,
    ) -> Dict[str, Any]:
        """
        Update test case with execution results.

        Args:
            campaign_id: Campaign ID
            testcase_id: Test case ID
            result: Test result (pass, fail, partial, skip)
            notes: Test execution notes
            detected: Whether detection triggered
            false_positives: Number of false positive alerts

        Returns:
            Updated test case object
        """
        update_data = {
            "status": "completed",
            "result": result,
            "execution_date": datetime.utcnow().isoformat(),
            "detected": detected,
            "false_positives": false_positives,
        }

        if notes:
            update_data["notes"] = notes

        return self.client.update_test_case(campaign_id, testcase_id, update_data)

    def bulk_create_from_directory(
        self,
        campaign_id: str,
        yaml_dir: str = "data/groups",
        filter_group: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create test cases for all detections in a directory.

        Args:
            campaign_id: Parent campaign ID
            yaml_dir: Directory containing detection YAML files
            filter_group: Only create for specific threat group

        Returns:
            Summary of created test cases
        """
        yaml_path = Path(yaml_dir)
        yaml_files = list(yaml_path.glob("*.yaml"))

        # Filter out example files
        yaml_files = [f for f in yaml_files if "_example" not in f.name]

        created = []
        skipped = []

        for yaml_file in yaml_files:
            try:
                # Load YAML to check group filter
                with open(yaml_file, "r", encoding="utf-8") as f:
                    detection = yaml.safe_load(f)

                # Check group filter
                if filter_group:
                    tags = detection.get("tags", [])
                    group_match = False
                    for tag in tags:
                        if filter_group.lower() in tag.lower() and "(Group)" in tag:
                            group_match = True
                            break

                    if not group_match:
                        skipped.append(str(yaml_file))
                        continue

                # Create test case
                test_case = self.create_detection_test_case(campaign_id, str(yaml_file))
                created.append(
                    {"file": str(yaml_file), "test_case_id": test_case.get("id")}
                )

            except Exception as e:
                print(f"⚠️  Failed to create test case for {yaml_file}: {e}")
                skipped.append(str(yaml_file))

        summary = {
            "campaign_id": campaign_id,
            "total_files": len(yaml_files),
            "created": len(created),
            "skipped": len(skipped),
            "test_cases": created,
        }

        print(f"\n✅ Created {len(created)} test cases ({len(skipped)} skipped)")

        return summary

    def get_detection_coverage(self, campaign_id: str) -> Dict[str, Any]:
        """
        Analyze detection coverage for a campaign.

        Args:
            campaign_id: Campaign ID

        Returns:
            Coverage statistics by technique, tactic, platform
        """
        test_cases = self.client.list_test_cases(campaign_id)

        coverage = {
            "total_test_cases": len(test_cases),
            "by_technique": {},
            "by_tactic": {},
            "by_platform": {},
            "by_status": {"pending": 0, "completed": 0},
            "by_result": {"pass": 0, "fail": 0, "partial": 0, "skip": 0},
        }

        for tc in test_cases:
            # Techniques
            for technique_id in tc.get("technique_ids", []):
                coverage["by_technique"][technique_id] = (
                    coverage["by_technique"].get(technique_id, 0) + 1
                )

            # Tactics
            for tactic in tc.get("tactics", []):
                coverage["by_tactic"][tactic] = coverage["by_tactic"].get(tactic, 0) + 1

            # Platforms
            for platform in tc.get("platforms", []):
                coverage["by_platform"][platform] = (
                    coverage["by_platform"].get(platform, 0) + 1
                )

            # Status
            status = tc.get("status", "pending")
            coverage["by_status"][status] = coverage["by_status"].get(status, 0) + 1

            # Results (for completed tests)
            if status == "completed":
                result = tc.get("result", "skip")
                coverage["by_result"][result] = coverage["by_result"].get(result, 0) + 1

        return coverage

    def generate_coverage_report(
        self, campaign_id: str, output_file: Optional[str] = None
    ) -> str:
        """
        Generate a coverage report in markdown format.

        Args:
            campaign_id: Campaign ID
            output_file: Optional file path to save report

        Returns:
            Markdown report as string
        """
        coverage = self.get_detection_coverage(campaign_id)
        campaign = self.client.get_campaign(campaign_id)

        # Build markdown report
        report = []
        report.append(f"# VECTR Coverage Report: {campaign.get('name')}")
        report.append(f"\nGenerated: {datetime.utcnow().isoformat()}\n")

        # Summary
        report.append("## Summary")
        report.append(f"- Total Test Cases: {coverage['total_test_cases']}")
        report.append(f"- Pending: {coverage['by_status'].get('pending', 0)}")
        report.append(f"- Completed: {coverage['by_status'].get('completed', 0)}")
        report.append("")

        # Results
        if coverage["by_status"].get("completed", 0) > 0:
            report.append("## Test Results")
            report.append(f"- Passed: {coverage['by_result'].get('pass', 0)}")
            report.append(f"- Failed: {coverage['by_result'].get('fail', 0)}")
            report.append(f"- Partial: {coverage['by_result'].get('partial', 0)}")
            report.append(f"- Skipped: {coverage['by_result'].get('skip', 0)}")
            report.append("")

        # Technique coverage
        report.append("## Coverage by Technique")
        for technique_id, count in sorted(coverage["by_technique"].items()):
            report.append(f"- {technique_id}: {count} test case(s)")
        report.append("")

        # Tactic coverage
        report.append("## Coverage by Tactic")
        for tactic, count in sorted(coverage["by_tactic"].items()):
            report.append(f"- {tactic}: {count} test case(s)")
        report.append("")

        # Platform coverage
        report.append("## Coverage by Platform")
        for platform, count in sorted(coverage["by_platform"].items()):
            report.append(f"- {platform}: {count} test case(s)")
        report.append("")

        report_text = "\n".join(report)

        # Save to file if specified
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report_text)
            print(f"✅ Coverage report saved to {output_file}")

        return report_text

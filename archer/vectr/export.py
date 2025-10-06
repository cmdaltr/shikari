"""
VECTR Export/Import Functionality

Bidirectional sync between Archer detections and VECTR test cases.
"""

import json
import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
from .client import VECTRClient
from .campaigns import CampaignManager
from .testcases import TestCaseManager


def export_to_vectr(
    threat_group: str,
    campaign_name: Optional[str] = None,
    yaml_dir: str = "data/generate",
    environment: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Export Archer detections to VECTR as a campaign with test cases.

    Args:
        threat_group: Threat group name (e.g., "APT29")
        campaign_name: Campaign name (default: "{threat_group} Hunt - {date}")
        yaml_dir: Directory containing detection YAML files
        environment: Target environment name

    Returns:
        Export summary with campaign and test case details
    """
    from archer.config import VECTRConfig

    if not VECTRConfig.is_configured():
        raise ValueError(
            "VECTR not configured. Set ENABLE_VECTR=true and VECTR_API_TOKEN"
        )

    # Generate campaign name if not provided
    if not campaign_name:
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        campaign_name = f"{threat_group} Hunt - {date_str}"

    print("=" * 70)
    print(f"Exporting to VECTR: {campaign_name}")
    print("=" * 70)
    print()

    # Initialize managers
    campaign_mgr = CampaignManager()
    testcase_mgr = TestCaseManager()

    # Create campaign
    print(f"Creating campaign for {threat_group}...")
    campaign = campaign_mgr.create_hunt_campaign(
        name=campaign_name,
        threat_group=threat_group,
        description=f"Archer-generated threat hunt for {threat_group}",
        environment=environment,
    )

    campaign_id = campaign.get("id")

    # Create test cases from YAML files
    print(f"\nCreating test cases from {yaml_dir}...")
    test_summary = testcase_mgr.bulk_create_from_directory(
        campaign_id=campaign_id, yaml_dir=yaml_dir, filter_group=threat_group
    )

    # Export campaign to local file
    print("\nExporting campaign data...")
    export_data = campaign_mgr.export_campaign(campaign_id)

    summary = {
        "status": "success",
        "campaign": {
            "id": campaign_id,
            "name": campaign_name,
            "threat_group": threat_group,
        },
        "test_cases": test_summary,
        "export_file": f"data/vectr/campaigns/{campaign_name.replace(' ', '_')}.json",
    }

    print()
    print("=" * 70)
    print("EXPORT SUMMARY")
    print("=" * 70)
    print(f"Campaign ID: {campaign_id}")
    print(f"Test Cases Created: {test_summary['created']}")
    print(f"Files Skipped: {test_summary['skipped']}")
    print()

    return summary


def import_from_vectr(
    campaign_id: str, update_yamls: bool = False, output_dir: str = "data/generate"
) -> Dict[str, Any]:
    """
    Import test results from VECTR and update Archer detections.

    Args:
        campaign_id: VECTR campaign ID to import
        update_yamls: Whether to update YAML files with test results
        output_dir: Directory to update YAML files

    Returns:
        Import summary with updated detections
    """
    from archer.config import VECTRConfig

    if not VECTRConfig.is_configured():
        raise ValueError(
            "VECTR not configured. Set ENABLE_VECTR=true and VECTR_API_TOKEN"
        )

    print("=" * 70)
    print(f"Importing from VECTR Campaign: {campaign_id}")
    print("=" * 70)
    print()

    # Initialize managers
    campaign_mgr = CampaignManager()
    client = VECTRClient()

    # Get campaign and test cases
    print("Fetching campaign data...")
    campaign = client.get_campaign(campaign_id)
    test_cases = client.list_test_cases(campaign_id)

    print(f"Campaign: {campaign.get('name')}")
    print(f"Test Cases: {len(test_cases)}")
    print()

    # Process test results
    updated_files = []
    results_summary = {"total": 0, "passed": 0, "failed": 0, "pending": 0}

    for tc in test_cases:
        results_summary["total"] += 1
        status = tc.get("status")
        result = tc.get("result")

        if status == "completed":
            if result == "pass":
                results_summary["passed"] += 1
            elif result == "fail":
                results_summary["failed"] += 1
        else:
            results_summary["pending"] += 1

        # Update YAML if requested and file is specified
        if update_yamls and tc.get("detection_file"):
            detection_file = Path(tc["detection_file"])

            if detection_file.exists():
                try:
                    with open(detection_file, "r", encoding="utf-8") as f:
                        detection = yaml.safe_load(f)

                    # Add VECTR test results section
                    if "vectr_validation" not in detection:
                        detection["vectr_validation"] = {}

                    detection["vectr_validation"]["campaign_id"] = campaign_id
                    detection["vectr_validation"]["test_case_id"] = tc.get("id")
                    detection["vectr_validation"]["status"] = status
                    detection["vectr_validation"]["result"] = result
                    detection["vectr_validation"]["tested_date"] = tc.get(
                        "execution_date", datetime.utcnow().isoformat()
                    )

                    if tc.get("detected"):
                        detection["vectr_validation"]["detected"] = True
                        detection["vectr_validation"]["confidence"] = "high"
                    else:
                        detection["vectr_validation"]["detected"] = False
                        detection["vectr_validation"]["confidence"] = "low"

                    if tc.get("false_positives", 0) > 0:
                        detection["vectr_validation"]["false_positives"] = tc[
                            "false_positives"
                        ]

                    # Write back to file
                    with open(detection_file, "w", encoding="utf-8") as f:
                        yaml.dump(detection, f, default_flow_style=False, sort_keys=False)

                    updated_files.append(str(detection_file))
                    print(f"✅ Updated {detection_file.name} with test results")

                except Exception as e:
                    print(f"⚠️  Failed to update {detection_file}: {e}")

    summary = {
        "status": "success",
        "campaign": campaign,
        "results": results_summary,
        "updated_files": updated_files,
    }

    print()
    print("=" * 70)
    print("IMPORT SUMMARY")
    print("=" * 70)
    print(f"Total Test Cases: {results_summary['total']}")
    print(f"Passed: {results_summary['passed']}")
    print(f"Failed: {results_summary['failed']}")
    print(f"Pending: {results_summary['pending']}")
    if update_yamls:
        print(f"Files Updated: {len(updated_files)}")
    print()

    return summary


def sync_with_vectr(
    campaign_id: str,
    threat_group: Optional[str] = None,
    yaml_dir: str = "data/generate",
    bidirectional: bool = True,
) -> Dict[str, Any]:
    """
    Bidirectional sync between Archer and VECTR.

    Args:
        campaign_id: VECTR campaign ID
        threat_group: Filter to specific threat group
        yaml_dir: Directory containing YAML files
        bidirectional: If True, both export new detections and import results

    Returns:
        Sync summary
    """
    from archer.config import VECTRConfig

    if not VECTRConfig.is_configured():
        raise ValueError(
            "VECTR not configured. Set ENABLE_VECTR=true and VECTR_API_TOKEN"
        )

    print("=" * 70)
    print(f"Syncing with VECTR Campaign: {campaign_id}")
    print("=" * 70)
    print()

    testcase_mgr = TestCaseManager()

    # Export: Create test cases for new detections
    print("📤 Exporting new detections to VECTR...")
    export_result = testcase_mgr.bulk_create_from_directory(
        campaign_id=campaign_id, yaml_dir=yaml_dir, filter_group=threat_group
    )

    import_result = None
    if bidirectional:
        # Import: Update YAMLs with test results
        print("\n📥 Importing test results from VECTR...")
        import_result = import_from_vectr(
            campaign_id=campaign_id, update_yamls=True, output_dir=yaml_dir
        )

    summary = {
        "status": "success",
        "campaign_id": campaign_id,
        "export": export_result,
        "import": import_result,
        "sync_date": datetime.utcnow().isoformat(),
    }

    return summary

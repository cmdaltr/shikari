"""
VECTR Campaign Management

Manages threat hunting campaigns in VECTR, organizing detections, test cases,
and assessment activities.
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from .client import VECTRClient


class CampaignManager:
    """Manages VECTR campaigns for threat hunting operations."""

    def __init__(self, client: Optional[VECTRClient] = None):
        """
        Initialize campaign manager.

        Args:
            client: VECTR API client (creates new if not provided)
        """
        self.client = client or VECTRClient()

    def create_hunt_campaign(
        self,
        name: str,
        threat_group: str,
        description: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a new threat hunting campaign in VECTR.

        Args:
            name: Campaign name (e.g., "APT29 Hunt - Q1 2025")
            threat_group: Threat actor group being hunted
            description: Campaign description
            environment: Target environment name

        Returns:
            Created campaign object
        """
        from archer.config import VECTRConfig

        campaign_data = {
            "name": name,
            "description": description
            or f"Threat hunting campaign for {threat_group}",
            "threat_group": threat_group,
            "campaign_type": "threat_hunt",
            "status": "active",
            "created_date": datetime.utcnow().isoformat(),
            "environment": environment or VECTRConfig.default_environment,
            "tags": [threat_group, "archer", "threat-hunt"],
        }

        campaign = self.client.create_campaign(campaign_data)
        print(f"✅ Created campaign: {campaign.get('name')} (ID: {campaign.get('id')})")

        return campaign

    def list_campaigns(self, filter_by: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all campaigns, optionally filtered.

        Args:
            filter_by: Filter by campaign type or threat group

        Returns:
            List of campaign objects
        """
        campaigns = self.client.list_campaigns()

        if filter_by:
            filter_lower = filter_by.lower()
            campaigns = [
                c
                for c in campaigns
                if filter_lower in c.get("name", "").lower()
                or filter_lower in c.get("threat_group", "").lower()
                or filter_lower in c.get("campaign_type", "").lower()
            ]

        return campaigns

    def get_campaign_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Find campaign by name.

        Args:
            name: Campaign name (partial match)

        Returns:
            Campaign object if found, None otherwise
        """
        campaigns = self.list_campaigns(filter_by=name)

        if not campaigns:
            return None

        # Exact match first
        for campaign in campaigns:
            if campaign.get("name") == name:
                return campaign

        # Return first partial match
        return campaigns[0]

    def update_campaign_status(
        self, campaign_id: str, status: str, notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update campaign status.

        Args:
            campaign_id: Campaign ID
            status: New status (active, completed, on_hold, cancelled)
            notes: Optional status notes

        Returns:
            Updated campaign object
        """
        update_data = {
            "status": status,
            "updated_date": datetime.utcnow().isoformat(),
        }

        if notes:
            update_data["status_notes"] = notes

        return self.client.update_campaign(campaign_id, update_data)

    def get_campaign_summary(self, campaign_id: str) -> Dict[str, Any]:
        """
        Get campaign summary with statistics.

        Args:
            campaign_id: Campaign ID

        Returns:
            Campaign summary with test case counts, coverage, etc.
        """
        campaign = self.client.get_campaign(campaign_id)
        test_cases = self.client.list_test_cases(campaign_id)

        # Calculate statistics
        total_tests = len(test_cases)
        completed_tests = len([tc for tc in test_cases if tc.get("status") == "completed"])
        passed_tests = len([tc for tc in test_cases if tc.get("result") == "pass"])
        failed_tests = len([tc for tc in test_cases if tc.get("result") == "fail"])

        # Extract unique techniques
        techniques = set()
        for tc in test_cases:
            technique_id = tc.get("technique_id")
            if technique_id:
                techniques.add(technique_id)

        summary = {
            "campaign": campaign,
            "statistics": {
                "total_test_cases": total_tests,
                "completed": completed_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "in_progress": total_tests - completed_tests,
                "completion_rate": (completed_tests / total_tests * 100)
                if total_tests > 0
                else 0,
                "success_rate": (passed_tests / completed_tests * 100)
                if completed_tests > 0
                else 0,
            },
            "coverage": {
                "techniques_covered": len(techniques),
                "technique_ids": sorted(list(techniques)),
            },
        }

        return summary

    def export_campaign(
        self, campaign_id: str, output_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export campaign data to JSON file.

        Args:
            campaign_id: Campaign ID
            output_file: Output file path (default: data/vectr/campaigns/{campaign_name}.json)

        Returns:
            Exported campaign data
        """
        campaign = self.client.get_campaign(campaign_id)
        test_cases = self.client.list_test_cases(campaign_id)

        export_data = {
            "campaign": campaign,
            "test_cases": test_cases,
            "export_date": datetime.utcnow().isoformat(),
            "exported_by": "archer",
        }

        # Determine output file
        if not output_file:
            campaign_name = campaign.get("name", "campaign").replace(" ", "_")
            output_file = f"data/vectr/campaigns/{campaign_name}.json"

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)

        print(f"✅ Exported campaign to {output_path}")

        return export_data

    def import_campaign(self, input_file: str) -> Dict[str, Any]:
        """
        Import campaign from JSON file.

        Args:
            input_file: Path to campaign JSON export

        Returns:
            Imported campaign object
        """
        with open(input_file, "r", encoding="utf-8") as f:
            import_data = json.load(f)

        campaign_data = import_data.get("campaign", {})
        test_cases = import_data.get("test_cases", [])

        # Create campaign (remove ID fields for import)
        campaign_data.pop("id", None)
        campaign_data.pop("created_date", None)
        campaign_data["name"] = f"{campaign_data.get('name')} (Imported)"

        campaign = self.client.create_campaign(campaign_data)
        campaign_id = campaign.get("id")

        # Import test cases
        imported_count = 0
        for tc_data in test_cases:
            tc_data.pop("id", None)
            tc_data.pop("campaign_id", None)
            try:
                self.client.create_test_case(campaign_id, tc_data)
                imported_count += 1
            except Exception as e:
                print(f"⚠️  Failed to import test case: {e}")

        print(
            f"✅ Imported campaign with {imported_count}/{len(test_cases)} test cases"
        )

        return campaign

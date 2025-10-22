"""
VECTR API Client

Provides HTTP client interface for VECTR REST API.
"""

import requests
from typing import Dict, List, Optional, Any


class VECTRClient:
    """Client for interacting with VECTR API."""

    def __init__(self, url: Optional[str] = None, api_token: Optional[str] = None):
        """
        Initialize VECTR API client.

        Args:
            url: VECTR server URL (default: from VECTR_URL env var)
            api_token: API authentication token (default: from VECTR_API_TOKEN env var)
        """
        from archer.config import VECTRConfig

        self.url = (url or VECTRConfig.url).rstrip("/")
        self.api_token = api_token or VECTRConfig.api_token

        if not self.api_token:
            raise ValueError(
                "VECTR API token not configured. Set VECTR_API_TOKEN environment variable."
            )

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
            }
        )

    def _request(
        self, method: str, endpoint: str, data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Make HTTP request to VECTR API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            data: Request payload for POST/PUT

        Returns:
            Response JSON as dictionary

        Raises:
            requests.HTTPError: If request fails
        """
        url = f"{self.url}/api/v1/{endpoint.lstrip('/')}"

        try:
            if method.upper() == "GET":
                response = self.session.get(url)
            elif method.upper() == "POST":
                response = self.session.post(url, json=data)
            elif method.upper() == "PUT":
                response = self.session.put(url, json=data)
            elif method.upper() == "DELETE":
                response = self.session.delete(url)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response.json() if response.text else {}

        except requests.exceptions.RequestException as e:
            raise requests.HTTPError(f"VECTR API request failed: {e}")

    # Campaign endpoints

    def list_campaigns(self) -> List[Dict[str, Any]]:
        """List all campaigns."""
        return self._request("GET", "/campaigns")

    def get_campaign(self, campaign_id: str) -> Dict[str, Any]:
        """Get campaign details by ID."""
        return self._request("GET", f"/campaigns/{campaign_id}")

    def create_campaign(self, campaign_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new campaign.

        Args:
            campaign_data: Campaign details (name, description, etc.)

        Returns:
            Created campaign object
        """
        return self._request("POST", "/campaigns", campaign_data)

    def update_campaign(
        self, campaign_id: str, campaign_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update an existing campaign."""
        return self._request("PUT", f"/campaigns/{campaign_id}", campaign_data)

    # Test Case endpoints

    def list_test_cases(self, campaign_id: str) -> List[Dict[str, Any]]:
        """List all test cases for a campaign."""
        return self._request("GET", f"/campaigns/{campaign_id}/testcases")

    def get_test_case(self, campaign_id: str, testcase_id: str) -> Dict[str, Any]:
        """Get test case details."""
        return self._request(
            "GET", f"/campaigns/{campaign_id}/testcases/{testcase_id}"
        )

    def create_test_case(
        self, campaign_id: str, testcase_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a new test case in a campaign.

        Args:
            campaign_id: Parent campaign ID
            testcase_data: Test case details

        Returns:
            Created test case object
        """
        return self._request(
            "POST", f"/campaigns/{campaign_id}/testcases", testcase_data
        )

    def update_test_case(
        self, campaign_id: str, testcase_id: str, testcase_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update an existing test case."""
        return self._request(
            "PUT", f"/campaigns/{campaign_id}/testcases/{testcase_id}", testcase_data
        )

    # Environment endpoints

    def list_environments(self) -> List[Dict[str, Any]]:
        """List all environments."""
        return self._request("GET", "/environments")

    def create_environment(self, env_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new environment."""
        return self._request("POST", "/environments", env_data)

    # Assessment Group endpoints

    def list_assessment_groups(self) -> List[Dict[str, Any]]:
        """List all assessment groups."""
        return self._request("GET", "/assessmentgroups")

    def create_assessment_group(self, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new assessment group."""
        return self._request("POST", "/assessmentgroups", group_data)

    # Utility methods

    def test_connection(self) -> bool:
        """
        Test connection to VECTR server.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self._request("GET", "/health")
            return True
        except Exception:
            return False

    def get_server_info(self) -> Dict[str, Any]:
        """Get VECTR server information."""
        return self._request("GET", "/info")

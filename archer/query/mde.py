"""
Microsoft Defender for Endpoint (MDE) API client for query execution.

Uses Microsoft Graph API to execute KQL queries.
"""

import os
import requests
from typing import Dict, List, Optional
from datetime import datetime, timedelta


class MDEClient:
    """Microsoft Defender for Endpoint API client"""

    def __init__(
        self,
        tenant_id: str = None,
        client_id: str = None,
        client_secret: str = None,
    ):
        """
        Initialize MDE client with Azure AD credentials.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Azure AD app client ID
            client_secret: Azure AD app client secret

        Environment variables:
            MDE_TENANT_ID
            MDE_CLIENT_ID
            MDE_CLIENT_SECRET
        """
        self.tenant_id = tenant_id or os.getenv("MDE_TENANT_ID")
        self.client_id = client_id or os.getenv("MDE_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("MDE_CLIENT_SECRET")

        if not all([self.tenant_id, self.client_id, self.client_secret]):
            raise ValueError(
                "MDE credentials required. Set MDE_TENANT_ID, MDE_CLIENT_ID, MDE_CLIENT_SECRET"
            )

        self.token = None
        self.token_expires = None
        self.base_url = "https://api.securitycenter.microsoft.com/api"

    def _get_token(self) -> str:
        """Get OAuth token for Microsoft Graph API"""
        # Check if token is still valid
        if self.token and self.token_expires and datetime.now() < self.token_expires:
            return self.token

        # Request new token
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }

        response = requests.post(url, data=data)
        response.raise_for_status()

        token_data = response.json()
        self.token = token_data["access_token"]
        # Token typically expires in 3600 seconds, refresh 5 minutes early
        self.token_expires = datetime.now() + timedelta(seconds=token_data["expires_in"] - 300)

        return self.token

    def execute_query(
        self,
        query: str,
        timespan: str = "P1D",  # ISO 8601 duration
    ) -> Dict:
        """
        Execute KQL query against MDE Advanced Hunting.

        Args:
            query: KQL query string
            timespan: Time range (ISO 8601 duration, e.g., P1D = 1 day, PT1H = 1 hour)

        Returns:
            Dict with 'results' (list of rows) and 'stats' (execution metadata)
        """
        token = self._get_token()

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # MDE Advanced Hunting API
        url = f"{self.base_url}/advancedhunting/run"
        payload = {"Query": query}

        response = requests.post(url, headers=headers, json=payload)

        if response.status_code == 200:
            data = response.json()
            return {
                "status": "success",
                "results": data.get("Results", []),
                "stats": {
                    "row_count": len(data.get("Results", [])),
                    "execution_time": data.get("Stats", {}).get("ExecutionTime"),
                    "resource_usage": data.get("Stats", {}).get("ResourceUsage"),
                },
            }
        else:
            return {
                "status": "error",
                "error": response.text,
                "status_code": response.status_code,
            }

    def test_connection(self) -> bool:
        """Test if MDE API credentials are valid"""
        try:
            token = self._get_token()
            # Simple query to test
            result = self.execute_query("DeviceInfo | take 1")
            return result["status"] == "success"
        except Exception as e:
            print(f"MDE connection test failed: {e}")
            return False

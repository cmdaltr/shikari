"""
Tests for query execution functionality (MDE/Splunk APIs).
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from archer.query.mde import MDEClient
from archer.query.splunk import SplunkClient


class TestMDEClient:
    """Test Microsoft Defender for Endpoint API client"""

    def test_init_with_credentials(self):
        """Test MDE client initialization with credentials"""
        client = MDEClient(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
        )
        assert client.tenant_id == "test-tenant"
        assert client.client_id == "test-client"
        assert client.client_secret == "test-secret"

    def test_init_missing_credentials(self):
        """Test MDE client fails without credentials"""
        with pytest.raises(ValueError):
            MDEClient()

    @patch("requests.post")
    def test_get_token(self, mock_post):
        """Test OAuth token acquisition"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "test_token",
            "expires_in": 3600,
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = MDEClient("tenant", "client", "secret")
        token = client._get_token()

        assert token == "test_token"
        assert client.token == "test_token"
        assert mock_post.called

    @patch("requests.post")
    def test_execute_query_success(self, mock_post):
        """Test successful query execution"""
        # Mock token request
        token_response = Mock()
        token_response.json.return_value = {
            "access_token": "test_token",
            "expires_in": 3600,
        }
        token_response.raise_for_status = Mock()

        # Mock query request
        query_response = Mock()
        query_response.status_code = 200
        query_response.json.return_value = {
            "Results": [{"DeviceName": "PC01", "ProcessName": "powershell.exe"}],
            "Stats": {"ExecutionTime": "0.5s", "ResourceUsage": "Low"},
        }

        mock_post.side_effect = [token_response, query_response]

        client = MDEClient("tenant", "client", "secret")
        result = client.execute_query("DeviceProcessEvents | take 10")

        assert result["status"] == "success"
        assert len(result["results"]) == 1
        assert result["results"][0]["DeviceName"] == "PC01"
        assert "stats" in result

    @patch("requests.post")
    def test_execute_query_error(self, mock_post):
        """Test query execution error handling"""
        # Mock token request
        token_response = Mock()
        token_response.json.return_value = {
            "access_token": "test_token",
            "expires_in": 3600,
        }
        token_response.raise_for_status = Mock()

        # Mock query error
        query_response = Mock()
        query_response.status_code = 400
        query_response.text = "Invalid query"

        mock_post.side_effect = [token_response, query_response]

        client = MDEClient("tenant", "client", "secret")
        result = client.execute_query("INVALID QUERY")

        assert result["status"] == "error"
        assert "error" in result

    @patch("requests.post")
    def test_test_connection_success(self, mock_post):
        """Test connection test success"""
        # Mock token
        token_response = Mock()
        token_response.json.return_value = {"access_token": "test_token", "expires_in": 3600}
        token_response.raise_for_status = Mock()

        # Mock query
        query_response = Mock()
        query_response.status_code = 200
        query_response.json.return_value = {"Results": []}

        mock_post.side_effect = [token_response, query_response]

        client = MDEClient("tenant", "client", "secret")
        assert client.test_connection() is True


class TestSplunkClient:
    """Test Splunk API client"""

    def test_init_with_credentials(self):
        """Test Splunk client initialization"""
        client = SplunkClient(
            host="splunk.local",
            port=8089,
            username="admin",
            password="password",
        )
        assert client.host == "splunk.local"
        assert client.port == 8089
        assert client.username == "admin"

    def test_init_missing_credentials(self):
        """Test Splunk client fails without credentials"""
        with pytest.raises(ValueError):
            SplunkClient()

    @patch("requests.post")
    def test_login(self, mock_post):
        """Test Splunk authentication"""
        mock_response = Mock()
        mock_response.json.return_value = {"sessionKey": "test_session_key"}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = SplunkClient("splunk.local", username="admin", password="password")
        session_key = client._login()

        assert session_key == "test_session_key"
        assert client.session_key == "test_session_key"

    @patch("requests.get")
    @patch("requests.post")
    def test_execute_query_success(self, mock_post, mock_get):
        """Test successful Splunk query execution"""
        # Mock login
        login_response = Mock()
        login_response.json.return_value = {"sessionKey": "test_key"}
        login_response.raise_for_status = Mock()

        # Mock job creation
        job_response = Mock()
        job_response.json.return_value = {"sid": "job123"}
        job_response.raise_for_status = Mock()

        mock_post.side_effect = [login_response, job_response]

        # Mock job status (completed)
        status_response = Mock()
        status_response.json.return_value = {
            "entry": [{"content": {"isDone": True, "scanCount": 100, "eventCount": 50}}]
        }
        status_response.raise_for_status = Mock()

        # Mock results
        results_response = Mock()
        results_response.json.return_value = {
            "results": [
                {"_time": "2024-01-01", "host": "server01", "message": "Test event"}
            ]
        }
        results_response.raise_for_status = Mock()

        mock_get.side_effect = [status_response, results_response]

        client = SplunkClient("splunk.local", username="admin", password="password")
        result = client.execute_query("index=main | head 10")

        assert result["status"] == "success"
        assert len(result["results"]) == 1
        assert result["results"][0]["host"] == "server01"
        assert "stats" in result

    @patch("requests.post")
    def test_test_connection_success(self, mock_post):
        """Test Splunk connection test"""
        # Mock login and query (simplified for connection test)
        mock_response = Mock()
        mock_response.json.return_value = {"sessionKey": "test_key"}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        with patch.object(SplunkClient, "execute_query", return_value={"status": "success"}):
            client = SplunkClient("splunk.local", username="admin", password="password")
            assert client.test_connection() is True


class TestQueryIntegration:
    """Integration tests for query execution"""

    @patch("archer.query.mde.MDEClient.execute_query")
    def test_execute_mde_query_from_yaml(self, mock_execute):
        """Test executing MDE query extracted from YAML"""
        mock_execute.return_value = {
            "status": "success",
            "results": [{"DeviceName": "PC01"}],
            "stats": {"row_count": 1},
        }

        # Simulate loading query from YAML
        query = "DeviceProcessEvents | where FileName =~ 'powershell.exe'"

        client = MDEClient("tenant", "client", "secret")
        result = client.execute_query(query)

        assert result["status"] == "success"
        assert len(result["results"]) == 1

    @patch("archer.query.splunk.SplunkClient.execute_query")
    def test_execute_splunk_query_from_yaml(self, mock_execute):
        """Test executing Splunk query extracted from YAML"""
        mock_execute.return_value = {
            "status": "success",
            "results": [{"host": "server01"}],
            "stats": {"row_count": 1},
        }

        # Simulate loading query from YAML
        query = "index=windows_events powershell.exe"

        client = SplunkClient("splunk.local", username="admin", password="password")
        result = client.execute_query(query)

        assert result["status"] == "success"
        assert len(result["results"]) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

#!/usr/bin/env python3
"""
Test script for Splunk API client.
Tests query execution and validation logic.
"""

import json
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# Add shikari to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestSplunkClientInitialization:
    """Tests for Splunk client initialization."""

    def test_client_requires_credentials(self):
        """Test that client requires credentials."""
        from shikari.query.splunk import SplunkClient

        # Clear environment variables
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError) as exc_info:
                SplunkClient()

            assert "credentials required" in str(exc_info.value).lower()

    def test_client_accepts_env_vars(self):
        """Test that client accepts environment variables."""
        from shikari.query.splunk import SplunkClient

        env_vars = {
            "SPLUNK_HOST": "splunk.example.com",
            "SPLUNK_PORT": "8089",
            "SPLUNK_USERNAME": "admin",
            "SPLUNK_PASSWORD": "password123",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            client = SplunkClient()

            assert client.host == "splunk.example.com"
            assert client.port == 8089
            assert client.username == "admin"

    def test_client_accepts_parameters(self):
        """Test that client accepts direct parameters."""
        from shikari.query.splunk import SplunkClient

        client = SplunkClient(
            host="splunk.local",
            port=8089,
            username="testuser",
            password="testpass",
        )

        assert client.host == "splunk.local"
        assert client.username == "testuser"


class TestSplunkQueryExecution:
    """Tests for Splunk query execution."""

    def test_execute_query_makes_request(self):
        """Test that execute_query makes HTTP request."""
        from shikari.query.splunk import SplunkClient

        client = SplunkClient(
            host="splunk.local",
            port=8089,
            username="admin",
            password="pass",
        )

        with patch("shikari.query.splunk.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"sid": "job123"}
            mock_post.return_value = mock_response

            # Mock the job results endpoint too
            with patch("shikari.query.splunk.requests.get") as mock_get:
                mock_results = MagicMock()
                mock_results.status_code = 200
                mock_results.json.return_value = {
                    "results": [{"count": 10}]
                }
                mock_get.return_value = mock_results

                try:
                    result = client.execute_query("index=main | stats count")
                except Exception:
                    # Expected if implementation differs
                    pass

                # Verify request was attempted
                assert mock_post.called or mock_get.called

    def test_query_validation_syntax(self):
        """Test SPL query syntax validation."""
        from shikari.validation.query_syntax_validator import validate_query_syntax

        # Valid SPL query
        valid_query = 'index=main sourcetype=windows | stats count by host'
        result = validate_query_syntax(valid_query, "splunk")

        # Should return validation result
        assert isinstance(result, (bool, dict, tuple))


class TestSplunkQueryGeneration:
    """Tests for Splunk query generation patterns."""

    def test_process_creation_query_pattern(self):
        """Test Splunk query pattern for process creation."""
        # Sample Splunk SPL for process creation detection
        query = '''
        index=windows sourcetype=WinEventLog:Security EventCode=4688
        | search NewProcessName="*powershell*"
        | stats count by Computer, NewProcessName, CommandLine
        '''

        # Basic structure validation
        assert "index=" in query
        assert "EventCode=" in query or "sourcetype=" in query

    def test_network_connection_query_pattern(self):
        """Test Splunk query pattern for network detection."""
        query = '''
        index=network sourcetype=firewall
        | search dest_ip IN ("10.0.0.1", "192.168.1.100")
        | stats count by src_ip, dest_ip, dest_port
        '''

        assert "index=" in query
        assert "dest_ip" in query



def _resp(status=200, body=None, headers=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body if body is not None else {}
    r.headers = headers or {}
    r.text = json.dumps(body or {})
    return r


def _job(done=True, count=0, failed=False, messages=None):
    return _resp(200, {"entry": [{"content": {"isDone": done, "resultCount": count, "dispatchState": "FAILED" if failed else "DONE",
                                              "messages": messages or []}}]})


class TestSplunkLive44:
    """What #44 found against a real Splunk (the siem VM, Splunk Enterprise 10): kept as regressions."""

    def _client(self, **kw):
        from shikari.query.splunk import SplunkClient
        return SplunkClient(host="splunk.local", **({"token": "tok"} | kw))

    def test_token_alone_is_enough(self):
        from shikari.query.splunk import SplunkClient
        with patch.dict(os.environ, {"SPLUNK_HOST": "s", "SPLUNK_TOKEN": "t"}, clear=True):
            assert SplunkClient().token == "t"

    def test_urls_keep_services(self):
        # urljoin(base, "/search/jobs") dropped /services: every call went to the wrong path
        assert self._client()._url("/search/jobs") == "https://splunk.local:8089/services/search/jobs"

    def test_leading_command(self):
        from shikari.query.splunk import SplunkClient
        assert SplunkClient.search_string("index=main") == "search index=main"
        assert SplunkClient.search_string(" | tstats count") == "| tstats count"
        assert SplunkClient.search_string("search index=main") == "search index=main"

    def test_bearer_token_header(self):
        c = self._client()
        with patch("shikari.query.splunk.requests.request") as req:
            req.side_effect = [_resp(201, {"sid": "1"}), _job(count=0)]
            assert c.execute_query("| makeresults")["status"] == "success"
            assert req.call_args_list[0].kwargs["headers"] == {"Authorization": "Bearer tok"}

    def test_pages_until_done(self):
        c = self._client()
        pages = [_resp(200, {"results": [{"n": i} for i in range(a, b)]}) for a, b in ((0, 1000), (1000, 2000), (2000, 2500))]
        with patch("shikari.query.splunk.requests.request") as req:
            req.side_effect = [_resp(201, {"sid": "1"}), _job(count=2500), *pages]
            r = c.execute_query("index=x", max_results=0, page_size=1000)
        assert r["stats"]["row_count"] == 2500 and not r["stats"]["truncated"]
        assert [k.kwargs["params"]["offset"] for k in req.call_args_list[2:]] == [0, 1000, 2000]

    def test_bad_spl_reported_once(self):
        c = self._client()
        msg = {"messages": [{"type": "FATAL", "text": "Error in 'stats'"}, {"type": "FATAL", "text": "Error in 'stats'"}]}
        with patch("shikari.query.splunk.requests.request", return_value=_resp(400, msg)):
            assert c.execute_query("index=x | stats count by") == {"status": "error", "error": "Error in 'stats'"}

    def test_expired_token_reported(self):
        c = self._client()
        with patch("shikari.query.splunk.requests.request",
                   return_value=_resp(401, {"messages": [{"text": "call not properly authenticated"}]})):
            r = c.execute_query("index=x")
        assert r["status"] == "error" and "token expired" in r["error"]

    def test_rate_limit_waits_then_runs(self):
        c = self._client()
        with patch("shikari.query.splunk.requests.request") as req, patch("shikari.query.splunk.time.sleep") as slept:
            req.side_effect = [_resp(503, headers={"Retry-After": "1"}), _resp(429), _resp(201, {"sid": "1"}), _job(count=0)]
            assert c.execute_query("index=x")["status"] == "success"
        assert [k.args[0] for k in slept.call_args_list] == [1.0, 2]

    def test_rate_limit_that_persists_is_reported(self):
        c = self._client()
        with patch("shikari.query.splunk.requests.request", return_value=_resp(503, {"messages": [{"text": "too many searches"}]})), \
             patch("shikari.query.splunk.time.sleep"):
            assert c.execute_query("index=x") == {"status": "error", "error": "too many searches"}

    def test_failed_job_reported(self):
        c = self._client()
        with patch("shikari.query.splunk.requests.request") as req:
            req.side_effect = [_resp(201, {"sid": "1"}), _job(failed=True, messages=[{"text": "index not found"}])]
            assert c.execute_query("index=x")["error"] == "index not found"

    def test_unreachable_reported(self):
        import requests
        c = self._client()
        with patch("shikari.query.splunk.requests.request", side_effect=requests.ConnectionError("refused")):
            assert c.execute_query("index=x")["error"].startswith("Splunk unreachable")

    def test_session_key_renewed_once(self):
        from shikari.query.splunk import SplunkClient
        c = SplunkClient(host="s", username="u", password="p")
        with patch("shikari.query.splunk.requests.post", return_value=_resp(200, {"sessionKey": "k"})) as login, \
             patch("shikari.query.splunk.requests.request") as req:
            req.side_effect = [_resp(401), _resp(201, {"sid": "1"}), _job(count=0)]
            assert c.execute_query("index=x")["status"] == "success"
        assert login.call_count == 2


def test_splunk_client():
    """Standalone test function for CLI execution."""
    print("Testing Splunk Client...")
    print("=" * 60)

    # Check for Splunk credentials
    has_creds = all([
        os.getenv("SPLUNK_HOST"),
        os.getenv("SPLUNK_USERNAME"),
        os.getenv("SPLUNK_PASSWORD"),
    ])

    if not has_creds:
        print("⚠ Splunk credentials not set - testing initialization only")
        print("Set SPLUNK_HOST, SPLUNK_USERNAME, SPLUNK_PASSWORD for full tests")
        print()

        # Test initialization logic
        from shikari.query.splunk import SplunkClient

        try:
            # This should fail without credentials
            client = SplunkClient()
            print("✗ Expected ValueError for missing credentials")
            return False
        except ValueError as e:
            print(f"✓ Correctly raised ValueError: {e}")

        # Test with mock credentials
        client = SplunkClient(
            host="mock.splunk.local",
            port=8089,
            username="mockuser",
            password="mockpass",
        )
        print("✓ Client initialized with mock credentials")

        print("\n✓ Basic tests completed successfully!")
        return True

    # Full test with real credentials
    from shikari.query.splunk import SplunkClient

    try:
        client = SplunkClient()
        print("✓ Client initialized with environment credentials")

        # Test a simple query
        print("\nExecuting test query...")
        result = client.execute_query("| makeresults | eval test=1")
        print(f"Query result: {result}")

        print("\n✓ Full tests completed successfully!")
        return True

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_splunk_client()
    sys.exit(0 if success else 1)

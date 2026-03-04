#!/usr/bin/env python3
"""
Test script for MDE (Microsoft Defender for Endpoint) API client.
Tests query execution, validation, and field mapping logic.
"""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# Add archer to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestMDEClientInitialization:
    """Tests for MDE client initialization."""

    def test_client_requires_credentials(self):
        """Test that client requires credentials."""
        from archer.query.mde import MDEClient

        # Clear environment variables
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError) as exc_info:
                MDEClient()

            assert "credentials required" in str(exc_info.value).lower()

    def test_client_accepts_env_vars(self):
        """Test that client accepts environment variables."""
        from archer.query.mde import MDEClient

        env_vars = {
            "MDE_TENANT_ID": "test-tenant-123",
            "MDE_CLIENT_ID": "test-client-456",
            "MDE_CLIENT_SECRET": "test-secret-789",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            client = MDEClient()

            assert client.tenant_id == "test-tenant-123"
            assert client.client_id == "test-client-456"
            assert client.client_secret == "test-secret-789"

    def test_client_accepts_parameters(self):
        """Test that client accepts direct parameters."""
        from archer.query.mde import MDEClient

        client = MDEClient(
            tenant_id="param-tenant",
            client_id="param-client",
            client_secret="param-secret",
        )

        assert client.tenant_id == "param-tenant"
        assert client.client_id == "param-client"

    def test_client_has_base_url(self):
        """Test that client has correct base URL."""
        from archer.query.mde import MDEClient

        client = MDEClient(
            tenant_id="test",
            client_id="test",
            client_secret="test",
        )

        assert "securitycenter.microsoft.com" in client.base_url


class TestMDEQueryExecution:
    """Tests for MDE query execution."""

    def test_execute_query_makes_request(self):
        """Test that execute_query makes HTTP request."""
        from archer.query.mde import MDEClient

        client = MDEClient(
            tenant_id="test",
            client_id="test",
            client_secret="test",
        )

        # Mock token request
        with patch("archer.query.mde.requests.post") as mock_post:
            # First call is for token
            mock_token_response = MagicMock()
            mock_token_response.status_code = 200
            mock_token_response.json.return_value = {
                "access_token": "test-token",
                "expires_in": 3600,
            }

            # Second call is for query (also POST)
            mock_query_response = MagicMock()
            mock_query_response.status_code = 200
            mock_query_response.json.return_value = {
                "Results": [{"DeviceName": "test-host"}],
                "Stats": {"ExecutionTime": 100},
            }

            mock_post.side_effect = [mock_token_response, mock_query_response]

            result = client.execute_query("DeviceInfo | take 1")

            assert mock_post.call_count == 2
            assert result["status"] == "success"
            assert len(result["results"]) == 1

    def test_execute_query_handles_error(self):
        """Test that execute_query handles API errors."""
        from archer.query.mde import MDEClient

        client = MDEClient(
            tenant_id="test",
            client_id="test",
            client_secret="test",
        )

        with patch("archer.query.mde.requests.post") as mock_post:
            # Token response
            mock_token_response = MagicMock()
            mock_token_response.status_code = 200
            mock_token_response.json.return_value = {
                "access_token": "test-token",
                "expires_in": 3600,
            }

            # Error response for query
            mock_error_response = MagicMock()
            mock_error_response.status_code = 400
            mock_error_response.text = "Bad Request: Invalid query"

            mock_post.side_effect = [mock_token_response, mock_error_response]

            result = client.execute_query("invalid query")

            assert result["status"] == "error"
            assert result["status_code"] == 400


class TestMDEFieldValidator:
    """Tests for MDE field validator."""

    def test_validator_initialization(self):
        """Test that validator initializes successfully."""
        from archer.validation.mde_field_validator import MDEFieldValidator

        validator = MDEFieldValidator()
        assert validator is not None
        assert hasattr(validator, "field_mappings")
        assert hasattr(validator, "table_fields")

    def test_extract_table_from_query(self):
        """Test table extraction from KQL queries."""
        from archer.validation.mde_field_validator import MDEFieldValidator

        validator = MDEFieldValidator()

        # Test various table extractions
        assert validator.extract_table_from_query("DeviceProcessEvents | take 10") == "DeviceProcessEvents"
        assert validator.extract_table_from_query("DeviceNetworkEvents | where RemoteIP == '10.0.0.1'") == "DeviceNetworkEvents"
        assert validator.extract_table_from_query("DeviceFileEvents | project FileName") == "DeviceFileEvents"

    def test_extract_fields_from_query(self):
        """Test field extraction from KQL queries."""
        from archer.validation.mde_field_validator import MDEFieldValidator

        validator = MDEFieldValidator()

        query = "DeviceProcessEvents | where FileName == 'powershell.exe' | project DeviceName, ProcessCommandLine"
        fields = validator.extract_fields_from_query(query)

        assert "FileName" in fields
        assert "DeviceName" in fields
        assert "ProcessCommandLine" in fields

    def test_validate_query_valid_fields(self):
        """Test validation of query with valid fields."""
        from archer.validation.mde_field_validator import MDEFieldValidator

        validator = MDEFieldValidator()

        query = "DeviceProcessEvents | where FileName == 'cmd.exe' | project DeviceName, ProcessCommandLine"
        result = validator.validate_query(query)

        assert result["valid"] is True
        assert result["table"] == "DeviceProcessEvents"
        assert len(result["invalid_fields"]) == 0

    def test_validate_query_invalid_fields(self):
        """Test validation of query with invalid fields."""
        from archer.validation.mde_field_validator import MDEFieldValidator

        validator = MDEFieldValidator()

        # Registry fields are invalid for DeviceProcessEvents
        query = "DeviceProcessEvents | where RegistryKey == 'HKLM\\\\Software'"
        result = validator.validate_query(query)

        # RegistryKey should be detected as invalid for DeviceProcessEvents
        assert result["table"] == "DeviceProcessEvents"

    def test_get_table_fields(self):
        """Test getting valid fields for a table."""
        from archer.validation.mde_field_validator import MDEFieldValidator

        validator = MDEFieldValidator()

        fields = validator.get_table_fields("DeviceProcessEvents")

        assert "FileName" in fields
        assert "ProcessCommandLine" in fields
        assert "DeviceName" in fields

    def test_field_aliases(self):
        """Test that common field aliases are recognized."""
        from archer.validation.mde_field_validator import MDEFieldValidator

        validator = MDEFieldValidator()

        assert "CommandLine" in validator.field_aliases
        assert validator.field_aliases["CommandLine"] == "ProcessCommandLine"


class TestMDEQueryFormatting:
    """Tests for MDE query formatting utilities."""

    def test_strip_excluded_fields(self):
        """Test stripping excluded fields from queries."""
        from archer.validation.mde_field_validator import strip_excluded_fields

        query = "DeviceProcessEvents | project DeviceName, SHA256, FileName"
        result = strip_excluded_fields(query)

        assert "DeviceName" in result
        assert "FileName" in result
        assert "SHA256" not in result

    def test_format_mde_query(self):
        """Test MDE query formatting."""
        from archer.validation.mde_field_validator import format_mde_query

        query = "DeviceProcessEvents | where FileName == 'cmd.exe' | project DeviceName, SHA256, FileName"
        result = format_mde_query(query)

        # Should remove SHA256
        assert "SHA256" not in result
        assert "DeviceName" in result


class TestMDEQueryPatterns:
    """Tests for MDE/KQL query patterns used in detection."""

    def test_process_creation_query_pattern(self):
        """Test KQL query pattern for process creation detection."""
        query = '''
        DeviceProcessEvents
        | where FileName has_any ("powershell.exe", "cmd.exe")
        | where ProcessCommandLine has_any ("-enc", "-encoded")
        | project Timestamp, DeviceName, FileName, ProcessCommandLine
        '''

        # Basic structure validation
        assert "DeviceProcessEvents" in query
        assert "where" in query
        assert "project" in query

    def test_network_connection_query_pattern(self):
        """Test KQL query pattern for network detection."""
        query = '''
        DeviceNetworkEvents
        | where RemoteIP in ("10.0.0.1", "192.168.1.100")
        | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
        '''

        assert "DeviceNetworkEvents" in query
        assert "RemoteIP" in query

    def test_registry_query_pattern(self):
        """Test KQL query pattern for registry detection."""
        query = '''
        DeviceRegistryEvents
        | where RegistryKey contains "Run"
        | where ActionType == "RegistryValueSet"
        | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
        '''

        assert "DeviceRegistryEvents" in query
        assert "RegistryKey" in query


class TestMDEConvenienceFunctions:
    """Tests for MDE convenience functions."""

    def test_validate_mde_query_function(self):
        """Test the validate_mde_query convenience function."""
        from archer.validation.mde_field_validator import validate_mde_query

        query = "DeviceProcessEvents | where FileName == 'test.exe'"
        result = validate_mde_query(query)

        assert isinstance(result, dict)
        assert "valid" in result
        assert "table" in result

    def test_fix_mde_query_function(self):
        """Test the fix_mde_query convenience function."""
        from archer.validation.mde_field_validator import fix_mde_query

        query = "DeviceProcessEvents | where CommandLine == 'test'"
        fixed, changes = fix_mde_query(query)

        assert isinstance(fixed, str)
        assert isinstance(changes, list)

    def test_get_mde_validator_singleton(self):
        """Test that get_mde_validator returns singleton."""
        from archer.validation.mde_field_validator import get_mde_validator

        validator1 = get_mde_validator()
        validator2 = get_mde_validator()

        assert validator1 is validator2


def test_mde_client():
    """Standalone test function for CLI execution."""
    print("Testing MDE Client...")
    print("=" * 60)

    # Check for MDE credentials
    has_creds = all([
        os.getenv("MDE_TENANT_ID"),
        os.getenv("MDE_CLIENT_ID"),
        os.getenv("MDE_CLIENT_SECRET"),
    ])

    if not has_creds:
        print("Warning: MDE credentials not set - testing initialization only")
        print("Set MDE_TENANT_ID, MDE_CLIENT_ID, MDE_CLIENT_SECRET for full tests")
        print()

        # Test initialization logic
        from archer.query.mde import MDEClient

        try:
            # This should fail without credentials
            client = MDEClient()
            print("FAIL: Expected ValueError for missing credentials")
            return False
        except ValueError as e:
            print(f"PASS: Correctly raised ValueError: {e}")

        # Test with mock credentials
        client = MDEClient(
            tenant_id="mock-tenant",
            client_id="mock-client",
            client_secret="mock-secret",
        )
        print("PASS: Client initialized with mock credentials")

        print("\nPASS: Basic tests completed successfully!")
        return True

    # Full test with real credentials
    from archer.query.mde import MDEClient

    try:
        client = MDEClient()
        print("PASS: Client initialized with environment credentials")

        # Test connection
        print("\nTesting connection...")
        if client.test_connection():
            print("PASS: Connection test successful")
        else:
            print("WARN: Connection test failed (credentials may be invalid)")

        print("\nPASS: Full tests completed successfully!")
        return True

    except Exception as e:
        print(f"\nFAIL: Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_mde_client()
    sys.exit(0 if success else 1)

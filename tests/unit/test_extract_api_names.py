"""Bare PascalCase names in ATT&CK procedures (shikari.mitre.extract): cloud API calls get
their CLI form, Windows API functions become Defender API-call events, and the rest are
kept as literals or left out, never guessed into an AWS command."""

import pytest

from shikari.mitre.extract import _api_to_cli, classify_name, extract_commands


@pytest.mark.unit
def test_known_cloud_calls_get_their_cli_with_the_service():
    out = extract_commands("In AWS the group ran `ListRolePolicies` and `CreateAccessKey`.")
    assert out["api"] == ["ListRolePolicies", "CreateAccessKey"]
    assert out["cmd"] == ["aws iam list-role-policies", "aws iam create-access-key"]


@pytest.mark.unit
def test_unknown_names_are_never_guessed_into_aws_commands():
    assert _api_to_cli("CreateToolhelp32Snapshot") is None
    out = extract_commands("It called `CreateToolhelp32Snapshot` and `IsDebuggerPresent`.")
    assert not any(c.startswith("aws ") for c in out.get("cmd", []))
    assert "api" not in out


@pytest.mark.unit
def test_windows_api_calls_become_defender_api_events():
    out = extract_commands("Injected with `WriteProcessMemory`, `VirtualAllocEx` and `QueueUserAPC`.")
    assert out["api_event"] == ["WriteProcessMemoryApiCall", "NtAllocateVirtualMemoryRemoteApiCall", "QueueUserApcRemoteApiCall"]
    assert "cmd" not in out and "api" not in out


@pytest.mark.unit
@pytest.mark.parametrize("name, context, kind", [
    ("DescribeInstances", "", "cloud"),
    ("GetBucketReplication", "against S3 buckets in AWS", "cloud"),
    ("GetBucketReplication", "on the host", "term"),
    ("ShowWindow", "", "winapi"),
    ("NtUnmapViewOfSection", "", "winapi"),
    ("EnumDisplayDevicesW", "", "winapi"),
    ("Index", "", "word"),
    ("ExampleFunctionA", "", "placeholder"),
    ("MSExchangeIS", "", "term"),
    ("AnyDesk", "", "term"),
])
def test_classify_name(name, context, kind):
    assert classify_name(name, context) == kind

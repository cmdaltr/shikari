"""
Platform Validation Module

Prevents generation of illogical detections by validating that indicators
are compatible with target platforms/indexes.

Example problems this solves:
- Windows Event 4776 queries for linux_syslog index
- Windows registry queries for Azure indexes
- Windows file paths (C:\\) in Linux/Unix queries
"""

import re
# Removed unused import: from typing import List, Set, Optional


# Platform/Index classification
WINDOWS_INDEXES = {
    "edr_events",
    "windows_events",
    "windows_events",
    "windows_events",
    "av_console",
}

LINUX_UNIX_INDEXES = {
    "linux_syslog",
    "linux_syslog",
    "linux_syslog",
}

MACOS_INDEXES = {
    "macos_logs",
    "macos_logs",
}

CLOUD_INDEXES = {
    "azure_signin",
    "azure_activity",
    "aws_cloudtrail",
    "aws_directory",
    "m365_audit",
    "m365_audit",
}

AZURE_INDEXES = {
    "azure_signin",
    "azure_activity",
    "azure_sentinel",
}

AWS_INDEXES = {
    "aws_cloudtrail",
    "aws_directory",
    "aws_securityhub",
}

# MDE tables
MDE_WINDOWS_TABLES = {
    "DeviceProcessEvents",
    "DeviceFileEvents",
    "DeviceRegistryEvents",
    "DeviceNetworkEvents",
    "DeviceLogonEvents",
    "DeviceEvents",
    "DeviceInfo",
}

MDE_CLOUD_TABLES = {
    "AADSignInEventsBeta",
    "CloudAppEvents",
    "IdentityLogonEvents",
    "IdentityQueryEvents",
    "IdentityDirectoryEvents",
}


def get_index_platforms(index_name: str) -> Set[str]:
    """
    Get the platforms/OS that an index or table name represents.

    Args:
        index_name: Splunk index name or MDE table name

    Returns:
        Set of platform names: {"Windows", "Linux", "macOS", "Azure", "AWS", "Cloud"}
    """
    index_lower = index_name.lower()
    platforms = set()

    # Check Splunk indexes
    if index_name in WINDOWS_INDEXES or "windows" in index_lower or "microsoft" in index_lower:
        platforms.add("Windows")

    if index_name in LINUX_UNIX_INDEXES or "unix" in index_lower or "linux" in index_lower:
        platforms.add("Linux")
        platforms.add("Unix")

    if index_name in MACOS_INDEXES or "mac" in index_lower or "osx" in index_lower:
        platforms.add("macOS")

    if index_name in AZURE_INDEXES or "azure" in index_lower:
        platforms.add("Azure")
        platforms.add("Cloud")

    if index_name in AWS_INDEXES or "aws" in index_lower:
        platforms.add("AWS")
        platforms.add("Cloud")

    if index_name in CLOUD_INDEXES or "o365" in index_lower or "office" in index_lower:
        platforms.add("Cloud")

    # Check MDE tables
    if index_name in MDE_WINDOWS_TABLES or index_name.startswith("Device"):
        platforms.add("Windows")

    if index_name in MDE_CLOUD_TABLES or "AAD" in index_name or "Identity" in index_name or "CloudApp" in index_name:
        platforms.add("Azure")
        platforms.add("Cloud")

    return platforms


def is_indicator_compatible(indicator_text: str, index_platforms: Set[str]) -> bool:
    """
    Check if an indicator is compatible with the target platforms.

    Args:
        indicator_text: The indicator description (e.g., "Windows Event 4776", "C:\\Windows\\System32")
        index_platforms: Set of platforms the index supports (from get_index_platforms())

    Returns:
        True if compatible, False if incompatible
    """
    if not indicator_text or not index_platforms:
        return True  # Don't block if we can't determine

    indicator_lower = indicator_text.lower()

    # Windows-specific indicators
    windows_indicators = [
        r'\bwindows event\b',
        r'\bevent(id)?\s+\d{4,5}\b',  # Event 4776, EventID 4624
        r'\bsecurity\.evtx\b',
        r'\bsystem\.evtx\b',
        r'\bapplication\.evtx\b',
        r'\c:[/\\]',  # C:\ or C:/
        r'\\windows\\',
        r'\\program files',
        r'\\system32\\',
        r'\\syswow64\\',
        r'\bntlm\b',
        r'\bkerberos ticket\b',
        r'\bsam database\b',
        r'\blsass\.exe\b',
        r'\bwinlogon\.exe\b',
        r'\bregistry\s+(key|value|hive)\b',
        r'\bhklm\\',
        r'\bhkcu\\',
        r'\bhkey_',
        r'\bactive directory\s+replication\b',
        r'\bgroup policy\b',
        r'\bwmi\b',
        r'\bpowershell\.exe\b',
        r'\bcmd\.exe\b',
        r'\bsvchost\.exe\b',
    ]

    for pattern in windows_indicators:
        if re.search(pattern, indicator_lower):
            if "Windows" not in index_platforms:
                return False  # Windows indicator, but not a Windows index

    # Linux/Unix-specific indicators
    linux_indicators = [
        r'/etc/',
        r'/var/',
        r'/tmp/',
        r'/usr/',
        r'/bin/',
        r'/sbin/',
        r'/home/',
        r'/root/',
        r'\bsyslog\b',
        r'\bauth\.log\b',
        r'\bsecure\.log\b',
        r'\b/proc/\b',
        r'\bsudo\b',
        r'\bcron\b',
        r'\bssh\b',
        r'\bbash\b',
        r'\bsh\b',
        r'\b/dev/\b',
    ]

    for pattern in linux_indicators:
        if re.search(pattern, indicator_lower):
            if "Linux" not in index_platforms and "Unix" not in index_platforms:
                return False  # Linux indicator, but not a Linux index

    # Azure-specific indicators
    azure_indicators = [
        r'\bazure\s+ad\b',
        r'\baad\b',
        r'\bazure active directory\b',
        r'\bsigninlogs\b',
        r'\bauditlogs\b',
        r'\bidentity protection\b',
        r'\bconditional access\b',
        r'\bentra\s+id\b',
    ]

    for pattern in azure_indicators:
        if re.search(pattern, indicator_lower):
            if "Azure" not in index_platforms and "Cloud" not in index_platforms:
                return False  # Azure indicator, but not Azure/Cloud index

    # AWS-specific indicators
    aws_indicators = [
        r'\bcloudtrail\b',
        r'\biam\s+role\b',
        r'\bs3\s+bucket\b',
        r'\bec2\s+instance\b',
        r'\blambda\s+function\b',
    ]

    for pattern in aws_indicators:
        if re.search(pattern, indicator_lower):
            if "AWS" not in index_platforms and "Cloud" not in index_platforms:
                return False  # AWS indicator, but not AWS/Cloud index

    return True  # No incompatibility detected


def validate_procedure_for_index(procedure_text: str, index_name: str, vendor: str = "Splunk") -> bool:
    """
    Validate if a procedure/indicator is compatible with a specific index.

    Args:
        procedure_text: Full procedure description with indicators
        index_name: Splunk index or MDE table name
        vendor: "Splunk" or "MDE"

    Returns:
        True if compatible and should generate query, False to skip
    """
    # Get platforms for this index
    index_platforms = get_index_platforms(index_name)

    if not index_platforms:
        # Can't determine platforms, allow it (don't block unknowns)
        return True

    # Check if procedure indicators are compatible
    return is_indicator_compatible(procedure_text, index_platforms)


def should_generate_query(
    technique_id: str,
    procedure_text: str,
    index_name: str,
    vendor: str = "Splunk"
) -> tuple[bool, Optional[str]]:
    """
    Determine if a query should be generated for this combination.

    Args:
        technique_id: MITRE technique ID (e.g., "T1003.001")
        procedure_text: Procedure description with indicators
        index_name: Target index/table name
        vendor: "Splunk" or "MDE"

    Returns:
        Tuple of (should_generate: bool, reason: str|None)
    """
    if not validate_procedure_for_index(procedure_text, index_name, vendor):
        reason = f"Indicator incompatible with index platform (index={index_name})"
        return (False, reason)

    return (True, None)


# Example usage:
if __name__ == "__main__":
    # Test cases
    test_cases = [
        ("Windows Event 4776 - Credential Validation", "linux_syslog"),
        ("Registry key HKLM\\Software", "linux_syslog"),
        ("File path C:\\Windows\\System32", "azure_signin"),
        ("/etc/passwd modification", "linux_syslog"),
        ("/etc/passwd modification", "windows_events"),
        ("Azure AD sign-in anomaly", "azure_signin"),
        ("Azure AD sign-in anomaly", "linux_syslog"),
    ]

    for indicator, index in test_cases:
        platforms = get_index_platforms(index)
        compatible = is_indicator_compatible(indicator, platforms)
        print(f"Indicator: {indicator[:50]}")
        print(f"  Index: {index}")
        print(f"  Platforms: {platforms}")
        print(f"  Compatible: {compatible}")
        print()

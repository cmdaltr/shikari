"""
Enhanced Platform Validation Module v2

Comprehensive validation rules:
1. Event logs & Registry → Windows ONLY
2. Path separators: \ (Windows) vs / (Unix/Linux/macOS)
3. Commands parsed from technique description context
4. Software compatibility based on technique platforms
5. Context-aware validation using technique metadata

Examples:
- T1098.007: "On Windows... net localgroup" vs "On Linux... usermod"
- T1105: File transfer - check paths for platform indicators
- Registry indicators → ONLY Windows indexes
- Event log indicators → ONLY Windows indexes
"""

import re
from typing import Set, Optional, Dict, Tuple


# ============================================================================
# Platform/Index Classification
# ============================================================================

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


# ============================================================================
# Strict Rules (Always Apply)
# ============================================================================

def has_windows_only_indicators(text: str) -> bool:
    """
    Check for indicators that ONLY exist on Windows.
    These should NEVER appear in non-Windows queries.
    """
    if not text:
        return False

    text_lower = text.lower()

    # Event Logs (Windows ONLY)
    event_log_patterns = [
        r'\bwindows event\b',
        r'\bevent\s*(?:id|code)?\s*\d{4,5}\b',  # Event 4776, EventID 4624
        r'\bsecurity\.evtx\b',
        r'\bsystem\.evtx\b',
        r'\bapplication\.evtx\b',
        r'\bevtx\b',
    ]

    for pattern in event_log_patterns:
        if re.search(pattern, text_lower):
            return True

    # Registry (Windows ONLY)
    registry_patterns = [
        r'\bregistry\s+(key|value|hive|path)\b',
        r'\bhklm\\',
        r'\bhkcu\\',
        r'\bhkey_',
        r'\bhkcr\\',
        r'\bhku\\',
        r'\bregedit\b',
        r'\breg\s+add\b',
        r'\breg\s+query\b',
    ]

    for pattern in registry_patterns:
        if re.search(pattern, text_lower):
            return True

    # Windows-specific paths with backslashes
    windows_path_patterns = [
        r'c:[/\\]',  # C:\ or C:/
        r'd:[/\\]',  # D:\ etc
        r'\\windows\\',
        r'\\program files',
        r'\\system32\\',
        r'\\syswow64\\',
        r'\\programdata\\',
        r'\\appdata\\',
        r'\\users\\',
        r'\\winnt\\',
    ]

    for pattern in windows_path_patterns:
        if re.search(pattern, text_lower):
            return True

    # Windows-specific processes/services
    windows_specific_procs = [
        r'\blsass\.exe\b',
        r'\bwinlogon\.exe\b',
        r'\bcsrss\.exe\b',
        r'\bsmss\.exe\b',
        r'\bservices\.exe\b',
        r'\bwininit\.exe\b',
        r'\bntoskrnl\.exe\b',
        r'\bsam database\b',
        r'\bntlm\b',
        r'\bkerberos ticket\b',
        r'\bactive directory replication\b',
        r'\bgroup policy\b',
        r'\bwmi\b',
    ]

    for pattern in windows_specific_procs:
        if re.search(pattern, text_lower):
            return True

    return False


def has_linux_only_indicators(text: str) -> bool:
    """
    Check for indicators that ONLY exist on Linux/Unix.
    These should NEVER appear in Windows queries.
    """
    if not text:
        return False

    text_lower = text.lower()

    # Linux/Unix paths (forward slash + specific directories)
    linux_path_patterns = [
        r'/etc/',
        r'/var/',
        r'/tmp/',
        r'/usr/',
        r'/bin/',
        r'/sbin/',
        r'/home/',
        r'/root/',
        r'/opt/',
        r'/lib/',
        r'/dev/',
        r'/proc/',
        r'/sys/',
        r'/boot/',
        r'/mnt/',
    ]

    for pattern in linux_path_patterns:
        if re.search(pattern, text_lower):
            return True

    # Linux-specific logs
    linux_log_patterns = [
        r'\bsyslog\b',
        r'\bauth\.log\b',
        r'\bsecure\.log\b',
        r'\bmessages\.log\b',
        r'\bkern\.log\b',
        r'\bdmesg\b',
    ]

    for pattern in linux_log_patterns:
        if re.search(pattern, text_lower):
            return True

    # Linux-specific commands (not available on Windows)
    linux_commands = [
        r'\busermod\b',
        r'\buseradd\b',
        r'\buserdel\b',
        r'\bgroupadd\b',
        r'\bsu\s+-\b',
        r'\bsudo\s+',
        r'\bapt-get\b',
        r'\byum\b',
        r'\bsystemctl\b',
        r'\bservice\s+',
        r'\bchmod\b',
        r'\bchown\b',
        r'\biptables\b',
        r'\bcrontab\b',
    ]

    for pattern in linux_commands:
        if re.search(pattern, text_lower):
            return True

    return False


def has_macos_only_indicators(text: str) -> bool:
    """
    Check for indicators specific to macOS.
    """
    if not text:
        return False

    text_lower = text.lower()

    macos_patterns = [
        r'/library/launchdaemons',
        r'/library/launchagents',
        r'/system/library',
        r'/applications/',
        r'\.plist\b',
        r'\blaunchctl\b',
        r'\bdefaults write\b',
        r'\bosascript\b',
        r'\.app/',
    ]

    for pattern in macos_patterns:
        if re.search(pattern, text_lower):
            return True

    return False


# ============================================================================
# Context-Aware Validation (Parse from Technique Description)
# ============================================================================

def parse_platform_specific_commands(technique_desc: str) -> Dict[str, Set[str]]:
    """
    Parse technique description to extract platform-specific commands.

    Example from T1098.007:
    "On Windows, accounts may use the `net localgroup` and `net group` commands"
    "On Linux, adversaries may use the `usermod` command"

    Returns:
        Dict mapping platform to set of commands:
        {
            "Windows": {"net localgroup", "net group"},
            "Linux": {"usermod"}
        }
    """
    platform_commands = {
        "Windows": set(),
        "Linux": set(),
        "macOS": set(),
        "Unix": set(),
    }

    if not technique_desc:
        return platform_commands

    # Pattern: "On {Platform}, ... `command`"
    # Matches: On Windows, On Linux, On macOS, On Unix
    pattern = r'On\s+(Windows|Linux|macOS|Unix).*?`([^`]+)`'

    matches = re.finditer(pattern, technique_desc, re.IGNORECASE)

    for match in matches:
        platform = match.group(1)
        command = match.group(2).strip()

        # Normalize platform name
        if platform.lower() == "windows":
            platform_commands["Windows"].add(command.lower())
        elif platform.lower() == "linux":
            platform_commands["Linux"].add(command.lower())
            platform_commands["Unix"].add(command.lower())
        elif platform.lower() == "macos":
            platform_commands["macOS"].add(command.lower())
        elif platform.lower() == "unix":
            platform_commands["Unix"].add(command.lower())
            platform_commands["Linux"].add(command.lower())

    return platform_commands


def check_command_platform_compatibility(
    command: str,
    platform_commands: Dict[str, Set[str]],
    target_platforms: Set[str]
) -> bool:
    """
    Check if a command is compatible with target platforms.

    Args:
        command: Command to check (e.g., "net localgroup")
        platform_commands: Dict from parse_platform_specific_commands()
        target_platforms: Platforms the index supports (e.g., {"Windows"})

    Returns:
        True if compatible, False if incompatible
    """
    command_lower = command.lower()

    # Check if command is explicitly assigned to a platform
    for platform, commands in platform_commands.items():
        if command_lower in commands:
            # Command is specific to this platform
            if platform in target_platforms:
                return True  # Platform matches
            else:
                return False  # Platform mismatch

    # Command not explicitly assigned - allow it
    return True


# ============================================================================
# Index Platform Detection
# ============================================================================

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


# ============================================================================
# Main Validation Functions
# ============================================================================

def validate_indicator_for_index(
    indicator_text: str,
    technique_desc: str,
    technique_platforms: list,
    index_name: str
) -> Tuple[bool, Optional[str]]:
    """
    Comprehensive validation of indicator compatibility.

    Args:
        indicator_text: The indicator/procedure text
        technique_desc: Full technique description from MITRE
        technique_platforms: List of platforms from technique metadata
        index_name: Target index/table name

    Returns:
        Tuple of (is_valid: bool, reason: str|None)
    """
    # Get target platforms
    index_platforms = get_index_platforms(index_name)

    if not index_platforms:
        # Can't determine - allow it
        return (True, None)

    # RULE 1: Strict Windows-only indicators
    if has_windows_only_indicators(indicator_text):
        if "Windows" not in index_platforms:
            return (False, "Windows-only indicator (event log/registry/path) for non-Windows index")

    # RULE 2: Strict Linux-only indicators
    if has_linux_only_indicators(indicator_text):
        if "Linux" not in index_platforms and "Unix" not in index_platforms:
            return (False, "Linux-only indicator (path/command/log) for non-Linux index")

    # RULE 3: Strict macOS-only indicators
    if has_macos_only_indicators(indicator_text):
        if "macOS" not in index_platforms:
            return (False, "macOS-only indicator for non-macOS index")

    # RULE 4: Parse platform-specific commands from technique description
    platform_commands = parse_platform_specific_commands(technique_desc)

    # Check each command in the indicator
    # Extract commands in backticks or quoted strings
    command_matches = re.findall(r'`([^`]+)`|"([^"]+)"', indicator_text)
    for match in command_matches:
        command = match[0] or match[1]
        if command:
            if not check_command_platform_compatibility(command, platform_commands, index_platforms):
                return (False, f"Command '{command}' not compatible with {index_platforms}")

    # RULE 5: Check technique platforms against index platforms
    # If technique doesn't support index platform at all, skip
    if technique_platforms:
        technique_platform_set = set(p.lower() for p in technique_platforms)
        index_platform_lower = set(p.lower() for p in index_platforms)

        # Basic overlap check
        has_overlap = False
        for tp in technique_platform_set:
            for ip in index_platform_lower:
                if tp in ip or ip in tp:
                    has_overlap = True
                    break

        if not has_overlap:
            # Check for generic platforms that might apply
            generic_platforms = {"iaas", "saas", "cloud", "office suite", "network"}
            if not any(gp in technique_platform_set for gp in generic_platforms):
                return (False, f"Technique platforms {technique_platforms} don't overlap with {index_platforms}")

    # RULE 6: STRICT OS SEPARATION - If technique supports multiple OS platforms,
    # require specific indicators for OS-specific indexes
    if technique_platforms and len(technique_platforms) > 1:
        # Check if technique supports BOTH Windows and Linux/Unix
        supports_windows = any(p.lower() == "windows" for p in technique_platforms)
        supports_linux = any(p.lower() in ["linux", "unix"] for p in technique_platforms)
        supports_macos = any(p.lower() == "macos" for p in technique_platforms)

        # DEBUG: Log Rule 6 evaluation
        print(f"      🔍 RULE 6: Multi-OS check - supports_win={supports_windows}, supports_linux={supports_linux}, index_platforms={index_platforms}")

        if supports_windows and (supports_linux or supports_macos):
            # Multi-OS technique - REQUIRE specific indicators for OS-specific indexes
            if "Windows" in index_platforms and "Linux" not in index_platforms and "macOS" not in index_platforms:
                # Windows-only index - MUST have Windows-specific indicators
                has_strict = has_windows_only_indicators(indicator_text)
                print(f"         → Windows index: has_strict_windows={has_strict}, checking indicator_text[:100]='{indicator_text[:100]}'")
                if not has_strict:
                    # Check for Windows-suggestive patterns (less strict)
                    windows_suggestive = any(pattern in indicator_text.lower() for pattern in [
                        ".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", "powershell",
                        "cmd.exe", "svchost", "lsass", "winlogon", "explorer.exe"
                    ])
                    print(f"         → Windows-suggestive={windows_suggestive}")
                    if not windows_suggestive:
                        return (False, f"Multi-OS technique ({technique_platforms}) requires Windows-specific indicators for Windows index, but none found")

            elif ("Linux" in index_platforms or "Unix" in index_platforms) and "Windows" not in index_platforms:
                # Linux/Unix-only index - MUST have Linux-specific indicators
                has_strict = has_linux_only_indicators(indicator_text)
                print(f"         → Linux/Unix index: has_strict_linux={has_strict}, checking indicator_text[:100]='{indicator_text[:100]}'")
                if not has_strict:
                    # Check for Linux-suggestive patterns (less strict)
                    linux_suggestive = any(pattern in indicator_text.lower() for pattern in [
                        "/bin/", "/usr/", "/etc/", "/var/", "/home/", "/root/", "/tmp/",
                        "bash", "sh", "chmod", "chown", "sudo", "systemctl", "systemd"
                    ])
                    print(f"         → Linux-suggestive={linux_suggestive}")
                    if not linux_suggestive:
                        return (False, f"Multi-OS technique ({technique_platforms}) requires Linux-specific indicators for Linux index, but none found")

            elif "macOS" in index_platforms and "Windows" not in index_platforms and "Linux" not in index_platforms:
                # macOS-only index - MUST have macOS-specific indicators
                if not has_macos_only_indicators(indicator_text):
                    # Check for macOS-suggestive patterns (less strict)
                    macos_suggestive = any(pattern in indicator_text.lower() for pattern in [
                        "/library/", "/applications/", "/users/", "launchctl", "defaults",
                        ".app", ".plist", "~/library"
                    ])
                    if not macos_suggestive:
                        return (False, f"Multi-OS technique ({technique_platforms}) requires macOS-specific indicators for macOS index, but none found")

    return (True, None)


# ============================================================================
# Simplified API for Integration
# ============================================================================

def validate_procedure_for_index(
    procedure_text: str,
    index_name: str,
    vendor: str = "Splunk",
    technique_desc: str = "",
    technique_platforms: list = None
) -> bool:
    """
    Simplified validation for integration with detections.py

    Args:
        procedure_text: Procedure/indicator text
        index_name: Target index/table name
        vendor: "Splunk" or "MDE"
        technique_desc: Full technique description (optional but recommended)
        technique_platforms: List of platforms from technique (optional)

    Returns:
        True if compatible, False to skip
    """
    # DEBUG: Log what we're receiving
    print(f"    🔍 VALIDATOR for {index_name}:")
    print(f"      - technique_desc len: {len(technique_desc or '')}")
    print(f"      - technique_platforms: {technique_platforms}")
    print(f"      - procedure_text sample: {(procedure_text or '')[:80]}")

    is_valid, reason = validate_indicator_for_index(
        procedure_text,
        technique_desc or "",
        technique_platforms or [],
        index_name
    )

    if not is_valid and reason:
        print(f"      ❌ REJECTED: {reason}")

    return is_valid


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    # Test cases
    test_cases = [
        # Windows-only indicators
        ("Windows Event 4776 - Credential Validation", "", [], "linux_syslog"),
        ("Registry key HKLM\\Software", "", [], "linux_syslog"),
        ("File path C:\\Windows\\System32", "", [], "azure_signin"),

        # Linux-only indicators
        ("/etc/passwd modification", "", [], "linux_syslog"),
        ("/etc/passwd modification", "", [], "windows_events"),
        ("usermod command executed", "", [], "windows_events"),

        # Context-aware commands
        ("net localgroup administrators", "On Windows, use `net localgroup`", ["Windows", "Linux"], "linux_syslog"),
        ("usermod -aG sudo user", "On Linux, use `usermod`", ["Windows", "Linux"], "windows_events"),

        # Azure-specific
        ("Azure AD sign-in anomaly", "", ["Azure AD"], "azure_signin"),
        ("Azure AD sign-in anomaly", "", ["Azure AD"], "linux_syslog"),
    ]

    print("Platform Validation Test Results\n" + "="*60)

    for indicator, desc, platforms, index in test_cases:
        is_valid, reason = validate_indicator_for_index(indicator, desc, platforms, index)
        print(f"\nIndicator: {indicator[:60]}")
        print(f"  Index: {index}")
        print(f"  Valid: {is_valid}")
        if reason:
            print(f"  Reason: {reason}")

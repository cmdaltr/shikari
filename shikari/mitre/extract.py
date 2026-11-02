#!/usr/bin/env python3 -tt
import re


def extract_network_indicators(combined_desc):
    """
    Extract network-related indicators (ports, protocols, services) from text.
    Uses context-aware patterns to avoid false positives from dates, versions, etc.

    Returns:
        Dictionary with 'port', 'protocol', and 'service' keys
    """
    result = {}

    # Common well-known ports to validate against
    COMMON_PORTS = {
        '20', '21',      # FTP
        '22',            # SSH
        '23',            # Telnet
        '25',            # SMTP
        '53',            # DNS
        '67', '68',      # DHCP
        '80',            # HTTP
        '110',           # POP3
        '123',           # NTP
        '135', '137', '138', '139',  # NetBIOS/SMB
        '143',           # IMAP
        '161', '162',    # SNMP
        '389',           # LDAP
        '443',           # HTTPS
        '445',           # SMB
        '465',           # SMTPS
        '514',           # Syslog
        '587',           # SMTP Submission
        '636',           # LDAPS
        '993',           # IMAPS
        '995',           # POP3S
        '1433', '1434',  # SQL Server
        '1521',          # Oracle
        '3306',          # MySQL
        '3389',          # RDP
        '5432',          # PostgreSQL
        '5900',          # VNC
        '6379',          # Redis
        '8080', '8443', '8888',  # Alternative HTTP/HTTPS
        '9200', '9300',  # Elasticsearch
        '27017',         # MongoDB
    }

    # Extract ports with context - only when explicitly mentioned as ports
    # Pattern 1: "port 443", "Port: 80", "port number 22"
    explicit_port_pattern = r'\bport[:\s]+(?:number[:\s]+)?(\d{1,5})\b'
    explicit_matches = re.findall(explicit_port_pattern, combined_desc, re.IGNORECASE)

    # Pattern 2: Port with protocol suffix "443/tcp", "80/udp"
    protocol_suffix_pattern = r'\b(\d{1,5})/(tcp|udp)\b'
    protocol_suffix_matches = re.findall(protocol_suffix_pattern, combined_desc, re.IGNORECASE)

    # Pattern 3: Colon-prefixed in URL or network context ":443", ":8080"
    # But exclude time stamps (avoid :00, :01, :30, etc.)
    colon_pattern = r'[^\d]:(\d{2,5})\b'
    colon_matches = re.findall(colon_pattern, combined_desc)

    # Combine and validate all port matches
    ports = []

    # Add explicit port mentions
    for port in explicit_matches:
        if port.isdigit() and 1 <= int(port) <= 65535:
            ports.append(port)

    # Add ports with protocol suffix
    for port, proto in protocol_suffix_matches:
        if port.isdigit() and 1 <= int(port) <= 65535:
            ports.append(port)

    # Add colon-prefixed ports, but only if they're common ports (to avoid false positives)
    for port in colon_matches:
        if port.isdigit() and port in COMMON_PORTS:
            ports.append(port)

    if ports:
        result["port"] = sorted(list(set(ports)), key=int)

    # Protocols - only extract common network protocol acronyms
    # Exclude generic terms like TCP/UDP when they're just transport layer mentions
    # Focus on application layer protocols
    # IMPORTANT: Remove URLs first to avoid extracting protocols from URL schemes (https://, ftp://, etc.)
    text_without_urls = re.sub(r'https?://[^\s]+', '', combined_desc, flags=re.IGNORECASE)
    text_without_urls = re.sub(r'ftps?://[^\s]+', '', text_without_urls, flags=re.IGNORECASE)

    protocol_pattern = r'\b(HTTPS?|FTPS?|SFTP|SSH|SMB|CIFS|RDP|DNS|LDAPS?|SMTP|POP3S?|IMAPS?|SNMP|TELNET|TFTP|NFS|NTP|DHCP|SOCKS)\b'
    protocol_matches = re.findall(protocol_pattern, text_without_urls, re.IGNORECASE)
    if protocol_matches:
        result["protocol"] = sorted(list(set([p.upper() for p in protocol_matches])))

    # Services - be more selective, only extract when clearly mentioned as a service
    # Avoid extracting protocol names that might also be service names
    service_pattern = r'\b(apache2?|nginx|iis|microsoft-iis|mysql|mariadb|postgresql|postgres|mssql|mongodb|mongo|redis|memcached|elasticsearch|elastic|docker|dockerd|kubernetes|k8s|kubelet)\b'
    service_matches = re.findall(service_pattern, combined_desc, re.IGNORECASE)
    if service_matches:
        # Normalize service names
        normalized = []
        for s in service_matches:
            s_lower = s.lower()
            # Normalize variants
            if s_lower in ('apache', 'apache2'):
                normalized.append('apache')
            elif s_lower in ('postgres', 'postgresql'):
                normalized.append('postgresql')
            elif s_lower in ('mongo', 'mongodb'):
                normalized.append('mongodb')
            elif s_lower in ('elastic', 'elasticsearch'):
                normalized.append('elasticsearch')
            elif s_lower in ('k8s', 'kubernetes', 'kubelet'):
                normalized.append('kubernetes')
            else:
                normalized.append(s_lower)
        result["service"] = sorted(list(set(normalized)))

    return result


def transform_url_to_api_method(url_indicator):
    """
    Transform URL-based API indicators to method name format.

    Examples:
        GET https://cloudidentity.googleapis.com/v1/groups -> cloudidentity.groups.list
        POST https://iam.googleapis.com/v1/projects/{project}/serviceAccounts -> iam.serviceAccounts.create
        https://graph.microsoft.com/v1.0/users -> microsoft.graph.users.list
    """
    import re

    # Remove HTTP method if present
    url = re.sub(r'^(GET|POST|PUT|DELETE|PATCH)\s+', '', url_indicator.strip())

    # GCP API URLs
    gcp_match = re.match(r'https?://([^.]+)\.googleapis\.com/v\d+/(.+)', url)
    if gcp_match:
        service = gcp_match.group(1)  # e.g., cloudidentity, iam
        path = gcp_match.group(2)     # e.g., groups, projects/{project}/serviceAccounts

        # Clean path - remove variable placeholders and trailing slashes
        path = re.sub(r'\{[^}]+\}/?', '', path)
        path = path.rstrip('/')

        # Convert path to method name
        # groups -> groups.list, projects/serviceAccounts -> serviceAccounts
        parts = [p for p in path.split('/') if p and not p.startswith('{')]
        if parts:
            resource = parts[-1]  # Last part is the resource
            return f"{service}.{resource}.list"

    # Azure/Microsoft Graph API URLs
    azure_match = re.match(r'https?://(?:graph\.microsoft\.com|management\.azure\.com)/[^/]+/(.+)', url)
    if azure_match:
        path = azure_match.group(1)
        path = re.sub(r'\{[^}]+\}/?', '', path)
        path = path.rstrip('/')
        parts = [p for p in path.split('/') if p]
        if parts:
            return '.'.join(parts[-2:]) if len(parts) >= 2 else parts[-1]

    # AWS API - typically already in method format, but handle URLs
    aws_match = re.match(r'https?://([^.]+)\.amazonaws\.com', url)
    if aws_match:
        service = aws_match.group(1)
        return service

    # Return original if no transformation applied
    return url_indicator


# Mapping from known cloud API names to their AWS CLI equivalents.
# Used to generate cmd-type indicators for endpoint telemetry (ProcessCommandLine)
# alongside the api-type indicator for CloudTrail/ActivityLog.
# Format: api_name → (cli_prefix, subcommand)
# e.g. "aws ec2 describe-instances" appears in ProcessCommandLine on MDE endpoints.
_AWS_API_TO_CLI = {
    # EC2 / compute
    "DescribeInstances":          ("aws ec2", "describe-instances"),
    "DescribeInstanceStatus":     ("aws ec2", "describe-instance-status"),
    "DescribeImages":             ("aws ec2", "describe-images"),
    "DescribeVpcs":               ("aws ec2", "describe-vpcs"),
    "DescribeSubnets":            ("aws ec2", "describe-subnets"),
    "DescribeSecurityGroups":     ("aws ec2", "describe-security-groups"),
    "DescribeSnapshots":          ("aws ec2", "describe-snapshots"),
    "DescribeVolumes":            ("aws ec2", "describe-volumes"),
    "DescribeKeyPairs":           ("aws ec2", "describe-key-pairs"),
    "DescribeLoadBalancers":      ("aws elbv2", "describe-load-balancers"),
    # S3
    "ListBuckets":                ("aws s3api", "list-buckets"),
    "HeadBucket":                 ("aws s3api", "head-bucket"),
    "GetBucketAcl":               ("aws s3api", "get-bucket-acl"),
    "GetBucketPolicy":            ("aws s3api", "get-bucket-policy"),
    "GetPublicAccessBlock":       ("aws s3api", "get-public-access-block"),
    "ListObjectsV2":              ("aws s3api", "list-objects-v2"),
    # RDS
    "DescribeDBInstances":        ("aws rds", "describe-db-instances"),
    "DescribeDBClusters":         ("aws rds", "describe-db-clusters"),
    "DescribeDBSnapshots":        ("aws rds", "describe-db-snapshots"),
    # IAM
    "ListUsers":                  ("aws iam", "list-users"),
    "ListGroups":                 ("aws iam", "list-groups"),
    "ListRoles":                  ("aws iam", "list-roles"),
    "ListPolicies":               ("aws iam", "list-policies"),
    "GetCallerIdentity":          ("aws sts", "get-caller-identity"),
    "ListAttachedRolePolicies":   ("aws iam", "list-attached-role-policies"),
    # Lambda / serverless
    "ListFunctions":              ("aws lambda", "list-functions"),
    # CloudFormation / infra
    "DescribeStacks":             ("aws cloudformation", "describe-stacks"),
    "ListStackResources":         ("aws cloudformation", "list-stack-resources"),
    # IAM: the calls ATT&CK's cloud procedures cite
    "AttachUserPolicy":           ("aws iam", "attach-user-policy"),
    "AttachRolePolicy":           ("aws iam", "attach-role-policy"),
    "AttachGroupPolicy":          ("aws iam", "attach-group-policy"),
    "PutUserPolicy":              ("aws iam", "put-user-policy"),
    "PutRolePolicy":              ("aws iam", "put-role-policy"),
    "CreateUser":                 ("aws iam", "create-user"),
    "CreateAccessKey":            ("aws iam", "create-access-key"),
    "CreateLoginProfile":         ("aws iam", "create-login-profile"),
    "UpdateLoginProfile":         ("aws iam", "update-login-profile"),
    "CreatePolicyVersion":        ("aws iam", "create-policy-version"),
    "SetDefaultPolicyVersion":    ("aws iam", "set-default-policy-version"),
    "UpdateAssumeRolePolicy":     ("aws iam", "update-assume-role-policy"),
    "AddUserToGroup":             ("aws iam", "add-user-to-group"),
    "GetAccountPasswordPolicy":   ("aws iam", "get-account-password-policy"),
    "GetAccountAuthorizationDetails": ("aws iam", "get-account-authorization-details"),
    "ListAccessKeys":             ("aws iam", "list-access-keys"),
    "ListRolePolicies":           ("aws iam", "list-role-policies"),
    "ListUserPolicies":           ("aws iam", "list-user-policies"),
    "ListAttachedUserPolicies":   ("aws iam", "list-attached-user-policies"),
    "DeleteAccessKey":            ("aws iam", "delete-access-key"),
    # STS
    "AssumeRole":                 ("aws sts", "assume-role"),
    "GetSessionToken":            ("aws sts", "get-session-token"),
    "GetFederationToken":         ("aws sts", "get-federation-token"),
    # EC2
    "CreateKeyPair":              ("aws ec2", "create-key-pair"),
    "ImportKeyPair":              ("aws ec2", "import-key-pair"),
    "RunInstances":               ("aws ec2", "run-instances"),
    "ModifyInstanceAttribute":    ("aws ec2", "modify-instance-attribute"),
    "CreateSnapshot":             ("aws ec2", "create-snapshot"),
    "ModifySnapshotAttribute":    ("aws ec2", "modify-snapshot-attribute"),
    "ModifyImageAttribute":       ("aws ec2", "modify-image-attribute"),
    "AuthorizeSecurityGroupIngress": ("aws ec2", "authorize-security-group-ingress"),
    "GetPasswordData":            ("aws ec2", "get-password-data"),
    "DescribeRegions":            ("aws ec2", "describe-regions"),
    "DescribeAccountAttributes":  ("aws ec2", "describe-account-attributes"),
    "DeleteFlowLogs":             ("aws ec2", "delete-flow-logs"),
    # S3
    "GetObject":                  ("aws s3api", "get-object"),
    "PutBucketPolicy":            ("aws s3api", "put-bucket-policy"),
    "DeleteBucketPolicy":         ("aws s3api", "delete-bucket-policy"),
    "PutBucketAcl":               ("aws s3api", "put-bucket-acl"),
    "PutBucketLifecycleConfiguration": ("aws s3api", "put-bucket-lifecycle-configuration"),
    "DeleteObjects":              ("aws s3api", "delete-objects"),
    # Logging and defences
    "StopLogging":                ("aws cloudtrail", "stop-logging"),
    "DeleteTrail":                ("aws cloudtrail", "delete-trail"),
    "UpdateTrail":                ("aws cloudtrail", "update-trail"),
    "PutEventSelectors":          ("aws cloudtrail", "put-event-selectors"),
    "DeleteDetector":             ("aws guardduty", "delete-detector"),
    "UpdateDetector":             ("aws guardduty", "update-detector"),
    "DeleteConfigurationRecorder": ("aws configservice", "delete-configuration-recorder"),
    "StopConfigurationRecorder":  ("aws configservice", "stop-configuration-recorder"),
    # Secrets, parameters, keys
    "GetSecretValue":             ("aws secretsmanager", "get-secret-value"),
    "ListSecrets":                ("aws secretsmanager", "list-secrets"),
    "GetParameter":               ("aws ssm", "get-parameter"),
    "GetParameters":              ("aws ssm", "get-parameters"),
    "SendCommand":                ("aws ssm", "send-command"),
    "StartSession":               ("aws ssm", "start-session"),
    "Decrypt":                    ("aws kms", "decrypt"),
    "ScheduleKeyDeletion":        ("aws kms", "schedule-key-deletion"),
    "DisableKey":                 ("aws kms", "disable-key"),
    "ListKeys":                   ("aws kms", "list-keys"),
    # Organizations, Lambda
    "ListAccounts":               ("aws organizations", "list-accounts"),
    "DescribeOrganization":       ("aws organizations", "describe-organization"),
    "LeaveOrganization":          ("aws organizations", "leave-organization"),
    "CreateFunction":             ("aws lambda", "create-function"),
    "UpdateFunctionCode":         ("aws lambda", "update-function-code"),
    "AddPermission":              ("aws lambda", "add-permission"),
}

# Windows API functions ATT&CK's procedures name. They never appear in a command line;
# Defender XDR records some of them as DeviceEvents ActionTypes, and those become
# "api_event" indicators. The rest are left out of queries.
_WINAPI_TO_MDE_ACTION = {
    "CreateRemoteThread":         "CreateRemoteThreadApiCall",
    "CreateRemoteThreadEx":       "CreateRemoteThreadApiCall",
    "NtCreateThreadEx":           "CreateRemoteThreadApiCall",
    "RtlCreateUserThread":        "CreateRemoteThreadApiCall",
    "GetAsyncKeyState":           "GetAsyncKeyStateApiCall",
    "VirtualAllocEx":             "NtAllocateVirtualMemoryRemoteApiCall",
    "VirtualAlloc":               "NtAllocateVirtualMemoryApiCall",
    "NtAllocateVirtualMemory":    "NtAllocateVirtualMemoryApiCall",
    "VirtualProtectEx":           "MemoryRemoteProtect",
    "VirtualProtect":             "NtProtectVirtualMemoryApiCall",
    "NtProtectVirtualMemory":     "NtProtectVirtualMemoryApiCall",
    "NtMapViewOfSection":         "NtMapViewOfSectionRemoteApiCall",
    "ZwMapViewOfSection":         "NtMapViewOfSectionRemoteApiCall",
    "MapViewOfFile2":             "NtMapViewOfSectionRemoteApiCall",
    "OpenProcess":                "OpenProcessApiCall",
    "QueueUserAPC":               "QueueUserApcRemoteApiCall",
    "NtQueueApcThread":           "QueueUserApcRemoteApiCall",
    "NtQueueApcThreadEx":         "QueueUserApcRemoteApiCall",
    "ReadProcessMemory":          "ReadProcessMemoryApiCall",
    "NtReadVirtualMemory":        "ReadProcessMemoryApiCall",
    "SetThreadContext":           "SetThreadContextRemoteApiCall",
    "NtSetContextThread":         "SetThreadContextRemoteApiCall",
    "WriteProcessMemory":         "WriteProcessMemoryApiCall",
    "NtWriteVirtualMemory":       "WriteProcessMemoryApiCall",
}
_WINAPI_NAMES = set(_WINAPI_TO_MDE_ACTION) | {
    "AdjustTokenPrivileges", "CheckRemoteDebuggerPresent", "CopyFromScreen", "CreateFileMapping", "CreateProcess",
    "CreateProcessA", "CreateProcessW", "CreateProcessAsUser", "CreateProcessAsUserA", "CreateProcessAsUserW",
    "CreateProcessWithLogonW", "CreateProcessWithTokenW", "CreateService", "CreateToolhelp32Snapshot", "CredEnumerate",
    "CredEnumerateA", "CredEnumerateW", "CryptUnprotectData", "DuplicateToken", "DuplicateTokenEx", "EnumProcesses",
    "EnumSystemLocalesW", "EnumWindows", "FindWindow", "FindWindowA", "FindWindowW", "GetComputerName", "GetDriveType",
    "GetForegroundWindow", "GetKeyboardLayoutList", "GetKeyState", "GetLocaleInfoW", "GetModuleHandle", "GetProcAddress",
    "GetSystemDefaultUILanguage", "GetSystemTimeAsFileTime", "GetTickCount", "GetUserDefaultLangID",
    "GetUserDefaultUILanguage", "GetUserName", "GetWindowText", "ImpersonateLoggedOnUser", "IsDebuggerPresent",
    "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "LoadLibraryEx", "LogonUser", "LogonUserA", "LogonUserW",
    "LookupPrivilegeValue", "MiniDumpWriteDump", "NtCreateProcess", "NtCreateProcessEx", "NtQueryInformationProcess",
    "NtQuerySystemInformation", "NtResumeThread", "NtUnmapViewOfSection", "OpenThread", "PostMessage", "ResumeThread",
    "RegisterHotKey", "SendMessage", "SetThreadToken", "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "ShellExecute", "ShowWindow", "SuspendThread", "URLDownloadToFile", "WinExec", "ZwUnmapViewOfSection",
}
# Shape of a Windows API name the lists above don't have: a native-API prefix, or the
# A/W/Ex suffix of the Win32 ANSI, wide and extended variants
_WINAPI_SHAPE = re.compile(r"^(?:Nt|Zw|Rtl|Ldr)[A-Z][A-Za-z]+$|^[A-Z][a-z]+(?:[A-Z][a-z0-9]+)+(?:Ex)?[AW]$|^[A-Z][a-z]+(?:[A-Z][a-z0-9]+)+Ex$")
# Placeholder names from documentation ("ExampleFunctionA")
_PLACEHOLDER_NAME = re.compile(r"^(?:Example|Sample|Foo|Bar|Test)[A-Z]")
# Words that mark a procedure as being about a cloud platform, so an unknown
# PascalCase operation can be treated as a cloud API call
_CLOUD_CONTEXT = re.compile(r"\b(?:AWS|Amazon|CloudTrail|S3|EC2|IAM|Azure|Entra|GCP|Google Cloud|Kubernetes|Okta|"
                            r"Graph API|Microsoft 365|Office 365|M365|O365|CloudWatch|Lambda)\b")
_CLOUD_VERB = re.compile(r"^(?:Describe|List|Get|Create|Delete|Put|Attach|Detach|Update|Modify|Run|Start|Stop|"
                         r"Import|Export|Assume|Set|Add|Remove|Enable|Disable|Invoke|Send|Copy|Restore|Authorize)[A-Z]")


def _api_to_cli(api_name: str):
    """The AWS CLI form of a cloud API call ("aws ec2 describe-instances"), which is what
    a process command line shows when someone runs it from a shell. None for a name the
    table doesn't have: the CLI needs the service, and guessing it gives a command
    nobody ever ran."""
    if api_name in _AWS_API_TO_CLI:
        prefix, sub = _AWS_API_TO_CLI[api_name]
        return f"{prefix} {sub}"
    return None


def classify_name(name: str, context: str = "") -> str:
    """What a bare PascalCase name from a procedure is: "cloud" (a cloud API call),
    "winapi" (a Windows API function), "placeholder" or "word" (left out), or "term"
    (a literal worth matching as written, such as MSExchangeIS or AnyDesk)."""
    if name in _AWS_API_TO_CLI:
        return "cloud"
    if name in _WINAPI_NAMES:
        return "winapi"
    if _PLACEHOLDER_NAME.match(name):
        return "placeholder"
    if re.fullmatch(r"[A-Z][a-z]+", name):
        return "word"  # one capitalised word ("Index", "Data"): matches everything
    if _CLOUD_VERB.match(name) and _CLOUD_CONTEXT.search(context):
        return "cloud"
    if _WINAPI_SHAPE.match(name):
        return "winapi"
    return "term"


def extract_commands(combined_desc):
    cleaned_desc = (
        combined_desc.replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2018", "'")
        .replace("\u2019", "'")
    )
    cmds = re.findall("(?:`|<code>)([^`<]+)(?:`|</code>)", cleaned_desc)
    normalised_cmds = [cmd.strip() for cmd in cmds]

    # Classify indicators as API calls vs. commands
    # API calls are AWS/Azure/GCP API operations (also run from a shell, as the CLI), not
    # Windows API functions, which go to Defender's API-call events instead
    api_calls = []
    commands = []
    api_events = []

    # Patterns that indicate API calls (not CLI commands)
    api_patterns = [
        # Standard PascalCase: DescribeInstances, ListBuckets, GetPublicAccessBlock
        r'^[A-Z][a-z]+(?:[A-Z][a-z]+)*$',
        # PascalCase with acronyms (DB, RDS, VPC, ACL, IAM, S3, EC2, KMS, SQS…)
        # e.g. DescribeDBInstances, GetIAMPolicy, ListS3Buckets, DescribeVPCs
        r'^[A-Z][A-Za-z0-9]+$',
    ]

    # Patterns that indicate URL-based API calls
    url_api_patterns = [
        r'^(GET|POST|PUT|DELETE|PATCH)\s+https?://',  # HTTP method + URL
        r'^https?://[^/]+\.googleapis\.com/',          # GCP API URLs
        r'^https?://graph\.microsoft\.com/',           # Microsoft Graph API
        r'^https?://management\.azure\.com/',          # Azure Management API
        r'^https?://[^/]+\.amazonaws\.com/',           # AWS API URLs
    ]

    # Patterns that indicate CLI commands (not API calls)
    cli_patterns = [
        r'^aws\s',      # aws iam list-users (AWS CLI)
        r'^gcloud\s',   # gcloud compute instances list (gcloud CLI)
        r'^az\s',       # az vm list (Azure CLI)
        r'^kubectl\s',  # kubectl get pods
        r'\s',          # Contains spaces (likely a command with args)
        r'[/\\.]',      # Contains path separators or dots in middle (./script, net.exe)
    ]

    for cmd in normalised_cmds:
        # Check if it's a URL-based API call
        is_url_api = any(re.search(pattern, cmd, re.IGNORECASE) for pattern in url_api_patterns)

        if is_url_api:
            # Transform URL to method name format
            method_name = transform_url_to_api_method(cmd)
            api_calls.append(method_name)
            continue

        # Check if it's clearly a CLI command
        is_cli = any(re.search(pattern, cmd) for pattern in cli_patterns)

        # Check if it looks like an API call (PascalCase)
        is_api = any(re.match(pattern, cmd) for pattern in api_patterns)

        if is_api and not is_cli:
            kind = classify_name(cmd, cleaned_desc)
            if kind == "cloud":
                api_calls.append(cmd)
                # The same call run from a shell shows in the process command line
                cli_form = _api_to_cli(cmd)
                if cli_form:
                    commands.append(cli_form)
            elif kind == "winapi":
                if cmd in _WINAPI_TO_MDE_ACTION:
                    api_events.append(_WINAPI_TO_MDE_ACTION[cmd])
            elif kind == "term":
                commands.append(cmd)
        else:
            commands.append(cmd)

    # Deduplicate while preserving order
    seen: set = set()
    commands = [c for c in commands if not (c.lower() in seen or seen.add(c.lower()))]

    result = {}
    if commands:
        result["cmd"] = commands
    if api_calls:
        result["api"] = api_calls
    if api_events:
        result["api_event"] = list(dict.fromkeys(api_events))

    # Also extract network indicators from the full description
    network_indicators = extract_network_indicators(cleaned_desc)
    result.update(network_indicators)

    return result


def extract_software(combined_desc):
    return {
        "sw": re.findall(
            r"\[([^\]]+)\]\(https:\/\/attack\.mitre\.org\/software/S",
            combined_desc,
        )
    }


def extract_registry_evidence(combined_desc):
    reg_evidence = re.findall(
        r"([Hh][Kk](?:[Ll][Mm]|[Cc][Uu]|[Ee][Yy])[^\{\}\|\"'!$<>`]+)",
        combined_desc.lower()
        .replace("hkey_local_machine", "hklm")
        .replace("hkey_current_user", "hkcu")
        .replace("[hklm]", "hklm")
        .replace("[hkcu]", "hkcu")
        .replace("hklm]", "hklm")
        .replace("hkcu]", "hkcu")
        .replace("“", '"')
        .replace("”", '"')
        .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
        .replace("\\\\\\\\\\\\\\\\", "\\")
        .replace("\\\\\\\\\\\\", "\\")
        .replace("\\\\\\\\", "\\")
        .replace("£\\\\t£", "\\\\t")
        .replace('""', '"')
        .replace("  ", " ")
        .replace("[.]", ".")
        .replace("[:]", ":")
        .replace("&#42;", "*")
        .replace("&lbrace;", "{")
        .replace("&rbrace;", "}")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("[username]", "%username%")
        .replace("\\]\\", "]\\")
        .replace('""', '"')
        .replace('""', '"')
        .strip("\\")
        .strip(),
    )
    return {"reg": sorted(list(set(reg_evidence)))}


def extract_evts(detection):
    evts = re.findall(r"(?:(?:Event ?|E)I[Dd]( ==)? ?\"?(\d{1,5}))", detection)
    return {"evt": re.findall(r"'(\d+)'", str(sorted(list(set(evts)))))}


def extract_red(combined_desc):
    if "`" in combined_desc or "<code>" in combined_desc:  # operator_guidance
        command_evidence = extract_commands(combined_desc)
    else:
        command_evidence = ""
    if "software" in combined_desc.lower():
        software_evidence = extract_software(combined_desc)  # attacker_tools
    else:
        software_evidence = ""
    return (command_evidence, software_evidence)


def extract_blue(combined_desc, detection):
    combined_desc = f"{combined_desc}\n\n{detection}"
    if "event id" in combined_desc.lower() or "eid" in combined_desc.lower():
        evt_evidence = extract_evts(combined_desc)  # detection_guidance
    else:
        evt_evidence = ""
    if (
        "hklm\\" in combined_desc.lower()
        or "hkcu\\" in combined_desc.lower()
        or "hkey\\" in combined_desc.lower()
        or "hklm]" in combined_desc.lower()
        or "hkcu]" in combined_desc.lower()
        or "hkey_" in combined_desc.lower()
    ):  # detection_guidance
        registry_evidence = extract_registry_evidence(combined_desc)
    else:
        registry_evidence = ""
    return (evt_evidence, registry_evidence)

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


def extract_commands(combined_desc):
    cleaned_desc = (
        combined_desc.replace(""", '"')
        .replace(""", '"')
        .replace("'", "'")
        .replace("'", "'")
    )
    cmds = re.findall("(?:`|<code>)([^`<]+)(?:`|</code>)", cleaned_desc)
    normalised_cmds = [cmd.strip() for cmd in cmds]

    # Classify indicators as API calls vs. commands
    # API calls are AWS/Azure/GCP API operations, not CLI commands
    api_calls = []
    commands = []

    # Patterns that indicate API calls (not CLI commands)
    api_patterns = [
        # AWS API call patterns (PascalCase without spaces, typical AWS API naming)
        r'^[A-Z][a-z]+(?:[A-Z][a-z]+)*$',  # DescribeInstances, ListBuckets, GetPublicAccessBlock
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
            api_calls.append(cmd)
        else:
            commands.append(cmd)

    result = {}
    if commands:
        result["cmd"] = commands
    if api_calls:
        result["api"] = api_calls

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

#!/usr/bin/env python3 -tt
import re


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
        # Check if it's clearly a CLI command
        is_cli = any(re.search(pattern, cmd) for pattern in cli_patterns)

        # Check if it looks like an API call
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

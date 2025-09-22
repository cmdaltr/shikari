#!/usr/bin/env python3 -tt
import re


def extract_commands(combined_desc):
    return {"cmd": re.findall("(?:`|<code>)([^`<]+)(?:`|</code>)", combined_desc)}


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

#!/usr/bin/env python3 -tt
from .enterprise import (
    consolidate_tactics,
    find_procedure_evidence,
    merge_detect_guidance,
)
import re


def get_technique_id(bundle, technique_ref):
    """
    Get the MITRE ATT&CK technique ID (e.g., T1036) from a technique reference.

    Args:
        bundle: MITRE ATT&CK bundle
        technique_ref: Technique reference ID (e.g., 'attack-pattern--...')

    Returns:
        Technique ID string (e.g., 'T1036') or None
    """
    for obj in bundle.objects:
        if obj.get("id") == technique_ref and obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    return ref.get("external_id")
    return None


def is_parent_technique(tech_id):
    """
    Check if technique ID is a parent technique (e.g., T1036 vs T1036.001).

    Args:
        tech_id: Technique ID string (e.g., 'T1036' or 'T1036.001')

    Returns:
        Boolean: True if parent technique (no dot), False if subtechnique
    """
    return tech_id and "." not in tech_id


def find_subtechniques(bundle, parent_tech_id):
    """
    Find all subtechniques for a parent technique.

    Args:
        bundle: MITRE ATT&CK bundle
        parent_tech_id: Parent technique ID (e.g., 'T1036')

    Returns:
        List of tuples: [(subtechnique_ref, subtechnique_id, subtechnique_name), ...]
    """
    subtechniques = []

    for obj in bundle.objects:
        if obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id")

                    # Check if this is a subtechnique of our parent
                    if tech_id and tech_id.startswith(parent_tech_id + "."):
                        subtechniques.append((
                            obj.get("id"),
                            tech_id,
                            obj.get("name")
                        ))
                        break

    return subtechniques


def get_subtechnique_procedures(bundle, subtechnique_ref):
    """
    Get procedures and indicators for a subtechnique.

    Args:
        bundle: MITRE ATT&CK bundle
        subtechnique_ref: Subtechnique reference ID

    Returns:
        Tuple: (description, tactics, detection_guidance, op_guidance)
    """
    for obj in bundle.objects:
        if obj.get("id") == subtechnique_ref and obj.get("type") == "attack-pattern":
            # Extract procedure information
            description = obj.get("description", "")
            tactics = consolidate_tactics(obj.get("kill_chain_phases", []))
            detection = obj.get("x_mitre_detection", "")

            # Parse for indicators
            red_info, blue_info = find_procedure_evidence("", description, detection)
            op_guidance, red_tools = red_info

            return (description, tactics, detection, op_guidance)

    return (None, None, None, None)


def extract_indicators_from_guidance(op_guidance):
    """
    Extract indicators from operational guidance dict.

    Args:
        op_guidance: Dictionary containing guidance data

    Returns:
        Set of indicator strings
    """
    indicators = set()

    if not isinstance(op_guidance, dict):
        return indicators

    for key, value in op_guidance.items():
        if isinstance(value, str):
            # Extract quoted values, file paths, commands, etc.

            # File names
            file_pattern = r'\b([a-zA-Z0-9_-]+\.(exe|dll|bat|ps1|sh|py))\b'
            file_matches = re.findall(file_pattern, value, re.IGNORECASE)
            for match in file_matches:
                indicators.add(match[0] if isinstance(match, tuple) else match)

            # Commands/processes
            cmd_pattern = r'\b(net|whoami|ipconfig|cmd|powershell|bash|sh)\b'
            cmd_matches = re.findall(cmd_pattern, value, re.IGNORECASE)
            indicators.update(cmd_matches)

            # Paths
            path_pattern = r'[A-Z]:\\[^\s"]+|/[a-z/]+/[a-z]+'
            path_matches = re.findall(path_pattern, value, re.IGNORECASE)
            indicators.update(path_matches)

            # Network Ports (common format: :port or port/tcp or port/udp)
            port_pattern = r'\b(?:port\s+)?(\d{1,5})(?:/(?:tcp|udp))?\b|\:(\d{1,5})\b'
            port_matches = re.findall(port_pattern, value, re.IGNORECASE)
            for match in port_matches:
                port = match[0] or match[1]
                if port and 1 <= int(port) <= 65535:
                    indicators.add(f"port:{port}")

            # Protocols (HTTP, HTTPS, FTP, SSH, SMB, RDP, DNS, etc.)
            protocol_pattern = r'\b(HTTP|HTTPS|FTP|FTPS|SSH|SMB|RDP|DNS|LDAP|SMTP|POP3|IMAP|SNMP|TELNET|TFTP|NFS|ICMP|TCP|UDP)\b'
            protocol_matches = re.findall(protocol_pattern, value, re.IGNORECASE)
            for proto in protocol_matches:
                indicators.add(f"protocol:{proto.upper()}")

            # Services (common service names)
            service_pattern = r'\b(apache|nginx|iis|mysql|postgresql|mongodb|redis|elasticsearch|docker|kubernetes|ssh|ftp|smb|rdp|dns|dhcp|ntp|syslog)\b'
            service_matches = re.findall(service_pattern, value, re.IGNORECASE)
            for service in service_matches:
                indicators.add(f"service:{service.lower()}")
        elif isinstance(value, list):
            # If the value is already a list of indicators, add them
            for item in value:
                if isinstance(item, str) and len(item) >= 3:
                    indicators.add(item)

    return indicators


def retrieve_group(bundle, group):
    for obj in bundle.objects:
        if (
            obj.get("type") == "intrusion-set"
            and obj.get("name").lower() == group.lower()
        ):
            return obj["id"]


def retrieve_techniques(bundle, group_id):
    techniques = []
    software_to_expand = []  # Track software that needs to be expanded to techniques

    for obj in bundle.objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "uses"
            and obj.get("source_ref") == group_id
        ):
            target_ref = obj.get("target_ref")
            description = obj.get("description")

            # Check if target is software (tool or malware) or a technique (attack-pattern)
            target_type = None
            for target_obj in bundle.objects:
                if target_obj.get("id") == target_ref:
                    target_type = target_obj.get("type")
                    break

            if target_type in ["tool", "malware"]:
                # This is software - we need to expand it to get techniques
                software_to_expand.append((description, target_ref))
            elif target_type == "attack-pattern":
                # This is a technique - add it directly
                techniques.append((description, target_ref))
            else:
                # Unknown type - add it anyway for backward compatibility
                techniques.append((description, target_ref))

    # Now expand software to their techniques
    # For each software, find what techniques it uses
    for sw_desc, sw_ref in software_to_expand:
        sw_tech_count = 0
        for rel_obj in bundle.objects:
            if (
                rel_obj.get("type") == "relationship"
                and rel_obj.get("relationship_type") == "uses"
                and rel_obj.get("source_ref") == sw_ref
            ):
                # This software uses a technique
                tech_ref = rel_obj.get("target_ref")
                tech_desc = rel_obj.get("description")

                # Combine the group's description of using the software
                # with the software's use of the technique
                combined_desc = f"{sw_desc} {tech_desc}" if tech_desc else sw_desc

                techniques.append((combined_desc, tech_ref))
                sw_tech_count += 1

    # Also include techniques from campaigns attributed to this group
    # This matches how MITRE ATT&CK website displays group techniques
    campaign_ids = []
    for obj in bundle.objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "attributed-to"
            and obj.get("target_ref") == group_id
        ):
            campaign_ids.append(obj.get("source_ref"))

    # Get techniques used by each campaign
    existing_tech_refs = {t[1] for t in techniques}  # Track existing techniques to avoid duplicates
    for campaign_id in campaign_ids:
        for obj in bundle.objects:
            if (
                obj.get("type") == "relationship"
                and obj.get("relationship_type") == "uses"
                and obj.get("source_ref") == campaign_id
            ):
                target_ref = obj.get("target_ref")
                # Only add if not already in techniques list
                if target_ref not in existing_tech_refs:
                    # Check if target is a technique
                    for target_obj in bundle.objects:
                        if target_obj.get("id") == target_ref and target_obj.get("type") == "attack-pattern":
                            description = obj.get("description")
                            techniques.append((description, target_ref))
                            existing_tech_refs.add(target_ref)
                            break

    return techniques


def retrieve_additional_techniques(bundle, procedure_ref):
    """
    Retrieve additional techniques/procedures from other groups for a specific procedure.

    Args:
        bundle: The MITRE ATT&CK bundle
        procedure_ref: The reference ID of the procedure to find additional evidence for

    Returns:
        List of tuples with (group_id, description, target_ref) for the procedure
    """
    additional_techniques = []

    # Find all relationships that use this procedure
    for obj in bundle.objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "uses"
            and obj.get("target_ref") == procedure_ref
            and obj.get("source_ref") != procedure_ref  # Avoid self-references
        ):
            source_ref = obj.get("source_ref")

            # Check if source is a group (intrusion-set), not software (tool/malware)
            # We only want additional evidence from other groups, not from software
            for source_obj in bundle.objects:
                if source_obj.get("id") == source_ref:
                    if source_obj.get("type") == "intrusion-set":
                        # This is a group - add it
                        additional_techniques.append(
                            (source_ref, obj.get("description"), obj.get("target_ref"))
                        )
                    # Silently skip tool/malware types - we don't want software procedures here
                    break

    return additional_techniques


def get_all_groups(bundle):
    """
    Get a list of all intrusion-set groups in the bundle

    Args:
        bundle: The MITRE ATT&CK bundle

    Returns:
        Dictionary mapping group IDs to group names
    """
    groups = {}
    for obj in bundle.objects:
        if obj.get("type") == "intrusion-set":
            groups[obj.get("id")] = obj.get("name")
    return groups


def retrieve_procedures(bundle, retrieved_techniques):
    procedures = []
    group_ids = get_all_groups(bundle)

    # Track parent techniques for expansion
    parent_techniques = {}  # {parent_tech_id: (procedure_ref, indicators, parent_proc)}

    # Process each technique once (not for every object in bundle)
    for group_procedure_desc, procedure_ref in retrieved_techniques:
        # Find the matching attack-pattern object
        for obj in bundle.objects:
            if obj.get("type") == "attack-pattern" and obj.get("id") == procedure_ref:
                red_info, blue_info = find_procedure_evidence(
                    group_procedure_desc, obj["description"], obj.get("x_mitre_detection", "")
                )
                tactics = consolidate_tactics(obj["kill_chain_phases"])
                op_guidance, red_tools = red_info

                # Make sure op_guidance is a dictionary
                if isinstance(op_guidance, str):
                    # If op_guidance is a string, convert it to a dictionary with a default key
                    op_guidance = {"description": op_guidance} if op_guidance else {}
                elif op_guidance == "":
                    # Empty string should become empty dict
                    op_guidance = {}

                # Filter out short values
                op_guidance = filter_short_values(op_guidance)

                additional_procedures = []

                # Check if we need to gather additional evidence
                evidence_needed = False

                # Only try to access dictionary keys if op_guidance is actually a dictionary
                if isinstance(op_guidance, dict):
                    if not op_guidance.get("cmd"):
                        evidence_needed = True
                    if not op_guidance.get("reg"):
                        evidence_needed = True
                    if not op_guidance.get("evt"):
                        evidence_needed = True
                    if not op_guidance.get("sw"):
                        evidence_needed = True
                    # Network indicators are optional - don't require them for evidence
                else:
                    # If op_guidance is not a dictionary, we definitely need more evidence
                    evidence_needed = True

                # Get additional techniques from other groups if needed
                if evidence_needed:
                    additional_data = retrieve_additional_techniques(
                        bundle, procedure_ref
                    )

                    for group_id, add_desc, add_ref in additional_data:
                        # Skip if it's from the same group we're already processing
                        if group_id in [t[1] for t in retrieved_techniques]:
                            continue

                        # Get additional evidence
                        for add_obj in bundle.objects:
                            if (
                                add_obj.get("type") == "attack-pattern"
                                and add_obj.get("id") == add_ref
                            ):
                                add_red_info, _ = find_procedure_evidence(
                                    add_desc,
                                    add_obj["description"],
                                    add_obj.get("x_mitre_detection", ""),
                                )
                                add_op_guidance, add_red_tools = add_red_info

                                # Make sure add_op_guidance is a dictionary
                                if isinstance(add_op_guidance, str):
                                    add_op_guidance = (
                                        {"description": add_op_guidance}
                                        if add_op_guidance
                                        else {}
                                    )
                                elif add_op_guidance == "":
                                    add_op_guidance = {}

                                # Filter short values
                                add_op_guidance = filter_short_values(add_op_guidance)

                                # Merge evidence - ensure both are dictionaries
                                if isinstance(op_guidance, dict) and isinstance(
                                    add_op_guidance, dict
                                ):
                                    for key in ["cmd", "reg", "evt", "sw", "port", "protocol", "service"]:
                                        if add_op_guidance.get(
                                            key
                                        ) and not op_guidance.get(key):
                                            op_guidance[key] = add_op_guidance[key]
                                elif isinstance(add_op_guidance, dict):
                                    # If op_guidance is not a dict but add_op_guidance is, use add_op_guidance
                                    op_guidance = add_op_guidance

                                # Merge tools - Handle cases where tools may be a dict or list
                                if add_red_tools:
                                    if not red_tools:
                                        red_tools = add_red_tools
                                    else:
                                        # Convert to list if needed
                                        if isinstance(red_tools, dict) and isinstance(
                                            add_red_tools, dict
                                        ):
                                            # Merge dictionaries
                                            for key, value in add_red_tools.items():
                                                if key in red_tools:
                                                    if isinstance(red_tools[key], list):
                                                        if isinstance(value, list):
                                                            red_tools[key].extend(value)
                                                        else:
                                                            red_tools[key].append(value)
                                                    else:
                                                        if isinstance(value, list):
                                                            red_tools[key] = [
                                                                red_tools[key]
                                                            ] + value
                                                        else:
                                                            red_tools[key] = [
                                                                red_tools[key],
                                                                value,
                                                            ]
                                                else:
                                                    red_tools[key] = value
                                        elif isinstance(red_tools, list) and isinstance(
                                            add_red_tools, list
                                        ):
                                            # Both are lists, simply extend
                                            red_tools.extend(add_red_tools)
                                        elif isinstance(red_tools, list):
                                            # red_tools is a list but add_red_tools is not
                                            if (
                                                isinstance(add_red_tools, dict)
                                                and "sw" in add_red_tools
                                            ):
                                                red_tools.extend(add_red_tools["sw"])
                                            else:
                                                # Convert add_red_tools to a list and extend
                                                red_tools.append(add_red_tools)
                                        else:
                                            # red_tools is not a list but add_red_tools might be
                                            if isinstance(add_red_tools, list):
                                                if (
                                                    isinstance(red_tools, dict)
                                                    and "sw" in red_tools
                                                ):
                                                    red_tools["sw"].extend(
                                                        add_red_tools
                                                    )
                                                else:
                                                    # Convert red_tools to a list and extend
                                                    red_tools = [
                                                        red_tools
                                                    ] + add_red_tools

                # Retrieve platform metadata
                software_refs = []
                if isinstance(red_tools, list):
                    software_refs = [
                        tool.get("id")
                        for tool in red_tools
                        if isinstance(tool, dict) and "id" in tool
                    ]
                elif isinstance(red_tools, dict) and "sw" in red_tools:
                    # red_tools["sw"] contains software NAMES, not IDs
                    # Convert names to STIX IDs
                    software_names = red_tools["sw"] if isinstance(red_tools["sw"], list) else [red_tools["sw"]]
                    software_refs = []
                    for sw_name in software_names:
                        # Find the STIX ID for this software name
                        # IMPORTANT: Use sw_obj instead of obj to avoid shadowing the outer loop variable
                        for sw_obj in bundle.objects:
                            if (sw_obj.get("type") in ["tool", "malware"]
                                and sw_obj.get("name", "").lower() == sw_name.lower()):
                                software_refs.append(sw_obj.get("id"))
                                break

                # NOTE: Software expansion is now handled in retrieve_techniques()
                # We no longer need to traverse software here since we already expanded
                # software to their techniques at the retrieval stage.
                # This prevents duplicate processing and software IDs appearing in final output.

                # DISABLED: Expand software to techniques and extract their indicators
                # This implements: Group -> Software -> Techniques -> Indicators
                if False and software_refs:
                    software_techniques = get_software_techniques(bundle, software_refs)

                    # For each technique used by the software, extract indicators
                    for sw_tech_id, sw_tech_name, sw_tech_desc in software_techniques:

                        # Find the technique object
                        for sw_tech_obj in bundle.objects:
                            if (sw_tech_obj.get("type") == "attack-pattern"
                                and sw_tech_obj.get("external_references", [{}])[0].get("external_id") == sw_tech_id):

                                # Extract indicators from this software technique
                                sw_red_info, sw_blue_info = find_procedure_evidence(
                                    sw_tech_desc,  # How the software uses this technique
                                    sw_tech_obj["description"],  # Technique description
                                    sw_tech_obj.get("x_mitre_detection", "")
                                )
                                sw_op_guidance, _ = sw_red_info

                                # Make sure sw_op_guidance is a dictionary
                                if isinstance(sw_op_guidance, str):
                                    sw_op_guidance = {"description": sw_op_guidance} if sw_op_guidance else {}
                                elif sw_op_guidance == "":
                                    sw_op_guidance = {}

                                # Filter short values
                                sw_op_guidance = filter_short_values(sw_op_guidance)

                                # Merge software technique indicators into main op_guidance
                                # This ensures we get indicators like "net use", "fsutil" from BlackCat
                                if isinstance(op_guidance, dict) and isinstance(sw_op_guidance, dict):
                                    for key in ["cmd", "reg", "evt", "sw", "api", "network"]:
                                        if sw_op_guidance.get(key):
                                            if not op_guidance.get(key):
                                                # No existing indicators for this type, add software's
                                                op_guidance[key] = sw_op_guidance[key]
                                            else:
                                                # Merge and deduplicate
                                                existing = op_guidance[key] if isinstance(op_guidance[key], list) else [op_guidance[key]]
                                                new_indicators = sw_op_guidance[key] if isinstance(sw_op_guidance[key], list) else [sw_op_guidance[key]]
                                                # Combine and remove duplicates (case-insensitive)
                                                combined = existing + [ind for ind in new_indicators if ind.lower() not in [e.lower() for e in existing]]
                                                op_guidance[key] = combined
                                break

                    # IMPORTANT: After software traversal, remove software names from red_tools
                    # Software indicators have been extracted and merged into op_guidance
                    # We don't want software NAMES (like "BoomBox", "BlackCat") as detection indicators
                    # Only the actual technique indicators (commands, APIs, etc.) should be used
                    if isinstance(red_tools, dict) and "sw" in red_tools:
                        del red_tools["sw"]
                    elif isinstance(red_tools, list):
                        # If red_tools is a list of software names/objects, clear it in place
                        red_tools.clear()

                # ALSO: Remove software names from red_tools even if no software_refs were traversed
                # This handles cases where software names appear as indicators but shouldn't be used
                if isinstance(red_tools, dict) and "sw" in red_tools:
                    del red_tools["sw"]

                procedure_platforms, software_platforms = retrieve_platform_metadata(
                    bundle, procedure_ref, software_refs
                )

                try:
                    detect_guidance = merge_detect_guidance(
                        obj["x_mitre_data_sources"], blue_info
                    )
                except Exception:
                    detect_guidance = [[""]]

                # Extract technique description and platforms for enhanced validation
                technique_description = obj.get("description", "")
                technique_platforms = obj.get("x_mitre_platforms", [])

                tech_id = obj["external_references"][0]["external_id"]
                tech_name = obj["name"]

                procedures.append(
                    (
                        tech_id,
                        tech_name,
                        tactics,
                        group_procedure_desc,
                        op_guidance,
                        red_tools,
                        detect_guidance,
                        procedure_platforms,
                        software_platforms,
                        technique_description,
                        technique_platforms,
                    )
                )

                # Track if this is a parent technique for later expansion
                if is_parent_technique(tech_id):
                    parent_indicators = extract_indicators_from_guidance(op_guidance)
                    parent_techniques[tech_id] = (procedure_ref, parent_indicators, procedures[-1])

                # Break after finding and processing this technique
                break

    # EXPANSION LOGIC: Process parent techniques to add subtechniques
    for parent_tech_id, (parent_ref, parent_indicators, parent_proc) in parent_techniques.items():
        # Find all subtechniques
        subtechniques = find_subtechniques(bundle, parent_tech_id)

        for sub_ref, sub_tech_id, sub_name in subtechniques:
            # Get subtechnique-specific procedures
            sub_desc, sub_tactics, sub_detection, sub_op_guidance = get_subtechnique_procedures(bundle, sub_ref)

            if not sub_desc:
                continue

            # Make sure sub_op_guidance is a dictionary
            if isinstance(sub_op_guidance, str):
                sub_op_guidance = {"description": sub_op_guidance} if sub_op_guidance else {}
            elif sub_op_guidance == "":
                sub_op_guidance = {}

            # Filter out short values
            sub_op_guidance = filter_short_values(sub_op_guidance)

            # Extract indicators from subtechnique
            sub_indicators = extract_indicators_from_guidance(sub_op_guidance)

            # Check if subtechnique has unique indicators
            unique_indicators = sub_indicators - parent_indicators

            if len(unique_indicators) > 0:
                # Get subtechnique platforms and other metadata
                sub_procedure_platforms, sub_software_platforms = retrieve_platform_metadata(bundle, sub_ref, [])

                # Get technique description and platforms
                sub_technique_description = sub_desc
                sub_technique_platforms = []
                for sub_obj in bundle.objects:
                    if sub_obj.get("id") == sub_ref and sub_obj.get("type") == "attack-pattern":
                        sub_technique_platforms = sub_obj.get("x_mitre_platforms", [])
                        break

                # Create detect_guidance for subtechnique
                try:
                    sub_detect_guidance = [[""]]
                    for sub_obj in bundle.objects:
                        if sub_obj.get("id") == sub_ref and sub_obj.get("type") == "attack-pattern":
                            if "x_mitre_data_sources" in sub_obj:
                                sub_detect_guidance = merge_detect_guidance(
                                    sub_obj["x_mitre_data_sources"], []
                                )
                            break
                except Exception:
                    sub_detect_guidance = [[""]]

                # Create procedure entry for subtechnique
                # Use parent's group description but with subtechnique-specific data
                subtechnique_proc = (
                    sub_tech_id,  # tech_id
                    sub_name,  # tech_name
                    sub_tactics if sub_tactics else parent_proc[2],  # tactics (use subtechnique's or fallback to parent's)
                    parent_proc[3],  # group_procedure_desc (use parent's)
                    sub_op_guidance,  # op_guidance (subtechnique-specific)
                    {},  # red_tools (empty for subtechniques)
                    sub_detect_guidance,  # detect_guidance
                    sub_procedure_platforms,  # procedure_platforms
                    sub_software_platforms,  # software_platforms
                    sub_technique_description,  # technique_description
                    sub_technique_platforms,  # technique_platforms
                )

                procedures.append(subtechnique_proc)

    return procedures


def retrieve_platform_metadata(bundle, procedure_ref, software_refs):
    """
    Retrieve platform metadata for procedures and software

    Args:
        bundle: The MITRE ATT&CK bundle
        procedure_ref: Reference ID of the procedure
        software_refs: List of software reference IDs

    Returns:
        Tuple of (procedure_platforms, software_platforms)
    """
    procedure_platforms = []
    software_platforms = {}

    # Get platforms for the procedure
    for obj in bundle.objects:
        if obj.get("type") == "attack-pattern" and obj.get("id") == procedure_ref:
            if "x_mitre_platforms" in obj:
                procedure_platforms = obj["x_mitre_platforms"]

    # Get platforms for each software
    for software_ref in software_refs:
        for obj in bundle.objects:
            if obj.get("type") in ["tool", "malware"] and obj.get("id") == software_ref:
                if "x_mitre_platforms" in obj:
                    software_platforms[software_ref] = obj["x_mitre_platforms"]

    return procedure_platforms, software_platforms


def get_software_techniques(bundle, software_refs):
    """
    Retrieve all techniques used by the specified software (malware/tools).

    This enables the pattern: Group -> Software -> Techniques -> Procedures -> Indicators
    Instead of just using software names as indicators, we extract the actual technical indicators
    from the techniques that software employs.

    Args:
        bundle: STIX bundle containing MITRE ATT&CK data
        software_refs: List of software reference IDs (e.g., ["malware--abc123", "tool--def456"])

    Returns:
        List of tuples: [(technique_id, technique_name, description), ...]
    """
    if not software_refs:
        return []

    for sw_ref in software_refs:
        # Get software name for better logging
        found = False
        for obj in bundle.objects:
            if obj.get("id") == sw_ref:
                sw_name = obj.get("name", sw_ref)
                found = True
                break

    software_techniques = []

    # Find all "uses" relationships where software uses techniques
    for obj in bundle.objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
            source_ref = obj.get("source_ref", "")
            target_ref = obj.get("target_ref", "")

            # Check if this relationship is from our software to a technique
            if source_ref in software_refs and target_ref.startswith("attack-pattern--"):
                # Get the description from the relationship (how the software uses this technique)
                relationship_desc = obj.get("description", "")

                # Find the technique object to get technique ID and name
                for tech_obj in bundle.objects:
                    if tech_obj.get("type") == "attack-pattern" and tech_obj.get("id") == target_ref:
                        technique_id = tech_obj.get("external_references", [{}])[0].get("external_id", "")
                        technique_name = tech_obj.get("name", "")

                        # Store technique with the software's specific usage description
                        software_techniques.append((
                            technique_id,
                            technique_name,
                            relationship_desc
                        ))
                        break

    return software_techniques


def is_compatible_with_index(platforms, index_name):
    """
    Determine if a set of platforms is compatible with a Splunk index name

    Args:
        platforms: List of platform names (e.g., ["Windows", "macOS"])
        index_name: Name of the Splunk index

    Returns:
        Boolean indicating compatibility
    """
    index_name_lower = index_name.lower()

    # Define platform mappings
    cloud_platforms = ["aws", "azure", "gcp", "cloud"]
    os_platforms = ["windows", "linux", "macos"]

    # Check if index is cloud-specific
    is_cloud_index = any(cloud in index_name_lower for cloud in cloud_platforms)

    # Handle cloud CLI commands (which can run on any OS)
    has_cloud_platform = any(
        platform.lower() in cloud_platforms for platform in platforms
    )

    # Handle OS-specific commands
    has_os_platform = any(platform.lower() in os_platforms for platform in platforms)

    # Cloud CLI commands can run on any OS
    if has_cloud_platform:
        return True

    # OS-specific commands can't run on cloud infrastructure
    if is_cloud_index and not has_cloud_platform:
        return False

    # Check for specific OS compatibility
    for platform in platforms:
        platform_lower = platform.lower()
        # If index is OS-specific, it should match the platform
        if platform_lower in index_name_lower:
            return True

    return False


def filter_short_values(data, min_length=3):
    """
    Filter out values that are shorter than the minimum length

    Args:
        data: Dictionary, list or string containing values to filter
        min_length: Minimum character length (default: 3)

    Returns:
        Filtered data structure (same type as input)
    """
    # If it's a string, just check its length
    if isinstance(data, str):
        return data if len(data) >= min_length else ""

    # If it's a list, filter each item
    elif isinstance(data, list):
        return [v for v in data if len(str(v)) >= min_length]

    # If it's a dictionary, filter each value
    elif isinstance(data, dict):
        filtered = {}
        for key, values in data.items():
            if isinstance(values, list):
                filtered[key] = [v for v in values if len(str(v)) >= min_length]
            elif isinstance(values, str) and len(values) >= min_length:
                filtered[key] = values
            elif isinstance(values, dict):
                filtered[key] = filter_short_values(values, min_length)
            else:
                # Preserve non-string, non-list, non-dict values
                filtered[key] = values
        return filtered

    # Return as is for other types
    else:
        return data

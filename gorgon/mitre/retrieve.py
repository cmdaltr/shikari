#!/usr/bin/env python3 -tt
from .enterprise import (
    consolidate_tactics,
    find_procedure_evidence,
    merge_detect_guidance,
)


def retrieve_group(bundle, group):
    for obj in bundle.objects:
        if (
            obj.get("type") == "intrusion-set"
            and obj.get("name").lower() == group.lower()
        ):
            return obj["id"]


def retrieve_techniques(bundle, group_id):
    techniques = []
    for obj in bundle.objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "uses"
            and obj.get("source_ref") == group_id
        ):
            techniques.append((obj.get("description"), obj.get("target_ref")))

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
            # Get the group that uses this technique
            source_group = obj.get("source_ref")
            additional_techniques.append(
                (source_group, obj.get("description"), obj.get("target_ref"))
            )

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

    for obj in bundle.objects:
        for group_procedure_desc, procedure_ref in retrieved_techniques:
            if obj.get("type") == "attack-pattern" and obj.get("id") == procedure_ref:
                red_info, blue_info = find_procedure_evidence(
                    group_procedure_desc, obj["description"], obj["x_mitre_detection"]
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
                                    for key in ["cmd", "reg", "evt", "sw"]:
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
                    software_refs = red_tools["sw"]

                procedure_platforms, software_platforms = retrieve_platform_metadata(
                    bundle, procedure_ref, software_refs
                )

                try:
                    detect_guidance = merge_detect_guidance(
                        obj["x_mitre_data_sources"], blue_info
                    )
                except Exception:
                    detect_guidance = [[""]]

                procedures.append(
                    (
                        obj["external_references"][0]["external_id"],
                        obj["name"],
                        tactics,
                        group_procedure_desc,
                        op_guidance,
                        red_tools,
                        detect_guidance,
                        procedure_platforms,
                        software_platforms,
                    )
                )

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

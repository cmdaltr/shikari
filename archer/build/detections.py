from .yaml import construct_yaml
from archer.mitre.enterprise import (
    get_stix_data,
    obtain_all_techniques,
    obtain_technique_descriptions,
)
from archer.mitre.retrieve import retrieve_procedures
import json
import os
from pathlib import Path


def load_indicator_mappings():
    """Load indicator mappings from JSON files in the mappings directory"""
    import os
    import json
    import sys

    # Use only one specific path for mappings
    mappings_dir = (
        Path(os.path.dirname(__file__)) / ".." / "mappings"
    )  # archer/mappings

    # Check for user-specific mappings first (not committed to GitHub)
    user_mapping_file = mappings_dir / "indicatorMappings.json"
    sample_mapping_file = mappings_dir / "indicatorMappings_sample.json"

    # Check if directory exists
    if not mappings_dir.exists():
        print(
            f"CRITICAL ERROR: Mappings directory does not exist: {mappings_dir.resolve()}"
        )
        print("Please create the mappings directory and add your JSON mapping files.")
        sys.exit(1)

    # Load JSON files in order of preference
    mappings = {}

    # Try to load user-specific mappings first
    if user_mapping_file.exists():
        try:
            with open(user_mapping_file, "r") as f:
                mappings = json.load(f)
            print(f"Using custom mappings from: {user_mapping_file}")
        except json.JSONDecodeError as e:
            print(f"ERROR: Could not parse {user_mapping_file}: {e}")
            print("Falling back to sample mappings...")

    # If no user mappings or they failed to load, try sample mappings
    if not mappings and sample_mapping_file.exists():
        try:
            with open(sample_mapping_file, "r") as f:
                mappings = json.load(f)
            print(f"Using sample mappings from: {sample_mapping_file}")
        except json.JSONDecodeError as e:
            print(f"ERROR: Could not parse {sample_mapping_file}: {e}")

    # If we still don't have mappings, try other JSON files in the directory
    if not mappings:
        json_files = list(mappings_dir.glob("*.json"))
        if not json_files:
            print(f"CRITICAL ERROR: No JSON files found in: {mappings_dir.resolve()}")
            print("Please add JSON mapping files to the mappings directory.")
            sys.exit(1)

        # Load each JSON file in the mappings directory
        for mapping_file in json_files:
            try:
                with open(mapping_file, "r") as f:
                    mapping_data = json.load(f)
                    mappings.update(mapping_data)
            except json.JSONDecodeError as e:
                print(f"WARNING: Could not parse {mapping_file}: {e}")

    # Make sure we have the expected indicator types
    required_types = ["cmd", "reg", "evt", "sw"]
    missing_types = [t for t in required_types if t not in mappings]
    if missing_types:
        print(
            f"CRITICAL ERROR: Missing required indicator types in mappings: {', '.join(missing_types)}"
        )
        print(f"Please ensure your mapping files include all required indicator types.")
        sys.exit(1)

    return mappings


def create_indicatorMappings():
    """Create default mappings if none are found"""
    print("Creating default mappings")
    indicatorMappings = {
        "cmd": {
            "Splunk": {
                "index=windows_events": [
                    "properties.command",
                    "properties.CommandLine",
                    "properties.Process_CommandLine",
                ],
                "index=linux_syslog": ["properties.command", "properties.cmdline"],
                "index=aws_cloudtrail": [
                    "properties.command",
                    "properties.commandline",
                ],
                "index=aws_directoryservicead": ["properties.command"],
            },
            "MDE": {
                "DeviceProcessEvents": ["ProcessCommandLine"],
                "DeviceEvents": ["AdditionalFields"],
            },
        },
        "reg": {
            "Splunk": {
                "index=windows_events": [
                    "properties.TargetObject",
                    "properties.Registry_Key_Path",
                ]
            },
            "MDE": {"DeviceRegistryEvents": ["RegistryKey", "RegistryValueData"]},
        },
        "evt": {
            "Splunk": {
                "index=windows_events": ["properties.event_id", "properties.EventID"]
            },
            "MDE": {"DeviceEvents": ["ActionType"]},
        },
        "sw": {
            "Splunk": {
                "index=windows_events": [
                    "properties.Image",
                    "properties.process_path",
                    "properties.process_name",
                    "properties.ParentImage",
                ],
                "index=linux_syslog": ["properties.process", "properties.process_name"],
                "index=aws_cloudtrail": ["properties.service", "properties.process"],
            },
            "MDE": {
                "DeviceProcessEvents": [
                    "FileName",
                    "ProcessVersionInfoProductName",
                    "ProcessVersionInfoCompanyName",
                ],
                "DeviceFileEvents": ["FileName"],
            },
        },
    }
    return indicatorMappings


def compile_query(retrieved_data):
    from archer.build.queries import is_query_applicable

    # Load indicator mappings
    indicator_mappings = load_indicator_mappings()

    name = retrieved_data.get("technique")
    tid = retrieved_data.get("technique_id")
    tdesc = retrieved_data.get("activity_desc")
    tactic = retrieved_data.get("tactic")
    tag = retrieved_data.get("group_name")
    op_guidance = retrieved_data.get("op_guidance", {})
    red_tool = retrieved_data.get("red_tool", {})
    log_sources = retrieved_data.get("detect_guidance", [])

    # Get all identifiers
    if isinstance(op_guidance, dict) and isinstance(red_tool, dict):
        identifiers = {**op_guidance, **red_tool}
    elif isinstance(op_guidance, dict):
        identifiers = op_guidance
    elif isinstance(red_tool, dict):
        identifiers = red_tool
    else:
        identifiers = {}

    # Extract platform information if available
    procedure_platforms = retrieved_data.get("procedure_platforms", [])
    software_platforms = retrieved_data.get("software_platforms", {})

    # Only construct YAML if there are identifiers for detection
    if identifiers:
        compatible_found = False
        yaml_files_created = False

        # Check if any YAML files already exist for this technique
        import os
        name_clean = name.replace(" ", "").replace("/", "")
        existing_yamls = []
        if os.path.exists("data/generate"):
            for fname in os.listdir("data/generate"):
                if fname.startswith(name_clean) and fname.endswith(".yaml"):
                    existing_yamls.append(fname)

        if existing_yamls:
            yaml_files_created = True

        # Check each indicator type
        for indicator_type in identifiers:
            if indicator_type not in indicator_mappings:
                continue

            indicators = identifiers[indicator_type]
            if not indicators:
                continue

            # SPLUNK
            if "Splunk" in indicator_mappings[indicator_type]:
                for index_name in indicator_mappings[indicator_type]["Splunk"]:
                    clean_index_name = index_name.replace("index=", "")
                    is_compatible = is_query_applicable(
                        procedure_platforms, software_platforms, clean_index_name
                    )
                    if is_compatible:
                        compatible_found = True
                        print(
                            f"✅ Query built for {name} ({tid}) on {index_name}"
                        )
                        construct_yaml(
                            name,
                            tid,
                            tdesc,
                            tactic,
                            tag,
                            identifiers,
                            log_sources,
                            index_name,
                            procedure_platforms,
                            software_platforms,
                        )
                    # DO NOT call construct_yaml here if not compatible!

            # MDE
            if "MDE" in indicator_mappings[indicator_type]:
                for table_name in indicator_mappings[indicator_type]["MDE"]:
                    is_compatible = is_query_applicable(
                        procedure_platforms, software_platforms, table_name
                    )
                    if is_compatible:
                        compatible_found = True
                        print(
                            f"✅ Query built for {name} ({tid}) on {table_name}"
                        )
                        construct_yaml(
                            name,
                            tid,
                            tdesc,
                            tactic,
                            tag,
                            identifiers,
                            log_sources,
                            table_name,
                            procedure_platforms,
                            software_platforms,
                        )
                    # DO NOT call construct_yaml here if not compatible!

        # Print summary for this technique
        if not compatible_found:
            if yaml_files_created:
                print(f"❌ No more compatible platforms found for {name}\n")
            else:
                print(
                    f"❌ No compatible platforms found for {name} - skipping YAML generation\n"
                )
    else:
        print(f"No identifiers found for {name} - skipping YAML generation")


def main():
    # Load MITRE enterprise ATT&CK bundle
    bundle = get_stix_data(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    )

    # Get all techniques
    techniques = obtain_all_techniques(bundle)

    # Process each technique
    for technique in techniques:
        # Find procedures for the technique
        procedures = retrieve_procedures(bundle, [technique])
        for procedure in procedures:
            compile_query(procedure)


def is_query_applicable(procedure_platforms, software_platforms, index_name):
    # Get platforms for this index from mapping
    index_platforms = get_platforms_for_index(index_name)

    # If no mapping, be strict
    if not index_platforms:
        return False

    # If procedure is Windows-only, only allow if index is also Windows
    procedure_is_windows_only = (
        len(procedure_platforms) == 1 and procedure_platforms[0].lower() == "windows"
    )
    index_is_windows = "Windows" in index_platforms

    if procedure_is_windows_only and not index_is_windows:
        return False

    # Otherwise, require at least one overlap
    for platform in procedure_platforms:
        if platform in index_platforms:
            return True

    return False


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Interactive Mapping Files Setup Script

Adds your Splunk indexes and Defender tables to the schema overrides that the
query builder reads first:

    bespoke/mappings/schemas/schemaSplunk_custom.json
    bespoke/mappings/schemas/schemaMDE_custom.json

An override replaces the base schema (schemaSplunk.json / schemaMDE.json)
wholesale, so the wizard starts from the existing override, or the base schema
if there is none, and merges your entries in. Existing pipelines survive.

It does not create the other required mapping files (indicatorMapping.json,
sources/*.json, ...); see bespoke/README.md.

Usage:
    python scripts/validation/setup_mappings.py
"""

import json
import os
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMAS_DIR = REPO_ROOT / "bespoke" / "mappings" / "schemas"


def print_header(text):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70 + "\n")


def print_section(text):
    """Print a formatted section header."""
    print(f"\n--- {text} ---\n")


def get_yes_no(prompt, default=True):
    """Get yes/no input from user."""
    default_str = "Y/n" if default else "y/N"
    while True:
        response = input(f"{prompt} [{default_str}]: ").strip().lower()
        if not response:
            return default
        if response in ['y', 'yes']:
            return True
        if response in ['n', 'no']:
            return False
        print("Please enter 'y' or 'n'")


def get_input(prompt, default=None):
    """Get text input from user."""
    if default:
        response = input(f"{prompt} [{default}]: ").strip()
        return response if response else default
    else:
        while True:
            response = input(f"{prompt}: ").strip()
            if response:
                return response
            print("This field is required.")


def get_list_input(prompt):
    """Get a list of items from user (comma-separated)."""
    print(f"{prompt}")
    print("(Enter items separated by commas, or press Enter to skip)")
    response = input("> ").strip()
    if not response:
        return []
    return [item.strip() for item in response.split(',') if item.strip()]


def main():
    print_header("Archer Mapping Files Setup Wizard")

    print("""
This wizard adds your Splunk indexes and Microsoft Defender tables to
Archer's schema overrides in bespoke/mappings/schemas/. Anything already
configured there is kept; entries you enter here are added or replaced.
""")

    if not get_yes_no("Ready to begin?", default=True):
        print("\nSetup cancelled. Run this script again when ready.")
        return

    # Step 1: Platform Selection
    print_header("Step 1: Platform Selection")

    platforms = []
    if get_yes_no("Do you use Splunk?"):
        platforms.append("splunk")
    if get_yes_no("Do you use Microsoft Defender / Sentinel?"):
        platforms.append("mde")
    if get_yes_no("Do you use Elastic?"):
        platforms.append("elastic")

    if not platforms:
        print("\n❌ You must select at least one platform!")
        return

    print(f"\n✓ Selected platforms: {', '.join(platforms)}")

    # Step 2: Splunk Configuration
    splunk_config = {}
    if "splunk" in platforms:
        print_header("Step 2: Splunk Configuration")

        print("""
For Splunk, you need to provide your INDEX NAMES and SOURCETYPES.

Example:
  Index: windows_events
  Sourcetype: WinEventLog:Security

Archer adds the index clause itself and generates queries like:
  index=windows_events earliest=-1d
  | fields _time device user process_command_line
  | search process_command_line="*whoami*"

Each index gets a starter pipeline with Archer's standard field names. If your
fields are named differently, add `| rename yourfield AS standardfield` lines
to the saved pipeline afterwards.
""")

        splunk_config = configure_splunk()

    # Step 3: MDE Configuration
    mde_config = {}
    if "mde" in platforms:
        print_header("Step 3: Microsoft Defender / Sentinel Configuration")

        print("""
For Microsoft Defender/Sentinel, you query TABLES (not indices).

Common tables:
  - DeviceProcessEvents (command-line execution)
  - DeviceFileEvents (file activity)
  - DeviceRegistryEvents (registry changes)
  - DeviceNetworkEvents (network connections)
  - DeviceLogonEvents (authentication)

These tables usually don't need customization, but we'll verify
which ones are available in your environment.
""")

        mde_config = configure_mde()

    # Step 4: Review and Save
    print_header("Step 4: Review Configuration")

    print("\n📋 Configuration Summary:\n")
    if splunk_config:
        print("Splunk Sources:")
        for itype, sources in splunk_config.items():
            print(f"  {itype}: {len(sources)} source(s)")

    if mde_config:
        print("\nMicrosoft Defender Tables:")
        for table in mde_config.keys():
            print(f"  ✓ {table}")

    if not get_yes_no("\nSave this configuration?", default=True):
        print("\n❌ Configuration not saved.")
        return

    # Save configuration: merge into the existing override (or the base schema)
    SCHEMAS_DIR.mkdir(parents=True, exist_ok=True)

    if splunk_config:
        splunk_file = save_merged(splunk_config, "schemaSplunk", nested=True)
        print(f"\n✓ Saved Splunk configuration to: {splunk_file.relative_to(REPO_ROOT)}")

    if mde_config:
        mde_file = save_merged(mde_config, "schemaMDE", nested=False)
        print(f"✓ Saved MDE configuration to: {mde_file.relative_to(REPO_ROOT)}")

    # Step 5: Next Steps
    print_header("Setup Complete!")

    print("""
✅ Schema overrides saved.

Next Steps:

1. REVIEW bespoke/mappings/schemas/schemaSplunk_custom.json and
   schemaMDE_custom.json, and add `| rename` lines where your field names
   differ from Archer's standard ones.

2. CHECK all required mapping files are present (see bespoke/README.md):
   python -c "from archer.build.bespoke import validate_bespoke_components as v; print(v(verbose=False)['missing_critical'])"

3. RESTART Archer and generate a test hunt; verify the queries run in your SIEM.

Happy hunting! 🎯
""")


def save_merged(new_entries, schema_name, nested):
    """
    Merge wizard entries into bespoke/mappings/schemas/<schema_name>_custom.json.

    The override replaces the base schema wholesale when it exists, so start from
    the current override, else the base schema, else empty. nested=True for
    Splunk ({indicator_type: {index: pipeline}}), False for MDE ({table: clause}).
    Any previous override is kept as <name>_custom.json.bak.
    """
    custom_file = SCHEMAS_DIR / f"{schema_name}_custom.json"
    base_file = SCHEMAS_DIR / f"{schema_name}.json"
    source = custom_file if custom_file.exists() else base_file
    merged = json.loads(source.read_text()) if source.exists() else {}

    for key, value in new_entries.items():
        if nested:
            merged.setdefault(key, {}).update(value)
        else:
            merged[key] = value

    if custom_file.exists():
        shutil.copy2(custom_file, custom_file.with_suffix(".json.bak"))
    custom_file.write_text(json.dumps(merged, indent=2))
    return custom_file


def configure_splunk():
    """Configure Splunk mapping files."""
    config = {}

    print_section("Command-Line Execution Logs (cmd)")

    print("""
Command-line execution logs capture process creation with command-line arguments.

Examples:
  - Windows Security Event Log (EventCode 4688)
  - Sysmon (EventCode 1)
  - Microsoft Defender for Endpoint
  - EDR solutions (CrowdStrike, Carbon Black, etc.)
""")

    cmd_sources = get_list_input("Enter your index names for command-line logs")
    if cmd_sources:
        config["cmd"] = {}
        for source in cmd_sources:
            source_clean = source.replace("index=", "").replace(" ", "_")
            # Create basic template
            config["cmd"][source_clean] = (
                "| fields _time device user process_command_line"
            )

    print_section("File Activity Logs (file)")

    print("""
File activity logs capture file creation, modification, and deletion.

Examples:
  - Sysmon (EventCode 11, 23, 26)
  - Microsoft Defender for Endpoint (DeviceFileEvents)
  - EDR file monitoring
""")

    file_sources = get_list_input("Enter your index names for file activity logs")
    if file_sources:
        config["file"] = {}
        for source in file_sources:
            source_clean = source.replace("index=", "").replace(" ", "_")
            config["file"][source_clean] = (
                "| fields _time device file_name file_path file_hash"
            )

    print_section("Registry Activity Logs (reg)")

    print("""
Registry activity logs capture Windows registry modifications.

Examples:
  - Sysmon (EventCode 12, 13, 14)
  - Microsoft Defender for Endpoint (DeviceRegistryEvents)
""")

    if get_yes_no("Do you have registry activity logs?"):
        reg_sources = get_list_input("Enter your index names for registry logs")
        if reg_sources:
            config["reg"] = {}
            for source in reg_sources:
                source_clean = source.replace("index=", "").replace(" ", "_")
                config["reg"][source_clean] = (
                    "| fields _time device registry_key registry_value"
                )

    print_section("Network Activity Logs (network)")

    print("""
Network activity logs capture network connections and traffic.

Examples:
  - Sysmon (EventCode 3)
  - Microsoft Defender for Endpoint (DeviceNetworkEvents)
  - Firewall logs
  - Proxy logs
""")

    if get_yes_no("Do you have network activity logs?"):
        network_sources = get_list_input("Enter your index names for network logs")
        if network_sources:
            config["network"] = {}
            for source in network_sources:
                source_clean = source.replace("index=", "").replace(" ", "_")
                config["network"][source_clean] = (
                    "| fields _time src_ip dest_ip dest_port url"
                )

    if not config:
        print("\n⚠️  WARNING: No Splunk sources configured!")
        print("You can add them later by editing bespoke/mappings/schemas/schemaSplunk_custom.json")

    return config


def configure_mde():
    """Configure Microsoft Defender/Sentinel mapping files."""

    print("""
Microsoft Defender tables are standardized. Select which tables
are available in your environment:
""")

    available_tables = {
        "DeviceProcessEvents": "Process creation and execution",
        "DeviceFileEvents": "File creation, modification, deletion",
        "DeviceRegistryEvents": "Registry key modifications",
        "DeviceNetworkEvents": "Network connections",
        "DeviceLogonEvents": "Authentication events",
        "DeviceEvents": "General device events",
        "DeviceImageLoadEvents": "DLL/driver loading"
    }

    config = {}

    for table, description in available_tables.items():
        if get_yes_no(f"Do you have access to {table}? ({description})"):
            # Use standard MDE schema
            if table == "DeviceProcessEvents":
                config[table] = (
                    "\n| summarize by Timestamp, DeviceName, ActionType, AccountName, "
                    "ProcessCommandLine, InitiatingProcessCommandLine, FileName, FolderPath"
                )
            elif table == "DeviceFileEvents":
                config[table] = (
                    "\n| summarize by Timestamp, DeviceName, ActionType, FileName, "
                    "FolderPath, SHA256, InitiatingProcessCommandLine"
                )
            elif table == "DeviceRegistryEvents":
                config[table] = (
                    "\n| summarize by Timestamp, DeviceName, ActionType, RegistryKey, "
                    "RegistryValueName, RegistryValueData, InitiatingProcessCommandLine"
                )
            elif table == "DeviceNetworkEvents":
                config[table] = (
                    "\n| summarize by Timestamp, DeviceName, RemoteIP, RemotePort, "
                    "RemoteUrl, InitiatingProcessCommandLine"
                )
            else:
                config[table] = (
                    f"\n| summarize by Timestamp, DeviceName, ActionType"
                )

    if not config:
        print("\n⚠️  WARNING: No MDE tables configured!")
        print("You can add them later by editing bespoke/mappings/schemas/schemaMDE_custom.json")

    return config


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Setup cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

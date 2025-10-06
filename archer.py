#!/usr/bin/env python3
"""
Command-line interface for Archer functionality.
Run this script directly to access core features without starting the web server.
"""

import os
import sys
import argparse
from pathlib import Path

# Add the project root to the path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent))


def process_group(group_name, hypothesis=None, manual_data=None, run_correlation=False):
    """Run the process_group function to generate YAML files"""
    from archer.build.orchestrator import process_group

    print(f"Generating queries for: {group_name}")
    if hypothesis:
        print(f" Hypothesis: {hypothesis}")
    if manual_data:
        print(f" Using manual data with {len(manual_data)} entries")

    process_group(group_name, hypothesis, manual_data, run_correlation=run_correlation)
    print(f"Detection query generation complete for {group_name}\n\n")


def generate_detection(technique_name):
    """Generate a detection for a specific technique"""
    from archer.mitre import get_stix_data, obtain_all_techniques
    from archer.mitre.retrieve import retrieve_procedures
    from archer.build.detections import compile_query

    print(f"Generating detection for technique: {technique_name}")

    bundle = get_stix_data(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    )
    techniques = obtain_all_techniques(bundle)

    # Find matching technique
    matching = [t for t in techniques if technique_name.lower() in t.lower()]

    if not matching:
        print(f"Error: No technique found matching '{technique_name}'")
        return

    if len(matching) > 1:
        print(f"Multiple techniques match '{technique_name}':")
        for i, m in enumerate(matching, 1):
            print(f"{i}. {m}")
        try:
            idx = int(input("Enter the number of the technique to use: ")) - 1
            if 0 <= idx < len(matching):
                technique = matching[idx]
            else:
                print("Invalid selection.")
                return
        except (ValueError, IndexError):
            print("Invalid selection.")
            return
    else:
        technique = matching[0]

    print(f"Using technique: {technique}")
    procedures = retrieve_procedures(bundle, [technique])

    if not procedures:
        print(f"No procedures found for {technique}")
        return

    print(f"Found {len(procedures)} procedures. Generating detections...")

    for procedure in procedures:
        compile_query(procedure)

    print("Detection generation complete.")


def build_correlations(yaml_dir=None, output_file=None, min_queries=2, max_queries=5, threat_group=None, verbose=False):
    """Build correlation queries from YAML detection files"""
    from archer.genai import build_correlation_queries

    print("=" * 70)
    print("Correlation Query Builder")
    print("=" * 70)
    print()

    try:
        result = build_correlation_queries(
            yaml_dir=yaml_dir,
            output_file=output_file,
            min_queries=min_queries,
            max_queries=max_queries,
            threat_group=threat_group
        )

        print()
        print("=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"Total queries analyzed: {result['total_queries_analyzed']}")
        print(f"Correlations built: {result['total_correlations']}")
        print(
            f"Minimum queries per correlation: {result['min_queries_per_correlation']}"
        )
        print()

        if verbose and result["total_correlations"] > 0:
            print("Correlation Details:")
            print("-" * 70)
            for corr in result["correlations"]:
                print(f"\n{corr['correlation_id']}: {corr['name']}")
                print(f"  Platform: {corr['platform']}")
                print(f"  Threat Groups: {', '.join(corr['threat_groups'])}")
                print(
                    f"  Tactics: {', '.join(corr['tactics'][:5])}{'...' if len(corr['tactics']) > 5 else ''}"
                )
                print(f"  Queries: {corr['query_count']}")

        print()
        print(
            f"✓ Output saved to: {result.get('output_file', output_file or 'data/correlate/correlation_queries.json')}"
        )
        print()

        return result

    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print(
            "\nPlease ensure the YAML directory exists and contains detection files.",
            file=sys.stderr,
        )
        return None

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if verbose:
            import traceback

            traceback.print_exc()
        return None


def run_emulation(
    technique_id=None,
    threat_group=None,
    framework="atomic",
    execute=False,
    enrich=False,
    max_techniques=None,
    verbose=False,
):
    """Execute adversary emulation tests for a technique or threat group"""
    from archer.config import EmulationConfig

    if not EmulationConfig.enabled:
        print("ERROR: Emulation module is not enabled.", file=sys.stderr)
        print("Set ENABLE_EMULATION=true to use this feature.", file=sys.stderr)
        return None

    if not technique_id and not threat_group:
        print(
            "ERROR: Either --technique-id or --threat-group required", file=sys.stderr
        )
        return None

    print("=" * 70)
    print(f"Adversary Emulation - {framework.upper()}")
    print("=" * 70)
    print()

    try:
        if framework == "atomic":
            from archer.emulation import AtomicRedTeam
            from archer.emulation.enrich import enrich_from_group_emulation

            if not EmulationConfig.is_atomic_configured():
                print(
                    f"ERROR: Atomic Red Team not found at {EmulationConfig.atomic_path}",
                    file=sys.stderr,
                )
                print("\nInstall with:", file=sys.stderr)
                print(
                    "  git clone https://github.com/redcanaryco/atomic-red-team.git",
                    file=sys.stderr,
                )
                print(
                    f"  export ATOMIC_REDTEAM_PATH=/path/to/atomic-red-team",
                    file=sys.stderr,
                )
                return None

            atomic = AtomicRedTeam()

            # Set execution mode
            if execute:
                os.environ["EMULATION_EXECUTE_MODE"] = "live"
                print(
                    "⚠️  LIVE EXECUTION MODE - Tests will actually run on this system!"
                )
                print()
            else:
                print(
                    "ℹ️  SIMULATION MODE - Tests will be simulated (set --execute to run live)"
                )
                print()

            # Group emulation
            if threat_group:
                print(
                    f"Executing Atomic Red Team tests for threat group: {threat_group}..."
                )
                print()

                results = atomic.execute_threat_group(
                    threat_group=threat_group, max_techniques=max_techniques
                )

                if results.get("status") in ["no_techniques", "no_atomic_tests"]:
                    print(f"⚠️  {results['message']}")
                    return None

                # Enrich detections if requested
                if enrich:
                    print()
                    print("Enriching detections with group emulation evidence...")
                    enrich_result = enrich_from_group_emulation(threat_group)

                    if enrich_result["status"] == "success":
                        print(
                            f"✓ Enriched {enrich_result['total_files_enriched']} detection files"
                        )
                        print(
                            f"✓ Generated {enrich_result['total_queries_generated']} additional queries"
                        )
                    else:
                        print(
                            f"⚠️  Enrichment status: {enrich_result.get('message', 'Unknown error')}"
                        )

                print()
                return results

            # Single technique emulation
            else:
                print(f"Executing Atomic Red Team tests for {technique_id}...")
                print()

                results = atomic.execute_technique(technique_id)

                if results.get("status") == "no_tests":
                    print(f"No atomic tests available for {technique_id}")
                    return None

                print()
                print("=" * 70)
                print("EXECUTION SUMMARY")
                print("=" * 70)
                print(
                    f"Technique: {results['technique_name']} ({results['technique_id']})"
                )
                print(f"Tests executed: {len(results['tests_executed'])}")
                print(f"Evidence collected: {len(results['evidence_collected'])}")
                print()

                if verbose:
                    print("Test Details:")
                    print("-" * 70)
                    for test in results["tests_executed"]:
                        status_icon = (
                            "✓" if test["status"] in ["success", "simulated"] else "✗"
                        )
                        print(
                            f"\n{status_icon} Test #{test['test_number']}: {test['test_name']}"
                        )
                        print(f"   Status: {test['status']}")
                        if "command" in test:
                            cmd = (
                                test["command"][:100] + "..."
                                if len(test["command"]) > 100
                                else test["command"]
                            )
                            print(f"   Command: {cmd}")

                # Enrich detections if requested
                if enrich:
                    print()
                    print("Enriching detections with emulation evidence...")
                    from archer.emulation import enrich_detections_with_emulation

                    enrich_result = enrich_detections_with_emulation(technique_id)

                    if enrich_result["status"] == "success":
                        print(
                            f"✓ Enriched {len(enrich_result['enriched_files'])} detection files"
                        )
                        print(
                            f"✓ Generated {enrich_result['additional_queries_generated']} additional queries"
                        )
                        print(
                            f"✓ Found indicators: {enrich_result['indicators_found']}"
                        )
                    else:
                        print(f"⚠️  Enrichment status: {enrich_result['message']}")

                print()
                return results

        else:
            print(
                f"ERROR: Framework '{framework}' not yet implemented", file=sys.stderr
            )
            print("Available: atomic (CALDERA and MACAT coming soon)", file=sys.stderr)
            return None

    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if verbose:
            import traceback

            traceback.print_exc()
        return None


def run_vectr_command(
    action,
    threat_group=None,
    campaign_id=None,
    campaign_name=None,
    update_yamls=False,
    verbose=False,
):
    """Execute VECTR integration commands"""
    from archer.config import VECTRConfig

    if not VECTRConfig.enabled:
        print("ERROR: VECTR module is not enabled.", file=sys.stderr)
        print("Set ENABLE_VECTR=true to use this feature.", file=sys.stderr)
        return None

    if not VECTRConfig.is_configured():
        print("ERROR: VECTR is not configured.", file=sys.stderr)
        print("Required environment variables:", file=sys.stderr)
        print("  VECTR_URL=https://your-vectr-server:8081", file=sys.stderr)
        print("  VECTR_API_TOKEN=your-api-token", file=sys.stderr)
        return None

    print("=" * 70)
    print(f"VECTR Integration - {action.upper()}")
    print("=" * 70)
    print()

    try:
        if action == "export":
            from archer.vectr import export_to_vectr

            if not threat_group:
                print("ERROR: --threat-group required for export", file=sys.stderr)
                return None

            result = export_to_vectr(
                threat_group=threat_group,
                campaign_name=campaign_name,
            )

            print("✅ Export complete!")
            print(f"Campaign ID: {result['campaign']['id']}")
            print(f"Use this ID to sync or import results later")
            return result

        elif action == "import":
            from archer.vectr import import_from_vectr

            if not campaign_id:
                print("ERROR: --campaign-id required for import", file=sys.stderr)
                return None

            result = import_from_vectr(
                campaign_id=campaign_id,
                update_yamls=update_yamls,
            )

            return result

        elif action == "sync":
            from archer.vectr import sync_with_vectr

            if not campaign_id:
                print("ERROR: --campaign-id required for sync", file=sys.stderr)
                return None

            result = sync_with_vectr(
                campaign_id=campaign_id,
                threat_group=threat_group,
            )

            return result

        elif action == "list":
            from archer.vectr import CampaignManager

            mgr = CampaignManager()
            campaigns = mgr.list_campaigns(filter_by=threat_group)

            if not campaigns:
                print("No campaigns found")
                return None

            print(f"Found {len(campaigns)} campaign(s):\n")
            for campaign in campaigns:
                print(f"ID: {campaign.get('id')}")
                print(f"Name: {campaign.get('name')}")
                print(f"Group: {campaign.get('threat_group')}")
                print(f"Status: {campaign.get('status')}")
                print(f"Created: {campaign.get('created_date')}")
                print("-" * 70)

            return campaigns

        elif action == "coverage":
            from archer.vectr import TestCaseManager

            if not campaign_id:
                print("ERROR: --campaign-id required for coverage", file=sys.stderr)
                return None

            mgr = TestCaseManager()
            report = mgr.generate_coverage_report(campaign_id)

            print(report)
            return report

        else:
            print(f"ERROR: Unknown action '{action}'", file=sys.stderr)
            return None

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if verbose:
            import traceback

            traceback.print_exc()
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Archer CLI - Threat hunting detection generator",
        epilog="Typical workflow: generate → correlate",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Step 1: Generate detections for a threat group
    generate_parser = subparsers.add_parser(
        "generate", help="Generate detections for a threat group (Step 1)"
    )
    generate_parser.add_argument(
        "group_name", help="Name of the threat group (e.g., APT29)"
    )
    generate_parser.add_argument(
        "--hypothesis", help="Optional hypothesis for the group"
    )
    generate_parser.add_argument(
        "--correlate",
        action="store_true",
        help="Run correlation after generating detections",
    )

    # Step 2: Correlate generated detections
    correlate_parser = subparsers.add_parser(
        "correlate",
        help="Correlate generated detections into multi-query searches (Step 2)",
    )
    correlate_parser.add_argument(
        "threat_group",
        help="Threat group name to correlate (e.g., 'Scattered Spider')",
    )
    correlate_parser.add_argument(
        "--yaml-dir", help="Directory containing YAML files (default: data/generate)"
    )
    correlate_parser.add_argument(
        "--output",
        help="Output JSON file path (default: data/correlations/correlation_queries.json)",
    )
    correlate_parser.add_argument(
        "--min-queries",
        type=int,
        default=2,
        help="Minimum number of queries to include in a correlation (default: 2)",
    )
    correlate_parser.add_argument(
        "--max-queries",
        type=int,
        default=5,
        help="Maximum number of queries to include in a correlation (default: 5)",
    )
    correlate_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    # Alternative: Hunt for a specific technique
    hunt_parser = subparsers.add_parser(
        "hunt", help="Hunt for a specific MITRE ATT&CK technique"
    )
    hunt_parser.add_argument(
        "technique",
        help="Name of the technique (partial match supported, e.g., 'PowerShell')",
    )

    # Optional: Emulation testing
    emulate_parser = subparsers.add_parser(
        "emulate",
        help="Execute adversary emulation tests (requires ENABLE_EMULATION=true)",
    )
    emulate_parser.add_argument(
        "--technique-id", help="MITRE ATT&CK technique ID (e.g., T1059.001)"
    )
    emulate_parser.add_argument(
        "--threat-group",
        help="Threat group name (e.g., APT29) - runs all group techniques",
    )
    emulate_parser.add_argument(
        "--framework",
        choices=["atomic", "caldera", "macat"],
        default="atomic",
        help="Emulation framework to use (default: atomic)",
    )
    emulate_parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually execute tests (default: simulate only)",
    )
    emulate_parser.add_argument(
        "--enrich",
        action="store_true",
        help="Enrich existing detections with emulation evidence",
    )
    emulate_parser.add_argument(
        "--max-techniques",
        type=int,
        help="Maximum number of techniques to test (for threat groups)",
    )
    emulate_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    # Optional: VECTR integration
    vectr_parser = subparsers.add_parser(
        "vectr", help="VECTR integration for hunt tracking (requires ENABLE_VECTR=true)"
    )
    vectr_parser.add_argument(
        "action",
        choices=["export", "import", "sync", "list", "coverage"],
        help="VECTR action to perform",
    )
    vectr_parser.add_argument(
        "--threat-group", help="Threat group name (required for export)"
    )
    vectr_parser.add_argument(
        "--campaign-id", help="VECTR campaign ID (required for import/sync/coverage)"
    )
    vectr_parser.add_argument("--campaign-name", help="Custom campaign name for export")
    vectr_parser.add_argument(
        "--update-yamls",
        action="store_true",
        help="Update YAML files with test results (for import)",
    )
    vectr_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    if args.command == "generate":
        process_group(args.group_name, args.hypothesis, run_correlation=args.correlate)
    elif args.command == "correlate":
        build_correlations(
            yaml_dir=args.yaml_dir,
            output_file=args.output,
            min_queries=args.min_queries,
            max_queries=args.max_queries,
            threat_group=args.threat_group,
            verbose=args.verbose,
        )
    elif args.command == "hunt":
        generate_detection(args.technique)
    elif args.command == "emulate":
        run_emulation(
            technique_id=args.technique_id,
            threat_group=args.threat_group,
            framework=args.framework,
            execute=args.execute,
            enrich=args.enrich,
            max_techniques=args.max_techniques,
            verbose=args.verbose,
        )
    elif args.command == "vectr":
        run_vectr_command(
            action=args.action,
            threat_group=args.threat_group,
            campaign_id=args.campaign_id,
            campaign_name=args.campaign_name,
            update_yamls=args.update_yamls,
            verbose=args.verbose,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

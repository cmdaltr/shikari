"""Generate detection queries for a MITRE ATT&CK threat group."""

from .base import BaseModule, ModuleOption


class GenerateModule(BaseModule):
    name = "generate"
    description = "Generate detection queries for a MITRE ATT&CK threat group"
    author = "Archer Team"
    references = ["https://attack.mitre.org/groups/"]

    def _register_options(self):
        self.options = {
            "GROUP": ModuleOption(
                name="GROUP",
                description="Threat group name (e.g., APT29, Scattered Spider)",
                required=True,
            ),
            "MODE": ModuleOption(
                name="MODE",
                description="Query generation mode: standard | llm | fallback",
                default="standard",
                choices=["standard", "llm", "fallback"],
            ),
            "CORRELATE": ModuleOption(
                name="CORRELATE",
                description="Run correlation after generation",
                default=False,
            ),
            "HYPOTHESIS": ModuleOption(
                name="HYPOTHESIS",
                description="Optional hypothesis for the group",
            ),
            "OSINT": ModuleOption(
                name="OSINT",
                description="Enable OSINT enhancement",
                default=False,
            ),
            "OSINT_COMPARE": ModuleOption(
                name="OSINT_COMPARE",
                description="Enable OSINT comparison (reference only)",
                default=False,
            ),
            "DRY_RUN": ModuleOption(
                name="DRY_RUN",
                description="Preview queries to stdout without writing any files",
                default=False,
            ),
            "SIEM": ModuleOption(
                name="SIEM",
                description="Comma-separated SIEMs to target: mde,splunk,elastic,secops (default: all)",
                default="",
            ),
            "INDEX": ModuleOption(
                name="INDEX",
                description="Only show queries whose index/table contains one of these strings "
                            "(e.g. edr_events,DeviceProcessEvents)",
                default="",
            ),
        }

    def run(self):
        from archer.build.orchestrator import process_group

        group = self.options["GROUP"].effective_value
        mode = self.options["MODE"].effective_value

        use_llm = False
        if mode == "llm":
            use_llm = "llm"
        elif mode == "fallback":
            use_llm = "fallback"

        dry_run = bool(self.options["DRY_RUN"].effective_value)
        action = "Previewing" if dry_run else "Generating"

        # Parse SIEM filter
        siem_raw = (self.options["SIEM"].effective_value or "").strip()
        siem_filter = None
        if siem_raw:
            from archer.build.detections import ALL_SIEMS
            siem_filter = {s.strip().lower() for s in siem_raw.split(",") if s.strip()}
            invalid = siem_filter - ALL_SIEMS
            if invalid:
                print(f"  Unknown SIEM(s): {', '.join(sorted(invalid))}. Valid: {', '.join(sorted(ALL_SIEMS))}")
                return
            print(f"\n[*] {action} detections for {group} (mode: {mode}, siems: {', '.join(sorted(siem_filter))})\n")
        else:
            print(f"\n[*] {action} detections for {group} (mode: {mode})\n")

        index_raw = (self.options["INDEX"].effective_value or "").strip()
        index_filter = {s.strip() for s in index_raw.split(",") if s.strip()} if index_raw else None

        process_group(
            group_name=group,
            hypothesis=self.options["HYPOTHESIS"].effective_value,
            run_correlation=bool(self.options["CORRELATE"].effective_value),
            osint_enhancement=bool(self.options["OSINT"].effective_value),
            osint_comparison=bool(self.options["OSINT_COMPARE"].effective_value),
            use_llm=use_llm,
            dry_run=dry_run,
            siem_filter=siem_filter,
            index_filter=index_filter,
        )

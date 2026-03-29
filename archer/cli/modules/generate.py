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

        print(f"\n[*] Generating detections for {group} (mode: {mode})\n")

        process_group(
            group_name=group,
            hypothesis=self.options["HYPOTHESIS"].effective_value,
            run_correlation=bool(self.options["CORRELATE"].effective_value),
            osint_enhancement=bool(self.options["OSINT"].effective_value),
            osint_comparison=bool(self.options["OSINT_COMPARE"].effective_value),
            use_llm=use_llm,
        )

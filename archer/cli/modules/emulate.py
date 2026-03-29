"""Execute adversary emulation tests."""

from .base import BaseModule, ModuleOption


class EmulateModule(BaseModule):
    name = "emulate"
    description = "Execute adversary emulation tests against MITRE ATT&CK techniques"
    author = "Archer Team"
    references = ["https://github.com/redcanaryco/atomic-red-team"]

    def _register_options(self):
        self.options = {
            "TARGET": ModuleOption(
                name="TARGET",
                description="Technique ID (T1059.001) or threat group name (APT29)",
                required=True,
            ),
            "FRAMEWORK": ModuleOption(
                name="FRAMEWORK",
                description="Emulation framework to use",
                default="atomic",
                choices=["atomic", "caldera", "macat"],
            ),
            "EXECUTE": ModuleOption(
                name="EXECUTE",
                description="Actually execute tests (default: simulate only)",
                default=False,
            ),
            "ENRICH": ModuleOption(
                name="ENRICH",
                description="Enrich with additional detection queries",
                default=False,
            ),
            "MAX_TECHNIQUES": ModuleOption(
                name="MAX_TECHNIQUES",
                description="Max techniques to emulate for a group",
                default=10,
            ),
            "REMOTE_HOST": ModuleOption(
                name="REMOTE_HOST",
                description="Remote host for execution",
            ),
            "REMOTE_USER": ModuleOption(
                name="REMOTE_USER",
                description="Remote username",
            ),
            "REMOTE_PLATFORM": ModuleOption(
                name="REMOTE_PLATFORM",
                description="Remote platform (windows/linux)",
                choices=["windows", "linux"],
            ),
            "VERBOSE": ModuleOption(
                name="VERBOSE",
                description="Enable verbose output",
                default=False,
            ),
        }

    def run(self):
        target = self.options["TARGET"].effective_value
        framework = self.options["FRAMEWORK"].effective_value
        print(f"\n[*] Emulating {target} using {framework}\n")

        try:
            from archer.emulation import AtomicRedTeam
        except ImportError:
            print("  Emulation module not available. Check dependencies.")
            return

        # Delegate to the existing emulation runner
        # Import is done lazily to avoid startup cost
        try:
            from archer import run_emulation
            run_emulation(
                target=target,
                framework=framework,
                execute=bool(self.options["EXECUTE"].effective_value),
                enrich=bool(self.options["ENRICH"].effective_value),
                max_techniques=int(self.options["MAX_TECHNIQUES"].effective_value),
                remote_host=self.options["REMOTE_HOST"].effective_value,
                remote_user=self.options["REMOTE_USER"].effective_value,
                remote_platform=self.options["REMOTE_PLATFORM"].effective_value,
                verbose=bool(self.options["VERBOSE"].effective_value),
            )
        except Exception as e:
            print(f"  Emulation error: {e}")

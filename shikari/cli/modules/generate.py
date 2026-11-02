"""Generate detection queries for a MITRE ATT&CK threat group."""

from .base import BaseModule, ModuleOption


class GenerateModule(BaseModule):
    name = "generate"
    description = "Generate detection queries for a MITRE ATT&CK threat group"
    author = "Shikari Team"
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
            "PROVIDER": ModuleOption(
                name="PROVIDER",
                description="MODE llm: assigned (profile of SHIKARI_EMAIL) | anthropic | openai | google | deepseek | qwen | grok",
                default="assigned",
            ),
            "MODEL": ModuleOption(
                name="MODEL",
                description="MODE llm: model override (blank = the profile's model)",
            ),
            "MAX_CALLS": ModuleOption(
                name="MAX_CALLS",
                description="MODE llm: max LLM calls this run (blank = the profile's limit)",
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
            "LOL": ModuleOption(
                name="LOL",
                description="LOLBAS, LOLDrivers and LOLRMM for tools the group is seen using",
                default=True,
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
        from shikari.build.orchestrator import process_group

        group = self.options["GROUP"].effective_value
        mode = self.options["MODE"].effective_value

        use_llm = False
        if mode == "llm":
            use_llm = "llm"
        elif mode == "fallback":
            use_llm = "fallback"

        llm_config = None
        if use_llm == "llm":
            llm_config = self._llm_config()
            if llm_config is False:
                return

        dry_run = bool(self.options["DRY_RUN"].effective_value)
        action = "Previewing" if dry_run else "Generating"

        # Parse SIEM filter
        siem_raw = (self.options["SIEM"].effective_value or "").strip()
        siem_filter = None
        if siem_raw:
            from shikari.build.detections import ALL_SIEMS
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
            lol_datasets=bool(self.options["LOL"].effective_value),
            use_llm=use_llm,
            llm_config=llm_config,
            dry_run=dry_run,
            siem_filter=siem_filter,
            index_filter=index_filter,
        )

    def _llm_config(self):
        """
        The detection provider from the profile of SHIKARI_EMAIL (the same resolution as a
        web hunt, call cap included); False when nothing usable is configured.
        """
        import os

        from shikari.ai.assignment import DEFAULT_MAX_DETECTION_CALLS, detection_llm_config, resolve
        from shikari.database.db import SessionLocal
        from shikari.database.models import User

        provider = (self.options["PROVIDER"].effective_value or "assigned").lower()
        model = self.options["MODEL"].effective_value or None
        max_calls = self.options["MAX_CALLS"].effective_value
        email = os.getenv("SHIKARI_EMAIL")
        db = SessionLocal()
        try:
            users = db.query(User).filter(User.email == email).all() if email else db.query(User).all()
            if len(users) != 1:
                print("  Set SHIKARI_EMAIL to the account whose AI settings and keys MODE llm should use")
                return False
            resolved = resolve(db, users[0].id, "detection", None if provider == "assigned" else provider, model)
        finally:
            db.close()
        if not resolved:
            print(f"  {users[0].email} has no {'detection provider assigned' if provider == 'assigned' else provider + ' key'}"
                  f" (Profile → API Keys)")
            return False
        config = detection_llm_config(resolved)
        if max_calls:
            config["max_calls"] = int(max_calls)
        print(f"  🤖 {resolved['label']} / {resolved['model'] or 'default model'}, "
              f"up to {config.get('max_calls', DEFAULT_MAX_DETECTION_CALLS)} LLM calls")
        return config

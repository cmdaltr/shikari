"""Intel-driven hunts on the Archer server: threat reports and company profiles."""

from .base import ModuleOption
from .server import ServerModule, client, run_options


def _tid(ttp) -> str:
    """Extraction TTPs are technique IDs (older extractions: dicts)."""
    return ttp if isinstance(ttp, str) else ttp.get("id") or ttp.get("technique_id", "")


class ReportModule(ServerModule):
    name = "intel/report"
    description = "Extract TTPs and IOCs from a report (URL or file) and hunt them"
    author = "Archer Team"

    def _register_options(self):
        self.options = {
            "URL": ModuleOption(name="URL", description="Report URL (e.g. a CISA advisory or vendor blog)"),
            "FILE": ModuleOption(name="FILE", description="Report file instead of a URL (PDF, DOCX, TXT, HTML, CSV, JSON)"),
            "MODE": ModuleOption(name="MODE", description="all = TTPs and IOCs | iocs = IOC sweeps only | review = extract and stop",
                                 default="all", choices=["all", "iocs", "review"]),
            "TECHNIQUES": ModuleOption(name="TECHNIQUES", description="Only these extracted techniques, comma-separated (blank = all)"),
            "USE_AI": ModuleOption(name="USE_AI", description="AI-assisted extraction", default=False),
            **run_options(),
        }

    def validate(self):
        errors = super().validate()
        if bool(self.options["URL"].effective_value) == bool(self.options["FILE"].effective_value):
            errors.append("Set URL or FILE (one of them)")
        return errors

    def execute(self):
        o = {k: v.effective_value for k, v in self.options.items()}
        c = client()
        extraction = (c.analyse_file(o["FILE"], use_ai=o["USE_AI"]) if o["FILE"]
                      else c.analyse_url(o["URL"], use_ai=o["USE_AI"]))
        ttps, iocs = extraction.get("ttps") or [], extraction.get("iocs") or {}
        print(f"\n  {extraction.get('synthetic_group_name')}: {len(ttps)} TTPs, "
              f"{sum(len(v) for v in iocs.values())} IOCs")
        print(f"    TTPs: {', '.join(_tid(t) for t in ttps)}")
        for kind, values in iocs.items():
            print(f"    {kind:<11} {', '.join(values[:6])}{f' … {len(values) - 6} more' if len(values) > 6 else ''}")
        if o["MODE"] == "review":
            return
        if o["MODE"] == "iocs":
            ttps = []
        elif o["TECHNIQUES"]:
            wanted = {t.strip().upper() for t in o["TECHNIQUES"].split(",")}
            ttps = [t for t in ttps if _tid(t).upper() in wanted]
        if not ttps and not any(iocs.values()):
            print("  Nothing to hunt")
            return
        self.follow(c.generate_from_extraction(extraction, ttps=ttps, iocs=iocs, from_file=bool(o["FILE"])))


class CompanyModule(ServerModule):
    name = "intel/company"
    description = "Profile a company from OSINT and hunt the threat groups that target it"
    author = "Archer Team"

    def _register_options(self):
        self.options = {
            "DOMAIN": ModuleOption(name="DOMAIN", description="Company domain (e.g. tesco.com)", required=True),
            "INDUSTRY": ModuleOption(name="INDUSTRY", description="Use industry targeting", default=True),
            "GEOGRAPHY": ModuleOption(name="GEOGRAPHY", description="Use geographic targeting", default=True),
            "TECH_STACK": ModuleOption(name="TECH_STACK", description="Use the detected technology stack", default=True),
            "SUPPLY_CHAIN": ModuleOption(name="SUPPLY_CHAIN", description="Use supply-chain exposure", default=True),
            "USE_AI": ModuleOption(name="USE_AI", description="AI-assisted profiling", default=False),
            "GROUPS": ModuleOption(name="GROUPS", description="Groups to hunt: top N recommended (a number) or names, comma-separated; 0 = profile only",
                                   default="3"),
            "CORRELATE": ModuleOption(name="CORRELATE", description="Build correlation queries", default=True),
            **run_options(),
        }

    def execute(self):
        o = {k: v.effective_value for k, v in self.options.items()}
        c = client()
        result = c.profile_company(o["DOMAIN"], industry=o["INDUSTRY"], geography=o["GEOGRAPHY"],
                                   tech_stack=o["TECH_STACK"], supply_chain=o["SUPPLY_CHAIN"], use_ai=o["USE_AI"])
        profile = result.get("profile") or {}
        info, threat = profile.get("company_info") or {}, profile.get("threat_profile") or {}
        industry = threat.get("industry") or {}
        tech = (threat.get("tech_stack") or {}).get("technologies") or []
        recommended = result.get("recommended_groups") or []
        print(f"\n  {info.get('company_name') or o['DOMAIN']} ({o['DOMAIN']}): {industry.get('sector', 'sector unknown')}"
              f"{', ' + industry['subsector'] if industry.get('subsector') else ''}; "
              f"{info.get('country') or 'country unknown'}; risk score {profile.get('risk_score', '?')}")
        if tech:
            print(f"  Technology: {', '.join(tech[:10])}")
        print(f"  Recommended groups ({len(recommended)}): {', '.join(recommended)}")
        groups_opt = str(o["GROUPS"]).strip()
        if groups_opt.isdigit():
            groups = recommended[:int(groups_opt)]
        else:
            groups = [g.strip() for g in groups_opt.split(",") if g.strip()]
        if not groups:
            return
        runs = c.hunt_company(o["DOMAIN"], groups, correlate=o["CORRELATE"])
        print(f"  Hunting {len(runs)} groups, one after another: {', '.join(runs)}")
        for run in runs:
            self.follow(run)

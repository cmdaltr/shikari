"""Research: find threat actors by keyword and consolidate their ATT&CK techniques."""

from .base import ModuleOption
from .server import ServerModule, client


class ResearchModule(ServerModule):
    name = "research/actors"
    description = "Find actors by keyword (country, industry) and consolidate their techniques"
    author = "Shikari Team"

    def _register_options(self):
        self.options = {
            "KEYWORDS": ModuleOption(name="KEYWORDS", description="Keywords, comma-separated (e.g. Iran,Finance)"),
            "MODE": ModuleOption(name="MODE", description="AND = all keywords | OR = any", default="AND", choices=["AND", "OR"]),
            "SCOPE": ModuleOption(name="SCOPE", description="Country keywords: attributed (from/sponsored by) | targeted",
                                  default="attributed", choices=["attributed", "targeted"]),
            "ACTORS": ModuleOption(name="ACTORS", description="Actors to consolidate, comma-separated (blank = the keyword matches)"),
            "TOP": ModuleOption(name="TOP", description="Techniques to list (most shared first)", default=25),
            "EXPORT": ModuleOption(name="EXPORT", description="Write the XLSX workbook to this path"),
        }

    def validate(self):
        errors = super().validate()
        if not self.options["KEYWORDS"].effective_value and not self.options["ACTORS"].effective_value:
            errors.append("Set KEYWORDS or ACTORS")
        return errors

    def execute(self):
        o = {k: v.effective_value for k, v in self.options.items()}
        c = client()
        actors = [a.strip() for a in (o["ACTORS"] or "").split(",") if a.strip()]
        if not actors:
            keywords = [k.strip() for k in o["KEYWORDS"].split(",") if k.strip()]
            actors = c.actors_by_keyword(keywords, mode=o["MODE"], scope=o["SCOPE"])
            joiner = f" {o['MODE']} "
            print(f"\n  {len(actors)} actors match {joiner.join(keywords)} ({o['SCOPE']}):")
            print("    " + ", ".join(actors))
        if not actors:
            return
        data = c.actor_techniques(actors)
        techniques = sorted(data.get("techniques") or [], key=lambda t: -t.get("actor_count", 0))
        print(f"\n  {data.get('total_techniques', len(techniques))} techniques, {data.get('shared_count', 0)} shared by more than one actor")
        if data.get("actors_not_found"):
            print(f"  Not found: {', '.join(data['actors_not_found'])}")
        for t in techniques[:int(o["TOP"])]:
            users = [a["name"] for a in t.get("actors") or []]
            print(f"    {t.get('technique_id', ''):<11} {t.get('technique_name', '')[:45]:<45} {len(users):>3}  "
                  f"{', '.join(users[:4])}{' …' if len(users) > 4 else ''}")
        if o["EXPORT"]:
            print(f"\n  Saved: {c.export_research(actors, o['EXPORT'])}")
        print()

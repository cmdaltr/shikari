"""Hunt for a specific MITRE ATT&CK technique."""

from .base import BaseModule, ModuleOption


class HuntModule(BaseModule):
    name = "hunt"
    description = "Hunt for a specific MITRE ATT&CK technique and generate detections"
    author = "Shikari Team"
    references = ["https://attack.mitre.org/techniques/"]

    def _register_options(self):
        self.options = {
            "TECHNIQUE": ModuleOption(
                name="TECHNIQUE",
                description="Technique name or ID (partial match, e.g., PowerShell, T1059)",
                required=True,
            ),
        }

    def run(self):
        from shikari.mitre.enterprise import (
            get_stix_data,
            obtain_all_techniques,
            obtain_technique_descriptions,
        )
        from shikari.mitre.retrieve import retrieve_procedures
        from shikari.build.detections import compile_query

        technique_input = self.options["TECHNIQUE"].effective_value
        print(f"\n[*] Hunting for technique: {technique_input}\n")

        url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        bundle = get_stix_data(url)
        all_techniques = obtain_all_techniques(bundle)
        technique_descriptions = obtain_technique_descriptions(bundle)

        # Find matching techniques
        matches = []
        for desc in technique_descriptions:
            if technique_input.lower() in desc.lower():
                matches.append(desc)

        if not matches:
            print(f"  No techniques found matching '{technique_input}'")
            return

        if len(matches) > 1:
            print(f"  Found {len(matches)} matching techniques:\n")
            for i, m in enumerate(matches, 1):
                tid = m.split(":")[0].strip() if ":" in m else m
                name = m.split(":", 1)[1].strip() if ":" in m else ""
                print(f"    {i}. {tid} - {name[:60]}")
            print()
            try:
                choice = input("  Select technique number (or 0 to cancel): ").strip()
                idx = int(choice) - 1
                if idx < 0 or idx >= len(matches):
                    print("  Cancelled.")
                    return
                selected = matches[idx]
            except (ValueError, EOFError, KeyboardInterrupt):
                print("\n  Cancelled.")
                return
        else:
            selected = matches[0]

        technique_id = selected.split(":")[0].strip() if ":" in selected else selected
        print(f"  Selected: {technique_id}")

        # Find the technique in STIX and generate detection
        for tech in all_techniques:
            ext_refs = tech.get("external_references", [])
            for ref in ext_refs:
                if ref.get("external_id") == technique_id:
                    procedures = retrieve_procedures(bundle, [(tech.get("description", ""), tech["id"])])
                    for procedure in procedures:
                        retrieved_data = {
                            "technique_id": procedure[0],
                            "technique": procedure[1],
                            "tactic": procedure[2][0] if procedure[2] else "",
                            "activity_desc": procedure[3],
                            "op_guidance": procedure[4],
                            "red_tool": procedure[5],
                            "detect_guidance": procedure[6][0] if procedure[6] else "",
                            "group_name": "Hunt",
                        }
                        if len(procedure) > 7:
                            retrieved_data["procedure_platforms"] = procedure[7]
                            retrieved_data["software_platforms"] = procedure[8]
                        if len(procedure) > 9:
                            retrieved_data["technique_description"] = procedure[9]
                            retrieved_data["technique_platforms"] = procedure[10]
                        compile_query(retrieved_data)
                    return

        print(f"  Could not find procedures for {technique_id}")

"""The Lab's CALDERA path from the console: plan, run, collect and check CALDERA operations.

Runs in this process against the CALDERA server directly (archer.lab.caldera) — the same
plan/run/collect/check the Emulate page drives over /api/lab/caldera/*, so the console reaches
exactly what the web UI and desktop app reach. Server and key come from the caldera: block in
bespoke/config.yaml (or CALDERA_URL / CALDERA_API_KEY)."""

from .base import BaseModule, ModuleOption


class CalderaModule(BaseModule):
    name = "lab/caldera"
    description = "Plan, run, collect and check CALDERA operations (Emulate → Lab)"
    author = "Archer Team"
    references = ["https://github.com/mitre/caldera"]

    def _register_options(self):
        self.options = {
            "ACTION": ModuleOption(
                name="ACTION",
                description="status (groups) | run | collect | check",
                default="status",
                choices=["status", "run", "collect", "check"],
            ),
            "KIND": ModuleOption(
                name="KIND",
                description="What TARGET names, for 'run'",
                default="technique",
                choices=["technique", "group", "cve"],
            ),
            "TARGET": ModuleOption(
                name="TARGET",
                description="Technique ID (T1059.001), threat group or CVE — for 'run'",
            ),
            "GROUP": ModuleOption(
                name="GROUP",
                description="CALDERA agent group to run against — for 'run'",
            ),
            "EXECUTE": ModuleOption(
                name="EXECUTE",
                description="Create and run the operation ('run'); false = plan only (dry run)",
                default=False,
            ),
            "CAPTURE": ModuleOption(
                name="CAPTURE",
                description="Capture each step's endpoint logs: none | caldera (over the agent's own C2)",
                default="none",
                choices=["none", "caldera"],
            ),
            "NAME": ModuleOption(
                name="NAME",
                description="Operation name — for 'run' (optional); the collected operation — for 'check'",
            ),
            "OPERATION_ID": ModuleOption(
                name="OPERATION_ID",
                description="CALDERA operation id — for 'collect'",
            ),
        }

    def run(self):
        from archer.config import GENERATE_DIR
        from archer.lab import caldera
        from archer.lab.runner import LabError

        if not caldera.configured():
            print("\n  CALDERA isn't configured. Set caldera.url and caldera.api_key in bespoke/config.yaml")
            print("  (or the CALDERA_URL / CALDERA_API_KEY environment variables).\n")
            return

        action = (self.options["ACTION"].effective_value or "status").lower()
        try:
            client = caldera.Client.from_settings()
            if action == "status":
                self._status(caldera, client)
            elif action == "run":
                self._run_op(caldera, client, GENERATE_DIR)
            elif action == "collect":
                self._collect(caldera, client, GENERATE_DIR)
            elif action == "check":
                self._check(caldera, GENERATE_DIR)
        except LabError as e:
            detail = f" — {e.detail}" if getattr(e, "detail", "") else ""
            print(f"\n  CALDERA error: {e.message}{detail}\n")

    def _status(self, caldera, client):
        rows = caldera.groups(client.agents())
        print(f"\n  CALDERA {client.url}\n")
        if not rows:
            print("  No agent groups — no agents have checked in.\n")
            return
        print(f"  {'Group':<24}{'Agents':<9}Platforms")
        for g in rows:
            print(f"  {(g['group'] or '(none)'):<24}{g['agents']:<9}{', '.join(g['platforms'])}")
        print()

    def _run_op(self, caldera, client, generate_dir):
        kind = (self.options["KIND"].effective_value or "technique").lower()
        target = (self.options["TARGET"].effective_value or "").strip()
        group = (self.options["GROUP"].effective_value or "").strip()
        name = (self.options["NAME"].effective_value or "").strip()
        execute = bool(self.options["EXECUTE"].effective_value)
        capture = (self.options["CAPTURE"].effective_value or "none").lower()

        if not target:
            print("\n  Set TARGET (a technique ID, threat group or CVE).\n")
            return
        if not group:
            print("\n  Set GROUP (the CALDERA agent group to run against — see ACTION=status).\n")
            return

        techs = caldera.resolve_techniques(kind, target, generate_dir)
        if not techs:
            print(f"\n  No techniques resolved from {kind} {target!r}.\n")
            return

        p = caldera.plan(client.abilities(), client.agents(), techs, group)
        print("\n  Plan (dry run — nothing created on CALDERA yet):\n")
        for line in caldera.plan_lines(p, name or "archer-operation"):
            print(f"    {line}")
        for w in p.get("warnings") or []:
            print(f"    ! {w}")

        if not execute:
            print("\n  Set EXECUTE true to create the adversary and run the operation.\n")
            return
        if not p.get("steps"):
            print("\n  Nothing runnable for this group — not starting an operation.\n")
            return

        print()
        run = caldera.operate(client, techs, group, name=name, target=f"{kind}: {target}", execute=True)
        state = caldera.wait(client, run["operation_id"])
        print(f"  Operation finished: {state}")
        manifest = caldera.collect(client, run["operation_id"], rebuild=(capture == "none"))
        if capture == "caldera":
            caldera.capture_via_agent(client, manifest)
        self._print_check(caldera, manifest, generate_dir)

    def _collect(self, caldera, client, generate_dir):
        op_id = (self.options["OPERATION_ID"].effective_value or "").strip()
        if not op_id:
            print("\n  Set OPERATION_ID (the id of an operation already run on CALDERA).\n")
            return
        print()
        manifest = caldera.collect(client, op_id, rebuild=True)
        self._print_check(caldera, manifest, generate_dir)

    def _check(self, caldera, generate_dir):
        name = (self.options["NAME"].effective_value or "").strip()
        if not name:
            ops = caldera.collected()
            if not ops:
                print("\n  No operations collected here yet. Run one, or ACTION=collect an existing id.\n")
                return
            print("\n  Set NAME to one of the collected operations:\n")
            for m in ops:
                print(f"    {m.get('name')}  ({m.get('operation_id')})")
            print()
            return
        manifest = caldera.load(name)
        if not manifest:
            print(f"\n  No collected operation named {name!r} (ACTION=check with no NAME lists them).\n")
            return
        self._print_check(caldera, manifest, generate_dir)

    def _print_check(self, caldera, manifest, generate_dir):
        res = caldera.check_operation(manifest, generate_dir)
        s = res["summary"]
        print(f"\n  Check of {res['operation'] or 'operation'} against {res['evidence']}:")
        print(f"  {s['matched']} matched, {s['missed']} missed, {s['no_detections']} with no detections, "
              f"of {s['techniques']} technique(s)\n")
        marks = {"matched": "✓", "missed": "✗", "no_detections": "–"}
        for t in res["techniques"]:
            print(f"    {marks.get(t['status'], '?')} {t['technique_id']}  {t['technique_name']}")

        corr = caldera.check_correlations(manifest, generate_dir)
        cs = corr["summary"]
        if cs["testable"]:
            print(f"\n  Correlations: {cs['fired']} fired, {cs['half_fired']} half-fired, "
                  f"{cs['missed']} missed, of {cs['testable']} testable")
            for c in corr["correlations"]:
                vendor = f" [{c['vendor']}]" if c.get("vendor") else ""
                print(f"    {c['status']:<11}{c['target']}{vendor}")
        else:
            print("\n  Correlations: none testable (no saved correlation had all its techniques run)")
        print()

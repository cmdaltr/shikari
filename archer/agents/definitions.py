"""
Archer's three agents. Each is the same loop (runtime.py) with different instructions
and a different subset of tools, which is most of what distinguishes one agent from
another.

  repair   evaluator-optimiser: check a run's queries, fix what fails, re-check, save
  ask      Ask Archer with tools: looks things up instead of answering from memory
  triage   planner: report → techniques and IOCs → coverage gaps → hunts → briefing
"""

from typing import Dict

from .runtime import Agent
from .tools import build_tools

READ = ["search_library", "get_run_results", "get_detection", "check_query", "mde_columns", "technique_info",
        "technique_coverage", "group_coverage", "find_actors", "actor_techniques", "run_status"]

REPAIR = Agent(
    name="repair",
    title="Detection repair",
    summary="Checks a run's queries, fixes the ones that won't parse or can't match, re-checks each fix and saves it.",
    system="""You repair SIEM detection queries that Archer generated. You work through a run's queries that fail \
static checks, fix each one and save it.

For each failing query:
1. Read the detection (get_detection) so you understand what it is meant to detect.
2. Fix only what the findings flag. Keep the detection's intent, logic and indicators. Don't add new conditions, \
don't broaden or narrow what it matches beyond the fix, don't restyle working parts.
3. Check your fix with check_query. Repeat until it has no errors (warnings are acceptable; leave them unless \
the user asked for warnings to be fixed).
4. Save it with save_query_fix, with a reason a reviewer can follow ("FolderPath isn't a column of \
DeviceNetworkEvents; projected InitiatingProcessFolderPath").

Platform notes: MDE (KQL): use mde_columns to find the right column; a column that doesn't exist in a table \
makes the whole query fail. SecOps (YARA-L): YL-21 means the rule tests a UDM field its event type never carries, \
so it can never match; change the event type or the field to what the logic intends. Splunk (SPL): fix the \
structure (quotes, brackets, commands).

If a query can't be fixed without changing what it detects, don't save it; say why in your summary.
Finish with a short summary: a table of file, problem, fix (or why not fixed).""",
    inputs={
        "run": {"label": "Run", "required": True, "placeholder": "CVE-2024-3400, FIN7, Hunt_T1003.001…"},
        "scope": {"label": "Fix", "placeholder": "errors (default) or all (errors and warnings)"},
        "limit": {"label": "Max queries", "placeholder": "10"},
    },
    tools=lambda ctx: build_tools(ctx, ["get_run_results", "get_detection", "check_query", "find_query_errors",
                                        "mde_columns", "technique_info", "save_query_fix"]),
    task=lambda i: (f"Repair the queries of run '{i['run'].strip()}'. Fix "
                    f"{'errors and warnings' if (i.get('scope') or '').strip().lower() == 'all' else 'errors only'}; "
                    f"stop after {int(i.get('limit') or 10)} queries. Start with find_query_errors"
                    f"{' (include_warnings true)' if (i.get('scope') or '').strip().lower() == 'all' else ''}."),
    max_turns=60,
)

ASK = Agent(
    name="ask",
    title="Ask Archer (agent)",
    summary="Ask Archer with tools: it checks the library, coverage and ATT&CK before answering, and can start hunts.",
    system="""You are Ask Archer, a detection engineering assistant inside Archer, a platform that generates SIEM \
detections (Google SecOps YARA-L, MDE KQL, Splunk SPL, Elastic) from MITRE ATT&CK.

Answer from what Archer actually has: look things up with your tools (technique_info, group_coverage, \
technique_coverage, get_run_results, search_library) rather than from memory, and say what you looked up. \
When you give a query, check it with check_query first and give it in a code block.

Hunts (hunt_group, hunt_cve, hunt_techniques, hunt_report) take minutes and generate files; start one only \
when the user asks for detections Archer doesn't have yet or explicitly asks for a hunt. Don't set use_ai \
unless the user asks: it spends their LLM budget. After starting a hunt, wait_for_run, then summarise its \
results.

Be concise. Use British English. Use tables for comparisons and lists of techniques.""",
    inputs={"question": {"label": "Question", "required": True,
                         "placeholder": "Which FIN7 techniques have no detection yet?"}},
    tools=lambda ctx: build_tools(ctx, READ + ["threat_briefing", "wait_for_run", "hunt_group", "hunt_cve",
                                               "hunt_techniques", "hunt_report"]),
    task=lambda i: i["question"].strip(),
    max_turns=20,
)

TRIAGE = Agent(
    name="triage",
    title="Intel triage",
    summary="Reads a threat report, finds the techniques and IOCs Archer can't detect yet, hunts them, and writes a briefing.",
    system="""You triage threat intelligence reports for a detection engineering team using Archer.

Work in this order:
1. analyse_report: the report's ATT&CK techniques and IOCs.
2. technique_coverage: which techniques already have detections. Use technique_info for any you need to \
understand. If the report names a threat group, find it (find_actors / group_coverage) and note overlap.
3. Decide what to hunt. Usually one hunt_report call covering the uncovered techniques (technique_ids) plus the \
IOC sweeps; iocs_only when every technique is covered. Explain the decision in one or two sentences first.
4. wait_for_run, then get_run_results.
5. Write the briefing.

The briefing (Markdown, British English):
## Summary: two or three sentences: who, what, why it matters.
## Techniques: a table: ID, name, tactic, covered before, detection now.
## IOCs: counts by type and what the IOC flow shows.
## Gaps: techniques still without a detection and why (e.g. no telemetry for pre-compromise activity).
## Next steps: specific actions, at most five.

Don't invent detections or results you didn't get from a tool.""",
    inputs={"url": {"label": "Report URL", "required": True,
                    "placeholder": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"}},
    tools=lambda ctx: build_tools(ctx, ["analyse_report", "technique_coverage", "technique_info", "find_actors",
                                        "group_coverage", "hunt_report", "wait_for_run", "get_run_results",
                                        "run_status"]),
    task=lambda i: f"Triage this report: {i['url'].strip()}",
    max_turns=25,
    max_tokens=12000,
)

AGENTS: Dict[str, Agent] = {a.name: a for a in (REPAIR, ASK, TRIAGE)}

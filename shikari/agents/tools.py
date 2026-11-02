"""
Shikari's tools, defined once: the agents use them, and the MCP server publishes the same
definitions to any MCP client (Claude Code, Claude Desktop, another agent).

Every tool goes through shikari.client, so it does exactly what the web app does. Tools
that change something (start a hunt, save a query) are marked changes=True: an agent
pauses for approval before calling one, and MCP clients see them as non-read-only.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional

from shikari.client import ShikariClient
from shikari.telemetry import check as _telemetry_check
from shikari.validation.static_check import check_query as _check_query
from shikari.validation.static_check import mde_table_columns

from .runtime import Tool


@dataclass
class ToolContext:
    client: ShikariClient


def _str(description: str) -> Dict:
    return {"type": "string", "description": description}


def _schema(properties: Dict, required: Optional[List[str]] = None) -> Dict:
    return {"type": "object", "properties": properties, "required": required or []}


def _results_summary(results: Dict, include_queries: bool, limit: int) -> Dict:
    detections = results.get("detections") or []
    out = []
    for d in detections[:limit]:
        entry = {k: d.get(k) for k in ("file", "name", "techniques", "tactics", "platforms")}
        if include_queries:
            entry["queries"] = d.get("queries")
        out.append(entry)
    flow = results.get("ioc_flow")
    return {
        "run": results.get("group_name"),
        "detection_count": len(detections),
        "detections": out,
        "truncated": len(detections) > limit,
        "correlation_count": len(results.get("correlations") or []),
        "correlations": [{k: c.get(k) for k in ("vendor", "techniques", "tactics", "relevance")}
                         for c in (results.get("correlations") or [])[:10]],
        "ioc_flow": {"source": flow.get("source"), "stats": flow.get("stats"),
                     "stages": [{"label": s["label"], "iocs": [n["value"] for n in s["nodes"][:15]]}
                                for s in flow.get("stages", [])]} if flow else None,
    }


def build_tools(ctx: ToolContext, names: Optional[List[str]] = None) -> List[Tool]:
    c = ctx.client

    # --- read ---------------------------------------------------------------

    def search_library(query: str = "") -> List[Dict]:
        return [{k: d.get(k) for k in ("id", "title", "detection_type", "platform", "tags", "creator", "created_at")}
                for d in c.search_library(query)[:40]]

    def get_run_results(run: str, include_queries: bool = False, latest_run_only: bool = True, limit: int = 40) -> Dict:
        return _results_summary(c.results(run, latest=latest_run_only), include_queries, max(1, min(limit, 200)))

    def get_detection(file: str) -> str:
        return c.detection_text(file)

    def check_query(query: str, platform: str = "") -> Dict:
        return _check_query(query, platform or None)

    def find_query_errors(run: str, include_warnings: bool = False, offset: int = 0, limit: int = 10) -> Dict:
        found = []
        for d in c.results(run, latest=True).get("detections") or []:
            for i, q in enumerate(d.get("queries") or []):
                result = _check_query(q.get("query", ""), q.get("platform"))
                findings = [f for f in result["findings"] if include_warnings or f["severity"] == "error"]
                if findings:
                    found.append({"file": d["file"], "index": i, "platform": q.get("platform"),
                                  "techniques": d.get("techniques"), "findings": findings})
        return {"run": run, "total_with_findings": len(found), "offset": offset,
                "items": found[offset:offset + limit], "more": offset + limit < len(found)}

    def mde_columns(table: str) -> Dict:
        columns = mde_table_columns(table)
        return {"table": table, "columns": columns} if columns else {"error": f"No schema for {table}"}

    def technique_info(technique_id: str) -> Dict:
        return c.technique(technique_id)

    def noisy_indicators(technique_id: str = "", indicators=None, min_techniques: int = 5) -> Dict:
        return _telemetry_check.noisy(indicators=_list(indicators), technique_id=technique_id,
                                      min_techniques=max(2, min_techniques))

    def technique_coverage(technique_ids: List[str]) -> Dict:
        return c.technique_coverage(_list(technique_ids))

    def group_coverage(group: str, tactic: str = "", include_covered: bool = False) -> Dict:
        cov = c.group_coverage(group)
        wanted = tactic.strip().lower().replace("-", " ")

        def pick(items):
            items = [t for t in items if not wanted or wanted in (t.get("tactic") or "").lower().replace("-", " ")]
            return [{k: t[k] for k in ("technique_id", "technique_name", "tactic")} for t in items[:150]]

        out = {k: cov.get(k) for k in ("group_name", "group_id", "total", "covered_count", "gap_count")}
        out["gaps"] = pick(cov.get("gaps", []))
        if include_covered:
            out["covered"] = pick(cov.get("covered", []))
        if wanted:
            out["tactic_filter"] = tactic
        return out

    def _list(value) -> List[str]:
        # Models sometimes pass "a, b" for an array; joining a string would split its characters
        return [v.strip() for v in (value.split(",") if isinstance(value, str) else value or []) if str(v).strip()]

    def find_actors(keywords: List[str], mode: str = "AND", scope: str = "attributed") -> Dict:
        actors = c.actors_by_keyword(_list(keywords), mode=mode, scope=scope)
        return {"count": len(actors), "actors": actors}

    def actor_techniques(actors: List[str], limit: int = 40) -> Dict:
        data = c.actor_techniques(_list(actors))
        techniques = sorted(data.get("techniques") or [], key=lambda t: -t.get("actor_count", 0))
        return {"total_techniques": data.get("total_techniques"), "shared_count": data.get("shared_count"),
                "actors_not_found": data.get("actors_not_found"),
                "techniques": [{"technique_id": t["technique_id"], "name": t["technique_name"], "tactic": t["tactic"],
                                "actors": [a["name"] for a in t["actors"]]} for t in techniques[:limit]]}

    def analyse_report(url: str) -> Dict:
        e = c.analyse_url(url)
        return {"run_name": e.get("synthetic_group_name"), "ttps": e.get("ttps"), "iocs": e.get("iocs"),
                "ttps_count": e.get("ttps_count"), "iocs_count": e.get("iocs_count")}

    def threat_briefing(group: str, top_n: int = 5) -> Dict:
        return c.threat_briefing(group, top_n)

    def rank_adversaries(domain: str) -> Dict:
        return c.rank_adversaries(domain)

    def ioc_search(ioc: str, days: int = 7, tiers: str = "") -> Dict:
        r = c.ioc_search(ioc, days=max(1, min(days, 30)), tiers=tiers)
        if r.get("hits"):  # trim for token economy
            r["hits"] = [{k: h.get(k) for k in ("source", "tier", "title", "url", "published", "snippet")}
                         for h in r["hits"][:40]]
        return r

    def profile_company(domain: str) -> Dict:
        return c.profile_company(domain)

    def run_status(run: str) -> Dict:
        p = c.progress(run)
        return {k: p.get(k) for k in ("status", "phase", "created_yaml", "error")}

    def wait_for_run(run: str, timeout_seconds: int = 900) -> Dict:
        try:
            p = c.wait(run, timeout=max(30, min(timeout_seconds, 1800)), poll=5)
        except Exception as e:
            return {"status": "still running", "note": str(e)}
        return {k: p.get(k) for k in ("status", "phase", "created_yaml", "error")} | {"results_url": c.results_url(run)}

    # --- change -------------------------------------------------------------

    def _ai(use_ai: bool):
        if not use_ai:
            return "", ""
        assigned = c.assigned_detection()
        return (assigned["provider"], assigned["model"]) if assigned else ("", "")

    def hunt_group(group: str, use_ai: bool = False, osint: bool = False) -> Dict:
        provider, model = _ai(use_ai)
        run = c.hunt_group(group, provider=provider, model=model, osint=osint)
        return {"run": run, "results_url": c.results_url(run), "ai": provider or "none"}

    def hunt_cve(cve: str, use_ai: bool = False) -> Dict:
        provider, model = _ai(use_ai)
        run = c.hunt_cve(cve, provider=provider, model=model)
        return {"run": run, "results_url": c.results_url(run), "ai": provider or "none"}

    def hunt_techniques(technique_ids: List[str], use_ai: bool = False) -> Dict:
        provider, model = _ai(use_ai)
        run = c.hunt_techniques(_list(technique_ids), provider=provider, model=model)
        return {"run": run, "results_url": c.results_url(run), "ai": provider or "none"}

    def hunt_report(url: str, iocs_only: bool = False, technique_ids: Optional[List[str]] = None) -> Dict:
        extraction = c.analyse_url(url)
        ttps = [] if iocs_only else extraction.get("ttps") or []
        if technique_ids and not iocs_only:
            wanted = {t.upper() for t in _list(technique_ids)}
            ttps = [t for t in ttps if (t if isinstance(t, str) else t.get("id", "")).upper() in wanted]
        run = c.generate_from_extraction(extraction, ttps=ttps)
        return {"run": run, "results_url": c.results_url(run), "ttps": len(ttps),
                "iocs": sum(len(v) for v in (extraction.get("iocs") or {}).values())}

    def save_query_fix(file: str, query: str, reason: str, index: int = 0) -> Dict:
        return c.save_query(file, query, index=index, reason=reason)

    tools = [
        Tool("search_library", "Search the user's saved detection library by title, tag or platform.",
             _schema({"query": _str("Search text (blank lists recent detections)")}), search_library),
        Tool("get_run_results", "Detections, correlations and IOC flow of a run (a group, CVE, report or technique hunt). "
             "Runs are named after what was hunted, e.g. 'FIN7', 'CVE-2024-3400', 'Hunt_T1003.001'.",
             _schema({"run": _str("Run name"),
                      "include_queries": {"type": "boolean", "description": "Include query text (large)"},
                      "latest_run_only": {"type": "boolean", "description": "Only the latest run's files (default true)"},
                      "limit": {"type": "integer", "description": "Max detections (default 40)"}}, ["run"]),
             get_run_results),
        Tool("get_detection", "The full YAML of one detection file.", _schema({"file": _str("File name, e.g. T1190__waf_prod_bespoke.yaml")}, ["file"]),
             get_detection),
        Tool("check_query", "Statically check a query: KQL (MDE schema and contract lint), UDM (SecOps search structure and joins), "
             "SPL (structure and commands), Elastic (structure). Errors mean it won't parse or can't match; "
             "warnings are style.",
             _schema({"query": _str("The query"), "platform": _str("mde | secops | splunk | elastic (blank = detect)")}, ["query"]),
             check_query),
        Tool("find_query_errors", "Check every query of a run's latest detections and list those with findings.",
             _schema({"run": _str("Run name"),
                      "include_warnings": {"type": "boolean", "description": "Also list warnings (default errors only)"},
                      "offset": {"type": "integer"}, "limit": {"type": "integer", "description": "Default 10"}}, ["run"]),
             find_query_errors),
        Tool("mde_columns", "The columns of an MDE advanced hunting table, e.g. DeviceProcessEvents.",
             _schema({"table": _str("Table name")}, ["table"]), mde_columns),
        Tool("technique_info", "An ATT&CK technique: name, tactics, platforms, description.",
             _schema({"technique_id": _str("e.g. T1003.001")}, ["technique_id"]), technique_info),
        Tool("noisy_indicators", "Which indicators are poor discriminators — recorded in many unrelated "
             "techniques' attack telemetry (a likely false-positive source). Pass indicators to vet a "
             "detection's own match values, or technique_id for that technique's recorded values shared "
             "with other techniques. Values also seen in lab background activity are flagged broad.",
             _schema({"technique_id": _str("e.g. T1059.001 (its own recorded values)"),
                      "indicators": {"type": "array", "items": {"type": "string"},
                                     "description": "Match values to vet, e.g. process names, paths, command fragments"},
                      "min_techniques": {"type": "integer", "description": "Flag at/above this many techniques (default 5)"}}),
             noisy_indicators),
        Tool("technique_coverage", "Which of these ATT&CK techniques already have a detection in Shikari.",
             _schema({"technique_ids": {"type": "array", "items": {"type": "string"}}}, ["technique_ids"]),
             technique_coverage),
        Tool("group_coverage", "An ATT&CK group's techniques and which lack detections (gaps); filter by tactic.",
             _schema({"group": _str("Group name or ID, e.g. FIN7 or G0046"),
                      "tactic": _str("Only this tactic, e.g. Execution (blank = all)"),
                      "include_covered": {"type": "boolean", "description": "Also list covered techniques"}}, ["group"]),
             group_coverage),
        Tool("find_actors", "ATT&CK groups whose descriptions match keywords (countries, industries).",
             _schema({"keywords": {"type": "array", "items": {"type": "string"}},
                      "mode": _str("AND (all keywords) or OR (any)"),
                      "scope": _str("Country keywords: attributed (from/sponsored by) or targeted")}, ["keywords"]),
             find_actors),
        Tool("actor_techniques", "Consolidated ATT&CK techniques of several groups, most shared first.",
             _schema({"actors": {"type": "array", "items": {"type": "string"}},
                      "limit": {"type": "integer", "description": "Max techniques (default 40)"}}, ["actors"]),
             actor_techniques),
        Tool("analyse_report", "Extract ATT&CK techniques and IOCs from a threat report URL (no hunt is run).",
             _schema({"url": _str("Report URL")}, ["url"]), analyse_report),
        Tool("rank_adversaries", "The ATT&CK groups most likely to target a profiled organisation, ranked (no AI) "
             "from its industry, geography, exposed OSINT and public incidents, each with the signals that drove it. "
             "Profile the domain first (profile_company).",
             _schema({"domain": _str("The organisation's domain, e.g. example.com")}, ["domain"]), rank_adversaries),
        Tool("ioc_search", "Search ~100 reputable sources' reporting from the last few days for an indicator — IP, "
             "domain, URL, hash, email or CVE — matching its defanged forms too. Returns hits ranked by source tier.",
             _schema({"ioc": _str("The indicator"), "days": {"type": "integer", "description": "Days back, 1–30 (default 7)"},
                      "tiers": _str("Optional source-tier filter, e.g. '1,2'")}, ["ioc"]), ioc_search),
        Tool("profile_company", "Start a background OSINT profile of a company by domain (exposure map and adversary "
             "list). Returns once it has started; the profile takes a few minutes.",
             _schema({"domain": _str("The company's domain")}, ["domain"]), profile_company, changes=True),
        Tool("threat_briefing", "An AI threat briefing for a group: prioritised techniques and coverage gaps. Costs an LLM call.",
             _schema({"group": _str("Group name or ID"), "top_n": {"type": "integer"}}, ["group"]), threat_briefing),
        Tool("run_status", "The progress of a run.", _schema({"run": _str("Run name")}, ["run"]), run_status),
        Tool("wait_for_run", "Wait for a run to finish (up to timeout_seconds, max 1800).",
             _schema({"run": _str("Run name"), "timeout_seconds": {"type": "integer"}}, ["run"]), wait_for_run),
        Tool("hunt_group", "Start a threat group hunt: generates detections for every technique the group uses. "
             "Takes minutes; use wait_for_run. use_ai spends LLM calls (capped by the user's profile).",
             _schema({"group": _str("Group name or alias"), "use_ai": {"type": "boolean"},
                      "osint": {"type": "boolean", "description": "OSINT enhancement"}}, ["group"]),
             hunt_group, changes=True),
        Tool("hunt_cve", "Start a CVE hunt: exploitation detections plus IOC sweeps from the CVE's references.",
             _schema({"cve": _str("CVE ID"), "use_ai": {"type": "boolean"}}, ["cve"]), hunt_cve, changes=True),
        Tool("hunt_techniques", "Start a hunt for ATT&CK techniques across every group that uses them.",
             _schema({"technique_ids": {"type": "array", "items": {"type": "string"}}, "use_ai": {"type": "boolean"}},
                     ["technique_ids"]), hunt_techniques, changes=True),
        Tool("hunt_report", "Start a hunt from a threat report URL: its techniques and IOC sweeps "
             "(iocs_only for sweeps only; technique_ids to limit the techniques).",
             _schema({"url": _str("Report URL"), "iocs_only": {"type": "boolean"},
                      "technique_ids": {"type": "array", "items": {"type": "string"}}}, ["url"]),
             hunt_report, changes=True),
        Tool("save_query_fix", "Replace one query in a detection file. Refused while the query still has errors; "
             "the previous query is kept in the file's repair_history.",
             _schema({"file": _str("Detection file name"), "query": _str("The corrected query"),
                      "reason": _str("What was wrong and what changed"),
                      "index": {"type": "integer", "description": "Which query in the file (default 0)"}},
                     ["file", "query", "reason"]), save_query_fix, changes=True),
    ]
    return [t for t in tools if names is None or t.name in names]

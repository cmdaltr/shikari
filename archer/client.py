"""
HTTP client for a running Archer server.

The console (adfconsole), the MCP server and the agents drive Archer through this
rather than importing the route logic, so every surface runs the same code as the web
app: profile AI assignment and call cap, IOC sweeps, IOC flow, latest-run view.

Connection settings come from the environment:
  ARCHER_URL       default http://127.0.0.1:8000
  ARCHER_TOKEN     an API token from Profile → Security → API tokens (works with MFA)
  ARCHER_EMAIL     or the account to sign in as...
  ARCHER_PASSWORD  ...and its password (the console prompts when unset and interactive)
"""

import getpass
import json
import os
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import requests

DEFAULT_URL = "http://127.0.0.1:8000"
TERMINAL_STATUSES = {"complete", "error", "failed", "cancelled"}


class ArcherError(RuntimeError):
    pass


class ArcherClient:
    def __init__(self, url: Optional[str] = None, email: Optional[str] = None,
                 password: Optional[str] = None, timeout: int = 120, session_cookie: Optional[str] = None,
                 token: Optional[str] = None):
        """
        token: an API token (ARCHER_TOKEN), sent as a bearer token on every request.
        session_cookie: an existing archer_session (agents running inside the server act as their user).
        """
        self.url = (url or os.getenv("ARCHER_URL") or DEFAULT_URL).rstrip("/")
        self.email = email or os.getenv("ARCHER_EMAIL")
        self._password = password or os.getenv("ARCHER_PASSWORD")
        self.timeout = timeout
        self.session = requests.Session()
        self._signed_in = False
        if session_cookie:
            self.session.cookies.set("archer_session", session_cookie)
            self._signed_in = True
        else:
            token = token or (None if email or password else os.getenv("ARCHER_TOKEN"))
            if token:
                self.session.headers["Authorization"] = f"Bearer {token}"
                self._signed_in = True

    # ------------------------------------------------------------------
    # Session
    # ------------------------------------------------------------------

    def login(self, interactive: bool = False) -> None:
        if self._signed_in:
            return
        if not self.email and interactive and sys.stdin.isatty():
            self.email = input("  Archer email: ").strip()
        if not self._password and interactive and sys.stdin.isatty():
            self._password = getpass.getpass("  Archer password: ")
        if not self.email or not self._password:
            raise ArcherError("Set ARCHER_TOKEN (Profile → Security → API tokens), or ARCHER_EMAIL and "
                              "ARCHER_PASSWORD (the account to sign in to Archer as)")
        try:
            page = self.session.get(f"{self.url}/login", timeout=15)
        except requests.ConnectionError:
            raise ArcherError(f"Archer isn't running at {self.url} (start it with `archer start`, or set ARCHER_URL)")
        token = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.text)
        if not token:
            raise ArcherError("The login page had no CSRF token")
        r = self.session.post(f"{self.url}/login", data={
            "email": self.email, "password": self._password, "csrf_token": token.group(1), "next_url": "/",
        }, allow_redirects=False, timeout=30)
        if "archer_session" not in self.session.cookies:
            hint = (" (this account uses MFA: create an API token in Profile → Security and set ARCHER_TOKEN)"
                    if "mfa" in r.text.lower() or "/mfa" in r.headers.get("location", "") else "")
            raise ArcherError(f"Sign-in failed for {self.email}{hint}")
        self._signed_in = True

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        self.login()
        kwargs.setdefault("timeout", self.timeout)
        try:
            r = self.session.request(method, f"{self.url}{path}", **kwargs)
        except requests.ConnectionError:
            raise ArcherError(f"Archer isn't running at {self.url} (start it with `archer start`, or set ARCHER_URL)")
        if r.status_code == 401:
            raise ArcherError("Invalid or revoked API token" if "Authorization" in self.session.headers
                              else "Not signed in (session expired?)")
        return r

    def _json(self, method: str, path: str, **kwargs) -> Any:
        r = self._request(method, path, **kwargs)
        try:
            data = r.json()
        except ValueError:
            raise ArcherError(f"{path} answered HTTP {r.status_code} without JSON")
        if r.status_code >= 400:
            detail = data.get("detail") or data.get("error") or data.get("message") if isinstance(data, dict) else data
            raise ArcherError(f"{path}: {detail or f'HTTP {r.status_code}'}")
        if isinstance(data, dict) and data.get("success") is False:
            raise ArcherError(f"{path}: {data.get('error') or data.get('message') or 'failed'}")
        return data

    @staticmethod
    def _flags(**flags) -> Dict[str, str]:
        """Form checkboxes: the routes read "true"; anything absent is off."""
        return {k: "true" for k, v in flags.items() if v}

    @staticmethod
    def _run_name(data: Dict) -> str:
        target = data.get("redirect_url") or data.get("redirect") or ""
        if "/manual" in target:
            raise ArcherError("Not a known ATT&CK group: Archer offers manual entry for it in the web app")
        name = (parse_qs(urlparse(target).query).get("group_name") or [""])[0]
        if not name:
            raise ArcherError(f"No run was started ({data})")
        return name

    # ------------------------------------------------------------------
    # AI
    # ------------------------------------------------------------------

    def ai_settings(self) -> Dict:
        return self._json("GET", "/api/profile/ai-settings")

    def update_ai_settings(self, update: Dict) -> Dict:
        return self._json("POST", "/api/profile/ai-settings", json=update)

    def ai_availability(self) -> Dict:
        return self._json("GET", "/api/ai/availability")

    def assigned_detection(self) -> Optional[Dict[str, str]]:
        """
        The provider a hunt uses when none is named, as the web Hunt prompt picks it: a
        remembered choice first, then the detection assignment. None = no AI.
        """
        settings = self.ai_settings().get("settings") or {}
        # A remembered {"provider": null} is "no AI", as in the web prompt
        choice = settings["remember"] if settings.get("remember") is not None else settings.get("detection") or {}
        return {"provider": choice["provider"], "model": choice.get("model") or ""} if choice.get("provider") else None

    @staticmethod
    def _ai_fields(provider: Optional[str], model: Optional[str]) -> Dict[str, str]:
        # provider "none" runs without AI; None leaves the profile's assignment to decide
        if provider is None:
            return {}
        return {"ai_provider": provider, "ai_model": model or ""}

    # ------------------------------------------------------------------
    # Hunts (each returns the run name; wait() follows it to completion)
    # ------------------------------------------------------------------

    def hunt_group(self, group: str, *, provider: Optional[str] = None, model: Optional[str] = None,
                   correlate: bool = True, osint: bool = False, osint_compare: bool = False,
                   merge_by_tactic: bool = False, merge_by_parent: bool = False,
                   exclude: Optional[List[str]] = None, validate: bool = False,
                   emulation: Optional[str] = None) -> str:
        """emulation: "simulate" or "live" runs Atomic Red Team after generation."""
        exclude = {s.lower() for s in exclude or []}
        data = {"group_name": group, **self._ai_fields(provider, model), **self._flags(
            run_correlation=correlate, osint_enhancement=osint, osint_comparison=osint_compare,
            merge_by_tactic=merge_by_tactic, merge_by_parent=merge_by_parent, auto_validate=validate,
            run_emulation=bool(emulation), exclude_splunk="splunk" in exclude, exclude_mde="mde" in exclude,
            exclude_secops="secops" in exclude, exclude_elastic="elastic" in exclude)}
        if emulation:
            data["emulation_mode"] = emulation
        return self._run_name(self._json("POST", "/generate", data=data))

    def hunt_cve(self, cve_id: str, *, provider: Optional[str] = None, model: Optional[str] = None,
                 correlate: bool = True) -> str:
        data = {"cve_id": cve_id, **self._ai_fields(provider, model), **self._flags(run_correlation=correlate)}
        return self._run_name(self._json("POST", "/generate/cve", data=data))

    def hunt_techniques(self, technique_ids: List[str], *, provider: Optional[str] = None,
                        model: Optional[str] = None, merge_by_tactic: bool = False,
                        merge_by_parent: bool = False, osint: bool = False, osint_compare: bool = False,
                        min_relevance: Optional[float] = None) -> str:
        data = {"technique_ids": ",".join(technique_ids), **self._ai_fields(provider, model), **self._flags(
            merge_by_tactic=merge_by_tactic, merge_by_parent=merge_by_parent,
            osint_enhancement=osint, osint_comparison=osint_compare)}
        if min_relevance is not None:
            data["correlation_min_relevance"] = str(min_relevance)
        return self._run_name(self._json("POST", "/hunt/technique", data=data))

    def technique_yield(self, technique_ids: Optional[List[str]] = None, *, ai: bool = False,
                        osint: bool = False) -> Dict:
        """Techniques that can't produce a detection (all, or those of a planned run)."""
        params = {"ai": str(ai).lower(), "osint": str(osint).lower()}
        if technique_ids:
            params["ids"] = ",".join(technique_ids)
        return self._json("GET", "/api/techniques/yield", params=params)

    # ------------------------------------------------------------------
    # Intel: reports, files, company profiles

    def feed(self) -> Dict:
        """The threat feed for the signed-in user's industries (last 7 days)."""
        return self._json("GET", "/api/feed")

    def refresh_feed(self) -> bool:
        return bool(self._json("POST", "/api/feed/refresh").get("started"))

    def industries(self) -> Dict:
        return self._json("GET", "/api/profile/industries")

    def set_industries(self, industries: List[str]) -> List[str]:
        return self._json("POST", "/api/profile/industries", json={"industries": industries})["industries"]

    # ------------------------------------------------------------------

    def analyse_url(self, url: str, *, use_ai: bool = False) -> Dict:
        """Extract TTPs and IOCs from a report URL (for review before generating)."""
        return self._json("POST", "/analyze_blog", data={"url": url, **self._flags(use_openai=use_ai)})

    def analyse_file(self, path: str, *, use_ai: bool = False) -> Dict:
        with open(path, "rb") as fh:
            return self._json("POST", "/upload", files={"file": (os.path.basename(path), fh)},
                              data=self._flags(use_openai=use_ai))

    def generate_from_extraction(self, extraction: Dict, *, ttps: Optional[List] = None,
                                 iocs: Optional[Dict] = None, from_file: bool = False) -> str:
        """Start a run from an analyse_url/analyse_file result; ttps=[] runs IOC sweeps only."""
        data = {
            "synthetic_group_name": extraction["synthetic_group_name"],
            "selected_ttps": json.dumps(extraction.get("ttps", []) if ttps is None else ttps),
            "selected_iocs": json.dumps(extraction.get("iocs", {}) if iocs is None else iocs),
        }
        result = self._json("POST", "/upload/generate" if from_file else "/blog/generate", data=data)
        return self._run_name(result)

    def profile_company(self, domain: str, *, industry: bool = True, geography: bool = True,
                        tech_stack: bool = True, supply_chain: bool = True, use_ai: bool = False) -> Dict:
        return self._json("POST", "/profile", data={"domain": domain, **self._flags(
            include_industry=industry, include_geography=geography, include_tech_stack=tech_stack,
            include_supply_chain=supply_chain, use_openai=use_ai, generate_detections=True)})

    def hunt_company(self, domain: str, groups: List[str], *, correlate: bool = True) -> List[str]:
        data = self._json("POST", "/profile/generate-detections", data={
            "domain": domain, "selected_groups": ",".join(groups), **self._flags(run_correlation=correlate)})
        return data.get("groups") or [self._run_name(data)]

    # ------------------------------------------------------------------
    # Research
    # ------------------------------------------------------------------

    def actors_by_keyword(self, keywords: List[str], *, mode: str = "AND", scope: str = "attributed") -> List[str]:
        data = self._json("GET", "/api/actors/by-keyword",
                          params={"keywords": ",".join(keywords), "mode": mode, "scope": scope})
        return data.get("actors", [])

    def actor_techniques(self, actors: List[str]) -> Dict:
        return self._json("POST", "/api/actors/techniques", json={"actors": actors})

    def export_research(self, actors: List[str], path: str, kind: str = "techniques") -> str:
        r = self._request("POST", "/api/research/export-xlsx", json={"type": kind, "actors": actors})
        if r.status_code >= 400:
            raise ArcherError(f"Export failed: HTTP {r.status_code}")
        with open(path, "wb") as fh:
            fh.write(r.content)
        return path

    # ------------------------------------------------------------------
    # Ask Archer and briefings
    # ------------------------------------------------------------------

    def ask(self, question: str, context: Optional[Dict] = None) -> Dict:
        return self._json("POST", "/api/ask", json={"question": question, "context": context})

    def threat_briefing(self, group: str, top_n: int = 5) -> Dict:
        return self._json("POST", "/api/threat-briefing", json={"group": group, "top_n": top_n})

    # ------------------------------------------------------------------
    # Runs and results
    # ------------------------------------------------------------------

    def progress(self, run: str) -> Dict:
        return self._json("GET", "/progress_status", params={"group_name": run}).get("progress") or {}

    def wait(self, run: str, *, timeout: int = 7200, poll: float = 5,
             on_update: Optional[Callable[[Dict], None]] = None) -> Dict:
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            progress = self.progress(run)
            status = progress.get("status") or progress.get("phase")
            if on_update and (status, progress.get("phase"), progress.get("created_yaml")) != last:
                on_update(progress)
                last = (status, progress.get("phase"), progress.get("created_yaml"))
            if status in TERMINAL_STATUSES:
                return progress
            time.sleep(poll)
        raise ArcherError(f"{run} still running after {timeout}s")

    def results(self, run: str, latest: bool = True) -> Dict:
        return self._json("GET", f"/api/results/{requests.utils.quote(run, safe='')}",
                          params={"run": "latest" if latest else ""})

    def download_all(self, run: str, path: str) -> str:
        r = self._request("GET", f"/api/download/all/{requests.utils.quote(run, safe='')}")
        if r.status_code >= 400:
            raise ArcherError(f"Download failed: HTTP {r.status_code}")
        with open(path, "wb") as fh:
            fh.write(r.content)
        return path

    def results_url(self, run: str) -> str:
        return f"{self.url}/results?group_name={requests.utils.quote(run)}&run=latest"

    # ------------------------------------------------------------------
    # Coverage, techniques, detections
    # ------------------------------------------------------------------

    def group_coverage(self, group: str) -> Dict:
        return self._json("GET", "/api/coverage", params={"group": group})

    def technique_coverage(self, technique_ids: List[str]) -> Dict:
        return self._json("GET", "/api/coverage", params={"techniques": ",".join(technique_ids)})

    def technique(self, technique_id: str) -> Dict:
        return self._json("GET", f"/api/techniques/{requests.utils.quote(technique_id)}")

    def detection_text(self, filename: str) -> str:
        r = self._request("GET", f"/api/detection/{requests.utils.quote(filename)}")
        if r.status_code >= 400:
            raise ArcherError(f"{filename}: HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return r.text
        if isinstance(data, list) and data and isinstance(data[0], dict) and data[0].get("error"):
            raise ArcherError(f"{filename}: {data[0]['error']}")
        return data if isinstance(data, str) else json.dumps(data)

    def save_query(self, filename: str, query: str, index: int = 0, reason: str = "") -> Dict:
        """Replace a query in a detection file; refused (422) while it still has errors."""
        r = self._request("POST", f"/api/detections/{requests.utils.quote(filename)}/query",
                          json={"index": index, "query": query, "reason": reason})
        data = r.json()
        if r.status_code >= 400:
            raise ArcherError(json.dumps(data))
        return data

    # ------------------------------------------------------------------
    # Agents (run on the server; see archer/agents)
    # ------------------------------------------------------------------

    def agents(self) -> List[Dict]:
        return self._json("GET", "/api/agents").get("agents", [])

    def start_agent(self, name: str, inputs: Dict, auto_approve: bool = False,
                    provider: Optional[str] = None, model: Optional[str] = None) -> str:
        """provider/model: any configured provider (anthropic, openai, local, ...); default as the web page."""
        return self._json("POST", f"/api/agents/{name}/start", json={
            "input": inputs, "auto_approve": auto_approve, "provider": provider or "", "model": model or "",
        })["session_id"]

    def agent_sessions(self, limit: int = 20) -> List[Dict]:
        """Recent agent sessions, newest first (kept across server restarts)."""
        return self._json("GET", "/api/agents/sessions", params={"limit": limit}).get("sessions", [])

    def agent_session(self, session_id: str, since: int = 0) -> Dict:
        return self._json("GET", f"/api/agents/sessions/{session_id}", params={"since": since})

    def agent_decision(self, session_id: str, approve: bool) -> Dict:
        return self._json("POST", f"/api/agents/sessions/{session_id}/decision", json={"approve": approve})

    def stop_agent(self, session_id: str) -> Dict:
        return self._json("POST", f"/api/agents/sessions/{session_id}/stop")

    def resume_agent(self, session_id: str, auto_approve: bool = False) -> str:
        """Continue an interrupted, stopped or turn-limited session on the provider it ran on."""
        return self._json("POST", f"/api/agents/sessions/{session_id}/resume",
                          json={"auto_approve": auto_approve})["session_id"]

    # ------------------------------------------------------------------
    # Library
    # ------------------------------------------------------------------

    def search_library(self, query: str = "", type_filter: str = "all") -> List[Dict]:
        return self._json("POST", "/api/library/search",
                          json={"query": query, "type_filter": type_filter}).get("detections", [])

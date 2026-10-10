"""
Headed Playwright walkthrough of the Archer UI, one captioned step per feature.

Run:  .venv/bin/python tests/ui/walkthrough.py [step ...] [--headless]
Steps: login group cve research upload upload-error profile ask library coverage manual how user
Env:  ARCHER_BASE_URL, ARCHER_EMAIL, ARCHER_PASSWORD, ARCHER_GEN_TIMEOUT (seconds)
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path

from playwright.sync_api import sync_playwright, Error as PWError, TimeoutError as PWTimeout

BASE = os.getenv("ARCHER_BASE_URL", "http://localhost:8000").rstrip("/")
# Defaults are the documented first-run admin from GETTING_STARTED.md
EMAIL = os.getenv("ARCHER_EMAIL", "admin@archer.app")
PASSWORD = os.getenv("ARCHER_PASSWORD", "£missary_0f_the_G0rg0nite$")
SHOTS = Path(__file__).parent.parent / "screenshots" / "walkthrough" / datetime.now().strftime("%Y%m%d-%H%M%S")
SHOTS.mkdir(parents=True, exist_ok=True)
GEN_TIMEOUT = int(os.getenv("ARCHER_GEN_TIMEOUT", 15 * 60))

results = []
step_no = 0

CAPTION_JS = """
(t) => {
  let el = document.getElementById('__walk_caption');
  if (!el) {
    el = document.createElement('div');
    el.id = '__walk_caption';
    el.style.cssText = 'position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:2147483647;'
      + 'background:#0b1f3a;color:#5eead4;font:600 16px "JetBrains Mono",monospace;padding:12px 20px;'
      + 'border:2px solid #14b8a6;border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,.45);max-width:80vw;pointer-events:none;';
    document.body.appendChild(el);
  }
  el.textContent = t;
}
"""


def caption(page, text):
    try:
        page.evaluate(CAPTION_JS, text)
    except Exception:
        pass
    print(f"    · {text}", flush=True)


def shot(page, name):
    global step_no
    path = SHOTS / f"{step_no:02d}_{name}.png"
    page.screenshot(path=str(path), full_page=False)
    return path


def step(name):
    def wrap(fn):
        def run(page):
            global step_no
            step_no += 1
            print(f"\n[{step_no:02d}] {name}", flush=True)
            t0 = time.time()
            try:
                note = fn(page) or ""
                results.append((step_no, name, "PASS", note, time.time() - t0))
                print(f"    PASS {note}", flush=True)
            except Exception as e:
                msg = str(e).splitlines()[0][:200]
                results.append((step_no, name, "FAIL", msg, time.time() - t0))
                print(f"    FAIL {msg}", flush=True)
                try:
                    caption(page, f"✗ {name}: {msg[:80]}")
                    shot(page, "FAIL")
                except Exception:
                    pass
            page.wait_for_timeout(1500)
        return run
    return wrap


def open_tab(page, tab):
    try:
        page.goto(f"{BASE}/")
    except PWError as e:
        # The previous results page can still be navigating (attack-flow build), aborting this one
        if "ERR_ABORTED" not in str(e):
            raise
        page.wait_for_timeout(1000)
        page.goto(f"{BASE}/")
    page.click(f'button.tab-button[data-tab="{tab}"]')
    page.wait_for_timeout(600)


def answer_ai_prompt(page):
    """The 'Use AI for this hunt?' modal appears on submit; decline for a deterministic run."""
    try:
        page.locator("#ai-prompt-no-btn").click(timeout=4000)
        caption(page, "Declined AI for this run (heuristic generation)")
    except PWTimeout:
        pass


def _progress_status(page):
    """Read the server's progress record for the run the progress page is showing."""
    from urllib.parse import parse_qs, urlparse

    group = parse_qs(urlparse(page.url).query).get("group_name", [None])[0]
    if not group or "/progress" not in page.url:
        return None
    resp = page.request.get(f"{BASE}/progress_status", params={"group_name": group})
    return (resp.json() or {}).get("progress") if resp.ok else None


def wait_for_results(page, label):
    deadline = time.time() + GEN_TIMEOUT
    last = ""
    while time.time() < deadline:
        url = page.url
        if "/results" in url:
            page.wait_for_load_state("domcontentloaded")
            return url
        if url != last:
            last = url
            caption(page, f"{label} — generating… ({url.replace(BASE, '')})")
        status = _progress_status(page)
        if status and status.get("status") == "failed":
            caption(page, f"{label} — run failed; checking the page reports it")
            try:
                page.wait_for_function(
                    "() => (document.getElementById('progress-state') || {}).textContent === 'Failed'",
                    timeout=15000,
                )
                shown = "page shows failure"
            except PWTimeout:
                shown = "PAGE DID NOT SHOW FAILURE"
            shot(page, "progress_failed")
            raise RuntimeError(f"run failed at stage {status.get('stage')} ({shown}): {status.get('error', 'no error recorded')}")
        page.wait_for_timeout(3000)
    raise TimeoutError(f"no /results after {GEN_TIMEOUT}s (stuck on {page.url})")


def tour_results(page, label):
    caption(page, f"{label} — results page")
    shot(page, "results_top")
    for _ in range(4):
        page.mouse.wheel(0, 700)
        page.wait_for_timeout(900)
    shot(page, "results_scrolled")
    page.mouse.wheel(0, -5000)
    queries = page.locator("pre, code").count()
    return f"{queries} query blocks rendered"


@step("Login with default admin")
def login(page):
    page.goto(f"{BASE}/login")
    caption(page, "Logging in as admin@archer.app")
    page.fill("#email", EMAIL)
    page.fill("#password", PASSWORD)
    shot(page, "login")
    page.click('form[action="/login"] button[type="submit"]')
    page.wait_for_url(lambda u: "/login" not in u, timeout=15000)
    shot(page, "home")
    return page.url


@step("Hunt — Threat Group (Scattered Spider) + Threat Briefing")
def hunt_group(page):
    open_tab(page, "generate")
    caption(page, "Hunt tab: generate detections for a threat group")
    page.fill("#group_name_input", "Scattered Spider")
    page.locator("details.options-section summary").first.click()
    caption(page, "Additional options: enabling Threat Briefing")
    page.check("#briefing_checkbox")
    shot(page, "hunt_group_form")
    page.wait_for_function("!document.getElementById('generate_btn').disabled", timeout=10000)
    page.click("#generate_btn")
    answer_ai_prompt(page)
    wait_for_results(page, "Scattered Spider")
    return tour_results(page, "Scattered Spider")


@step("Hunt — CVE (CVE-2024-3400, PAN-OS GlobalProtect)")
def hunt_cve(page):
    open_tab(page, "generate")
    caption(page, "Hunt tab: generate detections from a CVE with NVD enrichment")
    page.fill("#cve_input", "CVE-2024-3400")
    shot(page, "hunt_cve_form")
    page.wait_for_function("!document.getElementById('generate_btn').disabled", timeout=10000)
    page.click("#generate_btn")
    answer_ai_prompt(page)
    wait_for_results(page, "CVE-2024-3400")
    return tour_results(page, "CVE-2024-3400")


@step("Research — keyword + actor consolidation")
def research(page):
    open_tab(page, "research")
    caption(page, "Research tab: groups attributed to Iran")
    with page.expect_response(lambda r: "/api/actors/by-keyword" in r.url) as attributed:
        page.fill("#keyword-text-input", "Iran")
        page.press("#keyword-text-input", "Enter")
    attributed = set(attributed.value.json().get("actors", []))
    page.wait_for_timeout(1200)
    shot(page, "research_attributed")
    if "Strider" in attributed or "VOID MANTICORE" not in attributed:
        raise RuntimeError(f"attributed scope wrong: Strider in={'Strider' in attributed}, VOID MANTICORE in={'VOID MANTICORE' in attributed}")

    caption(page, "Switching to groups that have targeted Iran")
    with page.expect_response(lambda r: "scope=targeted" in r.url) as targeted:
        page.click("#kw-scope-btn")
    targeted = set(targeted.value.json().get("actors", []))
    page.wait_for_timeout(1200)
    shot(page, "research_targeted")
    if "Strider" not in targeted:
        raise RuntimeError("targeted scope missing Strider")

    caption(page, "Back to attributed")
    with page.expect_response(lambda r: "scope=attributed" in r.url):
        page.click("#kw-scope-btn")
    page.wait_for_timeout(1200)
    caption(page, "Adding actor APT33")
    page.fill("#actor-text-input", "APT33")
    page.press("#actor-text-input", "Enter")
    page.wait_for_timeout(1500)
    shot(page, "research_filters")
    page.wait_for_function("!document.getElementById('actor-consolidate-btn').disabled", timeout=15000)
    caption(page, "Consolidating techniques across selected actors")
    page.click("#actor-consolidate-btn")
    page.wait_for_selector("#actor-export-xlsx", state="visible", timeout=120000)
    page.wait_for_timeout(1500)
    shot(page, "research_table")
    caption(page, "Switching to flat view")
    try:
        page.click("#actor-view-flat", timeout=3000)
        page.wait_for_timeout(1200)
    except PWTimeout:
        pass
    shot(page, "research_flat")
    rows = page.locator("table tbody tr").count()
    return f"Iran attributed={len(attributed)} targeted={len(targeted)}; {rows} table rows"


@step("Upload — threat intel blog URL (CISA AA23-320A, Scattered Spider)")
def upload_blog(page):
    open_tab(page, "upload")
    caption(page, "Upload tab: extract TTPs/IOCs from a threat intel blog")
    page.fill("#blog_url_input", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a")
    shot(page, "upload_form")
    page.wait_for_function("!document.getElementById('upload_btn').disabled", timeout=10000)
    with page.expect_response(lambda r: "/analyze_blog" in r.url, timeout=120000) as resp_info:
        page.click("#upload_btn")
        answer_ai_prompt(page)
    resp = resp_info.value
    if not resp.ok:
        raise RuntimeError(f"/analyze_blog returned {resp.status}: {resp.json().get('message', '')[:150]}")
    page.wait_for_selector("#ttps-container", timeout=30000)
    caption(page, "Review extracted TTPs and IOCs")
    page.locator("#ttps-container").scroll_into_view_if_needed()
    shot(page, "upload_extraction")
    body = resp.json()
    extracted = f"{body.get('ttps_count', 0)} TTPs, {body.get('iocs_count', 0)} IOCs extracted"
    caption(page, f"{extracted} — proceeding to generation")
    page.click("#proceed-generation", timeout=5000)
    wait_for_results(page, "CISA AA23-320A")
    return f"{extracted}; {tour_results(page, 'CISA AA23-320A')}"


@step("Upload — rejected URL shows an inline error")
def upload_error(page):
    open_tab(page, "upload")
    caption(page, "Upload tab: a private-IP URL should be refused with a visible error")
    page.fill("#blog_url_input", "http://192.168.1.10/report.html")
    page.wait_for_function("!document.getElementById('upload_btn').disabled", timeout=10000)
    page.click("#upload_btn")
    answer_ai_prompt(page)
    err = page.locator("#upload-error")
    err.wait_for(state="visible", timeout=30000)
    err.scroll_into_view_if_needed()
    shot(page, "upload_error")
    text = err.inner_text().strip()
    if not text:
        raise RuntimeError("error element shown but empty")
    return text[:120]


@step("Profile — company OSINT (tesco.com)")
def profile(page):
    open_tab(page, "profile")
    caption(page, "Profile tab: industry-aware threat landscape from a company domain")
    page.fill("#domain_input", "tesco.com")
    shot(page, "profile_form")
    page.wait_for_function("!document.getElementById('profile_btn').disabled", timeout=10000)
    page.click("#profile_btn")
    answer_ai_prompt(page)
    caption(page, "Profiling tesco.com (Wikidata, homepage, OSINT)…")
    modal = page.locator("#threat-group-selection-overlay")
    modal.wait_for(state="visible", timeout=300000)
    summary = modal.inner_text()
    caption(page, "Profile summary: company, sector, location and recommended groups")
    shot(page, "profile_summary")
    expected = {"Tesco": "Tesco", "United Kingdom": "United Kingdom", "retail": "retail", "Scattered Spider": "Scattered Spider"}
    missing = [label for label, text in expected.items() if text not in summary]
    if missing:
        raise RuntimeError(f"profile summary missing: {', '.join(missing)}")
    page.click("#confirm-generation")
    wait_for_results(page, "tesco.com")
    return tour_results(page, "tesco.com")


@step("Ask Archer — conversational Q&A")
def ask_archer(page):
    page.goto(f"{BASE}/")
    caption(page, "Opening Ask Archer")
    page.click("#ask-archer-btn")
    page.fill("#aap-input", "Give me a Splunk query for T1003.001 LSASS memory dumping")
    shot(page, "ask_question")
    with page.expect_response(lambda r: "/api/ask" in r.url, timeout=180000) as resp_info:
        page.click("#aap-send")
        caption(page, "Waiting for Ask Archer to answer…")
    resp = resp_info.value
    page.wait_for_timeout(2000)
    shot(page, "ask_answer")
    if not resp.ok:
        raise RuntimeError(f"/api/ask returned {resp.status}: {str(resp.json().get('detail', ''))[:150]}")


@step("Library — saved detections")
def library(page):
    page.goto(f"{BASE}/library")
    caption(page, "Detection Library: search, tag, share, export")
    page.wait_for_timeout(1500)
    shot(page, "library")


@step("Coverage — detection coverage view")
def coverage(page):
    page.goto(f"{BASE}/coverage")
    caption(page, "Coverage: ATT&CK coverage across generated detections")
    page.locator("text=Loading coverage data").wait_for(state="hidden", timeout=30000)
    page.wait_for_timeout(1000)
    shot(page, "coverage")
    page.mouse.wheel(0, 900)
    page.wait_for_timeout(1000)


@step("Manual — hand-written detection entry")
def manual(page):
    page.goto(f"{BASE}/manual")
    caption(page, "Manual: author a detection YAML by hand")
    page.wait_for_timeout(1500)
    shot(page, "manual")


@step("How it works")
def how(page):
    page.goto(f"{BASE}/how-it-works")
    caption(page, "How it works")
    page.wait_for_timeout(1500)
    shot(page, "how_it_works")


@step("User profile / settings")
def user_profile(page):
    page.goto(f"{BASE}/profile")
    caption(page, "User profile: password, MFA, API keys")
    page.wait_for_timeout(1500)
    shot(page, "user_profile")


STEPS = {
    "login": login, "group": hunt_group, "cve": hunt_cve, "research": research,
    "upload": upload_blog, "upload-error": upload_error, "profile": profile, "ask": ask_archer, "library": library,
    "coverage": coverage, "manual": manual, "how": how, "user": user_profile,
}

if __name__ == "__main__":
    args = sys.argv[1:]
    headless = "--headless" in args
    wanted = [a for a in args if not a.startswith("--")] or list(STEPS)
    unknown = [w for w in wanted if w not in STEPS]
    if unknown:
        sys.exit(f"unknown step(s): {', '.join(unknown)}; choose from {', '.join(STEPS)}")
    if "login" not in wanted:
        wanted.insert(0, "login")
    print(f"Screenshots: {SHOTS}", flush=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, slow_mo=0 if headless else 250)
        ctx = browser.new_context(no_viewport=True)  # page tracks the real window size
        page = ctx.new_page()
        page.on("dialog", lambda d: d.dismiss())
        for key in wanted:
            STEPS[key](page)
        caption(page, "Walkthrough complete")
        page.wait_for_timeout(4000)
        browser.close()

    print("\n=== SUMMARY ===")
    for n, name, status, note, secs in results:
        print(f"{n:02d} {status:4} {secs:6.1f}s  {name}  {note}")
    sys.exit(1 if any(r[2] == "FAIL" for r in results) else 0)

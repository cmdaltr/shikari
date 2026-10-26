"""
Headed Playwright walkthrough of the Archer UI, one captioned step per feature.

Run:  .venv/bin/python tests/ui/walkthrough.py [step ...] [--headless]
Steps: login group cve research upload upload-iocs upload-error profile ask library coverage manual how user
Env:  ARCHER_BASE_URL, ARCHER_EMAIL, ARCHER_PASSWORD, ARCHER_GEN_TIMEOUT (seconds)
"""

import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

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
    page.goto(f"{BASE}/")
    page.click(f'button.tab-button[data-tab="{tab}"]')
    page.wait_for_timeout(600)


def decline_ai_if_asked(page, timeout=5000):
    """Upload asks the same AI question as Hunt (when the profile has a provider): decline it."""
    try:
        page.locator("#ai-prompt-modal").wait_for(state="visible", timeout=timeout)
    except PWTimeout:
        return
    page.locator("#ai-prompt-no-btn").click()
    caption(page, "Declined AI for this report (pattern extraction)")


def answer_ai_prompt(page):
    """The 'Use AI for this hunt?' modal appears on submit; decline for a deterministic run."""
    # Asked only when the profile has a provider that can generate detections (GitHub
    # #10): otherwise the hunt goes straight to progress
    page.wait_for_function(
        "() => location.pathname === '/progress' ||"
        " getComputedStyle(document.getElementById('ai-prompt-modal')).display !== 'none'",
        timeout=30000)
    if "/progress" not in page.url:
        page.locator("#ai-prompt-no-btn").click()
        caption(page, "Declined AI for this run (heuristic generation)")
    else:
        caption(page, "No AI provider in the profile: the hunt runs without asking")


def _progress_status(page):
    """Read the server's progress record for the run the progress page is showing."""
    from urllib.parse import parse_qs, urlparse

    group = parse_qs(urlparse(page.url).query).get("group_name", [None])[0]
    if not group or "/progress" not in page.url:
        return None
    resp = page.request.get(f"{BASE}/progress_status", params={"group_name": group})
    return (resp.json() or {}).get("progress") if resp.ok else None


_BAR_VALUES = """() => ['yaml-progress', 'genai-progress'].map(id => {
    const fill = document.getElementById(id);
    const track = fill && fill.closest('[role=progressbar]');
    return track ? Number(track.getAttribute('aria-valuenow')) : null;
})"""


def check_progress_bars(page, seen):
    """Correlations must not move before detections finish, and neither bar may go back.

    A Profile run moves through several groups; the bars start again for each one.
    """
    from urllib.parse import parse_qs, urlparse

    if "/progress" not in page.url:
        return
    try:
        det, corr = page.evaluate(_BAR_VALUES)
    except Exception:
        return  # navigating to results
    if det is None or corr is None:
        return
    group = parse_qs(urlparse(page.url).query).get("group_name", [""])[0]
    if corr > 0 and det < 100:
        raise RuntimeError(f"{group}: correlation bar at {corr}% while detections at {det}%")
    if seen and seen[-1][2] == group and (det < seen[-1][0] or corr < seen[-1][1]):
        raise RuntimeError(f"{group}: progress bar went backwards: {seen[-1][:2]} -> {(det, corr)}")
    seen.append((det, corr, group))


def wait_for_results(page, label):
    deadline = time.time() + GEN_TIMEOUT
    last = ""
    seen = []
    while time.time() < deadline:
        url = page.url
        if "/results" in url:
            page.wait_for_load_state("domcontentloaded")
            if seen:
                groups = list(dict.fromkeys(g for _, _, g in seen))
                across = f" across {len(groups)} groups ({', '.join(groups)})" if len(groups) > 1 else ""
                caption(page, f"{label} — progress bars: {len(seen)} samples{across}, in order, never backwards")
            return url
        check_progress_bars(page, seen)
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
        if (status and status.get("status") in ("complete", "genai_complete")
                and not status.get("created_yaml") and not status.get("ioc_sweeps")):
            try:
                page.wait_for_function(
                    "() => (document.getElementById('progress-state') || {}).textContent === 'Nothing generated'",
                    timeout=15000,
                )
                shown = "page says nothing was generated"
            except PWTimeout:
                shown = "PAGE STILL WAITING"
            shot(page, "progress_empty")
            raise RuntimeError(f"run completed with no detections ({shown})")
        page.wait_for_timeout(1000)
    raise TimeoutError(f"no /results after {GEN_TIMEOUT}s (stuck on {page.url})")


def expand_results(page):
    """Results sections start collapsed (templates/results.html has data-cards-collapsed), so the
    attack-flow / IOC-flow canvases and their nodes are hidden. Open every collapsed top-level card
    by clicking its title toggle, so the nodes are visible to click. Idempotent — already-open cards
    have aria-expanded="true" and are left alone."""
    page.evaluate(
        "() => document.querySelectorAll('.card-title-toggle[aria-expanded=\"false\"]')"
        ".forEach(t => t.click())")
    page.wait_for_timeout(300)


def tour_results(page, label):
    caption(page, f"{label} — results page")
    expand_results(page)
    shot(page, "results_top")
    for _ in range(4):
        page.mouse.wheel(0, 700)
        page.wait_for_timeout(900)
    shot(page, "results_scrolled")
    page.mouse.wheel(0, -5000)
    queries = page.locator("pre, code").count()
    flow = tour_attack_flow(page)
    iocs = tour_ioc_flow(page)
    return f"{queries} query blocks rendered; {flow}" + (f"; {iocs}" if iocs else "")


def tour_ioc_flow(page, required=False):
    """IOC flow: staged indicators, and a selected one shows the report's words for it."""
    if not page.locator("#ioc-flow").count():
        if required:
            raise AssertionError("no IOC flow on a run with IOC sweeps")
        return ""
    expand_results(page)
    page.locator("#ioc-flow").scroll_into_view_if_needed()
    stages = page.locator(".if-stage").count()
    nodes = page.locator(".if-node").count()
    links = page.locator("#if-edges path").count()
    if not stages or not nodes:
        raise AssertionError("IOC flow rendered no indicators")
    caption(page, f"IOC Flow: {nodes} indicators in {stages} stages, {links} links")
    shot(page, "ioc_flow")
    pick = page.locator("#if-edges path").first.get_attribute("data-from") if links else None
    node = page.locator(f'.if-node[data-id="{pick}"]') if pick else page.locator(".if-node:not(.is-inferred)").first
    if node.count():
        node.click()
        page.wait_for_selector("#if-detail:not([hidden])", timeout=5000)
        if "what the report says" not in page.inner_text("#if-detail").lower():
            raise AssertionError("selected IOC shows no evidence from the report")
        caption(page, "Selected indicator: the report's own words, and what it leads to")
        shot(page, "ioc_flow_selected")
        page.click("#if-detail-close")
    return f"IOC flow {nodes} IOCs / {stages} stages / {links} links"


def tour_flow_hiding(page):
    """Select several techniques, then Hide Others / Hide Selected / Show All."""
    visible = lambda: page.locator(".af-node:not([hidden])").count()
    total = visible()
    if total < 3:
        return
    ids = page.locator(".af-node:not([hidden])").evaluate_all("els => els.slice(0, 2).map(e => e.dataset.id)")
    page.click("#af-pick-mode")
    for tid in ids:
        page.locator(f'.af-node[data-id="{tid}"]').click()
    if page.locator(".af-node.is-picked").count() != 2 or page.locator("#af-detail:not([hidden])").count():
        raise AssertionError("Select mode should pick cards without opening the detail panel")
    page.click("#af-hide-others")
    if visible() != 2:
        raise AssertionError(f"Hide Others left {visible()} techniques, expected 2")
    caption(page, f"Hide Others: only {', '.join(ids)} remain")
    shot(page, "attack_flow_hide_others")
    page.click("#af-show-all")
    page.click("#af-pick-mode")
    page.locator(f'.af-node[data-id="{ids[0]}"]').click(modifiers=["ControlOrMeta"])
    page.click("#af-hide-picked")
    if visible() != total - 1:
        raise AssertionError(f"Hide Selected left {visible()} of {total}, expected {total - 1}")
    page.click("#af-show-all")
    if visible() != total or not page.locator("#af-show-all").is_hidden():
        raise AssertionError("Show All did not restore every technique")
    tour_flow_layout(page, total)


def tour_flow_layout(page, total):
    """Hide Undetected, drag, unlink, orientation, order, Undo and Reset."""
    visible = lambda: page.locator(".af-node:not([hidden])").count()
    # Hide Undetected hides every undetected technique — gaps plus intel-only and via-parent ones
    # (attack_flow.js: el.hidden = !detected). .is-gap is only the subset that is neither intel nor
    # via-parent, so assert by what stays visible, not by an exact gap count.
    undetected = page.locator(".af-node.is-gap, .af-node.is-intel").count()
    page.click("#af-toggle-gaps")
    if undetected:
        if page.locator(".af-node:not([hidden]).is-gap, .af-node:not([hidden]).is-intel").count():
            raise AssertionError("Hide Undetected left an undetected technique visible")
        if visible() >= total:
            raise AssertionError("Hide Undetected hid nothing")
    page.click("#af-undo")
    if visible() != total:
        raise AssertionError("Undo did not bring the undetected techniques back")

    card = page.locator(".af-node:not([hidden])").first
    box = card.bounding_box()
    # A plain drag snaps the card within its tactic lane; free pixel placement is an Option/Alt-drag
    # (attack_flow.js sets the drag's free flag from e.altKey). Hold Alt so it moves by the delta.
    page.keyboard.down("Alt")
    page.mouse.move(box["x"] + 20, box["y"] + 10)
    page.mouse.down()
    page.mouse.move(box["x"] + 80, box["y"] + 70, steps=6)
    page.mouse.up()
    page.keyboard.up("Alt")
    moved = card.bounding_box()
    # Page zoom scales the 60px drag, so only check it moved and didn't select
    if moved["x"] - box["x"] < 40 or page.locator("#af-detail:not([hidden])").count():
        raise AssertionError("dragging a card should move it without selecting it")

    links = lambda: page.locator("path.af-edge").count()
    if links():
        before = links()
        page.locator("path.af-edge-hit").first.dispatch_event("click")
        if links() != before - 1:
            raise AssertionError("clicking a link should remove it")
        caption(page, "Card dragged, one link removed")
        shot(page, "attack_flow_edited")

    page.click("#af-orient")
    if "af-vertical" not in (page.get_attribute("#attack-flow", "class") or ""):
        raise AssertionError("orientation toggle did not switch to vertical")
    page.click("#af-order")
    heads = page.locator(".af-lane:not([hidden]) .af-lane-head").evaluate_all(
        "els => els.map(e => [e.getBoundingClientRect().top, e.firstChild.textContent.trim()])")
    if len(heads) > 1 and not heads[0][0] > heads[-1][0]:
        raise AssertionError("reverse order should put the first tactic last")
    caption(page, "Vertical, reverse kill-chain order")
    shot(page, "attack_flow_vertical_reverse")
    page.click("#af-undo")
    page.click("#af-undo")
    if "af-vertical" in (page.get_attribute("#attack-flow", "class") or ""):
        raise AssertionError("Undo did not restore the horizontal layout")
    if card.bounding_box()["x"] - box["x"] < 40:
        raise AssertionError("Undo past a layout change should restore dragged positions")
    page.click("#af-reset")
    if abs(card.bounding_box()["x"] - box["x"]) > 3 or visible() != total:
        raise AssertionError("Reset did not restore the default view")
    if not page.locator("#af-undo").is_enabled():
        raise AssertionError("Reset should be undoable")


def tour_attack_flow(page):
    """ATT&CK Flow: lanes render, a linked technique traces its correlations, SecOps correlations lead."""
    flow = page.locator("#attack-flow")
    expand_results(page)
    flow.scroll_into_view_if_needed()
    nodes, links = page.locator(".af-node").count(), page.locator("path.af-edge").count()
    if not nodes:
        raise AssertionError("attack flow rendered no techniques")
    caption(page, f"ATT&CK Flow: {nodes} techniques, {links} correlation links")
    shot(page, "attack_flow")
    if links:
        start = page.locator("path.af-edge").first.get_attribute("data-from")
        page.locator(f'.af-node[data-id="{start}"]').click()
        page.wait_for_selector("#af-detail:not([hidden])", timeout=5000)
        caption(page, f"Tracing {start}: its correlations stay lit, the detail panel lists them")
        shot(page, "attack_flow_selected")
        page.locator("#af-detail-close").click()
    tour_flow_hiding(page)
    # Correlation vendors are listed SecOps first when SecOps has any
    order = [t.strip() for t in page.locator("#correlations-section-content .vendor-title > span:not([class])").all_inner_texts()]
    if "Google SecOps" in order and order[0] != "Google SecOps":
        raise AssertionError(f"correlation vendors out of order: {order}")
    secops = order.count("Google SecOps") and "SecOps correlations first" or "no SecOps correlations"
    return f"flow {nodes} techniques / {links} links; {secops}"


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
    shot(page, "hunt_group_form")
    page.wait_for_function("!document.getElementById('generate_btn').disabled", timeout=10000)
    page.click("#generate_btn")
    answer_ai_prompt(page)
    wait_for_results(page, "Scattered Spider")
    # Every results page opens with a threat briefing, worked out without AI
    briefing = page.locator("#briefing")
    briefing.wait_for(state="visible", timeout=15000)
    caption(page, "Threat briefing: coverage, the weakest stage and the gaps to close first")
    briefing.scroll_into_view_if_needed()
    shot(page, "results_briefing")
    gaps = briefing.locator(".briefing-gaps li").count()
    return tour_results(page, "Scattered Spider") + f"; briefing lists {gaps} gaps"


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
    # A firewall CVE: the exploit runs where no EDR does, so the detections are the
    # exploitation indicators from the CVE's write-ups (Volexity, Unit 42), one sweep per SIEM
    body = page.content()  # collapsed query blocks are not in inner_text
    # SecOps sweeps are UDM Search: the rule name is a // comment, not a YARA-L `rule {}`
    for siem, marker in (("SecOps", "archer_ioc_sweep_cve_2024_3400"), ("MDE", "RemoteIP in (ioc_ip)")):
        if marker not in body:
            raise AssertionError(f"no {siem} IOC sweep for CVE-2024-3400")
    if body.count("172.233.228.93") < 2:
        raise AssertionError("IOC sweep is missing Unit 42's exploitation IP 172.233.228.93")
    if page.locator(".af-node").count():
        return tour_results(page, "CVE-2024-3400")
    caption(page, "CVE-2024-3400 — results: SecOps and MDE IOC sweeps from the CVE's references")
    shot(page, "results_top")
    return f"IOC sweeps for SecOps and MDE; {tour_ioc_flow(page, required=True)}"


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


def _extract_blog(page):
    """Analyse the CISA advisory and wait for the review modal's technique list."""
    open_tab(page, "upload")
    caption(page, "Upload tab: extract TTPs/IOCs from a threat intel blog")
    page.fill("#blog_url_input", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a")
    shot(page, "upload_form")
    page.wait_for_function("!document.getElementById('upload_btn').disabled", timeout=10000)
    with page.expect_response(lambda r: "/analyze_blog" in r.url, timeout=120000) as resp_info:
        page.click("#upload_btn")
        decline_ai_if_asked(page)
    resp = resp_info.value
    if not resp.ok:
        raise RuntimeError(f"/analyze_blog returned {resp.status}: {resp.json().get('message', '')[:150]}")
    page.wait_for_selector("#ttps-container", timeout=30000)
    # Technique names load after the modal opens; Proceed stays disabled until they do
    page.wait_for_selector("#ttps-container .ttp-checkbox", timeout=30000)
    caption(page, "Review extracted TTPs and IOCs")
    page.locator("#ttps-container").scroll_into_view_if_needed()
    shot(page, "upload_extraction")
    body = resp.json()
    extracted = f"{body.get('ttps_count', 0)} TTPs, {body.get('iocs_count', 0)} IOCs extracted"
    return extracted


@step("Upload — threat intel blog URL (CISA AA23-320A, Scattered Spider)")
def upload_blog(page):
    extracted = _extract_blog(page)
    caption(page, f"{extracted} — proceeding to generation")
    page.click("#proceed-generation", timeout=5000)
    wait_for_results(page, "CISA AA23-320A")
    return f"{extracted}; {tour_results(page, 'CISA AA23-320A')}"


@step("Upload — IOCs only (every TTP deselected)")
def upload_iocs(page):
    extracted = _extract_blog(page)
    page.locator("#ttps-container .ttp-checkbox").evaluate_all("els => els.forEach(e => { e.checked = false; })")
    caption(page, f"{extracted} — every TTP deselected, IOCs kept")
    shot(page, "upload_iocs_only")
    page.click("#proceed-generation", timeout=5000)
    page.wait_for_url("**/progress**", timeout=30000)
    page.wait_for_function(
        "() => /IOC sweeps/.test((document.getElementById('last-yaml-file') || {}).textContent || '')"
        " || location.pathname === '/results'",
        timeout=120000,
    )
    state = page.evaluate("() => (document.getElementById('progress-state') || {}).textContent || ''")
    if state in ("Nothing generated", "Failed"):
        raise RuntimeError(f"IOC-only run ended as '{state}'")
    if "/progress" in page.url:
        shot(page, "upload_iocs_progress")
        caption(page, page.inner_text("#last-yaml-file"))
    page.wait_for_url("**/results**", timeout=60000)
    page.wait_for_load_state("domcontentloaded")
    shot(page, "upload_iocs_results")
    if "IOC Sweep" not in page.inner_text("body"):
        raise RuntimeError("results page has no IOC Sweep detection")
    tour_ioc_flow(page, required=True)
    # Earlier UNC3944 runs left technique detections: the page opens on this run only
    switch = page.locator(".run-view")
    if not switch.count():
        raise RuntimeError("no Latest run / All runs switch on the results page")
    latest = page.inner_text(".run-view-opt.is-active")
    if "Latest run" not in latest:
        raise RuntimeError(f"results opened on '{latest}', not the latest run")
    run_n = int(re.search(r"(\d+) files", latest).group(1))
    page.click(".run-view-opt:not(.is-active)")
    page.wait_for_load_state("domcontentloaded")
    all_n = int(re.search(r"(\d+) files", page.inner_text(".run-view-opt.is-active")).group(1))
    if all_n <= run_n:
        raise RuntimeError(f"All runs shows {all_n} files, latest run {run_n}")
    caption(page, f"Latest run: {run_n} files; all runs: {all_n} files")
    shot(page, "upload_iocs_all_runs")
    return f"IOC-only run completed; latest run {run_n} files (IOC Sweeps) of {all_n} for the group"


@step("Upload — rejected URL shows an inline error")
def upload_error(page):
    open_tab(page, "upload")
    caption(page, "Upload tab: a private-IP URL should be refused with a visible error")
    page.fill("#blog_url_input", "http://192.168.1.10/report.html")
    page.wait_for_function("!document.getElementById('upload_btn').disabled", timeout=10000)
    page.click("#upload_btn")
    decline_ai_if_asked(page)
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
    # Profiling runs in the background: a 7-stage progress page, then the Review page
    page.wait_for_url("**/profile-progress**", timeout=15000)
    caption(page, "Profiling tesco.com (Wikidata, homepage, OSINT)…")
    page.wait_for_url("**/review**", timeout=300000)
    page.wait_for_load_state("domcontentloaded")
    page.wait_for_selector(".rv-group", timeout=15000)
    caption(page, "Review: branding, summary, exposure map and the recommended groups")
    shot(page, "profile_review")
    body = page.inner_text("body")
    expected = ("Tesco", "United Kingdom", "retail", "Scattered Spider")
    missing = [label for label in expected if label not in body]
    if missing:
        raise RuntimeError(f"review page missing: {', '.join(missing)}")
    # Each group carries a likelihood, and only the top three start ticked
    if not page.locator(".rv-like-n").count():
        raise RuntimeError("no per-group likelihoods on the review page")
    ticked = page.locator(".rv-group-cb:checked").count()
    if ticked > 3:
        raise RuntimeError(f"{ticked} groups pre-ticked; only the top 3 should be")
    # Two groups: enough to follow the queue from one group to the next
    page.locator(".rv-group-cb").evaluate_all(
        "els => els.forEach((e, i) => { e.checked = i < 2; e.dispatchEvent(new Event('change', {bubbles: true})); })")
    caption(page, f"Two groups ticked; {page.inner_text('#rv-estimate')}")
    page.click("#rv-generate")
    wait_for_results(page, "tesco.com")
    return tour_results(page, "tesco.com")


@step("Ask Archer — conversational Q&A")
def ask_archer(page):
    page.goto(f"{BASE}/")
    caption(page, "Opening Ask Archer")
    if not page.locator("#ask-archer-panel.open").count():  # the panel remembers being open
        page.click("#ask-archer-btn")
    page.fill("#aap-input", "Give me a Splunk query for T1003.001 LSASS memory dumping")
    shot(page, "ask_question")
    with page.expect_response(lambda r: "/api/ask" in r.url, timeout=180000) as resp_info:
        page.click("#aap-send")
        caption(page, "Waiting for Ask Archer to answer…")
    resp = resp_info.value
    page.wait_for_timeout(2000)
    shot(page, "ask_answer")
    page.click("#aap-close")  # left open, it covers later steps' controls
    if not resp.ok:
        raise RuntimeError(f"/api/ask returned {resp.status}: {str(resp.json().get('detail', ''))[:150]}")


@step("Agents — detection repair (trace, MCP-shared tools)")
def agents(page):
    page.goto(f"{BASE}/agents")
    caption(page, "Agents: a model in a loop with Archer's tools")
    page.wait_for_selector(".ag-pick")
    if page.locator(".ag-start[disabled]").count():
        return "skipped: no AI provider in the profile"
    # A run whose queries all pass the checks: one or two turns, no changes to approve
    page.click('.ag-pick[data-agent="repair"]')
    page.fill('form[data-agent="repair"] input[name=run]', "CVE-2024-3400")
    page.click('form[data-agent="repair"] .ag-start')
    page.wait_for_selector("#ag-status.is-done, #ag-status.is-error, #ag-status.is-stopped", timeout=240000)
    shot(page, "agents")
    status = page.inner_text("#ag-status")
    assert status == "Done", f"agent ended: {status}"
    tools = page.locator(".ag-tool").all_inner_texts()
    assert "find_query_errors" in tools, f"tools called: {tools}"
    return f"repair agent: {', '.join(tools)}; {page.inner_text('#ag-usage')}"


@step("AI assignment — local model for Ask Archer (profile)")
def ai_assignment(page):
    """Profile → API Keys → AI Models: add a local endpoint row, assign Ask Archer to it (#10);
    detection generation can't take a local model yet (#9). The user's own settings are restored."""
    model = "llama3.2:3b"
    before = page.request.get(f"{BASE}/api/profile/ai-settings").json()["settings"]
    page.goto(f"{BASE}/profile")
    page.click('[data-tab="apikeys"]')
    page.wait_for_selector(".ai-provider-row")
    caption(page, "API Keys → AI Models: one row per provider, + adds another")
    row = page.locator(".ai-provider-row").last
    if row.locator(".ai-row-provider").input_value() != "local" or not row.locator(".ai-row-endpoint").input_value():
        page.locator(".ai-row-add:visible").last.click()
        row = page.locator(".ai-provider-row").last
        row.locator(".ai-row-provider").select_option("local")
    row.locator(".ai-row-endpoint").fill("http://localhost:11434")
    row.locator(".ai-row-test").click()
    # Needs a live local model server (Ollama on :11434). If it isn't running, skip rather than
    # fail — this step exercises the assignment UI, not Ollama's availability.
    try:
        row.locator(".ai-row-status.ai-status-ok").wait_for(timeout=15000)
    except PWTimeout:
        return f"skipped: local endpoint not reachable ({row.locator('.ai-row-status').inner_text().strip()})"
    if not row.locator(f'.ai-row-model option[value="{model}"]').count():
        raise RuntimeError(f"{model} not listed by the local endpoint: {row.locator('.ai-row-status').inner_text()}")
    row.locator(".ai-row-model").select_option(model)
    shot(page, "ai_local_model")
    page.locator("#ai-assignment").scroll_into_view_if_needed()
    if not page.locator('#assign-detection-provider option[value="local"]').is_disabled():
        raise AssertionError("a local model should not be assignable to detection generation yet (#9)")
    page.select_option("#assign-ask-provider", "local")
    page.fill("#assign-ask-model", model)
    caption(page, f"Ask Archer → local {model}; one Save for keys and assignment")
    with page.expect_response(lambda r: r.url.endswith("/api/profile/ai-settings") and r.request.method == "POST") as saved:
        page.click("button[onclick='saveAiTab()']")
    if not saved.value.json().get("success"):
        raise AssertionError(f"AI settings not saved: {saved.value.json()}")
    if (saved.value.json()["settings"].get("ask") or {}).get("provider") != "local":
        raise AssertionError("Save didn't store the Ask Archer assignment")
    shot(page, "ai_assignment")

    try:
        page.goto(f"{BASE}/")
        if not page.locator("#ask-archer-panel.open").count():  # the panel remembers being open
            page.click("#ask-archer-btn")
        page.fill("#aap-input", "In one sentence, what is LSASS?")
        with page.expect_response(lambda r: "/api/ask" in r.url, timeout=300000) as resp_info:
            page.click("#aap-send")
            caption(page, f"Asking Archer: answered by the assigned {model}")
        resp = resp_info.value
        if not resp.ok:
            raise RuntimeError(f"/api/ask returned {resp.status}: {str(resp.json().get('detail', ''))[:150]}")
        provider = resp.json().get("provider", "")
        if not provider.startswith("Local (") or model not in provider:
            raise AssertionError(f"Ask Archer answered with {provider!r}, not the assigned local {model}")
        page.wait_for_timeout(1500)
        shot(page, "ai_ask_answer")
        page.click("#aap-close")  # the panel stays open across pages and would cover the next step
    finally:
        # Put back the user's own Ask assignment and local endpoint; their keys were never touched
        page.request.post(f"{BASE}/api/profile/ai-settings",
                          data={"ask": before.get("ask"), "local": before.get("local") or {"endpoint": "", "model": ""}})
    return f"Ask Archer answered by {provider}"


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
    "upload": upload_blog, "upload-iocs": upload_iocs, "upload-error": upload_error, "profile": profile, "ask": ask_archer, "ai": ai_assignment, "agents": agents, "library": library,
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
        # Leave-page prompts (results page guards unsaved output) must be accepted or every
        # later goto aborts; anything else (confirm/alert) is dismissed
        page.on("dialog", lambda d: d.accept() if d.type == "beforeunload" else d.dismiss())
        for key in wanted:
            STEPS[key](page)
        caption(page, "Walkthrough complete")
        page.wait_for_timeout(4000)
        browser.close()

    print("\n=== SUMMARY ===")
    for n, name, status, note, secs in results:
        print(f"{n:02d} {status:4} {secs:6.1f}s  {name}  {note}")
    sys.exit(1 if any(r[2] == "FAIL" for r in results) else 0)

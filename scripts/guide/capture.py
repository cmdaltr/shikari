"""
Photograph every page in scripts/guide/pages.yaml for the in-app guide (Help → Guide).

Writes static/guide/img/<id>.jpg and static/guide/guide.json: each page's picture with the position of
every section it explains. Run it against a throwaway instance with sample data, never a real one,
because the pictures are committed (scripts/video/README.md sets one up):

    python scripts/guide/capture.py --base http://127.0.0.1:8010

Exits non-zero, writing nothing, when a selector matches nothing, so a changed page can't leave a
highlight pointing at the wrong place.
"""
import argparse
import json
import os
import sys
from pathlib import Path

import yaml
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
PAGES = Path(__file__).with_name("pages.yaml")
OUT = ROOT / "static" / "guide"
WIDTH, MAX_HEIGHT = 1440, 2600

# Nothing that floats over the page belongs in a still: the Ask Shikari button, toasts, and any of a
# previous visit's dialogs
TIDY = """() => {
  document.querySelectorAll('#ask-shikari-btn, #ask-shikari-panel, .ag-shade, .toast, .toast-container').forEach(e => e.remove());
  window.scrollTo(0, 0);
}"""

# Some pages scroll the body rather than the document, so measure where the content ends
PAGE_HEIGHT = """() => Math.ceil(Math.max(document.documentElement.scrollHeight, document.body.scrollHeight,
  ...[...document.body.querySelectorAll('body > *')].map(e => e.getBoundingClientRect().bottom + scrollY)))"""


def login(page, base, email, password):
    page.goto(f"{base}/login")
    page.fill('input[name="email"]', email)
    page.fill('input[name="password"]', password)
    page.locator('button[type="submit"]').first.click()
    page.wait_for_load_state("networkidle")
    if "/login" in page.url:
        sys.exit("Couldn't log in: set SHIKARI_GUIDE_EMAIL and SHIKARI_GUIDE_PASSWORD")


def settle(page):
    try:
        page.wait_for_load_state("networkidle", timeout=20000)
    except Exception:
        pass  # pages that poll never go idle
    page.wait_for_timeout(1200)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", default="http://127.0.0.1:8010")
    parser.add_argument("--only", nargs="*", help="page ids to capture (the rest keep their pictures)")
    args = parser.parse_args()
    email = os.environ.get("SHIKARI_GUIDE_EMAIL", "admin@shikari.app")
    password = os.environ.get("SHIKARI_GUIDE_PASSWORD", "BigGameHunter")

    spec = yaml.safe_load(PAGES.read_text())["pages"]
    previous = {}
    if (OUT / "guide.json").exists():
        previous = {p["id"]: p for p in json.loads((OUT / "guide.json").read_text())["pages"]}

    shots, pages, missing = {}, [], []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": WIDTH, "height": 900}, device_scale_factor=1, color_scheme="light")
        page = ctx.new_page()
        login(page, args.base, email, password)
        for p in spec:
            if args.only and p["id"] not in args.only:
                if p["id"] in previous:
                    pages.append({**previous[p["id"]], **{k: p[k] for k in ("menu", "title", "summary") if k in p},
                                  "sections": [{**old, **{k: s[k] for k in ("title", "what", "who", "when")}}
                                               for old, s in zip(previous[p["id"]]["sections"], p["sections"])]})
                continue
            page.goto(args.base + p["path"])
            settle(page)
            for step in p.get("before", []):
                if "click" in step:
                    page.locator(step["click"]).first.click()
                if "script" in step:
                    page.evaluate(step["script"])
                page.wait_for_timeout(600)
            page.evaluate(TIDY)
            # The window grows to the page's height so nothing reflows between measuring and the picture,
            # and content that only draws once scrolled into view is drawn
            # A long page can raise the cap (max_height in pages.yaml) to reach a card near its foot
            cap = p.get("max_height", MAX_HEIGHT)
            height = min(cap, page.evaluate(PAGE_HEIGHT))
            page.set_viewport_size({"width": WIDTH, "height": height})
            page.wait_for_timeout(1500)
            page.evaluate(TIDY)
            height = min(cap, page.evaluate(PAGE_HEIGHT))
            page.set_viewport_size({"width": WIDTH, "height": height})
            page.wait_for_timeout(500)

            sections = []
            for s in p["sections"]:
                loc = page.locator(s["selector"]).first
                box = loc.bounding_box() if loc.count() else None
                if not box or box["width"] < 4 or box["height"] < 4 or box["y"] >= height:
                    if not s.get("optional"):
                        missing.append(f"{p['id']}: {s['selector']}")
                    continue
                pad = 6
                x, y = max(0, box["x"] - pad), max(0, box["y"] - pad)
                sections.append({
                    "title": s["title"], "what": s["what"], "who": s["who"], "when": s["when"],
                    "box": [round(x), round(y), round(box["width"] + 2 * pad), round(min(box["height"] + 2 * pad, height - y))],
                })
            shots[p["id"]] = page.screenshot(type="jpeg", quality=82)
            page.set_viewport_size({"width": WIDTH, "height": 900})
            pages.append({
                "id": p["id"], "menu": p["menu"], "title": p["title"], "summary": p["summary"],
                "path": p["path"].split("?")[0], "href": p.get("href"),
                "image": f"/static/guide/img/{p['id']}.jpg", "width": WIDTH, "height": height,
                "sections": sections,
            })
            print(f"  {p['id']:<22} {len(sections)} sections, {height}px")
        browser.close()

    if missing:
        print("Selectors that matched nothing (nothing written):", *missing, sep="\n  ")
        return 1
    (OUT / "img").mkdir(parents=True, exist_ok=True)
    for pid, data in shots.items():
        (OUT / "img" / f"{pid}.jpg").write_bytes(data)
    (OUT / "guide.json").write_text(json.dumps({"pages": pages}, indent=1, ensure_ascii=False) + "\n")
    print(f"Wrote {len(shots)} pictures and {OUT / 'guide.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

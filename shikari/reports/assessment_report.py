"""
The assessment report (#42): what a consultant or internal red team hands the client or the SOC
at the end of a purple-team or CALDERA campaign, as Word and PDF.

Both formats carry the same content (assessment_data.py) and the same brand: a title page with
the bateleur on its branch filling the page, Calibri throughout, a header and footer on every
page after it with page numbers, and the logo's and the bird's colours in the tables and figures.
"""

import io
from typing import Dict, List, Optional, Sequence, Tuple

from shikari.reports import assessment_charts as charts
from shikari.reports import assessment_data as data

REPORT_KIND = "Adversary Emulation Assessment"
SECTIONS = ["Executive Summary", "Scope", "Assumptions", "Findings", "Risks", "Recommendations",
            "Conclusions", "Appendices"]


def _hex(rgb: Tuple[int, int, int]) -> str:
    return "%02X%02X%02X" % rgb


BLUE_FILL = {k: c for k, _, c in charts.BLUE_OUTCOMES}
RED_FILL = {k: c for k, _, c in charts.RED_OUTCOMES}
RATING_FILL = {**charts.RATING_COLOUR, "Unrated": (214, 206, 202)}
BAND = (247, 244, 242)        # alternate table rows: the wing grey at its palest
RULE = (214, 206, 202)


def _figures(c: Dict) -> Dict[str, bytes]:
    """Every figure the report uses, drawn once for both formats."""
    figs = {"background": charts.title_background(), "wordmark": charts.wordmark(True, 150),
            "wordmark_text": charts.wordmark(False, 150)}
    if c["rows"]:
        figs["scorecard"] = charts.scorecard([
            (str(len(c["techniques"])), "Techniques tested", charts.INK),
            (f"{c['detection_rate']}%", "Detection rate", charts.CHESTNUT),
            (f"{c['visibility']}%", "Visibility", charts.BARK),
            (str(c["high_or_worse"]), "High or Critical", charts.RED),
        ])
        figs["blue"] = charts.outcome_bars(c["blue"], charts.BLUE_OUTCOMES)
        figs["red"] = charts.donut(c["red"], charts.RED_OUTCOMES, "tests")
        figs["tactics"] = charts.tactic_stack(c["by_tactic"])
        figs["matrix"] = charts.coverage_matrix(c["matrix"])
    if c["rated"]:
        figs["heat"] = charts.risk_heatmap(c["heat"])
    if c["gaps"]:
        figs["ready"] = charts.readiness(c["ready"], c["unready"])
    return figs


# ── Shared content: the same tables in both formats ──────────────────────────
# A table is (headers, rows, widths in cm, fills): fills maps (row, column) to a colour.

Table = Tuple[List[str], List[List[str]], List[float], Dict[Tuple[int, int], Tuple[int, int, int]]]


def scope_table(c: Dict) -> Table:
    a = c["assessment"]
    rows = [
        ["Assessment", a.get("name") or ""],
        ["Client or target", a.get("target") or "Not recorded"],
        ["Operator", a.get("operator") or "Not recorded"],
        ["Run date", a.get("run_date") or "Not recorded"],
        ["Report date", c["report_date"]],
        ["Adversaries emulated", ", ".join(c["groups"]) or "Not recorded"],
        ["Techniques in scope", str(len(c["techniques"]))],
        ["Test cases", str(len(c["rows"]))],
        ["Tactics covered", ", ".join(c["tactics"]) or "None"],
    ]
    return ["Item", "Detail"], rows, [5.0, 12.0], {}


def tactic_table(c: Dict) -> Table:
    keys = ["prevented", "alerted", "logged", "not_logged", "not_assessed"]
    rows, fills = [], {}
    for t in c["tactics"]:
        counts = c["by_tactic"][t]
        rows.append([t] + [str(counts.get(k, 0)) for k in keys] + [str(sum(counts.values()))])
    for i, row in enumerate(rows):
        for j, k in enumerate(keys, 1):
            if row[j] != "0":
                fills[(i, j)] = BLUE_FILL[k]
    return (["Tactic"] + [data.BLUE_LABEL[k] for k in keys] + ["Total"], rows,
            [4.4, 2.1, 2.0, 2.0, 2.1, 2.3, 2.1], fills)


def top_risks_table(c: Dict, limit: int = 5) -> Table:
    rows, fills = [], {}
    for i, x in enumerate(c["rated"][:limit]):
        rows.append([x["ref"], f"{x['technique_id']} {x.get('technique_name') or ''}".strip(),
                     data.BLUE_LABEL[x["blue_outcome"]], x["rating"]])
        fills[(i, 2)] = BLUE_FILL[x["blue_outcome"]]
        fills[(i, 3)] = RATING_FILL[x["rating"]]
    return ["Ref", "Technique", "Defence", "Rating"], rows, [1.6, 9.8, 2.9, 2.7], fills


def risk_register(c: Dict) -> Table:
    rows, fills = [], {}
    for i, x in enumerate(c["rated"]):
        rows.append([x["ref"], f"{x['technique_id']} {x.get('technique_name') or ''}".strip(), x["tactic_name"],
                     f"{data.LEVEL[x['likelihood']]} ({data.RED_LABEL[x['red_outcome']].lower()})",
                     f"{data.LEVEL[x['impact']]} ({data.BLUE_LABEL[x['blue_outcome']].lower()})", x["rating"]])
        fills[(i, 5)] = RATING_FILL[x["rating"]]
    return (["Ref", "Technique", "Tactic", "Likelihood", "Impact", "Rating"], rows,
            [1.4, 5.0, 2.8, 2.8, 3.0, 2.0], fills)


def recommendations_table(c: Dict) -> Table:
    rows, fills = [], {}
    for i, x in enumerate(c["gaps"]):
        rows.append([x["ref"], x["rating"], f"{x['technique_id']} {x.get('technique_name') or ''}".strip(),
                     data.recommendation_for(x), f"{len(x['library'])}{_ai(x['library_ai'])}"])
        fills[(i, 1)] = RATING_FILL[x["rating"]]
    return ["Ref", "Priority", "Technique", "Action", "Library"], rows, [1.3, 1.9, 4.3, 7.8, 1.7], fills


def outcome_definitions() -> Table:
    blue = {"prevented": "A control stopped the activity.",
            "alerted": "A detection raised an alert for the activity.",
            "logged": "The activity reached the logs, but nothing alerted on it.",
            "not_logged": "The activity left no record in the logs collected.",
            "not_assessed": "The defensive outcome wasn't recorded."}
    red = {"executed": "The procedure ran to completion.",
           "failed": "The procedure ran but didn't succeed, for reasons other than a control.",
           "blocked": "A control stopped the procedure.",
           "not_run": "The test case wasn't run."}
    rows, fills = [], {}
    for k, label, colour in charts.BLUE_OUTCOMES:
        fills[(len(rows), 1)] = colour
        rows.append(["Blue (defence)", label, blue[k]])
    for k, label, colour in charts.RED_OUTCOMES:
        fills[(len(rows), 1)] = colour
        rows.append(["Red (attack)", label, red[k]])
    return ["Side", "Outcome", "Meaning"], rows, [3.2, 3.0, 10.8], fills


def rating_method() -> Table:
    rows, fills = [], {}
    for i, lk in enumerate((3, 2, 1)):
        row = [f"{data.LEVEL[lk]} likelihood"]
        for j, im in enumerate((1, 2, 3), 1):
            r = charts.rating_for(lk * im)
            row.append(f"{r} ({lk * im})")
            fills[(i, j)] = charts.RATING_COLOUR[r]
        rows.append(row)
    return (["", "Low impact (alerted or prevented)", "Medium impact (logged)", "High impact (not logged)"],
            rows, [3.8, 4.4, 4.4, 4.4], fills)


def lab_runs_table(c: Dict) -> Table:
    rows = [[r["run"], r["tool"], r["host"], r["started"], ", ".join(r["techniques"])] for r in c["lab_runs"]]
    return ["Run", "Tool", "Host", "Started (UTC)", "Techniques in scope"], rows, [4.6, 2.4, 3.0, 2.8, 4.2], {}


def test_cases_table(c: Dict) -> Table:
    rows, fills = [], {}
    for i, x in enumerate(sorted(c["rows"], key=lambda r: r.get("technique_id") or "")):
        rows.append([x["ref"], x.get("technique_id") or "", x.get("technique_name") or "", x["tactic_name"],
                     x.get("group_name") or "", data.RED_LABEL[x["red_outcome"]], data.BLUE_LABEL[x["blue_outcome"]]])
        fills[(i, 5)] = RED_FILL[x["red_outcome"]]
        fills[(i, 6)] = BLUE_FILL[x["blue_outcome"]]
    return (["Ref", "ID", "Technique", "Tactic", "Group", "Red", "Blue"], rows,
            [1.3, 1.9, 4.1, 2.9, 2.6, 2.1, 2.1], fills)


def candidates_table(c: Dict) -> Table:
    rows = []
    for x in c["gaps"]:
        for d in x["library"]:
            rows.append([x["ref"], x["technique_id"], d["siem"], (d["name"] or "") + _ai(d["ai"]), d["file"]])
    return ["Ref", "Technique", "SIEM", "Detection", "File"], rows, [1.3, 2.0, 2.6, 4.6, 6.5], {}


def finding_rows(x: Dict) -> List[Tuple[str, str, Optional[Tuple[int, int, int]]]]:
    """A finding's detail as (label, value, fill) rows."""
    lib = x["library"]
    fired = (x["fired"] + (f" ({x['fired_siem']})" if x["fired_siem"] else "") + _ai(x["fired_ai"])
             if x["fired"] else "None recorded")
    siems = sorted({d["siem"] for d in lib})
    return [
        ("Tactic", x["tactic_name"], None),
        ("Adversary", x.get("group_name") or "Not recorded", None),
        ("Procedure", x.get("procedure") or "Not recorded", None),
        ("Red outcome", data.RED_LABEL[x["red_outcome"]], RED_FILL[x["red_outcome"]]),
        ("Blue outcome", data.BLUE_LABEL[x["blue_outcome"]], BLUE_FILL[x["blue_outcome"]]),
        ("Detection that fired", fired, None),
        ("Library detections", f"{len(lib)} ({', '.join(siems)}){_ai(x['library_ai'])}" if lib else "None", None),
        ("Risk rating", x["rating"], RATING_FILL[x["rating"]]),
        ("Notes", x.get("notes") or "", None),
    ]


def _ai(flag: bool) -> str:
    return data.AI_MARK if flag else ""


def heading_mark(c: Dict, title: str) -> str:
    """A heading, marked when what's under it cites AI-written detections."""
    flagged = (title in c["ai_sections"]
               or (title == "Findings by technique" and "Findings" in c["ai_sections"])
               or (title in ("Closing the gaps", "Appendix E: Candidate detections") and c["ai_gaps"]))
    return title + (f" {data.AI_MARK}" if flagged else "")


def lab_paragraph(c: Dict) -> str:
    if not c["lab_runs"]:
        return ("No lab runs recorded in Shikari cover the techniques in this assessment. Record one with the lab "
                "recorders (Emulate → Lab) to keep the telemetry alongside the report.")
    return ("These lab runs recorded telemetry for techniques in this assessment. Each can be replayed into a "
            "SIEM with the export packs (Detections as code → Export to a SIEM), together with the "
            "detections, for example: shikari export siem --siem splunk --all --telemetry "
            f"{c['lab_runs'][0]['run']}")


# ── Word ──────────────────────────────────────────────────────────────────────

def to_docx(c: Dict, figs: Optional[Dict[str, bytes]] = None) -> bytes:
    from docx import Document
    from docx.enum.section import WD_SECTION
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_TAB_ALIGNMENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Cm, Pt, RGBColor

    figs = figs or _figures(c)
    a = c["assessment"]
    doc = Document()
    font = "Calibri"

    # Calibri everywhere: the defaults, then each style Word might reach for.
    rpr = doc.styles.element.find(qn("w:docDefaults")).find(qn("w:rPrDefault")).find(qn("w:rPr"))
    fonts = rpr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        rpr.insert(0, fonts)
    for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        fonts.set(qn(attr), font)
    for attr in ("w:asciiTheme", "w:hAnsiTheme", "w:cstheme", "w:eastAsiaTheme"):
        if fonts.get(qn(attr)) is not None:
            del fonts.attrib[qn(attr)]

    def style_font(name, size=None, bold=None, colour=None):
        st = doc.styles[name]
        st.font.name = font
        st.element.rPr.rFonts.set(qn("w:eastAsia"), font)
        for attr in ("w:asciiTheme", "w:hAnsiTheme", "w:cstheme", "w:eastAsiaTheme"):
            if st.element.rPr.rFonts.get(qn(attr)) is not None:
                del st.element.rPr.rFonts.attrib[qn(attr)]
        if size:
            st.font.size = Pt(size)
        if bold is not None:
            st.font.bold = bold
        if colour:
            st.font.color.rgb = RGBColor(*colour)
        return st

    normal = style_font("Normal", 10.5, colour=charts.INK)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.12
    h1 = style_font("Heading 1", 22, True, charts.INK)
    h1.paragraph_format.space_before = Pt(0)
    h1.paragraph_format.space_after = Pt(10)
    h2 = style_font("Heading 2", 14, True, charts.CHESTNUT)
    h2.paragraph_format.space_before = Pt(14)
    h2.paragraph_format.space_after = Pt(6)
    style_font("Heading 3", 12, True, charts.INK)
    for name in ("Caption", "List Bullet", "Title", "Subtitle", "TOC Heading"):
        try:
            style_font(name)
        except KeyError:
            pass
    caption = doc.styles["Caption"]
    caption.font.size = Pt(9)
    caption.font.italic = True
    caption.font.bold = False
    caption.font.color.rgb = RGBColor(*charts.SLATE)
    for level in (1, 2):
        try:
            st = doc.styles[f"TOC {level}"]
        except KeyError:
            st = doc.styles.add_style(f"TOC {level}", 1)
            st.base_style = normal
        st.font.name = font
        st.font.size = Pt(12 if level == 1 else 10.5)
        st.font.bold = level == 1
        st.paragraph_format.left_indent = Cm(0 if level == 1 else 0.8)
        st.paragraph_format.space_before = Pt(8 if level == 1 else 2)
        st.paragraph_format.space_after = Pt(2)

    def border(p, side, colour, size=12, space=4):
        ppr = p._p.get_or_add_pPr()
        bdr = ppr.find(qn("w:pBdr"))
        if bdr is None:
            bdr = OxmlElement("w:pBdr")
            ppr.append(bdr)
        el = OxmlElement(f"w:{side}")
        for k, v in (("val", "single"), ("sz", str(size)), ("space", str(space)), ("color", _hex(colour))):
            el.set(qn(f"w:{k}"), v)
        bdr.append(el)

    def field(p, code, placeholder="1", size=None, colour=None, bold=False):
        for kind, text in (("begin", None), ("instr", code), ("separate", None), ("text", placeholder), ("end", None)):
            run = p.add_run()
            if size:
                run.font.size = Pt(size)
            if colour:
                run.font.color.rgb = RGBColor(*colour)
            run.font.bold = bold
            if kind == "instr":
                el = OxmlElement("w:instrText")
                el.set(qn("xml:space"), "preserve")
                el.text = f" {code} "
                run._r.append(el)
            elif kind == "text":
                run.text = text
            else:
                el = OxmlElement("w:fldChar")
                el.set(qn("w:fldCharType"), kind)
                run._r.append(el)

    def shade(cell, rgb):
        tcpr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), _hex(rgb))
        tcpr.append(shd)

    def cell_text(cell, text, bold=False, colour=None, size=9.5, align=None):
        cell.text = ""
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.space_before = Pt(0)
        if align:
            p.alignment = align
        run = p.add_run(text)
        run.font.size = Pt(size)
        run.font.bold = bold
        if colour:
            run.font.color.rgb = RGBColor(*colour)

    def table(spec: Table, caption_text: str = "", header_fill=charts.INK, first_col_bold=False):
        headers, rows, widths, fills = spec
        t = doc.add_table(rows=1 + len(rows), cols=len(headers))
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        t.autofit = False
        tblpr = t._tbl.tblPr
        borders = OxmlElement("w:tblBorders")
        for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
            el = OxmlElement(f"w:{side}")
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), "4")
            el.set(qn("w:color"), _hex(RULE))
            borders.append(el)
        tblpr.append(borders)
        width = OxmlElement("w:tblW")
        width.set(qn("w:w"), str(int(sum(widths) * 567)))
        width.set(qn("w:type"), "dxa")
        for old in tblpr.findall(qn("w:tblW")):
            tblpr.remove(old)
        tblpr.append(width)
        margins = OxmlElement("w:tblCellMar")
        for side, v in (("top", 50), ("bottom", 50), ("left", 90), ("right", 90)):
            el = OxmlElement(f"w:{side}")
            el.set(qn("w:w"), str(v))
            el.set(qn("w:type"), "dxa")
            margins.append(el)
        tblpr.append(margins)
        for j, h in enumerate(headers):
            cell = t.rows[0].cells[j]
            cell_text(cell, h, bold=True, colour=charts.WHITE)
            shade(cell, header_fill)
        for cell in t.rows[0].cells:  # never leave the header row alone at the foot of a page
            cell.paragraphs[0].paragraph_format.keep_with_next = True
        trpr = t.rows[0]._tr.get_or_add_trPr()
        rep = OxmlElement("w:tblHeader")
        rep.set(qn("w:val"), "true")
        trpr.append(rep)
        for i, row in enumerate(rows):
            for j, value in enumerate(row):
                cell = t.rows[i + 1].cells[j]
                fill = fills.get((i, j))
                if fill:
                    cell_text(cell, value, bold=True, colour=charts._ideal_ink(fill))
                    shade(cell, fill)
                else:
                    cell_text(cell, value, bold=first_col_bold and j == 0)
                    if i % 2:
                        shade(cell, BAND)
        for row in t.rows:
            for j, w in enumerate(widths):
                row.cells[j].width = Cm(w)
        if caption_text:
            cap = doc.add_paragraph(caption_text, style="Caption")
            cap.paragraph_format.space_before = Pt(4)
        else:
            doc.add_paragraph().paragraph_format.space_after = Pt(2)
        return t

    counters = {"figure": 0, "table": 0}

    def figure(key, text, width_cm=17.0):
        if key not in figs:
            return
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.keep_with_next = True
        p.add_run().add_picture(io.BytesIO(figs[key]), width=Cm(width_cm))
        counters["figure"] += 1
        doc.add_paragraph(f"Figure {counters['figure']}: {text}", style="Caption").alignment = WD_ALIGN_PARAGRAPH.CENTER

    def captioned(spec, text, **kw):
        counters["table"] += 1
        return table(spec, f"Table {counters['table']}: {text}", **kw)

    numbers = {s: i for i, s in enumerate(SECTIONS, 1)}

    def heading1(title, numbered=True, page_break=True):
        if page_break:
            doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
            doc.paragraphs[-1].paragraph_format.space_after = Pt(0)
        text = f"{numbers[title]}  {heading_mark(c, title)}" if numbered and title in numbers else title
        p = doc.add_heading(text, level=1)
        border(p, "bottom", charts.GOLD, size=18, space=6)
        return p

    sub = {"n": 0, "sec": 0}

    def heading2(title):
        sub["n"] += 1
        return doc.add_heading(f"{sub['sec']}.{sub['n']}  {heading_mark(c, title)}", level=2)

    def start(title, page_break=True):
        sub.update(n=0, sec=numbers[title])
        return heading1(title, page_break=page_break)

    def para(text, italic=False):
        p = doc.add_paragraph()
        r = p.add_run(text)
        r.italic = italic
        return p

    def bullets(items):
        for item in items:
            doc.add_paragraph(item, style="List Bullet")

    # ── Section 1: the title page, no header or footer ──
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
    sec.left_margin = sec.right_margin = Cm(2.4)
    sec.top_margin, sec.bottom_margin = Cm(2.2), Cm(1.6)

    anchor_p = doc.paragraphs[0] if doc.paragraphs else doc.add_paragraph()
    run = anchor_p.add_run()
    run.add_picture(io.BytesIO(figs["background"]), width=Cm(21.0), height=Cm(29.7))
    _float_behind(run, Cm(21.0), Cm(29.7))
    run.add_picture(io.BytesIO(figs["wordmark"]), height=Cm(1.9))
    anchor_p.paragraph_format.space_after = Pt(0)

    def title_line(text, size, bold=False, colour=charts.INK, before=0, after=4, italic=False):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(before)
        p.paragraph_format.space_after = Pt(after)
        p.paragraph_format.right_indent = Cm(6.5)
        r = p.add_run(text)
        r.font.size = Pt(size)
        r.font.bold = bold
        r.font.italic = italic
        r.font.color.rgb = RGBColor(*colour)
        return p

    title_line(REPORT_KIND.upper(), 13, True, charts.GOLD, before=150, after=6)
    t = title_line(a.get("name") or "Assessment", 34, True, charts.INK, after=8)
    t.paragraph_format.line_spacing = 0.95
    border(t, "bottom", charts.RED, size=24, space=8)
    if a.get("target"):
        title_line(f"Prepared for {a['target']}", 16, False, charts.CHESTNUT, before=10, after=2)
    title_line(c["report_date"], 13, False, charts.SLATE, before=2, after=2)
    if a.get("operator"):
        title_line(f"Operator: {a['operator']}", 12, False, charts.SLATE, after=2)
    title_line("CONFIDENTIAL", 12, True, charts.RED, before=170, after=2)
    title_line("Prepared with Shikari: automated multi-vendor threat hunting and detection", 9.5, False,
               charts.SLATE, italic=True)

    # ── Section 2 onwards: header, footer, page numbers from 1 ──
    body = doc.add_section(WD_SECTION.NEW_PAGE)
    body.left_margin = body.right_margin = Cm(2.0)
    body.top_margin, body.bottom_margin = Cm(2.6), Cm(2.2)
    body.header_distance, body.footer_distance = Cm(1.0), Cm(1.0)
    pg = OxmlElement("w:pgNumType")
    pg.set(qn("w:start"), "1")
    body._sectPr.append(pg)
    for part in (body.header, body.footer):
        part.is_linked_to_previous = False
    sec.header.is_linked_to_previous = False
    sec.footer.is_linked_to_previous = False

    def own_tabs(p, *stops):
        # Clear the Header and Footer styles' own centre and right stops (8.25 and 16.5 cm).
        for pos in (Cm(8.255), Cm(16.51)):
            p.paragraph_format.tab_stops.add_tab_stop(pos, WD_TAB_ALIGNMENT.CLEAR)
        for pos, align in stops:
            p.paragraph_format.tab_stops.add_tab_stop(pos, align)

    hp = body.header.paragraphs[0]
    own_tabs(hp, (Cm(17.0), WD_TAB_ALIGNMENT.RIGHT))
    hp.add_run().add_picture(io.BytesIO(figs["wordmark"]), height=Cm(0.85))
    r = hp.add_run(f"\t{REPORT_KIND}  ·  {a.get('name') or ''}")
    r.font.size = Pt(9)
    r.font.color.rgb = RGBColor(*charts.SLATE)
    border(hp, "bottom", charts.GOLD, size=12, space=4)

    fp = body.footer.paragraphs[0]
    own_tabs(fp, (Cm(8.5), WD_TAB_ALIGNMENT.CENTER), (Cm(17.0), WD_TAB_ALIGNMENT.RIGHT))
    border(fp, "top", RULE, size=6, space=4)
    r = fp.add_run("CONFIDENTIAL")
    r.font.size, r.font.bold = Pt(8.5), True
    r.font.color.rgb = RGBColor(*charts.RED)
    r = fp.add_run(f"\t{('Prepared for ' + a['target']) if a.get('target') else 'Shikari'}  ·  {c['report_date']}\tPage ")
    r.font.size = Pt(8.5)
    r.font.color.rgb = RGBColor(*charts.SLATE)
    field(fp, "PAGE", "1", 8.5, charts.INK, True)
    r = fp.add_run(" of ")
    r.font.size = Pt(8.5)
    r.font.color.rgb = RGBColor(*charts.SLATE)
    field(fp, "SECTIONPAGES", "1", 8.5, charts.INK, True)

    # ── Table of Contents (Word fills the page numbers in when it opens the file) ──
    p = doc.add_heading("Table of Contents", level=1)
    p.style = doc.styles["TOC Heading"] if "TOC Heading" in [s.name for s in doc.styles] else p.style
    p.runs[0].font.size, p.runs[0].font.bold = Pt(22), True
    p.runs[0].font.color.rgb = RGBColor(*charts.INK)
    border(p, "bottom", charts.GOLD, size=18, space=6)
    toc = doc.add_paragraph()
    _toc_field(toc, [f"{i}  {s}" for i, s in enumerate(SECTIONS, 1)])
    _update_fields_on_open(doc)

    # 1 Executive Summary
    start("Executive Summary")
    if c["summary"]:
        for chunk in [s for s in c["summary"].split("\n\n") if s.strip()]:
            para(chunk.strip())
    for text in data.executive_paragraphs(c):
        para(text)
    figure("scorecard", "Headline results. Detection rate: alerted or prevented, of the tests assessed. "
                        "Visibility: reached the logs at all.")
    if c["rated"]:
        heading2("Highest-rated findings")
        captioned(top_risks_table(c), "The five highest-rated findings (all are in section 4).")

    # 2 Scope
    start("Scope")
    para("The assessment emulated the adversaries below against the target, one MITRE ATT&CK technique per test "
         "case, recording what each attack did (red) and what the defence saw (blue).")
    captioned(scope_table(c), "The assessment.", first_col_bold=True)
    if c["tactics"]:
        heading2("Techniques by tactic")
        captioned(tactic_table(c), "Test cases per tactic, by defensive outcome.")

    # 3 Assumptions
    start("Assumptions")
    bullets(data.assumptions(c))

    # 4 Findings
    start("Findings")
    if not c["rows"]:
        para("No test cases had been added to this assessment, so there are no findings.")
    else:
        heading2("Overview")
        para(f"{plural_tests(c)} The charts show what the defence saw, what the attacks did, and where in the "
             "attack the defence held or missed.")
        figure("blue", "Defensive (blue) outcomes across all test cases.")
        figure("red", "Attack (red) outcomes across all test cases.", 15.0)
        figure("tactics", "Defensive outcomes by tactic.")
        heading2("Coverage matrix")
        para("Each technique tested, under its tactic, coloured by its defensive outcome. A technique tested more "
             "than once shows its worst outcome.")
        figure("matrix", "The assessment's techniques as an ATT&CK matrix.")
        heading2("Findings by technique")
        para("Each test case as a finding, highest rated first. The reference (F-nn) is used throughout the report.")
        for x in c["rows"]:
            _finding_docx(doc, x, table_fn=table, shade=shade, cell_text=cell_text, Cm=Cm, Pt=Pt, RGBColor=RGBColor)

    # 5 Risks
    start("Risks")
    if not c["rated"]:
        para("No test case had both its attack and defensive outcome recorded, so no risk could be rated.")
    else:
        para("Each finding is rated by likelihood (what the attack did) and impact (what the defence saw), as "
             "Appendix B sets out. The matrix counts the findings at each rating.")
        figure("heat", "Findings by likelihood and impact.", 14.0)
        heading2("Risk register")
        captioned(risk_register(c), "Every rated finding.")

    # 6 Recommendations
    start("Recommendations")
    if c["gaps"]:
        para("Each technique that was logged but not alerted on, or not logged at all, is a gap. "
             + data.gaps_paragraph(c))
        figure("ready", "Gaps by whether deploying a library detection would close them.", 15.0)
        heading2("Closing the gaps")
        captioned(recommendations_table(c), "One action per gap, highest priority first. Library: detections available.")
    else:
        para(data.no_gaps_sentence(c))
    heading2("General recommendations")
    captioned((["Recommendation", "Detail"], [list(r) for r in data.GENERAL_RECOMMENDATIONS], [4.6, 12.4], {}),
              "Recommendations for the programme as a whole.", first_col_bold=True)

    # 7 Conclusions
    start("Conclusions")
    if c["conclusion"]:
        for chunk in [s for s in c["conclusion"].split("\n\n") if s.strip()]:
            para(chunk.strip())
    for text in data.conclusion_paragraphs(c):
        para(text)

    # 8 Appendices
    start("Appendices")
    heading2("Appendix A: Outcome definitions")
    captioned(outcome_definitions(), "What each recorded outcome means.")
    heading2("Appendix B: Risk rating method")
    para("Likelihood comes from the red outcome (executed 3, failed 2, blocked 1) and impact from the blue outcome "
         "(not logged 3, logged 2, alerted or prevented 1). The rating is their product.")
    captioned(rating_method(), "Ratings by likelihood and impact.", first_col_bold=True)
    heading2("Appendix C: Lab runs and SIEM export packs")
    para(lab_paragraph(c))
    if c["lab_runs"]:
        captioned(lab_runs_table(c), "Lab runs covering this assessment's techniques.")
    heading2("Appendix D: Test cases")
    if c["rows"]:
        captioned(test_cases_table(c), "Every test case in the assessment.")
    else:
        para("None.")
    heading2("Appendix E: Candidate detections")
    spec = candidates_table(c)
    if spec[1]:
        captioned(spec, "Detections in the Shikari library for each gap.")
    else:
        para("None: either there were no gaps, or the library holds no detections for them.")

    # The AI disclaimer, once, at the end of the report
    box = doc.add_table(rows=1, cols=1)
    box.autofit = False
    cell = box.rows[0].cells[0]
    cell.width = Cm(17.0)
    shade(cell, BAND)
    tcpr = cell._tc.get_or_add_tcPr()
    tcb = OxmlElement("w:tcBorders")
    for side, colour, size in (("left", charts.GOLD, "24"), ("top", RULE, "4"), ("bottom", RULE, "4"), ("right", RULE, "4")):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), size)
        el.set(qn("w:color"), _hex(colour))
        tcb.append(el)
    tcpr.append(tcb)
    cell.text = ""
    for i, text in enumerate(data.ai_disclaimer(c)):
        dp = cell.paragraphs[0] if i == 0 else cell.add_paragraph()
        dp.paragraph_format.space_after = Pt(4)
        r = dp.add_run(text)
        r.font.size = Pt(9)
        r.font.color.rgb = RGBColor(*charts.SLATE)
    doc.paragraphs[-1].paragraph_format.space_before = Pt(18)

    # Back cover: a section of its own, without the header and footer
    back = doc.add_section(WD_SECTION.NEW_PAGE)
    for part in (back.header, back.footer):
        part.is_linked_to_previous = False
    for _ in range(9):
        doc.add_paragraph()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run().add_picture(io.BytesIO(figs["wordmark"]), width=Cm(11.0))
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("Automated multi-vendor threat hunting and detection")
    r.font.size, r.font.color.rgb = Pt(12), RGBColor(*charts.SLATE)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def plural_tests(c: Dict) -> str:
    return (f"{data.plural(len(c['rows']), 'test case')} covered {data.plural(len(c['techniques']), 'technique')} "
            f"across {data.plural(len(c['tactics']), 'tactic')}.")


def _finding_docx(doc, x, table_fn, shade, cell_text, Cm, Pt, RGBColor):
    """A finding as a card: a coloured title bar, then its detail."""
    rows = finding_rows(x)
    fill = BLUE_FILL[x["blue_outcome"]]
    t = doc.add_table(rows=1 + len(rows), cols=2)
    t.autofit = False
    title = t.rows[0].cells[0].merge(t.rows[0].cells[1])
    cell_text(title, f"{x['ref']}   {x.get('technique_id') or ''}  {x.get('technique_name') or ''}   ·   {x['rating']}",
              bold=True, colour=charts._ideal_ink(fill), size=11)
    shade(title, fill)
    for i, (label, value, vfill) in enumerate(rows, 1):
        lc, vc = t.rows[i].cells
        cell_text(lc, label, bold=True, colour=charts.INK)
        shade(lc, BAND)
        if vfill:
            cell_text(vc, value, bold=True, colour=charts._ideal_ink(vfill))
            shade(vc, vfill)
        else:
            cell_text(vc, value)
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    borders = OxmlElement("w:tblBorders")
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), "4")
        el.set(qn("w:color"), _hex(RULE))
        borders.append(el)
    t._tbl.tblPr.append(borders)
    for row in t.rows[:-1]:  # keep the card on one page
        for cell in row.cells:
            for cp in cell.paragraphs:
                cp.paragraph_format.keep_with_next = True
    for row in t.rows[1:]:
        row.cells[0].width, row.cells[1].width = Cm(4.2), Cm(12.8)
        trpr = row._tr.get_or_add_trPr()
        cant = OxmlElement("w:cantSplit")
        trpr.append(cant)
    doc.add_paragraph().paragraph_format.space_after = Pt(4)


def _float_behind(run, width, height):
    """Turn the run's last inline picture into one anchored at the page's top left, behind the text."""
    from docx.oxml import parse_xml
    from docx.oxml.ns import nsdecls, qn

    inline = run._r.findall(".//" + qn("wp:inline"))[-1]
    anchor = parse_xml(
        f'<wp:anchor {nsdecls("wp")} distT="0" distB="0" distL="0" distR="0" simplePos="0" relativeHeight="0" '
        f'behindDoc="1" locked="1" layoutInCell="1" allowOverlap="1">'
        f'<wp:simplePos x="0" y="0"/>'
        f'<wp:positionH relativeFrom="page"><wp:posOffset>0</wp:posOffset></wp:positionH>'
        f'<wp:positionV relativeFrom="page"><wp:posOffset>0</wp:posOffset></wp:positionV>'
        f'<wp:extent cx="{int(width)}" cy="{int(height)}"/>'
        f'<wp:effectExtent l="0" t="0" r="0" b="0"/><wp:wrapNone/></wp:anchor>')
    for tag in ("wp:docPr", "wp:cNvGraphicFramePr", "a:graphic"):
        el = inline.find(qn(tag))
        if el is not None:
            anchor.append(el)
    inline.getparent().replace(inline, anchor)


def _toc_field(p, entries: Sequence[str]) -> None:
    """A TOC field whose cached result lists the sections, so the contents read even before Word
    updates the page numbers."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    def fld(kind):
        r = OxmlElement("w:r")
        el = OxmlElement("w:fldChar")
        el.set(qn("w:fldCharType"), kind)
        r.append(el)
        p._p.append(r)

    fld("begin")
    r = OxmlElement("w:r")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = ' TOC \\o "1-2" \\h \\z \\u '
    r.append(instr)
    p._p.append(r)
    fld("separate")
    for i, entry in enumerate(entries):
        r = OxmlElement("w:r")
        if i:
            r.append(OxmlElement("w:br"))
        t = OxmlElement("w:t")
        t.set(qn("xml:space"), "preserve")
        t.text = entry
        r.append(t)
        p._p.append(r)
    fld("end")


def _update_fields_on_open(doc) -> None:
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    settings = doc.settings.element
    el = OxmlElement("w:updateFields")
    el.set(qn("w:val"), "true")
    settings.append(el)


# ── PDF ───────────────────────────────────────────────────────────────────────

def _pdf_fonts() -> Tuple[str, str, str]:
    """Register Calibri (or Carlito) with reportlab: (regular, bold, italic) names, else Helvetica."""
    from reportlab.lib.fonts import addMapping
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    paths = {s: charts.font_path(s) for s in ("regular", "bold", "italic", "bolditalic")}
    if not all(paths.values()):
        return "Helvetica", "Helvetica-Bold", "Helvetica-Oblique"
    names = {"regular": "Calibri", "bold": "Calibri-Bold", "italic": "Calibri-Italic", "bolditalic": "Calibri-BoldItalic"}
    for style, name in names.items():
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, paths[style]))
    addMapping("Calibri", 0, 0, "Calibri")
    addMapping("Calibri", 1, 0, "Calibri-Bold")
    addMapping("Calibri", 0, 1, "Calibri-Italic")
    addMapping("Calibri", 1, 1, "Calibri-BoldItalic")
    return names["regular"], names["bold"], names["italic"]


def to_pdf(c: Dict, figs: Optional[Dict[str, bytes]] = None) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.platypus import (BaseDocTemplate, Frame, Image, KeepTogether, NextPageTemplate, PageBreak,
                                    PageTemplate, Paragraph, Spacer, Table as RLTable, TableStyle)
    from reportlab.platypus.tableofcontents import TableOfContents
    from xml.sax.saxutils import escape

    figs = figs or _figures(c)
    a = c["assessment"]
    regular, bold, italic = _pdf_fonts()
    W, H = A4

    def col(rgb):
        return colors.Color(rgb[0] / 255, rgb[1] / 255, rgb[2] / 255)

    INK, GOLD, RED, SLATE, CHESTNUT = (col(charts.INK), col(charts.GOLD), col(charts.RED), col(charts.SLATE),
                                       col(charts.CHESTNUT))
    st = {
        "body": ParagraphStyle("body", fontName=regular, fontSize=10.5, leading=14, textColor=INK, spaceAfter=6),
        "H1": ParagraphStyle("H1", fontName=bold, fontSize=22, leading=26, textColor=INK, spaceAfter=12),
        "H2": ParagraphStyle("H2", fontName=bold, fontSize=14, leading=18, textColor=CHESTNUT, spaceBefore=12,
                             spaceAfter=6),
        "cap": ParagraphStyle("cap", fontName=italic, fontSize=9, leading=11, textColor=SLATE, alignment=TA_CENTER,
                              spaceBefore=3, spaceAfter=10),
        "cell": ParagraphStyle("cell", fontName=regular, fontSize=9, leading=11, textColor=INK),
        "cellb": ParagraphStyle("cellb", fontName=bold, fontSize=9, leading=11, textColor=INK),
        "bullet": ParagraphStyle("bullet", fontName=regular, fontSize=10.5, leading=14, textColor=INK,
                                 leftIndent=14, bulletIndent=2, spaceAfter=4),
        "toc1": ParagraphStyle("toc1", fontName=bold, fontSize=12, leading=18, textColor=INK),
        "toc2": ParagraphStyle("toc2", fontName=regular, fontSize=10.5, leading=14, leftIndent=18, textColor=INK),
    }

    class Doc(BaseDocTemplate):
        def afterFlowable(self, f):
            if isinstance(f, Paragraph) and f.style.name in ("H1", "H2") and getattr(f, "_toc", True):
                level = 0 if f.style.name == "H1" else 1
                key = f"h{id(f)}"
                self.canv.bookmarkPage(key)
                self.notify("TOCEntry", (level, f.getPlainText(), self.page - 1, key))

    buf = io.BytesIO()
    doc = Doc(buf, pagesize=A4, title=f"{REPORT_KIND}: {a.get('name') or ''}", author=a.get("operator") or "Shikari",
              subject=REPORT_KIND, creator="Shikari")
    margin = 2.0 * cm
    frame = Frame(margin, 2.2 * cm, W - 2 * margin, H - 4.8 * cm, id="body", leftPadding=0, rightPadding=0)
    cover_frame = Frame(0, 0, W, H, id="cover")
    bg = ImageReader(io.BytesIO(figs["background"]))
    mark = ImageReader(io.BytesIO(figs["wordmark"]))
    mw, mh = mark.getSize()

    def on_title(cv, _doc):
        cv._kind = "title"
        cv.drawImage(bg, 0, 0, W, H)
        cv.drawImage(mark, 2.4 * cm, H - 2.2 * cm - 1.9 * cm, 1.9 * cm * mw / mh, 1.9 * cm, mask="auto")
        x, y = 2.4 * cm, H - 9.4 * cm
        cv.setFillColor(GOLD)
        cv.setFont(bold, 13)
        cv.drawString(x, y, REPORT_KIND.upper())
        y -= 1.5 * cm
        cv.setFillColor(INK)
        cv.setFont(bold, 34)
        for line in _wrap(a.get("name") or "Assessment", bold, 34, 11.5 * cm):
            cv.drawString(x, y, line)
            y -= 1.25 * cm
        cv.setStrokeColor(RED)
        cv.setLineWidth(3)
        cv.line(x, y + 0.75 * cm, x + 11.5 * cm, y + 0.75 * cm)
        y -= 0.6 * cm
        if a.get("target"):
            cv.setFillColor(CHESTNUT)
            cv.setFont(regular, 16)
            cv.drawString(x, y, f"Prepared for {a['target']}")
            y -= 0.8 * cm
        cv.setFillColor(SLATE)
        cv.setFont(regular, 13)
        cv.drawString(x, y, c["report_date"])
        y -= 0.65 * cm
        if a.get("operator"):
            cv.setFont(regular, 12)
            cv.drawString(x, y, f"Operator: {a['operator']}")
        cv.setFillColor(RED)
        cv.setFont(bold, 12)
        cv.drawString(x, 3.6 * cm, "CONFIDENTIAL")
        cv.setFillColor(SLATE)
        cv.setFont(italic, 9.5)
        cv.drawString(x, 3.0 * cm, "Prepared with Shikari: automated multi-vendor threat hunting and detection")

    def on_body(cv, _doc):
        cv._kind = "body"
        cv.saveState()
        hh = 0.85 * cm
        cv.drawImage(mark, margin, H - 1.0 * cm - hh, hh * mw / mh, hh, mask="auto")
        cv.setFont(regular, 9)
        cv.setFillColor(SLATE)
        cv.drawRightString(W - margin, H - 1.0 * cm - hh + 0.2 * cm, f"{REPORT_KIND}  ·  {a.get('name') or ''}")
        cv.setStrokeColor(GOLD)
        cv.setLineWidth(1.5)
        cv.line(margin, H - 1.0 * cm - hh - 0.15 * cm, W - margin, H - 1.0 * cm - hh - 0.15 * cm)
        cv.setStrokeColor(col(RULE))
        cv.setLineWidth(0.6)
        cv.line(margin, 1.55 * cm, W - margin, 1.55 * cm)
        cv.setFont(bold, 8.5)
        cv.setFillColor(RED)
        cv.drawString(margin, 1.05 * cm, "CONFIDENTIAL")
        cv.setFont(regular, 8.5)
        cv.setFillColor(SLATE)
        centre = (f"Prepared for {a['target']}" if a.get("target") else "Shikari") + f"  ·  {c['report_date']}"
        cv.drawCentredString(W / 2, 1.05 * cm, centre)
        cv.restoreState()

    def on_back(cv, _doc):
        cv._kind = "back"
        cv.setFillColor(col(charts.MIST))
        cv.rect(0, 0, W, H, stroke=0, fill=1)
        w = 11 * cm
        cv.drawImage(mark, (W - w) / 2, H / 2, w, w * mh / mw, mask="auto")
        cv.setFont(regular, 12)
        cv.setFillColor(SLATE)
        cv.drawCentredString(W / 2, H / 2 - 1.0 * cm, "Automated multi-vendor threat hunting and detection")

    class Numbered(rl_canvas.Canvas):
        """Page x of y in the footer, counting from the first page after the title."""
        def __init__(self, *args, **kw):
            super().__init__(*args, **kw)
            self._states = []
            self._kind = "title"

        def showPage(self):
            self._states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            body_pages = sum(1 for s in self._states if s.get("_kind") == "body")
            n = 0
            for state in self._states:
                self.__dict__.update(state)
                if state.get("_kind") == "body":
                    n += 1
                    self.setFont(regular, 8.5)
                    self.setFillColor(SLATE)
                    label = f"Page {n} of {body_pages}"
                    self.drawRightString(W - margin, 1.05 * cm, label)
                super().showPage()
            super().save()

    doc.addPageTemplates([PageTemplate(id="title", frames=[cover_frame], onPage=on_title),
                          PageTemplate(id="body", frames=[frame], onPage=on_body),
                          PageTemplate(id="back", frames=[cover_frame], onPage=on_back)])

    width = W - 2 * margin
    story: List = [NextPageTemplate("body"), PageBreak()]
    figure_n = [0]
    table_n = [0]

    def P(text, style="body"):
        return Paragraph(escape(text), st[style])

    def h1(title, numbered=True):
        n = SECTIONS.index(title) + 1 if numbered and title in SECTIONS else None
        p = Paragraph(escape(f"{n}  {heading_mark(c, title)}" if n else title), st["H1"])
        rule = RLTable([[""]], colWidths=[width], rowHeights=[2])
        rule.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, -1), 2, GOLD)]))
        return [p, rule, Spacer(1, 8)]

    sub = {"sec": 0, "n": 0}

    def section(title, first=False):
        sub.update(sec=SECTIONS.index(title) + 1, n=0)
        out = [] if first else [PageBreak()]
        return out + h1(title)

    def h2(title):
        sub["n"] += 1
        return Paragraph(escape(f"{sub['sec']}.{sub['n']}  {heading_mark(c, title)}"), st["H2"])

    def figure(key, text, width_cm=17.0):
        if key not in figs:
            return []
        reader = ImageReader(io.BytesIO(figs[key]))
        iw, ih = reader.getSize()
        w = min(width_cm * cm, width)
        figure_n[0] += 1
        return [KeepTogether([Image(io.BytesIO(figs[key]), w, w * ih / iw),
                              P(f"Figure {figure_n[0]}: {text}", "cap")])]

    def table(spec: Table, caption: str = "", first_col_bold=False):
        headers, rows, widths, fills = spec
        scale = width / (sum(widths) * cm)
        cells = [[Paragraph(escape(h), ParagraphStyle("th", parent=st["cellb"], textColor=colors.white))
                  for h in headers]]
        style = [("BACKGROUND", (0, 0), (-1, 0), INK), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("GRID", (0, 0), (-1, -1), 0.5, col(RULE)), ("TOPPADDING", (0, 0), (-1, -1), 3),
                 ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LEFTPADDING", (0, 0), (-1, -1), 5),
                 ("RIGHTPADDING", (0, 0), (-1, -1), 5)]
        for i, row in enumerate(rows):
            if i % 2:
                style.append(("BACKGROUND", (0, i + 1), (-1, i + 1), col(BAND)))
            line = []
            for j, value in enumerate(row):
                fill = fills.get((i, j))
                if fill:
                    style.append(("BACKGROUND", (j, i + 1), (j, i + 1), col(fill)))
                    line.append(Paragraph(escape(value), ParagraphStyle(
                        "f", parent=st["cellb"], textColor=col(charts._ideal_ink(fill)))))
                else:
                    line.append(Paragraph(escape(value), st["cellb" if first_col_bold and j == 0 else "cell"]))
            cells.append(line)
        t = RLTable(cells, colWidths=[w * cm * scale for w in widths], repeatRows=1)
        t.setStyle(TableStyle(style))
        out = [t]
        if caption:
            table_n[0] += 1
            out.append(P(f"Table {table_n[0]}: {caption}", "cap"))
        else:
            out.append(Spacer(1, 8))
        return out

    def finding(x):
        rows = finding_rows(x)
        fill = BLUE_FILL[x["blue_outcome"]]
        ink = col(charts._ideal_ink(fill))
        head = Paragraph(escape(f"{x['ref']}   {x.get('technique_id') or ''}  {x.get('technique_name') or ''}"
                                f"   ·   {x['rating']}"),
                         ParagraphStyle("fh", parent=st["cellb"], fontSize=11, leading=14, textColor=ink))
        cells = [[head, ""]]
        style = [("SPAN", (0, 0), (1, 0)), ("BACKGROUND", (0, 0), (1, 0), col(fill)),
                 ("GRID", (0, 0), (-1, -1), 0.5, col(RULE)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("BACKGROUND", (0, 1), (0, -1), col(BAND)), ("TOPPADDING", (0, 0), (-1, -1), 3),
                 ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
        for i, (label, value, vfill) in enumerate(rows, 1):
            if vfill:
                style.append(("BACKGROUND", (1, i), (1, i), col(vfill)))
                v = Paragraph(escape(value), ParagraphStyle("v", parent=st["cellb"],
                                                            textColor=col(charts._ideal_ink(vfill))))
            else:
                v = Paragraph(escape(value), st["cell"])
            cells.append([Paragraph(escape(label), st["cellb"]), v])
        t = RLTable(cells, colWidths=[4.2 * cm, width - 4.2 * cm])
        t.setStyle(TableStyle(style))
        return [KeepTogether([t]), Spacer(1, 10)]

    # Table of Contents
    toc = TableOfContents()
    toc.levelStyles = [st["toc1"], st["toc2"]]
    toc.dotsMinLevel = 0
    contents = Paragraph("Table of Contents", st["H1"])
    contents._toc = False
    rule = RLTable([[""]], colWidths=[width], rowHeights=[2])
    rule.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, -1), 2, GOLD)]))
    story += [contents, rule, Spacer(1, 10), toc]

    story += section("Executive Summary")
    if c["summary"]:
        story += [P(s.strip()) for s in c["summary"].split("\n\n") if s.strip()]
    story += [P(t) for t in data.executive_paragraphs(c)]
    story += figure("scorecard", "Headline results. Detection rate: alerted or prevented, of the tests assessed. "
                                 "Visibility: reached the logs at all.")
    if c["rated"]:
        story += [h2("Highest-rated findings")] + table(top_risks_table(c), "The five highest-rated findings "
                                                                           "(all are in section 4).")

    story += section("Scope")
    story.append(P("The assessment emulated the adversaries below against the target, one MITRE ATT&CK technique "
                   "per test case, recording what each attack did (red) and what the defence saw (blue)."))
    story += table(scope_table(c), "The assessment.", first_col_bold=True)
    if c["tactics"]:
        story += [h2("Techniques by tactic")] + table(tactic_table(c), "Test cases per tactic, by defensive outcome.")

    story += section("Assumptions")
    story += [Paragraph(escape(t), st["bullet"], bulletText="•") for t in data.assumptions(c)]

    story += section("Findings")
    if not c["rows"]:
        story.append(P("No test cases had been added to this assessment, so there are no findings."))
    else:
        story += [h2("Overview"), P(f"{plural_tests(c)} The charts show what the defence saw, what the attacks did, "
                                    "and where in the attack the defence held or missed.")]
        story += figure("blue", "Defensive (blue) outcomes across all test cases.")
        story += figure("red", "Attack (red) outcomes across all test cases.", 15.0)
        story += figure("tactics", "Defensive outcomes by tactic.")
        story += [h2("Coverage matrix"), P("Each technique tested, under its tactic, coloured by its defensive "
                                           "outcome. A technique tested more than once shows its worst outcome.")]
        story += figure("matrix", "The assessment's techniques as an ATT&CK matrix.")
        story += [h2("Findings by technique"), P("Each test case as a finding, highest rated first. The reference "
                                                  "(F-nn) is used throughout the report.")]
        for x in c["rows"]:
            story += finding(x)

    story += section("Risks")
    if not c["rated"]:
        story.append(P("No test case had both its attack and defensive outcome recorded, so no risk could be rated."))
    else:
        story.append(P("Each finding is rated by likelihood (what the attack did) and impact (what the defence saw), "
                       "as Appendix B sets out. The matrix counts the findings at each rating."))
        story += figure("heat", "Findings by likelihood and impact.", 14.0)
        story += [h2("Risk register")] + table(risk_register(c), "Every rated finding.")

    story += section("Recommendations")
    if c["gaps"]:
        story.append(P("Each technique that was logged but not alerted on, or not logged at all, is a gap. "
                       + data.gaps_paragraph(c)))
        story += figure("ready", "Gaps by whether deploying a library detection would close them.", 15.0)
        story += [h2("Closing the gaps")] + table(recommendations_table(c), "One action per gap, highest priority "
                                                                           "first. Library: detections available.")
    else:
        story.append(P(data.no_gaps_sentence(c)))
    story += [h2("General recommendations")] + table(
        (["Recommendation", "Detail"], [list(r) for r in data.GENERAL_RECOMMENDATIONS], [4.6, 12.4], {}),
        "Recommendations for the programme as a whole.", first_col_bold=True)

    story += section("Conclusions")
    if c["conclusion"]:
        story += [P(s.strip()) for s in c["conclusion"].split("\n\n") if s.strip()]
    story += [P(t) for t in data.conclusion_paragraphs(c)]

    story += section("Appendices")
    story += [h2("Appendix A: Outcome definitions")] + table(outcome_definitions(), "What each recorded outcome means.")
    story += [h2("Appendix B: Risk rating method"),
              P("Likelihood comes from the red outcome (executed 3, failed 2, blocked 1) and impact from the blue "
                "outcome (not logged 3, logged 2, alerted or prevented 1). The rating is their product.")]
    story += table(rating_method(), "Ratings by likelihood and impact.", first_col_bold=True)
    story += [h2("Appendix C: Lab runs and SIEM export packs"), P(lab_paragraph(c))]
    if c["lab_runs"]:
        story += table(lab_runs_table(c), "Lab runs covering this assessment's techniques.")
    story.append(h2("Appendix D: Test cases"))
    story += table(test_cases_table(c), "Every test case in the assessment.") if c["rows"] else [P("None.")]
    story.append(h2("Appendix E: Candidate detections"))
    spec = candidates_table(c)
    story += table(spec, "Detections in the Shikari library for each gap.") if spec[1] else [
        P("None: either there were no gaps, or the library holds no detections for them.")]

    note = ParagraphStyle("note", parent=st["cell"], textColor=SLATE, spaceAfter=4)
    box = RLTable([[[Paragraph(escape(t), note) for t in data.ai_disclaimer(c)]]], colWidths=[width])
    box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), col(BAND)), ("BOX", (0, 0), (-1, -1), 0.5, col(RULE)),
                             ("LINEBEFORE", (0, 0), (0, -1), 3, GOLD), ("LEFTPADDING", (0, 0), (-1, -1), 10),
                             ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story += [Spacer(1, 18), KeepTogether([box])]

    story += [NextPageTemplate("back"), PageBreak(), Spacer(1, 1)]
    doc.multiBuild(story, canvasmaker=Numbered)
    return buf.getvalue()


def _wrap(text: str, font: str, size: float, width: float) -> List[str]:
    from reportlab.pdfbase.pdfmetrics import stringWidth

    lines, line = [], ""
    for word in text.split():
        trial = (line + " " + word).strip()
        if stringWidth(trial, font, size) <= width or not line:
            line = trial
        else:
            lines.append(line)
            line = word
    return lines + ([line] if line else [])


def render(c: Dict, fmt: str) -> bytes:
    """The report as 'docx' or 'pdf'."""
    figs = _figures(c)
    return to_pdf(c, figs) if fmt == "pdf" else to_docx(c, figs)

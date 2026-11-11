"""
The branded report shell, in Word and PDF: a title page with the bateleur on its branch filling the
page, the TLP label, a header and footer on every page after it with page numbers, a table of
contents, numbered sections, Calibri throughout, the logo's and the bird's colours, and a back cover.

A report describes its content once, as blocks, and both formats render them:

    ("section", title)                      numbered, on a new page
    ("sub", title)                          numbered within its section
    ("para", text)
    ("bullets", [text, ...])
    ("table", spec, caption, first_col_bold)  spec: (headers, rows, widths in cm, {(row, col): fill})
    ("figure", png, caption, width_cm)
    ("card", title, fill, [(label, value, fill or None), ...])   kept on one page
    ("note", [text, ...])                   a boxed note (the AI disclaimer)
"""

import io
from dataclasses import dataclass, field as dc_field
from typing import Dict, List, Sequence, Tuple

from shikari.reports import assessment_charts as charts
from shikari.reports import theme as theme_mod
from shikari.reports import tlp as tlp_mod

BAND = (247, 244, 242)        # alternate table rows: the wing grey at its palest
RULE = (214, 206, 202)
TAGLINE = "Automated multi-vendor threat hunting and detection"

Table = Tuple[List[str], List[List[str]], List[float], Dict[Tuple[int, int], Tuple[int, int, int]]]


@dataclass
class Cover:
    kind: str                       # "Adversary Emulation Assessment"
    title: str                      # the assessment's or campaign's name
    date: str
    tlp: str
    prepared_for: str = ""
    lines: List[str] = dc_field(default_factory=list)   # under the date: "Operator: B. Smith"


def _hex(rgb: Tuple[int, int, int]) -> str:
    return "%02X%02X%02X" % rgb


def sections_of(blocks: Sequence[tuple]) -> List[str]:
    return [b[1] for b in blocks if b[0] == "section"]


# ── Word ──────────────────────────────────────────────────────────────────────

def to_docx(cover: Cover, blocks: Sequence[tuple], theme: "theme_mod.ReportTheme" = None) -> bytes:
    from docx import Document
    from docx.enum.section import WD_SECTION
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_TAB_ALIGNMENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Cm, Pt, RGBColor

    th = theme or theme_mod.DEFAULT
    brand = th.brand_assets()
    # The chrome palette comes from the theme; the neutral greys stay. Severity/rating fills are
    # passed in per cell by the report, so they're never touched here.
    INK, GOLD, RED, CHESTNUT = th.dark, th.primary, th.secondary, th.heading
    WHITE, SLATE, MIST = charts.WHITE, charts.SLATE, charts.MIST
    head_ink = charts._ideal_ink(INK)   # text that reads on the (possibly recoloured) header fill
    label = tlp_mod.normalise(cover.tlp)
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

    normal = style_font("Normal", 10.5, colour=INK)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.12
    h1 = style_font("Heading 1", 22, True, INK)
    h1.paragraph_format.space_before = Pt(0)
    h1.paragraph_format.space_after = Pt(10)
    h2 = style_font("Heading 2", 14, True, CHESTNUT)
    h2.paragraph_format.space_before = Pt(14)
    h2.paragraph_format.space_after = Pt(6)
    style_font("Heading 3", 12, True, INK)
    for name in ("Caption", "List Bullet", "Title", "Subtitle", "TOC Heading"):
        try:
            style_font(name)
        except KeyError:
            pass
    caption = doc.styles["Caption"]
    caption.font.size = Pt(9)
    caption.font.italic = True
    caption.font.bold = False
    caption.font.color.rgb = RGBColor(*SLATE)
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

    def fld(p, code, placeholder="1", size=None, colour=None, bold=False):
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

    def tlp_badge(p, size):
        """The TLP label as FIRST shows it: its colour on black."""
        r = p.add_run(f" {label} ")
        r.font.size, r.font.bold = Pt(size), True
        r.font.color.rgb = RGBColor(*tlp_mod.colour(label))
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), "000000")
        r._r.get_or_add_rPr().append(shd)

    def shade(cell, rgb):
        tcpr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), _hex(rgb))
        tcpr.append(shd)

    def cell_text(cell, text, bold=False, colour=None, size=9.5):
        cell.text = ""
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.space_before = Pt(0)
        run = p.add_run(text)
        run.font.size = Pt(size)
        run.font.bold = bold
        if colour:
            run.font.color.rgb = RGBColor(*colour)

    def grid(t):
        borders = OxmlElement("w:tblBorders")
        for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
            el = OxmlElement(f"w:{side}")
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), "4")
            el.set(qn("w:color"), _hex(RULE))
            borders.append(el)
        t._tbl.tblPr.append(borders)

    counters = {"figure": 0, "table": 0, "sec": 0, "sub": 0}

    def table(spec: Table, caption_text: str = "", first_col_bold=False):
        headers, rows, widths, fills = spec
        t = doc.add_table(rows=1 + len(rows), cols=len(headers))
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        t.autofit = False
        grid(t)
        tblpr = t._tbl.tblPr
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
            cell_text(cell, h, bold=True, colour=head_ink)
            shade(cell, INK)
            cell.paragraphs[0].paragraph_format.keep_with_next = True   # never alone at the foot of a page
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
            counters["table"] += 1
            cap = doc.add_paragraph(f"Table {counters['table']}: {caption_text}", style="Caption")
            cap.paragraph_format.space_before = Pt(4)
        else:
            doc.add_paragraph().paragraph_format.space_after = Pt(2)

    def card(title, fill, rows):
        t = doc.add_table(rows=1 + len(rows), cols=2)
        t.autofit = False
        head = t.rows[0].cells[0].merge(t.rows[0].cells[1])
        cell_text(head, title, bold=True, colour=charts._ideal_ink(fill), size=11)
        shade(head, fill)
        for i, (lab, value, vfill) in enumerate(rows, 1):
            lc, vc = t.rows[i].cells
            cell_text(lc, lab, bold=True, colour=INK)
            shade(lc, BAND)
            if vfill:
                cell_text(vc, value, bold=True, colour=charts._ideal_ink(vfill))
                shade(vc, vfill)
            else:
                cell_text(vc, value)
        grid(t)
        for row in t.rows[:-1]:  # keep the card on one page
            for cell in row.cells:
                for cp in cell.paragraphs:
                    cp.paragraph_format.keep_with_next = True
        for row in t.rows[1:]:
            row.cells[0].width, row.cells[1].width = Cm(4.2), Cm(12.8)
            row._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))
        doc.add_paragraph().paragraph_format.space_after = Pt(4)

    def note(paras):
        box = doc.add_table(rows=1, cols=1)
        box.autofit = False
        cell = box.rows[0].cells[0]
        cell.width = Cm(17.0)
        shade(cell, BAND)
        tcb = OxmlElement("w:tcBorders")
        for side, colour, size in (("left", GOLD, "24"), ("top", RULE, "4"), ("bottom", RULE, "4"),
                                   ("right", RULE, "4")):
            el = OxmlElement(f"w:{side}")
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), size)
            el.set(qn("w:color"), _hex(colour))
            tcb.append(el)
        cell._tc.get_or_add_tcPr().append(tcb)
        cell.text = ""
        for i, text in enumerate(paras):
            dp = cell.paragraphs[0] if i == 0 else cell.add_paragraph()
            dp.paragraph_format.space_after = Pt(4)
            r = dp.add_run(text)
            r.font.size = Pt(9)
            r.font.color.rgb = RGBColor(*SLATE)
        doc.paragraphs[-1].paragraph_format.space_before = Pt(18)

    # ── Section 1: the title page, no header or footer ──
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
    sec.left_margin = sec.right_margin = Cm(2.4)
    sec.top_margin, sec.bottom_margin = Cm(2.2), Cm(1.6)
    anchor_p = doc.paragraphs[0] if doc.paragraphs else doc.add_paragraph()
    run = anchor_p.add_run()
    run.add_picture(io.BytesIO(brand["background"]), width=Cm(21.0), height=Cm(29.7))
    _float_behind(run, Cm(21.0), Cm(29.7))
    run.add_picture(io.BytesIO(brand["lead"]), height=Cm(1.9))
    anchor_p.paragraph_format.space_after = Pt(0)

    def title_line(text, size, bold=False, colour=INK, before=0, after=4, italic=False):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(before)
        p.paragraph_format.space_after = Pt(after)
        p.paragraph_format.right_indent = Cm(6.5)
        r = p.add_run(text)
        r.font.size, r.font.bold, r.font.italic = Pt(size), bold, italic
        r.font.color.rgb = RGBColor(*colour)
        return p

    title_line(cover.kind.upper(), 13, True, GOLD, before=150, after=6)
    t = title_line(cover.title, 34, True, INK, after=8)
    t.paragraph_format.line_spacing = 0.95
    border(t, "bottom", RED, size=24, space=8)
    if cover.prepared_for:
        title_line(f"Prepared for {cover.prepared_for}", 16, False, CHESTNUT, before=10, after=2)
    title_line(cover.date, 13, False, SLATE, before=2, after=2)
    for line in cover.lines:
        title_line(line, 12, False, SLATE, after=2)
    badge = doc.add_paragraph()
    badge.paragraph_format.space_before = Pt(150)
    badge.paragraph_format.space_after = Pt(3)
    tlp_badge(badge, 12)
    title_line(tlp_mod.rule(label), 9.5, False, SLATE, after=10)
    if th.show_shikari:
        title_line(f"Prepared with Shikari: {TAGLINE.lower()}", 9.5, False, SLATE, italic=True)

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
    hp.add_run().add_picture(io.BytesIO(brand["lead"]), height=Cm(0.85))
    r = hp.add_run(f"\t{cover.kind}  ·  {cover.title}")
    r.font.size = Pt(9)
    r.font.color.rgb = RGBColor(*SLATE)
    border(hp, "bottom", GOLD, size=12, space=4)

    fp = body.footer.paragraphs[0]
    own_tabs(fp, (Cm(8.5), WD_TAB_ALIGNMENT.CENTER), (Cm(17.0), WD_TAB_ALIGNMENT.RIGHT))
    border(fp, "top", RULE, size=6, space=4)
    tlp_badge(fp, 8.5)
    default_who = "Shikari" if th.show_shikari else (th.org_name or "")
    who = f"Prepared for {cover.prepared_for}" if cover.prepared_for else default_who
    r = fp.add_run(f"\t{who}  ·  {cover.date}\tPage ")
    r.font.size = Pt(8.5)
    r.font.color.rgb = RGBColor(*SLATE)
    fld(fp, "PAGE", "1", 8.5, INK, True)
    r = fp.add_run(" of ")
    r.font.size = Pt(8.5)
    r.font.color.rgb = RGBColor(*SLATE)
    fld(fp, "SECTIONPAGES", "1", 8.5, INK, True)

    # ── Table of Contents (Word fills the page numbers in when it opens the file) ──
    p = doc.add_heading("Table of Contents", level=1)
    p.style = doc.styles["TOC Heading"] if "TOC Heading" in [s.name for s in doc.styles] else p.style
    p.runs[0].font.size, p.runs[0].font.bold = Pt(22), True
    p.runs[0].font.color.rgb = RGBColor(*INK)
    border(p, "bottom", GOLD, size=18, space=6)
    _toc_field(doc.add_paragraph(), [f"{i}  {s}" for i, s in enumerate(sections_of(blocks), 1)])
    _update_fields_on_open(doc)

    for b in blocks:
        kind = b[0]
        if kind == "section":
            counters["sec"] += 1
            counters["sub"] = 0
            doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
            doc.paragraphs[-1].paragraph_format.space_after = Pt(0)
            border(doc.add_heading(f"{counters['sec']}  {b[1]}", level=1), "bottom", GOLD, size=18, space=6)
        elif kind == "sub":
            counters["sub"] += 1
            doc.add_heading(f"{counters['sec']}.{counters['sub']}  {b[1]}", level=2)
        elif kind == "para":
            doc.add_paragraph().add_run(b[1])
        elif kind == "bullets":
            for item in b[1]:
                doc.add_paragraph(item, style="List Bullet")
        elif kind == "table":
            table(b[1], b[2], first_col_bold=b[3] if len(b) > 3 else False)
        elif kind == "figure":
            png, text, width_cm = b[1], b[2], b[3] if len(b) > 3 else 17.0
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.keep_with_next = True
            p.add_run().add_picture(io.BytesIO(png), width=Cm(width_cm))
            counters["figure"] += 1
            doc.add_paragraph(f"Figure {counters['figure']}: {text}", style="Caption").alignment = \
                WD_ALIGN_PARAGRAPH.CENTER
        elif kind == "card":
            card(b[1], b[2], b[3])
        elif kind == "note":
            note(b[1])

    # Back cover: a section of its own, without the header and footer. It carries the Shikari
    # co-brand mark, so it's dropped when the install has turned attribution off.
    back = doc.add_section(WD_SECTION.NEW_PAGE)
    for part in (back.header, back.footer):
        part.is_linked_to_previous = False
    if th.show_shikari:
        for _ in range(9):
            doc.add_paragraph()
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run().add_picture(io.BytesIO(brand["shikari"]), width=Cm(11.0))
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(TAGLINE)
        r.font.size, r.font.color.rgb = Pt(12), RGBColor(*SLATE)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


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

    el = OxmlElement("w:updateFields")
    el.set(qn("w:val"), "true")
    doc.settings.element.append(el)


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


def to_pdf(cover: Cover, blocks: Sequence[tuple], theme: "theme_mod.ReportTheme" = None) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.platypus import (BaseDocTemplate, Frame, Image, KeepTogether, NextPageTemplate, PageBreak,
                                    PageTemplate, Paragraph, Spacer, Table as RLTable, TableStyle)
    from reportlab.platypus.tableofcontents import TableOfContents
    from xml.sax.saxutils import escape

    th = theme or theme_mod.DEFAULT
    brand = th.brand_assets()
    label = tlp_mod.normalise(cover.tlp)
    regular, bold, italic = _pdf_fonts()
    W, H = A4

    def col(rgb):
        return colors.Color(rgb[0] / 255, rgb[1] / 255, rgb[2] / 255)

    # Chrome palette from the theme; neutral greys stay. head_ink reads on the (possibly
    # recoloured) table-header fill.
    INK, GOLD, RED, CHESTNUT = col(th.dark), col(th.primary), col(th.secondary), col(th.heading)
    SLATE = col(charts.SLATE)
    head_ink = col(charts._ideal_ink(th.dark))
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
                key = f"h{id(f)}"
                self.canv.bookmarkPage(key)
                self.notify("TOCEntry", (0 if f.style.name == "H1" else 1, f.getPlainText(), self.page - 1, key))

    buf = io.BytesIO()
    doc = Doc(buf, pagesize=A4, title=f"{cover.kind}: {cover.title}", author="Shikari", subject=cover.kind,
              creator="Shikari")
    margin = 2.0 * cm
    width = W - 2 * margin
    frame = Frame(margin, 2.2 * cm, width, H - 4.8 * cm, id="body", leftPadding=0, rightPadding=0)
    cover_frame = Frame(0, 0, W, H, id="cover")
    bg = ImageReader(io.BytesIO(brand["background"]))
    lead = ImageReader(io.BytesIO(brand["lead"]))          # cover + header mark (logo strip, or Shikari)
    lw, lh = lead.getSize()
    shikari_mark = ImageReader(io.BytesIO(brand["shikari"]))   # the co-brand mark on the back cover
    sw, sh = shikari_mark.getSize()

    def badge(cv, x, y, size):
        """The TLP label as FIRST shows it: its colour on black."""
        w = stringWidth(label, bold, size) + size * 0.8
        cv.setFillColor(colors.black)
        cv.rect(x, y - size * 0.3, w, size * 1.25, stroke=0, fill=1)
        cv.setFillColor(col(tlp_mod.colour(label)))
        cv.setFont(bold, size)
        cv.drawString(x + size * 0.4, y, label)

    def on_title(cv, _doc):
        cv._kind = "title"
        cv.drawImage(bg, 0, 0, W, H)
        cv.drawImage(lead, 2.4 * cm, H - 4.1 * cm, 1.9 * cm * lw / lh, 1.9 * cm, mask="auto")
        x, y = 2.4 * cm, H - 9.4 * cm
        cv.setFillColor(GOLD)
        cv.setFont(bold, 13)
        cv.drawString(x, y, cover.kind.upper())
        y -= 1.5 * cm
        cv.setFillColor(INK)
        cv.setFont(bold, 34)
        for line in _wrap(cover.title, bold, 34, 11.5 * cm):
            cv.drawString(x, y, line)
            y -= 1.25 * cm
        cv.setStrokeColor(RED)
        cv.setLineWidth(3)
        cv.line(x, y + 0.75 * cm, x + 11.5 * cm, y + 0.75 * cm)
        y -= 0.6 * cm
        if cover.prepared_for:
            cv.setFillColor(CHESTNUT)
            cv.setFont(regular, 16)
            cv.drawString(x, y, f"Prepared for {cover.prepared_for}")
            y -= 0.8 * cm
        cv.setFillColor(SLATE)
        cv.setFont(regular, 13)
        cv.drawString(x, y, cover.date)
        y -= 0.65 * cm
        cv.setFont(regular, 12)
        for line in cover.lines:
            cv.drawString(x, y, line)
            y -= 0.55 * cm
        badge(cv, x, 4.1 * cm, 12)
        cv.setFillColor(SLATE)
        cv.setFont(regular, 9.5)
        for i, line in enumerate(_wrap(tlp_mod.rule(label), regular, 9.5, 11.5 * cm)):
            cv.drawString(x, 3.45 * cm - i * 0.42 * cm, line)
        if th.show_shikari:
            cv.setFont(italic, 9.5)
            cv.drawString(x, 2.2 * cm, f"Prepared with Shikari: {TAGLINE.lower()}")

    def on_body(cv, _doc):
        cv._kind = "body"
        cv.saveState()
        hh = 0.85 * cm
        cv.drawImage(lead, margin, H - 1.0 * cm - hh, hh * lw / lh, hh, mask="auto")
        cv.setFont(regular, 9)
        cv.setFillColor(SLATE)
        cv.drawRightString(W - margin, H - 1.0 * cm - hh + 0.2 * cm, f"{cover.kind}  ·  {cover.title}")
        cv.setStrokeColor(GOLD)
        cv.setLineWidth(1.5)
        cv.line(margin, H - 1.0 * cm - hh - 0.15 * cm, W - margin, H - 1.0 * cm - hh - 0.15 * cm)
        cv.setStrokeColor(col(RULE))
        cv.setLineWidth(0.6)
        cv.line(margin, 1.55 * cm, W - margin, 1.55 * cm)
        badge(cv, margin, 1.05 * cm, 8.5)
        cv.setFont(regular, 8.5)
        cv.setFillColor(SLATE)
        default_who = "Shikari" if th.show_shikari else (th.org_name or "")
        who = f"Prepared for {cover.prepared_for}" if cover.prepared_for else default_who
        cv.drawCentredString(W / 2, 1.05 * cm, f"{who}  ·  {cover.date}")
        cv.restoreState()

    def on_back(cv, _doc):
        cv._kind = "back"
        cv.setFillColor(col(charts.MIST))
        cv.rect(0, 0, W, H, stroke=0, fill=1)
        if th.show_shikari:
            w = 11 * cm
            cv.drawImage(shikari_mark, (W - w) / 2, H / 2, w, w * sh / sw, mask="auto")
            cv.setFont(regular, 12)
            cv.setFillColor(SLATE)
            cv.drawCentredString(W / 2, H / 2 - 1.0 * cm, TAGLINE)

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
                    self.drawRightString(W - margin, 1.05 * cm, f"Page {n} of {body_pages}")
                super().showPage()
            super().save()

    doc.addPageTemplates([PageTemplate(id="title", frames=[cover_frame], onPage=on_title),
                          PageTemplate(id="body", frames=[frame], onPage=on_body),
                          PageTemplate(id="back", frames=[cover_frame], onPage=on_back)])

    def P(text, style="body"):
        return Paragraph(escape(text), st[style])

    def rule_line():
        r = RLTable([[""]], colWidths=[width], rowHeights=[2])
        r.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, -1), 2, GOLD)]))
        return r

    def table(spec: Table, caption: str, first_col_bold: bool):
        headers, rows, widths, fills = spec
        scale = width / (sum(widths) * cm)
        cells = [[Paragraph(escape(h), ParagraphStyle("th", parent=st["cellb"], textColor=head_ink))
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
        if caption:
            counters["table"] += 1
            return [t, P(f"Table {counters['table']}: {caption}", "cap")]
        return [t, Spacer(1, 8)]

    def card(title, fill, rows):
        head = Paragraph(escape(title), ParagraphStyle("fh", parent=st["cellb"], fontSize=11, leading=14,
                                                       textColor=col(charts._ideal_ink(fill))))
        cells = [[head, ""]]
        style = [("SPAN", (0, 0), (1, 0)), ("BACKGROUND", (0, 0), (1, 0), col(fill)),
                 ("GRID", (0, 0), (-1, -1), 0.5, col(RULE)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("BACKGROUND", (0, 1), (0, -1), col(BAND)), ("TOPPADDING", (0, 0), (-1, -1), 3),
                 ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
        for i, (lab, value, vfill) in enumerate(rows, 1):
            if vfill:
                style.append(("BACKGROUND", (1, i), (1, i), col(vfill)))
                v = Paragraph(escape(value), ParagraphStyle("v", parent=st["cellb"],
                                                            textColor=col(charts._ideal_ink(vfill))))
            else:
                v = Paragraph(escape(value), st["cell"])
            cells.append([Paragraph(escape(lab), st["cellb"]), v])
        t = RLTable(cells, colWidths=[4.2 * cm, width - 4.2 * cm])
        t.setStyle(TableStyle(style))
        return [KeepTogether([t]), Spacer(1, 10)]

    counters = {"figure": 0, "table": 0, "sec": 0, "sub": 0}
    toc = TableOfContents()
    toc.levelStyles = [st["toc1"], st["toc2"]]
    toc.dotsMinLevel = 0
    contents = Paragraph("Table of Contents", st["H1"])
    contents._toc = False
    story: List = [NextPageTemplate("body"), PageBreak(), contents, rule_line(), Spacer(1, 10), toc]

    for b in blocks:
        kind = b[0]
        if kind == "section":
            counters["sec"] += 1
            counters["sub"] = 0
            story += [PageBreak(), Paragraph(escape(f"{counters['sec']}  {b[1]}"), st["H1"]), rule_line(),
                      Spacer(1, 8)]
        elif kind == "sub":
            counters["sub"] += 1
            story.append(Paragraph(escape(f"{counters['sec']}.{counters['sub']}  {b[1]}"), st["H2"]))
        elif kind == "para":
            story.append(P(b[1]))
        elif kind == "bullets":
            story += [Paragraph(escape(t), st["bullet"], bulletText="•") for t in b[1]]
        elif kind == "table":
            story += table(b[1], b[2], b[3] if len(b) > 3 else False)
        elif kind == "figure":
            png, text, width_cm = b[1], b[2], b[3] if len(b) > 3 else 17.0
            iw, ih = ImageReader(io.BytesIO(png)).getSize()
            w = min(width_cm * cm, width)
            counters["figure"] += 1
            story.append(KeepTogether([Image(io.BytesIO(png), w, w * ih / iw),
                                       P(f"Figure {counters['figure']}: {text}", "cap")]))
        elif kind == "card":
            story += card(b[1], b[2], b[3])
        elif kind == "note":
            note = ParagraphStyle("note", parent=st["cell"], textColor=SLATE, spaceAfter=4)
            box = RLTable([[[Paragraph(escape(t), note) for t in b[1]]]], colWidths=[width])
            box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), col(BAND)),
                                     ("BOX", (0, 0), (-1, -1), 0.5, col(RULE)),
                                     ("LINEBEFORE", (0, 0), (0, -1), 3, GOLD), ("LEFTPADDING", (0, 0), (-1, -1), 10),
                                     ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
            story += [Spacer(1, 18), KeepTogether([box])]

    story += [NextPageTemplate("back"), PageBreak(), Spacer(1, 1)]
    doc.multiBuild(story, canvasmaker=Numbered)
    return buf.getvalue()


def render(cover: Cover, blocks: Sequence[tuple], fmt: str,
           theme: "theme_mod.ReportTheme" = None) -> bytes:
    """The report as 'docx' or 'pdf', in the install's branding (the stock Shikari look when
    none is set)."""
    th = theme or theme_mod.active_theme()
    return to_pdf(cover, blocks, th) if fmt == "pdf" else to_docx(cover, blocks, th)

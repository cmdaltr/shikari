"""
The assessment report (#42): what a consultant or internal red team hands the client or the SOC
at the end of a purple-team or CALDERA campaign, as Word and PDF.

Both formats carry the same content (assessment_data.py) and the same brand: a title page with
the bateleur on its branch filling the page, Calibri throughout, a header and footer on every
page after it with page numbers, and the logo's and the bird's colours in the tables and figures.
"""

from typing import Dict, List, Optional, Tuple

from shikari.reports import assessment_charts as charts
from shikari.reports import assessment_data as data
from shikari.reports import branded

REPORT_KIND = "Adversary Emulation Assessment"
SECTIONS = ["Executive Summary", "Scope", "Assumptions", "Findings", "Risks", "Recommendations",
            "Conclusions", "Appendices"]


BLUE_FILL = {k: c for k, _, c in charts.BLUE_OUTCOMES}
RED_FILL = {k: c for k, _, c in charts.RED_OUTCOMES}
RATING_FILL = {**charts.RATING_COLOUR, "Unrated": (214, 206, 202)}


def _figures(c: Dict) -> Dict[str, bytes]:
    """Every figure the report uses, drawn once for both formats."""
    figs = {}
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

Table = branded.Table


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


# ── The report: its content once, as blocks; branded.py renders both formats ──

def plural_tests(c: Dict) -> str:
    return (f"{data.plural(len(c['rows']), 'test case')} covered {data.plural(len(c['techniques']), 'technique')} "
            f"across {data.plural(len(c['tactics']), 'tactic')}.")


def cover(c: Dict) -> branded.Cover:
    a = c["assessment"]
    return branded.Cover(kind=REPORT_KIND, title=a.get("name") or "Assessment", date=c["report_date"], tlp=c["tlp"],
                         prepared_for=a.get("target") or "",
                         lines=[f"Operator: {a['operator']}"] if a.get("operator") else [])


def blocks(c: Dict, figs: Dict[str, bytes]) -> List[tuple]:
    out: List[tuple] = []

    def section(title):
        out.append(("section", heading_mark(c, title)))

    def sub(title):
        out.append(("sub", heading_mark(c, title)))

    def para(text):
        out.append(("para", text))

    def table(spec, caption, first_col_bold=False):
        out.append(("table", spec, caption, first_col_bold))

    def figure(key, caption, width_cm=17.0):
        if key in figs:
            out.append(("figure", figs[key], caption, width_cm))

    def own(text):
        for chunk in [s for s in (text or "").split("\n\n") if s.strip()]:
            para(chunk.strip())

    section("Executive Summary")
    own(c["summary"])
    for text in data.executive_paragraphs(c):
        para(text)
    figure("scorecard", "Headline results. Detection rate: alerted or prevented, of the tests assessed. "
                        "Visibility: reached the logs at all.")
    if c["rated"]:
        sub("Highest-rated findings")
        table(top_risks_table(c), "The five highest-rated findings (all are in section 4).")

    section("Scope")
    para("The assessment emulated the adversaries below against the target, one MITRE ATT&CK technique per test "
         "case, recording what each attack did (red) and what the defence saw (blue).")
    table(scope_table(c), "The assessment.", first_col_bold=True)
    if c["tactics"]:
        sub("Techniques by tactic")
        table(tactic_table(c), "Test cases per tactic, by defensive outcome.")

    section("Assumptions")
    out.append(("bullets", data.assumptions(c)))

    section("Findings")
    if not c["rows"]:
        para("No test cases had been added to this assessment, so there are no findings.")
    else:
        sub("Overview")
        para(f"{plural_tests(c)} The charts show what the defence saw, what the attacks did, and where in the "
             "attack the defence held or missed.")
        figure("blue", "Defensive (blue) outcomes across all test cases.")
        figure("red", "Attack (red) outcomes across all test cases.", 15.0)
        figure("tactics", "Defensive outcomes by tactic.")
        sub("Coverage matrix")
        para("Each technique tested, under its tactic, coloured by its defensive outcome. A technique tested more "
             "than once shows its worst outcome.")
        figure("matrix", "The assessment's techniques as an ATT&CK matrix.")
        sub("Findings by technique")
        para("Each test case as a finding, highest rated first. The reference (F-nn) is used throughout the report.")
        for x in c["rows"]:
            out.append(("card", f"{x['ref']}   {x.get('technique_id') or ''}  {x.get('technique_name') or ''}"
                                f"   ·   {x['rating']}", BLUE_FILL[x["blue_outcome"]], finding_rows(x)))

    section("Risks")
    if not c["rated"]:
        para("No test case had both its attack and defensive outcome recorded, so no risk could be rated.")
    else:
        para("Each finding is rated by likelihood (what the attack did) and impact (what the defence saw), as "
             "Appendix B sets out. The matrix counts the findings at each rating.")
        figure("heat", "Findings by likelihood and impact.", 14.0)
        sub("Risk register")
        table(risk_register(c), "Every rated finding.")

    section("Recommendations")
    if c["gaps"]:
        para("Each technique that was logged but not alerted on, or not logged at all, is a gap. "
             + data.gaps_paragraph(c))
        figure("ready", "Gaps by whether deploying a library detection would close them.", 15.0)
        sub("Closing the gaps")
        table(recommendations_table(c), "One action per gap, highest priority first. Library: detections available.")
    else:
        para(data.no_gaps_sentence(c))
    sub("General recommendations")
    table((["Recommendation", "Detail"], [list(r) for r in data.GENERAL_RECOMMENDATIONS], [4.6, 12.4], {}),
          "Recommendations for the programme as a whole.", first_col_bold=True)

    section("Conclusions")
    own(c["conclusion"])
    for text in data.conclusion_paragraphs(c):
        para(text)

    section("Appendices")
    sub("Appendix A: Outcome definitions")
    table(outcome_definitions(), "What each recorded outcome means.")
    sub("Appendix B: Risk rating method")
    para("Likelihood comes from the red outcome (executed 3, failed 2, blocked 1) and impact from the blue outcome "
         "(not logged 3, logged 2, alerted or prevented 1). The rating is their product.")
    table(rating_method(), "Ratings by likelihood and impact.", first_col_bold=True)
    sub("Appendix C: Lab runs and SIEM export packs")
    para(lab_paragraph(c))
    if c["lab_runs"]:
        table(lab_runs_table(c), "Lab runs covering this assessment's techniques.")
    sub("Appendix D: Test cases")
    if c["rows"]:
        table(test_cases_table(c), "Every test case in the assessment.")
    else:
        para("None.")
    sub("Appendix E: Candidate detections")
    spec = candidates_table(c)
    if spec[1]:
        table(spec, "Detections in the Shikari library for each gap.")
    else:
        para("None: either there were no gaps, or the library holds no detections for them.")
    out.append(("note", data.ai_disclaimer(c)))   # the AI disclaimer, once, at the end
    return out


def to_docx(c: Dict, figs: Optional[Dict[str, bytes]] = None) -> bytes:
    return branded.to_docx(cover(c), blocks(c, figs if figs is not None else _figures(c)))


def to_pdf(c: Dict, figs: Optional[Dict[str, bytes]] = None) -> bytes:
    return branded.to_pdf(cover(c), blocks(c, figs if figs is not None else _figures(c)))


def render(c: Dict, fmt: str, theme=None) -> bytes:
    """The report as 'docx' or 'pdf', in the given theme (the assessment's client brand, the
    installation brand, or the stock look when none is passed)."""
    return branded.render(cover(c), blocks(c, _figures(c)), fmt, theme=theme)

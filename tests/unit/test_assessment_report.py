"""Assessment reports (#42): Word and PDF from an assessment's recorded outcomes."""

import io

import pytest

from shikari.reports import assessment_data, assessment_report

DETECTION = """# shikari-generator: 3 query-sha256: 0
id: {id}
name: {name}
technique_id: {tid}
severity: High
requiredDataConnectors:
  - connectorId: {connector}
tactics:
  - Discovery
query: |
  search {tid}
{extra}"""

ASSESSMENT = {"name": "Q4 purple team", "target": "Example Ltd", "operator": "Op", "run_date": "2026-11-08",
              "notes": ""}


def _result(tid, name, red, blue, tactic="Discovery", **kw):
    return {"technique_id": tid, "technique_name": name, "tactic": tactic, "red_outcome": red,
            "blue_outcome": blue, "detection_file": None, "notes": "", "procedure": f"run {tid}",
            "group_name": "APT29", **kw}


# One test case per outcome, blue and red
RESULTS = [
    _result("T1033", "System Owner/User Discovery", "executed", "alerted", detection_file="T1033_splunk.yaml"),
    _result("T1057", "Process Discovery", "executed", "not_logged"),
    _result("T1016", "System Network Configuration Discovery", "executed", "logged"),
    _result("T1082", "System Information Discovery", "failed", "logged"),
    _result("T1562.001", "Disable or Modify Tools", "blocked", "prevented", tactic="Defense Evasion"),
    _result("T1486", "Data Encrypted for Impact", "not_run", "not_assessed", tactic="Impact"),
]


@pytest.fixture
def library(tmp_path):
    def write(fname, tid, connector="Splunk", extra=""):
        (tmp_path / fname).write_text(DETECTION.format(id=fname, name=f"{tid} detection", tid=tid,
                                                       connector=connector, extra=extra))
    write("T1033_splunk.yaml", "T1033")
    write("T1057_elastic.yaml", "T1057", "Elastic")
    write("T1016_bespoke.yaml", "T1016",
          extra="queries:\n  - comment: Generated via llm mode\n")   # written by an AI model
    return str(tmp_path)


def _build(library, results=RESULTS, **kw):
    return assessment_data.build(ASSESSMENT, results, library, [], **kw)


@pytest.mark.unit
def test_both_formats_render_and_the_word_file_reopens_with_every_section(library):
    from docx import Document

    c = _build(library)
    figs = assessment_report._figures(c)
    pdf = assessment_report.to_pdf(c, figs)
    assert pdf.startswith(b"%PDF") and pdf.count(b"/Type /Page\n") + pdf.count(b"/Type /Page ") > 5

    doc = Document(io.BytesIO(assessment_report.to_docx(c, figs)))
    headings = [p.text for p in doc.paragraphs if p.style.name.startswith("Heading 1") or p.text == "Table of Contents"]
    assert headings[0] == "Table of Contents"
    for i, section in enumerate(assessment_report.SECTIONS, 1):
        assert any(h.startswith(f"{i}  {section}") for h in headings), section
    # Calibri throughout, the title page apart from the body, the body numbered from 1
    assert doc.styles["Normal"].font.name == "Calibri"
    assert len(doc.sections) == 3
    assert "PAGE" in doc.sections[1].footer._element.xml and "SECTIONPAGES" in doc.sections[1].footer._element.xml
    # A finding card per test case, and every test case in Appendix D
    text = "\n".join(c2.text for t in doc.tables for r in t.rows for c2 in r.cells)
    for r in RESULTS:
        assert r["technique_id"] in text


@pytest.mark.unit
def test_gaps_are_exactly_the_logged_and_not_logged_with_their_candidates(library):
    c = _build(library)
    gaps = {x["technique_id"]: [d["file"] for d in x["library"]] for x in c["gaps"]}
    assert gaps == {"T1057": ["T1057_elastic.yaml"], "T1016": ["T1016_bespoke.yaml"], "T1082": []}
    # Only a logged gap with a library detection is ready: not logged needs its logging first
    assert c["ready"] == 1 and c["unready"] == 2
    actions = {x["technique_id"]: assessment_data.recommendation_for(x) for x in c["gaps"]}
    assert actions["T1082"].endswith("write one.")
    assert actions["T1057"].startswith("Turn on the logging")


@pytest.mark.unit
def test_ratings_follow_likelihood_times_impact(library):
    c = _build(library)
    rating = {x["technique_id"]: x["rating"] for x in c["rows"]}
    assert rating == {"T1057": "Critical", "T1016": "High", "T1082": "Medium", "T1033": "Medium",
                      "T1562.001": "Low", "T1486": "Unrated"}
    assert [x["ref"] for x in c["rows"]][:2] == ["F-01", "F-02"]
    assert c["rows"][0]["technique_id"] == "T1057"   # highest rated first
    assert c["detection_rate"] == 40 and c["visibility"] == 80


@pytest.mark.unit
def test_ai_written_detections_are_marked_and_the_disclaimer_closes_the_report(library):
    from docx import Document

    c = _build(library)
    assert c["ai_gaps"] and "Recommendations" in c["ai_sections"]
    doc = Document(io.BytesIO(assessment_report.render(c, "docx")))
    body = [p.text for p in doc.paragraphs]
    cells = "\n".join(cell.text for t in doc.tables for r in t.rows for cell in r.cells)
    mark = assessment_data.AI_MARK
    assert any(t.startswith("6  Recommendations " + mark) for t in body)
    assert f"T1016 detection{mark}" in cells       # the AI-written detection itself, in Appendix E
    assert "T1057 detection" + mark not in cells   # written without AI: unmarked
    assert doc.tables[-1].rows[0].cells[0].text.startswith(f"{mark} AI-assisted content")


@pytest.mark.unit
def test_without_ai_content_nothing_is_marked_but_the_disclaimer_says_so(tmp_path):
    c = assessment_data.build(ASSESSMENT, RESULTS, str(tmp_path), [])
    assert not c["ai_any"] and not c["ai_sections"]
    assert "Nothing in this report is marked" in " ".join(assessment_data.ai_disclaimer(c))


@pytest.mark.unit
def test_an_assessment_with_no_outcomes_says_so(library):
    from docx import Document

    c = _build(library, results=[])
    assert assessment_report.render(c, "pdf").startswith(b"%PDF")
    doc = Document(io.BytesIO(assessment_report.render(c, "docx")))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "No test cases had been added" in text
    assert "no detection gaps could be identified" in text
    assert "every assessed test was alerted on or prevented" not in text


@pytest.mark.unit
def test_operator_text_leads_the_summary_and_conclusion(library):
    c = _build(library, summary="Typed by the operator.", conclusion="Closing words.")
    from docx import Document

    text = "\n".join(p.text for p in Document(io.BytesIO(assessment_report.render(c, "docx"))).paragraphs)
    assert text.index("Typed by the operator.") < text.index("This assessment tested")
    assert "Closing words." in text


@pytest.mark.unit
def test_lab_runs_covering_the_techniques_go_in_the_appendix(library):
    runs = [("lab-1", {"tool": "CALDERA", "host": "win11", "started": "2026-11-08T10:43:33Z",
                       "tests": [{"technique": "T1033"}, {"technique": "T1599"}]}),
            ("lab-2", {"tool": "Atomic", "tests": [{"technique": "T1599"}]})]
    c = assessment_data.build(ASSESSMENT, RESULTS, library, runs)
    assert [(r["run"], r["techniques"]) for r in c["lab_runs"]] == [("lab-1", ["T1033"])]

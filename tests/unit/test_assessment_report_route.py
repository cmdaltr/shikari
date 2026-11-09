"""The assessment report download (#42): GET /api/assessments/{id}/export?fmt=docx|pdf."""

import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import shikari.app as app_module
from shikari.database.models import Assessment, AssessmentResult, Base, ThreatTestCase, User


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 't.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    s = factory()
    s.add(User(id=1, email="u@x", full_name="u", password_hash="x"))
    s.add(Assessment(id=1, user_id=1, name="Q4 purple team", target="Example Ltd", run_date="2026-11-08"))
    s.add(Assessment(id=2, user_id=2, name="Someone else's"))
    s.add(ThreatTestCase(id=1, user_id=1, signature="s1", technique_id="T1057", technique_name="Process Discovery",
                         tactic="Discovery", group_name="APT29", procedure="Get-Process"))
    s.add(AssessmentResult(assessment_id=1, user_id=1, test_case_id=1, technique_id="T1057",
                           technique_name="Process Discovery", tactic="Discovery", red_outcome="executed",
                           blue_outcome="logged"))
    s.commit()
    user = s.query(User).get(1)
    gdir = tmp_path / "groups"
    gdir.mkdir()
    monkeypatch.setattr(app_module, "GENERATE_DIR", str(gdir))
    monkeypatch.setattr(app_module, "require_auth", lambda request, session: (user, factory()))
    monkeypatch.setattr("shikari.telemetry.lab.runs", lambda: iter(()))
    return TestClient(app_module.app)


@pytest.mark.unit
def test_word_report_carries_the_test_case_and_the_operator_text(client):
    from docx import Document

    r = client.get("/api/assessments/1/export", params={"fmt": "docx", "summary": "Typed summary."})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/vnd.openxmlformats")
    assert 'filename="Q4 purple team_report.docx"' in r.headers["content-disposition"]
    doc = Document(io.BytesIO(r.content))
    text = "\n".join(p.text for p in doc.paragraphs)
    cells = "\n".join(c.text for t in doc.tables for row in t.rows for c in row.cells)
    assert "Typed summary." in text
    assert "Get-Process" in cells and "APT29" in cells   # from the test case behind the result


@pytest.mark.unit
def test_pdf_report(client):
    r = client.get("/api/assessments/1/export", params={"fmt": "pdf"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")


@pytest.mark.unit
def test_another_users_assessment_is_not_found(client):
    assert client.get("/api/assessments/2/export", params={"fmt": "pdf"}).status_code == 404


@pytest.mark.unit
def test_csv_still_the_default(client):
    r = client.get("/api/assessments/1/export")
    assert r.status_code == 200 and r.text.startswith("technique_id,")

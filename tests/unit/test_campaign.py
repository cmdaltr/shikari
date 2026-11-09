"""Campaign research (from ETHAN): sources merged, indicators triaged, the optional AI profile, the report and routes."""

import io
import json
from datetime import date

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from shikari.intelligence import campaign
from shikari.parsers.blog_analyzer import published_date
from shikari.reports import campaign_report

TODAY = date(2026, 11, 9)
SOURCES = {
    "https://a.example/new": {"success": True, "title": "New loader", "published": "2026-10-20", "group_name": "",
                              "techniques": ["T1059.001", "T1105"],
                              "iocs": {"ip": ["45.77.12.9", "103.0.0.0/24"], "domain": ["*.ladder.example"],
                                       "hash": ["a" * 64], "cmd": ["nbtstat -n"]}, "text": "new text"},
    "https://b.example/old": {"success": True, "title": "Old infrastructure", "published": "2026-04-02",
                              "group_name": "FIN7", "techniques": ["T1105"],
                              "iocs": {"ip": ["185.10.10.10", "45.77.12.9"], "hash": ["b" * 32]}, "text": "old text"},
    "https://c.example/blocked": {"success": False, "error": "Failed to fetch URL: 403"},
    "https://d.example/undated": {"success": True, "title": "Undated", "published": "", "group_name": "FIN7",
                                  "techniques": [], "iocs": {"domain": ["c2.example"]}},
}


def fake_analyse(url, include_text=False, bundle=None):
    return dict(SOURCES[url])


def run(**kw):
    return campaign.research("Shadow Ladder", kw.pop("urls", list(SOURCES)), analyse=fake_analyse, today=TODAY, **kw)


@pytest.mark.unit
def test_triage_by_kind_and_age():
    t = campaign.triage
    assert t("ip", "1.2.3.4", "2026-10-01", TODAY) == campaign.ACTIVE
    assert t("ip", "1.2.3.4", "2026-07-01", TODAY) == campaign.BURNED
    assert t("hash", "a" * 64, "2026-01-01", TODAY) == campaign.ACTIVE      # a hash keeps for a year
    assert t("hash", "a" * 64, "2025-01-01", TODAY) == campaign.BURNED
    assert t("ip", "10.0.0.0/8", "2026-10-01", TODAY) == campaign.PATTERN
    assert t("domain", "*.evil.example", "", TODAY) == campaign.PATTERN
    assert t("domain", "evil.example", "", TODAY) == campaign.UNKNOWN


@pytest.mark.unit
def test_sources_merge_into_one_campaign():
    c = run()
    assert c["sources_read"] == 3 and len(c["sources"]) == 4
    assert c["techniques"][0]["id"] == "T1105" and c["techniques"][0]["sources"] == 2
    assert c["groups"] == [{"name": "FIN7", "sources": 2}]
    assert c["first_reported"] == "2026-04-02" and [e["date"] for e in c["timeline"]] == ["2026-04-02", "2026-10-20"]
    by_value = {i["value"]: i for i in c["indicators"]}
    # cited by both sources: the newest decides, the oldest is when it was first seen
    assert by_value["45.77.12.9"]["triage"] == campaign.ACTIVE
    assert (by_value["45.77.12.9"]["first_seen"], by_value["45.77.12.9"]["sources"]) == ("2026-04-02", 2)
    assert by_value["185.10.10.10"]["triage"] == campaign.BURNED
    assert by_value["c2.example"]["triage"] == campaign.UNKNOWN
    assert c["other_iocs"] == {"cmd": ["nbtstat -n"]}
    assert c["profile"] is None and c["ai"] is False


@pytest.mark.unit
def test_search_more_adds_found_reports_and_bad_input_is_refused():
    found = {"sources": [{"url": "https://d.example/undated"}], "web": [{"url": "javascript:alert(1)"}]}
    c = run(urls=["https://a.example/new"], search_more=True, find=lambda q, b, w: found)
    assert [s["url"] for s in c["sources"]] == ["https://a.example/new", "https://d.example/undated"]
    with pytest.raises(ValueError):
        campaign.research("ab", ["https://a.example/new"], analyse=fake_analyse)
    with pytest.raises(ValueError):
        campaign.research("Shadow Ladder", ["not a url"], analyse=fake_analyse)


@pytest.mark.unit
def test_ai_profile_is_opt_in_and_survives_a_bad_answer(monkeypatch):
    calls = []

    def answer(prompt, cfg):
        calls.append(prompt)
        return 'Here: {"summary": "S", "actor": "A", "timeline": [{"date": "2026-04", "event": "E"}, {"x": 1}], ' \
               '"tooling": "nonsense", "victims": []}'

    real = campaign.ai_profile
    monkeypatch.setattr(campaign, "ai_profile", lambda n, t, c: real(n, t, c, call=answer))
    c = run(llm_config={"provider": "anthropic", "model": "m"})
    assert c["ai"] and c["profile"]["summary"] == "S" and c["profile"]["timeline"] == [{"date": "2026-04", "event": "E"}]
    assert c["profile"]["tooling"] == [] and c["profile"]["victims"] == {}
    assert "new text" in calls[0] and "old text" in calls[0]

    assert real("X", [{"title": "t", "url": "u", "text": "x"}], {}, call=lambda p, c: "no json here") is None
    assert real("X", [{"title": "t", "url": "u", "text": "x"}], {}, call=lambda p, c: 1 / 0) is None


@pytest.mark.unit
def test_extraction_leaves_burned_indicators_out_by_default():
    c = run()
    ex = campaign.extraction(c)
    assert ex["synthetic_group_name"] == "Campaign_Shadow_Ladder" and ex["ttps"] == ["T1105", "T1059.001"]
    assert "185.10.10.10" not in ex["iocs"]["ip"] and "45.77.12.9" in ex["iocs"]["ip"]
    assert "103.0.0.0/24" not in ex["iocs"]["ip"]           # a pattern, not something to match on
    assert ex["iocs"]["cmd"] == ["nbtstat -n"]
    assert "185.10.10.10" in campaign.extraction(c, active_only=False)["iocs"]["ip"]


@pytest.mark.unit
def test_storage_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(campaign, "CAMPAIGN_DIR", str(tmp_path))
    c = run()
    campaign.save(c)
    assert campaign.load("shadow-ladder")["name"] == "Shadow Ladder"
    assert campaign.load("../../etc/passwd") is None
    rows = campaign.all_campaigns()
    assert rows[0]["slug"] == "shadow-ladder" and rows[0]["active"] == c["triage_counts"][campaign.ACTIVE]
    assert campaign.delete("shadow-ladder") and not campaign.delete("shadow-ladder")


@pytest.mark.unit
def test_published_date_from_metadata():
    assert published_date(BeautifulSoup('<meta property="article:published_time" content="2026-10-22T08:45:00Z">',
                                        "html.parser")) == "2026-10-22"
    assert published_date(BeautifulSoup('<script type="application/ld+json">[{"datePublished": "2025-03-01"}]'
                                        '</script>', "html.parser")) == "2025-03-01"
    assert published_date(BeautifulSoup('<time datetime="2024-01-02">2 Jan</time>', "html.parser")) == "2024-01-02"
    assert published_date(BeautifulSoup("<p>nothing</p>", "html.parser")) == ""


def _docx_text(body):
    from docx import Document

    doc = Document(io.BytesIO(body))
    return "\n".join(p.text for p in doc.paragraphs) + "\n" + \
        "\n".join(c.text for t in doc.tables for row in t.rows for c in row.cells)


@pytest.mark.unit
def test_report_marks_only_the_ai_profile(tmp_path, monkeypatch):
    plain = campaign_report.context(run(), str(tmp_path), tlp="green", today=TODAY)
    text = _docx_text(campaign_report.to_docx(plain, figs={}))
    assert "TLP:GREEN" in text and "45.77.12.9" in text and "FIN7" in text
    assert "Nothing in this report is marked" in text and "Attribution †" not in text

    monkeypatch.setattr(campaign, "ai_profile",
                        lambda n, t, c: {"summary": "AI summary", "actor": "AI actor", "motivation": "", "timeline": [],
                                         "tooling": [], "victims": {}})
    ai = campaign_report.context(run(llm_config={"provider": "x"}), str(tmp_path), today=TODAY)
    text = _docx_text(campaign_report.to_docx(ai, figs={}))
    assert "Analyst profile †" in text and "AI summary" in text and "The actor †" in text
    assert "Nothing in this report is marked" not in text
    assert campaign_report.to_pdf(ai, figs={}).startswith(b"%PDF")


# ---------------------------------------------------------------- routes

@pytest.fixture
def client(tmp_path, monkeypatch):
    import shikari.app as app_module

    gdir, bdir = tmp_path / "groups", tmp_path / "blog"
    gdir.mkdir()
    monkeypatch.setattr(app_module, "GENERATE_DIR", str(gdir))
    monkeypatch.setattr(app_module, "BLOG_DIR", str(bdir))
    monkeypatch.setattr(campaign, "CAMPAIGN_DIR", str(tmp_path / "campaigns"))
    monkeypatch.setattr(app_module, "require_auth", lambda request, session: (object(), type("S", (), {"close": lambda s: None})()))
    real = campaign.research
    monkeypatch.setattr(campaign, "research", lambda name, urls, **kw: real(
        name, urls, analyse=fake_analyse, today=TODAY, **{k: v for k, v in kw.items() if k != "llm_config"}))
    return TestClient(app_module.app), bdir


@pytest.mark.unit
def test_research_report_generate_and_delete(client):
    http, bdir = client
    r = http.post("/api/campaigns", json={"name": "Shadow Ladder", "urls": list(SOURCES)})
    assert r.status_code == 200 and r.json()["redirect"] == "/campaigns/shadow-ladder"

    r = http.get("/api/campaigns/shadow-ladder/report", params={"fmt": "docx", "tlp": "red"})
    assert r.status_code == 200 and "TLP:RED" in _docx_text(r.content)
    assert http.get("/api/campaigns/shadow-ladder/report", params={"tlp": "purple"}).status_code == 400
    assert http.get("/api/campaigns/shadow-ladder/report", params={"fmt": "xlsx"}).status_code == 400

    r = http.post("/api/campaigns/shadow-ladder/extraction")
    assert r.status_code == 200 and r.json()["synthetic_group_name"] == "Campaign_Shadow_Ladder"
    saved = json.loads((bdir / "Campaign_Shadow_Ladder_extraction.json").read_text())
    assert "185.10.10.10" not in saved["iocs"]["ip"]

    assert http.delete("/api/campaigns/shadow-ladder").status_code == 200
    assert http.get("/api/campaigns/shadow-ladder/report").status_code == 404


@pytest.mark.unit
def test_research_refuses_when_nothing_can_be_read(client):
    http, _ = client
    r = http.post("/api/campaigns", json={"name": "Shadow Ladder", "urls": ["https://c.example/blocked"]})
    assert r.status_code == 422
    assert http.post("/api/campaigns", json={"name": "x", "urls": []}).status_code == 400


@pytest.mark.unit
def test_pages_render(client, monkeypatch):
    import shikari.app as app_module
    from shikari.database.models import User

    http, _ = client
    user = User(id=1, email="u@x", full_name="u", password_hash="x")
    monkeypatch.setattr(app_module, "require_auth", lambda request, session: (user, type("S", (), {"close": lambda s: None})()))
    http.post("/api/campaigns", json={"name": "Shadow Ladder", "urls": list(SOURCES)})
    r = http.get("/campaigns/shadow-ladder")
    assert r.status_code == 200 and "45.77.12.9" in r.text and "tri-Likely-burned" in r.text
    assert "Campaign_Shadow_Ladder" in r.text            # the master hunt query link
    assert http.get("/campaigns", follow_redirects=False).headers["location"] == "/catalogue?tab=campaigns"
    listed = http.get("/catalogue").text                 # the Catalogue's Campaigns tab
    assert "Research a campaign" in listed and 'href="/campaigns/shadow-ladder"' in listed
    assert http.get("/campaigns/nope", follow_redirects=False).status_code in (302, 307)

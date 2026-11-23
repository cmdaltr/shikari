"""The Catalogue's Hunts and Analyses tabs, the home page's Recent strips and the Library's "from:" chip
(shikari.catalogue), read from run files and extractions in a temporary data directory."""

import json
import os

import pytest

from shikari import catalogue


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


@pytest.fixture
def data(tmp_path, monkeypatch):
    from shikari.intelligence import campaign as campaign_mod

    runs, blog, uploads = tmp_path / "runs", tmp_path / "blog", tmp_path / "uploads"
    for d in (runs, blog, uploads):
        d.mkdir()
    monkeypatch.setattr(catalogue, "RUNS_DIR", str(runs))
    monkeypatch.setattr(catalogue, "BLOG_DIR", str(blog))
    monkeypatch.setattr(catalogue, "UPLOADS_DIR", str(uploads))
    monkeypatch.setattr(catalogue, "PROFILES_DIR", str(tmp_path / "profiles"))
    monkeypatch.setattr(campaign_mod, "CAMPAIGN_DIR", str(tmp_path / "campaigns"))
    monkeypatch.setattr(catalogue, "_api_runs", lambda user=None: {})

    def run(name, when, files=3, **extra):
        _write(runs / f"{name}.json", {"group": name, "started_at": when - 60, "completed_at": when,
                                       "files": [f"f{i}.yaml" for i in range(files)], "no_detection": ["T1"],
                                       "kept_edited": [], "stack_warnings": [], **extra})

    run("Scattered Spider", 1794400000)                       # a hunt for the group
    run("Scattered_Spider", 1794300000, files=2)              # a report naming the group
    run("CVE-2024-3400", 1794200000, files=5)
    run("Hunt_T1059_plus_2", 1794100000)
    run("Campaign_Shadow_Ladder", 1794000000)                 # the campaign's, not a hunt
    _write(runs / ".json", {"group": "", "files": []})        # a run given no name
    _write(blog / "Scattered_Spider_extraction.json", {
        "url": "https://www.cisa.gov/aa23-320a", "filename": "https://www.cisa.gov/aa23-320a",
        "group_name": "Scattered Spider", "ttps": ["T1566", "T1078"], "iocs": {"ip": ["1.2.3.4"], "domain": []},
        "procedures": [{}], "synthetic_group_name": "Scattered_Spider", "ai_provider": ""})
    _write(blog / "Report_Fake_Zoom_extraction.json", {
        "url": "https://thedfirreport.com/fake-zoom/", "filename": "https://thedfirreport.com/fake-zoom/",
        "group_name": "", "ttps": [], "iocs": {}, "synthetic_group_name": "Report_Fake_Zoom", "ai_provider": "ollama"})
    _write(uploads / "Upload_brief_1a2b3c4d_extraction.json", {
        "filename": "brief.pdf", "group_name": "", "ttps": ["T1059"], "iocs": {},
        "synthetic_group_name": "Upload_brief_1a2b3c4d"})
    _write(blog / "Campaign_Shadow_Ladder_extraction.json", {"synthetic_group_name": "Campaign_Shadow_Ladder"})
    return tmp_path


@pytest.mark.unit
def test_hunts_leave_out_analyses_campaigns_and_unnamed_runs(data):
    hunts = catalogue.hunts()
    assert [h["name"] for h in hunts] == ["Scattered Spider", "CVE-2024-3400", "Hunt_T1059_plus_2"]
    by = {h["name"]: h for h in hunts}
    assert by["CVE-2024-3400"]["hunt_kind"] == "cve" and by["CVE-2024-3400"]["detections"] == 5
    assert by["Hunt_T1059_plus_2"]["hunt_kind"] == "techniques" and by["Hunt_T1059_plus_2"]["title"] == "T1059 + 2 more"
    assert by["Scattered Spider"]["href"] == "/results?group_name=Scattered%20Spider&run=latest"
    assert by["Scattered Spider"]["no_detection"] == 1


@pytest.mark.unit
def test_analyses_name_their_source_and_whether_they_were_generated(data):
    by = {a["name"]: a for a in catalogue.analyses()}
    assert set(by) == {"Scattered_Spider", "Report_Fake_Zoom", "Upload_brief_1a2b3c4d"}
    spider = by["Scattered_Spider"]
    assert spider["title"] == "Scattered Spider" and spider["source"]["kind"] == "Blog URL"
    assert spider["source"]["text"] == "cisa.gov/aa23-320a" and spider["ttps"] == 2 and spider["iocs"] == 1
    assert spider["generated"] and spider["detections"] == 2 and spider["href"].endswith("Scattered_Spider&run=latest")
    zoom = by["Report_Fake_Zoom"]
    assert zoom["title"] == "Fake Zoom" and zoom["ai"] and not zoom["generated"] and zoom["href"] == ""
    upload = by["Upload_brief_1a2b3c4d"]
    assert upload["title"] == "brief" and upload["source"] == {"kind": "File", "text": "brief.pdf", "url": ""}


@pytest.mark.unit
def test_api_runs_without_a_run_file_are_listed_with_their_status(data, monkeypatch):
    monkeypatch.setattr(catalogue, "_api_runs", lambda user=None: {
        "apt29": {"group_name": "APT29", "kind": "group", "status": "failed", "external_ref": "OST-26-014",
                  "created_at": "2026-11-20T10:00:00Z", "error": "SIEM unreachable"},
        "scattered_spider": {"group_name": "Scattered Spider", "status": "complete", "external_ref": "OST-26-009",
                             "executed_at": "2026-11-21T10:00:00Z", "totals": {"run": 4, "hits": 2}}})
    by = {h["name"]: h for h in catalogue.hunts()}
    assert by["APT29"]["status"] == "failed" and by["APT29"]["href"] == "" and by["APT29"]["error"]
    assert by["Scattered Spider"]["external_ref"] == "OST-26-009" and by["Scattered Spider"]["totals"]["hits"] == 2


@pytest.mark.unit
def test_source_for_prefers_the_exact_spelling(data):
    index = catalogue.source_index()
    assert catalogue.source_for(index, "Scattered Spider")["kind"] == "hunt"
    assert catalogue.source_for(index, "Scattered_Spider")["kind"] == "analysis"
    assert catalogue.source_for(index, "cve-2024-3400")["label"] == "CVE-2024-3400"   # by _key
    assert catalogue.source_for(index, "Unknown") is None and catalogue.source_for(index, "Nobody") is None


@pytest.mark.unit
def test_recent_gives_three_of_each_and_the_counts(data):
    recent = catalogue.recent()
    assert len(recent["hunts"]) == 3 and recent["hunts"][0]["label"] == "Scattered Spider"
    assert recent["counts"] == {"hunts": 3, "analyses": 3, "companies": 0, "campaigns": 0}
    # An analysis not generated yet points at its Catalogue tab, not at an empty results page
    assert {r["href"] for r in recent["analyses"] if r["label"] == "Fake Zoom"} == {"/catalogue?tab=analyses"}


@pytest.mark.unit
def test_short_date():
    from datetime import datetime, timezone

    year = datetime.now(timezone.utc).year
    assert catalogue.short_date(f"{year}-11-12T09:00:00+00:00") == "12 Nov"
    assert catalogue.short_date("2020-03-01T00:00:00Z") == "1 Mar 2020"
    assert catalogue.short_date("") == ""

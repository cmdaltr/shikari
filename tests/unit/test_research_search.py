"""Research search (shikari/intelligence/research_search.py): archive, ATT&CK and web matching."""

from unittest import mock

import pytest

from shikari.intelligence import research_search as rs


@pytest.fixture(autouse=True)
def tmp_archive(tmp_path, monkeypatch):
    monkeypatch.setattr(rs, "ARCHIVE_PATH", str(tmp_path / "archive.json"))
    rs._cache.clear()


def post(title, url, summary="", published="2025-09-05T00:00:00+00:00", source="Huntress"):
    return {"title": title, "url": url, "summary": summary, "published": published, "source": source}


def test_archive_keeps_posts_and_adds_descriptions():
    assert rs.archive([post("RedSun loader", "https://a/1"), post("Other", "https://a/2")]) == 2
    assert rs.archive([post("RedSun loader", "https://a/1")]) == 0
    rs.archive([], {"https://a/1": {"description": "A loader dropping Cobalt Strike"}})
    assert rs.load_archive()["https://a/1"]["description"] == "A loader dropping Cobalt Strike"


def test_archive_matches_whole_words_in_any_order():
    rs.archive([post("Typhoon group Salt hits telcos", "https://a/1"), post("Salted hashes", "https://a/2"),
                post("Old", "https://a/3", summary="the redsun campaign", published="2017-01-01T00:00:00+00:00")])
    assert [p["url"] for p in rs.search_archive("salt typhoon")] == ["https://a/1"]
    assert [p["url"] for p in rs.search_archive("RedSun")] == ["https://a/3"]
    assert rs.search_archive("alt") == []


def test_attack_name_and_alias_rank_before_description():
    bundle = {"objects": [
        {"type": "intrusion-set", "name": "APT99", "aliases": ["APT99", "GhostAction"], "description": "",
         "external_references": [{"source_name": "mitre-attack", "external_id": "G9999", "url": "https://x/G9999"}]},
        {"type": "malware", "name": "Loader", "description": "Used in the GhostAction campaign",
         "external_references": [{"source_name": "mitre-attack", "external_id": "S9999"}]},
        {"type": "intrusion-set", "name": "Gone", "aliases": ["GhostAction"], "revoked": True},
        {"type": "attack-pattern", "name": "GhostAction"},
    ]}
    hits = rs.search_attack(bundle, "ghostaction")
    assert [(h["id"], h["named"]) for h in hits] == [("G9999", True), ("S9999", False)]
    assert hits[0]["aliases"] == ["GhostAction"]
    assert rs.search_attack(None, "ghostaction") == []


def test_bing_links_unwrapped():
    link = "http://www.bing.com/news/apiclick.aspx?ref=FexRss&aid=&tid=x&url=https%3a%2f%2fexample.com%2fstory&c=1"
    assert rs._real_url(link) == "https://example.com/story"
    assert rs._real_url("https://example.com/a") == "https://example.com/a"


def test_web_keeps_security_stories_and_dedupes():
    google = [post("GhostAction campaign steals 3,325 secrets - BleepingComputer", "https://g/1"),
              post("RedSun Projects launches new towers - Property Weekly", "https://g/2"),
              post("Unrelated story - Somewhere", "https://g/3")]
    bing = [post("GhostAction campaign steals 3,325 secrets", "https://b/1", summary="supply chain attack")]

    def fake(xml, name):
        return google if name == "Google News" else bing

    resp = mock.Mock(content=b"", raise_for_status=lambda: None)
    with mock.patch("requests.get", return_value=resp), mock.patch("shikari.intelligence.feed.parse_feed", side_effect=fake):
        assert [(r["title"], r["outlet"]) for r in rs.search_web("ghostaction")] == [
            ("GhostAction campaign steals 3,325 secrets", "BleepingComputer")]
        assert rs.search_web("redsun") == []


def test_search_needs_three_characters_and_caches():
    assert rs.search("ab")["error"]
    with mock.patch.object(rs, "search_web", return_value=[]) as web:
        first = rs.search("  GhostAction ", web=True)
        rs.search("ghostaction", web=True)
        assert web.call_count == 1 and first["query"] == "GhostAction"
        assert rs.search("ghostaction", web=False)["web"] is None


def test_web_drops_non_latin_titles():
    items = [post("Два взломанных аккаунта: GhostAction вернулся на GitHub", "https://r/1"),
             post("GhostAction hits GitHub - The Hacker News", "https://t/1")]
    resp = mock.Mock(content=b"", raise_for_status=lambda: None)
    with mock.patch("requests.get", return_value=resp), mock.patch("shikari.intelligence.feed.parse_feed", return_value=items):
        assert [r["url"] for r in rs.search_web("ghostaction")] == ["https://t/1"]

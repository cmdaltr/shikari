"""Threat feed: parsing RSS/Atom, and which posts matter to which industries."""

from types import SimpleNamespace

from shikari.intelligence import feed

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Lazarus  targets banks</title><link>https://example.com/a</link>
<pubDate>Mon, 12 Oct 2026 09:00:00 +0000</pubDate><description>&lt;p&gt;Read more&lt;/p&gt;</description></item>
<item><title>No link</title><pubDate>Mon, 12 Oct 2026 09:00:00 +0000</pubDate></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Atom post</title><link rel="alternate" href="https://example.com/b"/>
<updated>2026-10-11T08:00:00Z</updated><summary>s</summary></entry></feed>"""


def test_rss_and_atom_are_parsed():
    rss = feed.parse_feed(RSS, "Src")
    assert [(p["title"], p["url"], p["summary"]) for p in rss] == [("Lazarus targets banks", "https://example.com/a", "Read more")]
    assert rss[0]["published"].startswith("2026-10-12T09:00")
    atom = feed.parse_feed(ATOM, "Src")
    assert atom[0]["url"] == "https://example.com/b" and atom[0]["published"].startswith("2026-10-11T08:00")


def _analysed(text, title="t", summary="", groups=(), profiles=None):
    from unittest.mock import patch

    post = {"title": title, "url": "https://e/x", "source": "S", "published": "2026-10-12T00:00:00+00:00",
            "summary": summary}
    result = {"success": True, "text": text, "techniques": feed._INDICATOR.findall(text) and ["T1059"] or [], "iocs": {}}
    with patch("shikari.parsers.blog_analyzer.analyze_blog_post", return_value=result):
        return feed.analyse_post(post, list(groups), profiles or {})


APT38 = {"id": "G0082", "name": "APT38", "pattern": __import__("re").compile(r"\bAPT38\b"),
         "sectors": ["Finance / Banking"], "nexus": "North Korea", "financial": True}


def test_tags_come_from_groups_nations_and_motives_in_technical_paragraphs():
    text = "\n".join([
        "Japan's strategy paper mentions China-nexus actors in passing.",
        "Background.", "More background.",
        "APT38 operators ran powershell -enc to stage the loader.",
        "Chinese state-sponsored actors also used T1190 against edge devices.",
        "The campaign was financially motivated and deployed ransomware.",
    ])
    post = _analysed(text, groups=[APT38], profiles={"China": ["Government"], "North Korea": ["Finance / Banking"]})
    assert post["industries"] == {"Finance": ["APT38 (G0082)"], "Government": ["China-nexus activity"]}
    assert post["nations"] == ["China", "North Korea"]
    assert feed.tags(post)["motives"] == ["Financially motivated"]


def test_industries_from_sector_labels_and_older_saved_choices():
    assert feed.as_industries(["Defense / Military", "Finance / Banking", "Think Tank / Policy", "Media"]) == \
        ["Finance", "Media", "Military / Defence"]


def test_attribution_outside_technical_paragraphs_does_not_count():
    text = "\n".join(["China-nexus actors are a policy concern for Japan.", "A", "B", "C",
                      "Nothing technical here at all, just commentary on strategy."])
    post = _analysed(text, profiles={"China": ["Government"]})
    assert post["nations"] == [] and post["industries"] == {}


def test_description_prefers_a_real_summary_and_falls_back_to_the_opening():
    summary = ("Threat actors exploited a flaw in AhsayCBS to drop webshells. They then deployed XMRig "
               "on the servers. Patch to 10.3.4 now. A fourth sentence that should not appear.")
    assert feed.describe(summary, "") == ("Threat actors exploited a flaw in AhsayCBS to drop webshells. They then "
                                          "deployed XMRig on the servers. Patch to 10.3.4 now.")
    text = "\n".join(["Title", "By Someone", "Cisco Talos identified a spear-phishing campaign against research "
                      "organisations in Taiwan this month. The operators used public cloud services for staging."])
    assert feed.describe("Advisory at a Glance; Title", text, "Title").startswith("Cisco Talos identified")


def test_group_names_match_as_proper_nouns_only():
    bundle = SimpleNamespace(objects=[
        {"type": "intrusion-set", "name": "Silence", "aliases": ["Silence"], "external_references": [{"source_name": "mitre-attack", "external_id": "G0091"}]},
        {"type": "intrusion-set", "name": "APT29", "aliases": ["Cozy Bear"], "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}]},
    ])
    groups = feed.group_index(bundle, {"G0016": {"target_sectors": "Government", "primary_objectives": "Espionage", "nexus": "Russia"}})
    assert [g["name"] for g in groups] == ["APT29"]
    assert groups[0]["pattern"].search("attributed to Cozy Bear.") and not groups[0]["pattern"].search("cozy bear")
    assert groups[0]["sectors"] == ["Government"] and groups[0]["financial"] is False


def test_advisory_boilerplate_is_not_reported_exploitation():
    def reasons(text):
        return {r for pattern, r in feed.OPPORTUNISTIC if pattern.search(text)}

    assert "vulnerability exploitation" in reasons("Threat Actors Exploit Critical AhsayCBS Flaws")
    assert "vulnerability exploitation" in reasons("attackers have been exploiting CVE-2026-1234")
    assert not reasons("Successful exploitation of these vulnerabilities could allow an attacker to exploit the device")


def test_context_is_the_title_and_technical_paragraphs():
    text = "\n".join([
        "Japan's new strategy mentions APT29 among many others.",
        "Background paragraph.",
        "Another paragraph.",
        "The intrusion began with a phishing email.",
        "The loader ran rundll32.exe from %TEMP%; Lazarus staged payloads.",
        "Persistence followed.",
        "Unrelated closing remarks about Turla.",
    ])
    ctx = feed.technical_context("Report on Volt Typhoon", text)
    assert "Volt Typhoon" in ctx and "Lazarus" in ctx and "phishing email" in ctx and "Persistence" in ctx
    assert "APT29" not in ctx and "Turla" not in ctx
    assert feed.technical_context("Title", "Commentary only; APT29.") == "Title"


def test_nation_profiles_keep_the_industries_most_of_its_groups_target():
    meta = {"G1": {"nexus": "Iran", "target_sectors": "Government; Energy / Utilities"},
            "G2": {"nexus": "Iran", "target_sectors": "Government"},
            "G3": {"nexus": "Iran", "target_sectors": "Technology"},
            "G4": {"nexus": "Iran", "target_sectors": "Government"},
            "G5": {"nexus": "Iran", "target_sectors": "Technology"}}
    assert feed.nation_profiles(meta, share=0.5)["Iran"] == ["Government"]


def test_a_cve_counts_only_alongside_other_indicators():
    newsletter = "\n".join(["Welcome to the newsletter; Microsoft patched CVE-2026-1234 this week.",
                            "A", "B", "C", "China-nexus actors remain busy, says a government."])
    assert feed.technical_context("Newsletter", newsletter) == "Newsletter"
    assert not feed.technical({"techniques": [], "iocs": 0, "groups": [], "cves": ["CVE-2026-1234"],
                               "indicators": feed.has_indicators("Newsletter", newsletter)})
    report = newsletter + "\nThe actors then ran certutil -urlcache to fetch the payload."
    assert "CVE-2026-1234" in feed.technical_context("Report", report)
    assert feed.technical({"techniques": [], "iocs": 0, "groups": [], "cves": ["CVE-2026-1234"],
                           "indicators": feed.has_indicators("Report", report)})


def test_vendor_actor_names_give_nation_and_motive_without_attack():
    found = {a["name"]: a for a in feed.actors(
        "Storm-2603 and Linen Typhoon exploited SharePoint; Scattered Spider and UNC6040 phished helpdesks; "
        "CL-CRI-1032 ran extortion; a Teddy Bear lure and a Red Panda image were used")}
    assert set(found) == {"Storm-2603", "Linen Typhoon", "Scattered Spider", "UNC6040", "CL-CRI-1032"}
    assert found["Linen Typhoon"]["nation"] == "China"
    assert found["Scattered Spider"]["financial"] and found["CL-CRI-1032"]["financial"]
    assert found["Storm-2603"]["nation"] is None and not found["Storm-2603"]["financial"]


def test_actor_names_that_are_attack_aliases_are_not_counted_twice():
    assert feed.actors("Volt Typhoon and Silk Typhoon", known=["Volt Typhoon"]) == [
        {"name": "Silk Typhoon", "nation": "China", "financial": False}]


def test_a_named_actor_alone_makes_a_post_technical():
    assert feed.technical({"actors": [{"name": "UNC6040"}]})
    assert not feed.technical({})


def test_a_bad_character_does_not_lose_the_whole_feed():
    broken = RSS.replace(b"Lazarus  targets banks", b"Lazarus \x01 targets banks")
    assert [p["url"] for p in feed.parse_feed(broken, "s")] == ["https://example.com/a"]


def test_every_iiss_state_is_in_scope():
    for nation in ("United States", "United Kingdom", "Australia", "Canada", "China", "France", "Israel", "Russia",
                   "India", "Indonesia", "Iran", "Japan", "Malaysia", "North Korea", "Vietnam",
                   "Brazil", "Estonia", "Germany", "Netherlands", "Nigeria", "Saudi Arabia", "Singapore",
                   "South Africa", "Turkey", "United Arab Emirates"):
        assert nation in feed.NATIONS


def test_western_names_need_real_attribution():
    assert feed.nations_in("US-based companies and the UK's NCSC with US intelligence partners") == []
    assert feed.nations_in("help us hackers") == []
    assert feed.nations_in("US state-sponsored actors and a British government-linked espionage group") == [
        "United Kingdom", "United States"]


def test_any_country_before_nexus_counts():
    assert feed.nations_in("Kazakhstan-nexus UAT-6275 and DPRK-nexus activity") == ["Kazakhstan", "North Korea"]


def test_nations_with_few_attack_groups_get_no_industry_profile():
    meta = {f"G{i:04d}": {"nexus": "Vietnam", "target_sectors": "Government"} for i in range(2)}
    assert feed.nation_profiles(meta)["Vietnam"] == []


def test_custom_sources_are_checked_before_they_are_added(tmp_path, monkeypatch):
    monkeypatch.setattr(feed, "CUSTOM_SOURCES_PATH", str(tmp_path / "sources.json"))
    assert feed.add_source("", "")["error"]
    assert "private or local" in feed.add_source("Local", "http://127.0.0.1/feed")["error"]
    assert "already" in feed.add_source("Volexity", "https://example.com/feed")["error"]
    monkeypatch.setattr(feed, "check_source", lambda url: {"ok": True, "items": 3, "latest": None})
    assert feed.add_source("Mine", "https://example.com/rss")["ok"]
    assert ("Mine", "https://example.com/rss") in feed.all_sources()
    assert feed.remove_source("https://example.com/rss") and not feed.custom_sources()
    assert not feed.remove_source(feed.SOURCES[0][1])  # built-ins stay

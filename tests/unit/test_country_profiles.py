"""Attribution and targeting read from ATT&CK group descriptions (wording taken from ATT&CK)."""

from archer.intelligence import country_profiles as cp
from archer.intelligence.cyber_powers import countries, flag


def test_a_named_government_body_is_high_confidence():
    assert cp.attribution("APT28 is a threat group that has been attributed to Russia's General Staff Main "
                          "Intelligence Directorate (GRU) 85th Main Special Service Center (GTsSS) military unit 26165.",
                          ["APT28"]) == {"Russia": "High"}


def test_plain_statements_are_moderate_and_hedges_low():
    assert cp.attribution("Kimsuky is a Democratic People's Republic of Korea (DPRK)-based cyber espionage group.",
                          ["Kimsuky"]) == {"North Korea": "Moderate"}
    assert cp.attribution("Aoqin Dragon is a suspected Chinese cyber espionage threat group.", ["Aoqin Dragon"]) == {
        "China": "Low"}
    assert cp.attribution("HAFNIUM is a likely state-sponsored cyber espionage group operating out of China.",
                          ["HAFNIUM"]) == {"China": "Low"}


def test_targets_accusers_and_other_groups_are_not_attribution():
    assert cp.attribution("Strider is a threat group that has targeted victims in Russia, China, Sweden.", ["Strider"]) == {}
    assert cp.attribution("APT-C-23 has primarily focused its operations on the Middle East, including Israeli military "
                          "assets.", ["APT-C-23"]) == {}
    assert cp.attribution("Gamaredon Group is a suspected Russian cyber espionage group. In November 2021, the Ukrainian "
                          "government publicly attributed Gamaredon Group to Russia's Federal Security Service (FSB) "
                          "Center 18.", ["Gamaredon Group"]) == {"Russia": "High"}
    assert cp.attribution("SideCopy is a Pakistani threat group. SideCopy's name comes from its infection chain that "
                          "tries to mimic that of Sidewinder, a suspected Indian threat group.", ["SideCopy"]) == {
        "Pakistan": "Moderate"}
    assert cp.attribution("APT-C-36 is a suspected South American threat group.", ["APT-C-36"]) == {}


def test_targets_exclude_the_groups_own_nation():
    text = "Kimsuky is a North Korea-based group. The group initially targeted South Korean government agencies and Japan."
    assert cp.targets(text, cp.attribution(text, ["Kimsuky"])) == ["Japan", "South Korea"]


def test_motivation_shares_count_each_group_once():
    assert cp.motivation(["Espionage; Financial Crime", "Ransomware / Extortion; Financial Crime", ""]) == [
        {"motive": "Financial", "share": 100}, {"motive": "Espionage", "share": 50}]


def test_every_country_has_a_vendored_flag():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    assert flag("United Kingdom", "GB") == "/static/vendor/flag-icons/4x3/gb.svg"
    for c in countries():
        assert c["flag"] and (root / c["flag"].lstrip("/")).is_file(), c["name"]

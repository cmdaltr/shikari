"""Country mentions in ATT&CK group descriptions: attribution vs targeting."""
import pytest

from shikari.intelligence.country_context import country_matches

IRAN = ["iranian", "iran", "tehran", "irgc"]
RUSSIA = ["russian", "russia", "kremlin", "moscow", "gru", "fsb", "svr"]
CHINA = ["chinese", "china", "prc", "people's republic of china", "beijing"]
NK = ["north korean", "north korea", "dprk", "pyongyang"]

# Real ATT&CK phrasing (markdown links and citations included, as stored in the bundle)
CASES = [
    # Strider is the case that prompted this: targeting only, despite "threat group"
    ("[Strider](https://attack.mitre.org/groups/G0041) is a threat group that has been active since at least 2011 "
     "and has targeted victims in Russia, China, Sweden, Belgium, Iran, and Rwanda.(Citation: Symantec Strider Blog)",
     IRAN, False, True),
    ("[CURIUM](https://attack.mitre.org/groups/G1012) is an Iranian threat group, first reported in September 2019.",
     IRAN, True, False),
    ("[VOID MANTICORE](https://attack.mitre.org/groups/G1055) is a threat group assessed to operate on behalf of "
     "Iran’s Ministry of Intelligence and Security (MOIS). VOID MANTICORE has targeted government entities across "
     "Albania, Israel, and the United States.", IRAN, True, False),
    ("[Volt Typhoon](https://attack.mitre.org/groups/G1017) is a People's Republic of China (PRC) state-sponsored actor.",
     CHINA, True, False),
    ("Earth Lusca has targeted organizations in Australia, China, Hong Kong, Mongolia and Nepal.",
     CHINA, False, True),
    ("In April 2021, the US and UK governments attributed the SolarWinds Compromise to the SVR.",
     RUSSIA, True, False),
    ("Star Blizzard campaigns align closely with Russian state interests.", RUSSIA, True, False),
    ("[TA459](https://attack.mitre.org/groups/G0062) is a threat group believed to operate out of China that has "
     "targeted countries including Russia, Belarus, Mongolia, and others.", RUSSIA, False, True),
    ("Contagious Interview is a North Korea–aligned threat group active since 2023.", NK, True, False),
    ("Some of their attacks have been destructive.\n\nNorth Korean group definitions are known to overlap.",
     NK, True, False),
]


@pytest.mark.parametrize("text,terms,attributed,targeted", CASES)
def test_country_role(text, terms, attributed, targeted):
    assert country_matches(text, terms, "attributed") is attributed
    assert country_matches(text, terms, "targeted") is targeted


def test_citation_titles_are_ignored():
    text = "APT28 has been active since 2004.(Citation: DOJ GRU Indictment Jul 2018)"
    assert not country_matches(text, RUSSIA, "attributed")
    assert not country_matches(text, RUSSIA, "targeted")

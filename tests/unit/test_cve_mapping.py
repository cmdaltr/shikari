"""What a CVE run builds from: its ATT&CK techniques and the indicators its references give."""

from shikari.intelligence.cve_hunter import CVEHunter

JAVA4SHELL = {"description": "Vulnerability in the Oracle Java SE ... Successful attacks of this vulnerability can result "
                             "in takeover of Oracle Java SE.", "cwe": ["CWE-122"]}


def test_code_execution_maps_past_initial_access():
    assert sorted(CVEHunter._map_to_attack(None, {"nvd_data": JAVA4SHELL})) == ["T1059", "T1190"]
    # A weakness that runs nothing stays at the exploit
    assert CVEHunter._map_to_attack(None, {"nvd_data": {"description": "An information disclosure", "cwe": ["CWE-200"]}}) == ["T1190"]


def test_versions_credits_and_placeholder_hashes_are_not_indicators():
    assert CVEHunter._not_indicator("13.3.0.1", ["Oracle Application Testing Suite, version 13.3.0.1"])
    assert CVEHunter._not_indicator("21.1.0.7", ["Oracle AutoVue, versions 21.1.0, 21.1.0.7"])
    assert CVEHunter._not_indicator("calif.io", ["Quang Luong of Calif.io: CVE-2026-114938"])
    assert CVEHunter._not_indicator("a" * 64, [])


def test_real_indicators_stay():
    assert not CVEHunter._not_indicator("203.0.113.7", ["the implant beaconed to 203.0.113.7 over 443"])
    assert not CVEHunter._not_indicator("update-check.example", ["staged at update-check.example"])
    # Seen once as a version and once as C2: kept
    assert not CVEHunter._not_indicator("10.2.0.1", ["version 10.2.0.1", "C2 at 10.2.0.1"])
    assert not CVEHunter._not_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", [])

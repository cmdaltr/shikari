"""Detection quality and false-positive risk, without AI (#33)."""
from archer.validation import quality

SPECIFIC = {
    "name": "OS Credential Dumping", "technique_id": "T1003.001", "severity": "High", "tactics": ["Credential Access"],
    "description": "[APT29](https://attack.mitre.org/groups/G0016) dumped LSASS with comsvcs.dll MiniDump.",
    "requiredDataConnectors": [{"connectorId": "MicrosoftThreatProtection", "dataTypes": ["DeviceProcessEvents"]}],
    "indicators": {"cmd": ["rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump", "procdump -ma lsass.exe",
                           "comsvcs.dll MiniDump"]},
    "query": 'DeviceProcessEvents\n| where ProcessCommandLine has_all ("comsvcs.dll", "MiniDump")'
             ' or ProcessCommandLine has_all ("procdump", "-ma", "lsass")',
}
BARE = {
    "name": "Match Legitimate Resource Name", "technique_id": "T1036.005", "tactics": ["Defense Evasion"],
    "description": "short", "indicators": {"cmd": ["svchost.exe"]},
    "query": 'DeviceProcessEvents\n| where FileName =~ "svchost.exe"',
}


def test_a_specific_well_described_detection_outgrades_a_bare_one():
    good = quality.quality(SPECIFIC, "kql")
    bare = quality.quality(BARE, "kql")
    assert good["score"] > bare["score"]
    assert good["grade"] in ("A", "B")
    context = next(f for f in bare["factors"] if f["name"] == "context")
    assert "severity" in context["notes"][0] and "data connector" in context["notes"][0]


def test_a_bare_built_in_binary_is_high_risk_and_a_specific_command_low():
    bare = quality.fp_risk(BARE, "kql", known=[])
    assert bare["level"] == "high"
    assert any("built-in" in r for r in bare["reasons"])
    assert quality.fp_risk(SPECIFIC, "kql", known=[])["level"] == "low"


def test_community_false_positives_raise_the_risk_and_come_back_for_triage():
    known = [{"source": "Elastic", "rule": "LSASS access", "url": "", "text": "Backup agents read LSASS"}] * 3
    with_known = quality.fp_risk(SPECIFIC, "kql", known=known)
    assert with_known["score"] > quality.fp_risk(SPECIFIC, "kql", known=[])["score"]
    assert with_known["known_false_positives"] == known


def test_a_hash_match_lowers_the_risk():
    hashed = {**BARE, "indicators": {"hash": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},
              "query": 'DeviceProcessEvents\n| where SHA256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"'}
    assert quality.fp_risk(hashed, "kql", known=[])["level"] == "low"


def test_assess_runs_both():
    result = quality.assess(SPECIFIC, "kql")
    assert set(result) == {"quality", "fp_risk", "cost"}

"""Run cost and the CI gate (#34)."""
import yaml

from archer.validation import ci
from archer.validation.cost import cost


def checks(query, platform=None):
    return {f["check"] for f in cost(query, platform)["findings"]}


def test_kql_costs():
    assert "COST-NOTIME" in checks('DeviceProcessEvents\n| where FileName has "x.exe"', "kql")
    assert "COST-SUBSTRING" in checks('DeviceProcessEvents\n| where Timestamp > ago(1h)\n| where ProcessCommandLine contains "x"', "kql")
    assert checks('DeviceProcessEvents\n| where Timestamp > ago(1h)\n| where FileName has "x.exe"', "kql") == set()


def test_spl_costs():
    found = checks('index=* earliest=-1d\n| search cs1="*wmic.exe" | join user [search index=auth]', "splunk")
    assert {"COST-WIDE", "COST-SUBSTRING", "COST-JOIN"} <= found
    assert cost('index=edr earliest=-15m cs1="wmic.exe"', "splunk")["level"] == "low"


def test_yaral_costs():
    assert "COST-REGEX" in checks('rule x { events: $e.metadata.event_type = "PROCESS_LAUNCH" '
                                  'and re.regex($e.target.process.command_line, `.*mimikatz.*`) condition: $e }', "yara_l")


def _write(tmp_path, name, doc):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(doc))
    return str(path)


def test_the_gate_fails_bad_files_and_passes_good_ones(tmp_path, capsys):
    good = _write(tmp_path, "good.yaml", {
        "name": "LSASS dump", "technique_id": "T1003.001", "severity": "High", "tactics": ["Credential Access"],
        "description": "APT29 dumped LSASS with comsvcs.dll MiniDump, a well-known LOLBin technique.",
        "requiredDataConnectors": [{"connectorId": "MicrosoftThreatProtection"}],
        "indicators": {"cmd": ["comsvcs.dll MiniDump", "procdump -ma lsass.exe", "C:\\Windows\\Temp\\lsass.dmp"]},
        "query": 'DeviceProcessEvents\n| where Timestamp > ago(1h)\n| where ProcessCommandLine has_all ("comsvcs.dll", "MiniDump")'})
    (tmp_path / "broken.yaml").write_text("description: |\n   a\n  b\n")
    assert ci.main([good, "--min-grade", "C"]) == 0
    assert ci.main([str(tmp_path), "--format", "github"]) == 1
    out = capsys.readouterr().out
    assert "::error file=" in out and "broken.yaml" in out
    assert ci.main([str(tmp_path / "nothing")]) == 2

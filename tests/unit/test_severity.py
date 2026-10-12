"""Severity from the kill-chain stage (archer.build.severity, contract rubric R04.3)."""
import pytest
import yaml

from archer.build.severity import RATINGS, rate


@pytest.mark.parametrize("tactics,expected", [
    (["Discovery"], "Low"),
    (["Initial Access"], "Medium"),
    (["Credential Access"], "High"),
    (["Lateral Movement"], "High"),
    (["Impact"], "Critical"),
    (["credential-access"], "High"),          # STIX phase names
    (["command_and_control"], "High"),
    (["Command And Control"], "High"),        # Archer's title-cased form
    (["Discovery", "Exfiltration"], "High"),  # the most severe wins
    (["IOC Sweep"], "High"),
    ([], "Medium"),
    (["Not A Tactic"], "Medium"),
    ("Impact", "Critical"),                   # a single string
])
def test_rate(tactics, expected):
    assert rate(tactics) == expected


def test_never_low_for_credentials_lateral_or_impact():
    for t in ("Credential Access", "Lateral Movement", "Impact"):
        assert RATINGS.index(rate([t])) > RATINGS.index("Low")


def test_written_yaml_and_yaral_meta_agree(tmp_path, monkeypatch):
    from archer.build import yaml as yaml_writer
    from archer.build.secops import SecOpsGenerator

    monkeypatch.chdir(yaml_writer.os.path.dirname(yaml_writer.__file__) + "/../..")
    tactics = ["Execution", "Credential Access"]
    rule = SecOpsGenerator().generate_yaral_rule("T1003.001", "LSASS Memory", "Execution", "d",
                                                 {"cmd": ["procdump -ma lsass.exe"]}, tactics=tactics)
    out = tmp_path / "LSASS_GoogleSecOps.yaml"
    yaml_writer.write_yaml(str(out), "LSASS Memory", "T1003.001", "d", "GoogleSecOps", tactics, "Test",
                           rule["yaral_code"], datatype="PROCESS_LAUNCH")
    data = yaml.safe_load(out.read_text())
    assert data["severity"] == "High"
    assert 'severity = "HIGH"' in data["query"]


def test_ioc_sweep_rule_has_an_outcome():
    from archer.build.ioc_sweep import secops_sweep

    rule = secops_sweep({"domain": ["evil.example"], "sha256": ["a" * 64]}, "Test report")
    out = rule.split("outcome:")[1].split("condition:")[0]
    assert 'severity = "HIGH"' in rule and "$risk_score = 75" in out
    assert "$hostname = $e.principal.hostname" in out and "match:" not in rule

"""Severity from the kill-chain stage (shikari.build.severity, contract rubric R04.3)."""
import pytest
import yaml

from shikari.build.severity import RATINGS, rate


@pytest.mark.parametrize("tactics,expected", [
    (["Discovery"], "Low"),
    (["Initial Access"], "Medium"),
    (["Credential Access"], "High"),
    (["Lateral Movement"], "High"),
    (["Impact"], "Critical"),
    (["credential-access"], "High"),          # STIX phase names
    (["command_and_control"], "High"),
    (["Command And Control"], "High"),        # Shikari's title-cased form
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


def test_written_yaml_and_search_header_agree(tmp_path, monkeypatch):
    from shikari.build import yaml as yaml_writer
    from shikari.build.secops import SecOpsGenerator

    monkeypatch.chdir(yaml_writer.os.path.dirname(yaml_writer.__file__) + "/../..")
    tactics = ["Execution", "Credential Access"]
    rule = SecOpsGenerator().generate_query("T1003.001", "LSASS Memory", "Execution", "d",
                                                 {"cmd": ["procdump -ma lsass.exe"]}, tactics=tactics)
    out = tmp_path / "LSASS_GoogleSecOps.yaml"
    yaml_writer.write_yaml(str(out), "LSASS Memory", "T1003.001", "d", "GoogleSecOps", tactics, "Test",
                           rule["query"], datatype="PROCESS_LAUNCH")
    data = yaml.safe_load(out.read_text())
    assert data["severity"] == "High"
    assert "severity HIGH" in data["query"].splitlines()[0]


def test_ioc_sweep_is_a_high_severity_search():
    from shikari.build.ioc_sweep import secops_sweep

    query = secops_sweep({"domain": ["evil.example"], "sha256": ["a" * 64]}, "Test report")
    assert "severity HIGH" in query.splitlines()[0]
    assert "match:" not in query and "$e" not in query

"""One file per correlation, written once correlations are final; hand edits survive the next run."""
import yaml

from archer.build import correlation_files as cf
from archer.build.yaml import file_state

JOIN = """// archer_corr_t1134_then_t1098: Access Token Manipulation and Account Manipulation on the same host within 1h · ATT&CK T1134, T1098 · severity HIGH
$e1.metadata.event_type = "PROCESS_LAUNCH" and ($e1.target.process.command_line = /runas/ nocase)
$e1.principal.hostname = $host

$e2.metadata.event_type = "PROCESS_LAUNCH" and ($e2.target.process.command_line = /net\\.exe/ nocase)
$e2.principal.hostname = $host

match:
  $host over 1h"""


def _corr(**kw):
    return dict({"vendor": "googlesecops", "a": "data/groups/AccessTokenManipulation_GoogleSecOps.yaml",
                 "b": "data/groups/AccountManipulation_GoogleSecOps.yaml", "combined_query": JOIN,
                 "techniques_involved": ["Access Token Manipulation", "Account Manipulation"],
                 "tactics": ["Persistence"], "relevance_score": 0.9}, **kw)


def test_each_correlation_gets_a_file_with_the_query_as_is(tmp_path, monkeypatch):
    monkeypatch.setattr(cf, "CORRELATE_DIR", str(tmp_path))
    corrs = [_corr(), _corr(vendor="mde", combined_query="DeviceProcessEvents | take 1")]
    report = cf.write("Scattered Spider", corrs)

    assert sorted(report["written"]) == ["AccessTokenManipulation_and_AccountManipulation_DefenderXDR.yaml",
                                         "AccessTokenManipulation_and_AccountManipulation_GoogleSecOps.yaml"]
    path = tmp_path / corrs[0]["file"]
    data = yaml.safe_load(path.read_text())
    assert data["query"].rstrip() == JOIN and data["kind"] == "correlation"
    assert data["technique_ids"] == ["T1134", "T1098"] and data["time_window"] == "1h"
    assert data["parts"] == ["AccessTokenManipulation_GoogleSecOps.yaml", "AccountManipulation_GoogleSecOps.yaml"]
    assert cf.read_query(str(path)) == JOIN and not file_state(str(path))["edited"]


def test_an_edited_file_is_kept_and_wins(tmp_path, monkeypatch):
    monkeypatch.setattr(cf, "CORRELATE_DIR", str(tmp_path))
    corr = _corr()
    cf.write("G", [corr])
    path = tmp_path / corr["file"]
    path.write_text(path.read_text().replace("over 1h", "over 2h"))

    again = _corr()
    report = cf.write("G", [again])
    assert report["kept_edited"] == [path.name] and again["edited"]
    assert "over 2h" in again["combined_query"] and "over 2h" in path.read_text()


def test_files_a_run_no_longer_makes_are_removed_unless_edited(tmp_path, monkeypatch):
    monkeypatch.setattr(cf, "CORRELATE_DIR", str(tmp_path))
    keep, gone = _corr(), _corr(a="data/groups/Phishing_GoogleSecOps.yaml", b="data/groups/PowerShell_GoogleSecOps.yaml",
                                techniques_involved=["Phishing", "PowerShell"])
    cf.write("G", [keep, gone])
    (tmp_path / keep["file"]).write_text((tmp_path / keep["file"]).read_text().replace("over 1h", "over 3h"))

    report = cf.write("G", [])  # the next run makes neither
    assert report["removed"] == ["Phishing_and_PowerShell_GoogleSecOps.yaml"]
    assert (tmp_path / keep["file"]).exists()  # edited: never removed


def test_same_pair_twice_gets_numbered(tmp_path, monkeypatch):
    monkeypatch.setattr(cf, "CORRELATE_DIR", str(tmp_path))
    a, b = _corr(), _corr(combined_query=JOIN.replace("1h", "2h"))
    cf.write("G", [a, b])
    assert a["file"] != b["file"] and b["file"].endswith("_GoogleSecOps_2.yaml")


def test_name_leads_with_the_pair_and_counts_a_technique_once():
    corr = {"vendor": "mde", "a": "data/groups/AccessTokenManipulation_DeviceEvents.yaml",
            "b": "data/groups/CloudAccounts_DeviceEvents.yaml",
            "techniques_involved": ["Access Token Manipulation", "AccessTokenManipulation", "CachedDomainCredentials",
                                    "Cloud Accounts", "Deobfuscate/Decode Files or Information"]}
    assert cf.filename(corr) == "AccessTokenManipulation_and_CloudAccounts_plus2_DefenderXDR.yaml"
    assert cf.title(corr) == "Access Token Manipulation and Cloud Accounts (+2 more)"
    assert cf._techniques(corr)[2:] == ["Cached Domain Credentials", "Deobfuscate/Decode Files or Information"]

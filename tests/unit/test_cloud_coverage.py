"""Cloud coverage by provider (#36)."""

from shikari.build.cloud_coverage import applies, cloud_coverage, providers_of, siem_of

ATTACK = {
    "T1580": {"name": "Cloud Infrastructure Discovery", "x_mitre_platforms": ["IaaS"],
              "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}]},
    "T1078.004": {"name": "Cloud Accounts", "x_mitre_platforms": ["Identity Provider", "SaaS"], "kill_chain_phases": []},
    "T1059.001": {"name": "PowerShell", "x_mitre_platforms": ["Windows"], "kill_chain_phases": []},
}


def _write(tmp_path, name, text):
    (tmp_path / name).write_text(text)


def test_applies_by_platform():
    assert applies(["IaaS"]) == ["aws", "azure", "gcp"]
    assert applies(["SaaS", "Windows"]) == ["identity"]
    assert applies(["Windows", "Linux"]) == []


def test_providers_from_markers_and_cloudappevents():
    assert providers_of("x.yaml", "metadata.log_type = \"AWS_CLOUDTRAIL\"") == {"aws"}
    assert providers_of("x.yaml", "FROM logs-azure.signinlogs-*") == {"identity"}
    # Defender's CloudAppEvents carries every connected cloud unless the query names one
    assert providers_of("x.yaml", "CloudAppEvents | where ActionType == 'x'") == {"aws", "azure", "gcp"}
    assert providers_of("x.yaml", "CloudAppEvents | where Application == 'Amazon Web Services'") == {"aws"}
    assert providers_of("x.yaml", "DeviceProcessEvents") == set()


def test_siem_from_connector_then_filename():
    assert siem_of("a.yaml", "connectorId: GoogleSecOps") == "SecOps"
    assert siem_of("a_esql.yaml", "") == "Elastic"
    assert siem_of("a.yaml", "index=aws") == "Splunk"


def test_coverage_table(tmp_path):
    _write(tmp_path, "t1580_secops.yaml", "technique_id: T1580\nconnectorId: GoogleSecOps\nquery: AWS_CLOUDTRAIL\n")
    _write(tmp_path, "t1580_splunk.yaml", "technique_id: T1580\nquery: index=gcp\n")
    _write(tmp_path, "t1059.yaml", "technique_id: T1059.001\nquery: DeviceProcessEvents\n")
    result = cloud_coverage(str(tmp_path), ATTACK)
    rows = {r["technique_id"]: r for r in result["techniques"]}
    assert set(rows) == {"T1580", "T1078.004"}  # Windows-only techniques are left out
    assert rows["T1580"]["coverage"] == {"aws": ["SecOps"], "azure": [], "gcp": ["Splunk"], "identity": None}
    assert rows["T1078.004"]["coverage"]["identity"] == []
    assert result["summary"]["aws"] == {"applicable": 1, "covered": 1}
    assert result["summary"]["identity"] == {"applicable": 1, "covered": 0}


def test_sub_technique_counts_for_parent(tmp_path):
    attack = {"T1098": {"name": "Account Manipulation", "x_mitre_platforms": ["IaaS"], "kill_chain_phases": []}}
    _write(tmp_path, "d.yaml", "technique_id: T1098.001\nquery: AzureActivity\n")
    assert cloud_coverage(str(tmp_path), attack)["techniques"][0]["coverage"]["azure"] == ["Splunk"]


def test_missing_library(tmp_path):
    assert cloud_coverage(str(tmp_path / "none"), ATTACK)["summary"]["aws"]["covered"] == 0

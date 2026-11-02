"""Static query checks (shikari.validation.static_check)."""

import pytest

from shikari.build.ioc_sweep import mde_sweep
from shikari.validation.static_check import check_query


def _checks(result):
    return {f["check"] for f in result["findings"]}


@pytest.mark.unit
def test_mde_field_typos_are_errors_with_suggestions():
    r = check_query('DeviceProcessEvents | where ProcessCommandLne has "comsvcs"', "mde")
    assert r["ok"] is False and r["platform"] == "kql"
    assert "ProcessCommandLine" in next(f["message"] for f in r["findings"] if f["check"] == "MDE-FIELD")


@pytest.mark.unit
def test_contract_style_findings_are_warnings_only():
    r = check_query('DeviceProcessEvents | where ProcessCommandLine contains "comsvcs"', "mde")
    assert r["ok"] is True and r["warnings"] and not r["errors"]


@pytest.mark.unit
def test_spl_structure():
    assert check_query('index=wineventlog EventCode=4625 | stats count by user', "splunk")["ok"]
    assert check_query('| tstats count from datamodel=Endpoint.Processes by Processes.user', "splunk")["ok"]
    assert "SPL-4" in _checks(check_query("index=main | statz count", "splunk"))
    assert "SPL-3" in _checks(check_query("index=main | stats count |", "splunk"))
    assert "STRUCT-2" in _checks(check_query('index=main "unterminated', "splunk"))
    # A pipe inside a quoted string is not a stage
    assert check_query('index=main CommandLine="*a|b*" | table _time', "splunk")["ok"]
    r = check_query("EventCode=4625 | stats count", "splunk")
    assert r["ok"] and "SPL-2" in _checks(r)  # unscoped search: a warning


@pytest.mark.unit
def test_placeholders_are_errors():
    assert "PLACEHOLDER" in _checks(check_query("index=<INDEX_NAME> | stats count", "splunk"))


@pytest.mark.unit
def test_network_only_ioc_sweep_projects_network_columns():
    # MDE refused the old sweep: it projected FileName/FolderPath/SHA256 from DeviceNetworkEvents
    q = mde_sweep({"domain": ["level.io"], "ip": ["1.2.3.4"]})
    assert "FolderPath" not in q
    assert check_query(q, "mde")["ok"]

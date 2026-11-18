"""
Grades that say what a detection catches, and behaviour detections for the techniques whose
procedures quote only names.

A command line containing "SeDebugPrivilege" or "runas" was graded B with a low false-positive
risk; launches of osk.exe and Magnify.exe were graded A. Both match ordinary use and miss the attack.
"""

import tempfile

import pytest
import yaml

from shikari.build.behaviours import BEHAVIOURS, render_esql, render_kql, render_udm, write_behaviour_detections
from shikari.validation.precision import branch_findings, is_placeholder, prune_kql
from shikari.validation.quality import assess
from shikari.validation.static_check import check_query

TOKEN = {"query": 'metadata.event_type = "PROCESS_LAUNCH" and (target.process.command_line = /SeDebugPrivilege/ nocase '
                  'or target.process.command_line = /runas/ nocase)',
         "indicators": {"cmd": ["SeDebugPrivilege", "runas"]}, "technique_id": "T1134", "severity": "High",
         "tactics": ["Privilege Escalation"], "description": "SUNSPOT modified its security token to grant itself SeDebugPrivilege",
         "requiredDataConnectors": [{"connectorId": "GoogleSecOps"}]}
ACCESSIBILITY = {"query": 'DeviceProcessEvents\n| where ProcessCommandLine has_any(@"C:\\Windows\\System32\\sethc.exe", '
                          '@"C:\\Windows\\System32\\osk.exe", @"%systemdir%\\")',
                 "indicators": {"cmd": ["C:\\Windows\\System32\\sethc.exe", "C:\\Windows\\System32\\osk.exe", "%systemdir%\\"]},
                 "technique_id": "T1546.008", "severity": "High", "tactics": ["Persistence"],
                 "description": "Adversaries may replace accessibility binaries to get a shell at the logon screen",
                 "requiredDataConnectors": [{"connectorId": "MicrosoftThreatProtection"}]}


def test_names_alone_cant_grade_well():
    for detection, siem in ((TOKEN, "googlesecops"), (ACCESSIBILITY, "mde")):
        a = assess(detection, siem)
        assert a["quality"]["grade"] == "D" and a["fp_risk"]["level"] in ("medium", "high")
    checks = {f["check"] for f in check_query(TOKEN["query"], "googlesecops")["findings"]}
    assert {"PREC-PRIVILEGE", "PREC-BARE"} <= checks


def test_a_placeholder_from_attack_prose_is_one_but_a_real_variable_isnt():
    assert is_placeholder("%systemdir%\\") and not is_placeholder("%SystemRoot%\\NTDS\\ntds.dit")
    assert is_placeholder("[Responder") and is_placeholder("path]") and not is_placeholder("[0-9a-f]")


@pytest.mark.parametrize("query,siem", [
    ('index=edr | search cs1="*mshta*" OR (cs1="*mshta *" cs1="* vbscript:Close*")', "spl"),
    ('metadata.event_type = "PROCESS_LAUNCH" and (target.process.command_line = /reg\\s+query/ nocase '
     'or target.process.file.full_path = /netsh\\.exe/ nocase)', "udm"),
    ('FROM logs-endpoint.events.process-*\n| WHERE @timestamp >= NOW() - 1 day\n| WHERE (TO_LOWER(process.command_line) '
     'RLIKE ".*wevtutil cl.*")\n  OR (TO_LOWER(process.name) RLIKE ".*wevtutil\\\\.exe.*")', "elastic"),
])
def test_the_broadest_branch_decides(query, siem):
    assert any(f["check"] == "PREC-BARE-BRANCH" for f in branch_findings(query, siem))


def test_a_parent_and_child_of_built_ins_is_a_behaviour_not_a_bare_name():
    q = ('DeviceProcessEvents\n| where InitiatingProcessFileName in~ ("winlogon.exe") and FileName in~ ("cmd.exe")')
    checks = {f["check"] for f in check_query(q, "mde")["findings"]}
    assert not checks & {"PREC-BARE", "PREC-BARE-BRANCH"}


def test_generation_drops_a_bare_branch_beside_others_but_keeps_a_sole_one():
    out, removed = prune_kql('DeviceFileEvents\n| where InitiatingProcessCommandLine has_all("At.exe", "/interactive") '
                             'or FileName has "at.exe"')
    assert 'FileName has "at.exe"' not in out and removed
    assert prune_kql('DeviceProcessEvents\n| where FileName =~ "wmic.exe"')[0]


@pytest.mark.parametrize("tid", sorted(BEHAVIOURS))
def test_every_behaviour_renders_clean(tid):
    b = BEHAVIOURS[tid]
    for siem, query in (("mde", render_kql(b)), ("googlesecops", render_udm(b, tid)), ("elastic", render_esql(b))):
        if query:
            assert check_query(query, siem)["findings"] == [], (tid, siem)


def test_behaviours_are_written_and_grade_well():
    out = tempfile.mkdtemp()
    paths = write_behaviour_detections("T1546.008", "Accessibility Features", ["Persistence"], "APT29", out)
    assert [p.rsplit("_", 1)[1] for p in paths] == ["KQL.yaml", "UDM.yaml", "ESQL.yaml"]
    for path, siem in zip(paths, ("mde", "googlesecops", "elastic")):
        doc = yaml.safe_load(open(path, encoding="utf-8").read().split("\n", 1)[1])
        a = assess(doc, siem)
        assert a["quality"]["grade"] in "AB" and a["fp_risk"]["level"] == "low"
    # v18's ID finds the same behaviour; a technique without one writes nothing
    assert write_behaviour_detections("T1562.001", "Disable or Modify Tools", ["Defense Evasion"], "X", out)
    assert write_behaviour_detections("T1595", "Active Scanning", ["Reconnaissance"], "X", out) == []

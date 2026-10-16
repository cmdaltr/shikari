"""Recorded attack telemetry (#22 stage 1): parsing the recordings, and detections checked against them."""
from unittest.mock import patch

from archer.build.indicator_hygiene import GAP
from archer.telemetry import check, datasets as ds

SYSMON = (b"<Event xmlns='x'><System><EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
          b"<EventData><Data Name='Image'>C:\\Windows\\System32\\rundll32.exe</Data>"
          b"<Data Name='CommandLine'>rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Users\\bob\\lsass.dmp full</Data>"
          b"<Data Name='UtcTime'>2021-01-01</Data></EventData></Event>")
TEXT = b"""03/23/2021 01:40:45 PM
LogName=Security
EventCode=4688
Message=A new process has been created.
Process Information:
	New Process Name:	C:\\Windows\\System32\\schtasks.exe
	Process Command Line:	schtasks /create /tn Updater /tr evil.exe
"""


def test_parse_each_format():
    assert list(ds.parse(SYSMON)) == [("Microsoft-Windows-Sysmon/Operational 1", {
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Users\\bob\\lsass.dmp full"})]
    assert list(ds.parse(TEXT)) == [("Security 4688", {"NewProcessName": "C:\\Windows\\System32\\schtasks.exe",
                                                       "CommandLine": "schtasks /create /tn Updater /tr evil.exe"})]
    trail = b'{"eventSource": "iam.amazonaws.com", "eventName": "CreateUser", "userAgent": "aws-cli/2"}\n'
    assert list(ds.parse(trail))[0][0] == "CloudTrail iam.amazonaws.com CreateUser"
    azure = b'{"eventSource": {"value": "x"}, "operationName": {"value": "Microsoft.Automation/runbooks/write"}}\n'
    assert list(ds.parse(azure))[0][0] == "Azure Microsoft.Automation/runbooks/write"  # not CloudTrail
    audit = b'type=EXECVE msg=audit(1.1:2): argc=3 a0="useradd" a1="-o" a2="evil"\n'
    assert list(ds.parse(audit)) == [("auditd EXECVE", {"CommandLine": "useradd -o evil"})]
    esxi = b"May  7 13:23:06 10.0.0.1 2025-05-07T13:23:04Z host shell[264180]: [root]: esxcli system permission set --id x\n"
    assert list(ds.parse(esxi)) == [("syslog shell", {"CommandLine": "esxcli system permission set --id x"})]
    # The same channel in another case is the same log
    lower = SYSMON.replace(b"Microsoft-Windows-Sysmon/Operational", b"microsoft-windows-sysmon/operational")
    assert list(ds.parse(lower))[0][0] == "Microsoft-Windows-Sysmon/Operational 1"


def test_describe_maps_to_what_archer_generates():
    info = ds.describe("Microsoft-Windows-Sysmon/Operational 1")
    assert (info["mde"], info["udm"]) == ("DeviceProcessEvents", "PROCESS_LAUNCH")
    assert ds.describe("CloudTrail iam.amazonaws.com CreateUser")["label"] == "AWS CloudTrail: iam.amazonaws.com CreateUser"
    assert ds.describe("Made-Up 9")["mde"] == ""


RECORDINGS = {"datasets": [
    {"id": "a", "source": "splunk", "title": "comsvcs", "techniques": ["T1003.001"], "background": [],
     "events": {"Microsoft-Windows-Sysmon/Operational 1": 3, "Microsoft-Windows-Sysmon/Operational 10": 9}},
    {"id": "b", "source": "splunk", "title": "procdump", "techniques": ["T1003.001"], "background": [],
     "events": {"Microsoft-Windows-Sysmon/Operational 10": 4}},
] + [{"id": f"o{i}", "source": "splunk", "title": "other", "techniques": ["T1059.001"], "background": [],
      "events": {"Microsoft-Windows-Sysmon/Operational 1": 1}} for i in range(6)]}
VALUES = {
    "a": {"Microsoft-Windows-Sysmon/Operational 1": {"CommandLine": ["rundll32.exe comsvcs.dll, MiniDump 624 C:\\Users\\bob\\lsass.dmp full"]}},
    "b": {"Microsoft-Windows-Sysmon/Operational 10": {"TargetImage": ["C:\\Windows\\system32\\lsass.exe"]}},
    **{f"o{i}": {"Microsoft-Windows-Sysmon/Operational 1": {"CommandLine": ["powershell.exe -nop rundll32.exe"]}} for i in range(6)},
}


def recorded():
    check._haystack.clear()
    return patch.object(ds, "load", return_value=RECORDINGS), patch.object(ds, "values", return_value=VALUES)


def test_check_finds_indicators_in_their_techniques_recordings():
    a, b = recorded()
    with a, b:
        r = check.check({"technique_id": "T1003.001", "name": "LSASS Memory", "indicators": {
            "cmd": ["comsvcs.dll, MiniDump", "rundll32.exe", "never-recorded.exe"],
            "path": [f"C:\\Users\\{GAP}\\lsass.dmp"]}})
    assert r["status"] == "seen" and r["datasets"] == 2
    by = {i["value"]: i for i in r["indicators"]}
    assert by["comsvcs.dll, MiniDump"]["seen"][0]["label"].startswith("Sysmon 1")
    assert by[f"C:\\Users\\{GAP}\\lsass.dmp"]["seen"]  # any user's
    assert by["rundll32.exe"]["noisy"] and by["rundll32.exe"]["elsewhere"] == 6
    assert not by["never-recorded.exe"]["seen"]


def test_check_without_recordings_or_values():
    a, b = recorded()
    with a, b:
        assert check.check({"technique_id": "T1490", "indicators": {"cmd": ["vssadmin"]}})["status"] == "no_recordings"
    with patch.object(ds, "load", return_value=RECORDINGS), patch.object(ds, "values", return_value=None):
        check._haystack.clear()
        assert check.check({"technique_id": "T1003.001", "indicators": {"cmd": ["x.exe"]}})["status"] == "no_values"


def test_technique_view_and_data_sources():
    a, b = recorded()
    with a, b:
        t = check.technique("T1003.001")
        assert t["exact"] and len(t["recordings"]) == 2
        # Sysmon 10 is in both recordings, Sysmon 1 in one of two: both count as at least half
        assert {n["name"] for n in t["need"]["udm"]} == {"PROCESS_OPEN", "PROCESS_LAUNCH"}
        assert check.technique("T1003")["exact"] is False  # its family's
        by = {d["name"]: d["techniques"] for d in check.by_data_source()["mde"]}
    assert by["DeviceProcessEvents"] == 2 and by["DeviceEvents"] == 1


def test_evtx_samples_are_filed_by_technique():
    from archer.telemetry import evtx_attack

    assert evtx_attack.technique("TA0006-Credential Access/T1003-Credential dumping/ID4662-DCsync.evtx") == "T1003"
    assert evtx_attack.technique("TA0003-Persistence/T1098.xxx-Account manipulation/ID4738-x.evtx") == "T1098"
    assert evtx_attack.technique("TA0005-Defense Evasion/T1070.001-Clear Windows event logs/ID104.evtx") == "T1070.001"
    assert evtx_attack.technique("Antivirus/ID1116-Defender threat detected.evtx") == ""
    # Only auditd's process records are process events
    assert ds.describe("auditd EXECVE")["udm"] == "PROCESS_LAUNCH"
    assert ds.describe("auditd DAEMON_START")["mde"] == ""


def test_native_logs_alone():
    a, b = recorded()
    with a, b:
        native = {t["technique"]: t for t in check.overview(["native"])}
        everything = {t["technique"]: t for t in check.overview()}
    # Every recording here is Sysmon: without it, nothing records the technique
    assert native["T1003.001"]["visible"] == 0 and native["T1003.001"]["logs"] == []
    assert everything["T1003.001"]["visible"] == 2
    assert ds.collection("Security 4688") == "native" and ds.collection("Microsoft-Windows-Sysmon/Operational 1") == "sysmon"


def test_osquery_and_elastic_endpoint():
    osq = b'{"name":"pack_incident-response_launchd","hostIdentifier":"mac","columns":{"label":"com.evil","path":"/Library/LaunchDaemons/com.evil.plist","program_arguments":"/tmp/evil"}}\n'
    assert list(ds.parse(osq)) == [("osquery launchd", {"CommandLine": "/tmp/evil", "TargetFilename": "/Library/LaunchDaemons/com.evil.plist", "TaskName": "com.evil"})]
    elastic = b'''{\r\n "_source": {"data_stream": {"dataset": "endpoint.events.process"}, "event": {"action": "exec"},
      "process": {"executable": "/usr/bin/security", "args": ["security", "dump-keychain", """-d"""]}}\r\n}'''
    assert list(ds.parse(elastic)) == [("Elastic Endpoint process exec", {"CommandLine": "security dump-keychain -d", "Image": "/usr/bin/security"})]
    assert ds.platforms({"id": "x", "events": {"auditd EXECVE": 1, "osquery launchd": 1}}) == ["linux", "macos"]


def test_platform_counts_only_its_own_logs():
    mixed = {"datasets": [{"id": "splunk:T1021.004/x", "source": "splunk", "title": "ssh", "techniques": ["T1021.004"],
                           "background": [], "events": {"auditd EXECVE": 2, "Security 4688": 3}},
                          {"id": "splunk:T1021.004/esxi_ssh_enabled", "source": "splunk", "title": "esxi", "techniques": ["T1021.004"],
                           "background": [], "events": {"syslog shell": 1}}]}
    check._haystack.clear()
    with patch.object(ds, "load", return_value=mixed):
        linux = {t["technique"]: t for t in check.overview(platforms=["linux"])}
        esxi = {t["technique"]: t for t in check.overview(platforms=["esxi"])}
    assert linux["T1021.004"]["logs"] == ["Linux auditd: EXECVE (command line)"] and linux["T1021.004"]["recordings"] == 1
    assert esxi["T1021.004"]["platforms"] == ["esxi"]

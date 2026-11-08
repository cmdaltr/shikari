"""Lab telemetry in the SIEM export packs (#41)."""

import io
import json
import os
import zipfile
from datetime import datetime, timedelta, timezone

import yaml

from shikari.export import siem_pack, siem_telemetry as st

NS = "xmlns='http://schemas.microsoft.com/win/2004/08/events/event'"


def _event(provider, eid, when, data, channel="Microsoft-Windows-Sysmon/Operational"):
    fields = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (f"<Event {NS}><System><Provider Name='{provider}'/><EventID>{eid}</EventID>"
            f"<TimeCreated SystemTime='{when}'/><Channel>{channel}</Channel><Computer>LAB-WIN</Computer></System>"
            f"<EventData>{fields}</EventData></Event>")


def _run(tmp_path):
    run = tmp_path / "lab-run"
    (run / "T1016-1").mkdir(parents=True)
    (run / "T1059.004-2").mkdir()
    xml = "\n".join([
        _event(st.SYSMON, 1, "2026-11-01T10:00:00.1234567Z",
               {"Image": r"C:\Windows\System32\nbtstat.exe", "CommandLine": "nbtstat -n",
                "ParentImage": r"C:\Windows\System32\cmd.exe", "ParentCommandLine": "cmd /c nbtstat -n",
                "User": r"LAB\ben", "ProcessId": "4242", "Hashes": "SHA256=ABC,MD5=DEF,IMPHASH=0"}),
        _event(st.SECURITY, 4688, "2026-11-01T10:00:01Z",
               {"NewProcessName": r"C:\Windows\System32\ipconfig.exe", "CommandLine": "ipconfig /all",
                "ParentProcessName": r"C:\Windows\System32\cmd.exe", "SubjectUserName": "ben",
                "NewProcessId": "0x10"}, channel="Security"),
        _event(st.SYSMON, 13, "2026-11-01T10:00:02Z",
               {"TargetObject": r"HKLM\SOFTWARE\Run\evil", "Details": r"C:\evil.exe", "Image": r"C:\x.exe"}),
        _event(st.SYSMON, 22, "2026-11-01T10:00:03Z", {"QueryName": "evil.example.com", "Image": r"C:\x.exe"}),
        _event(st.SECURITY, 4624, "2026-11-01T10:00:04Z", {"TargetUserName": "ben"}, channel="Security"),
    ])
    (run / "T1016-1" / "events.xml").write_text("\ufeff" + xml, encoding="utf-8")
    es = {"time": "2026-11-01T10:00:05.123456789Z", "process": {"executable": {"path": "/bin/zsh"},
                                                                 "audit_token": {"pid": 1}},
          "event": {"exec": {"target": {"executable": {"path": "/usr/bin/curl"}, "audit_token": {"pid": 2, "euid": 501}},
                             "args": ["curl", "-s", "http://x"]}}, "event_type": 9}
    (run / "T1059.004-2" / "es.ndjson").write_text(json.dumps(es) + "\nnot json\n")
    (run / "manifest.json").write_text(json.dumps({"run": "lab-run", "host": "lab-win", "tests": [
        {"technique": "T1016", "folder": "T1016-1"},
        {"custom": True, "mapping": "T1059.004", "mapping_kind": "sub", "folder": "T1059.004-2"}]}))
    return str(run)


def test_read_run_keeps_matchable_events(tmp_path):
    manifest, events = st.read_run(_run(tmp_path))
    assert manifest["run"] == "lab-run"
    assert [e["kind"] for e in events] == ["process", "process", "registry", "dns", "process"]  # 4624 dropped
    first, sec, *_ , mac = events
    assert first["ts"] == datetime(2026, 11, 1, 10, 0, 0, 123456, tzinfo=timezone.utc)
    assert (first["cmd"], first["user"], first["pid"], first["technique"]) == ("nbtstat -n", "ben", 4242, "T1016")
    assert (sec["image"], sec["pid"]) == (r"C:\Windows\System32\ipconfig.exe", 16)
    assert (mac["platform"], mac["cmd"], mac["image"]) == ("macos", "curl -s http://x", "/usr/bin/curl")
    assert mac["technique"] == "T1059.004"  # a custom recording's mapping


def test_rebase_keeps_spacing(tmp_path):
    _, events = st.read_run(_run(tmp_path))
    gaps = [b["ts"] - a["ts"] for a, b in zip(events, events[1:])]
    now = datetime(2026, 12, 25, tzinfo=timezone.utc)
    st.rebase(events, now)
    assert events[-1]["ts"] == now - timedelta(minutes=1)
    assert [b["ts"] - a["ts"] for a, b in zip(events, events[1:])] == gaps


def test_ecs(tmp_path):
    _, events = st.read_run(_run(tmp_path))
    stream, doc = st.to_ecs(events[0], "lab-run")
    assert stream == "logs-endpoint.events.process-shikari"
    assert doc["process"]["command_line"] == "nbtstat -n" and doc["process"]["name"] == "nbtstat.exe"
    assert doc["process"]["parent"]["command_line"] == "cmd /c nbtstat -n"
    assert doc["process"]["hash"] == {"sha256": "abc", "md5": "def"}
    assert doc["event"]["category"] == ["process"] and doc["host"]["name"] == "lab-win"
    assert doc["labels"]["shikari_technique"] == "T1016"
    stream, doc = st.to_ecs(events[2], "lab-run")
    assert stream == "logs-endpoint.events.registry-shikari"
    assert doc["registry"]["path"] == r"HKLM\SOFTWARE\Run\evil" and doc["registry"]["value"] == "evil"
    stream, doc = st.to_ecs(events[3], "lab-run")
    assert stream == "logs-endpoint.events.network-shikari" and doc["dns"]["question"]["name"] == "evil.example.com"
    bodies = st.elastic_bulk(events, "lab-run")
    lines = bodies[0].splitlines()
    assert len(lines) == 2 * len(events) and json.loads(lines[0]) == {"create": {"_index": "logs-endpoint.events.process-shikari"}}


SPLUNK_DOCS = [
    {"indicators": {"cmd": ["nbtstat -n", "ipconfig /all"], "sw": ["nbtstat.exe"]},
     "query": 'index=windows_prod earliest=-1d | rename process_command_line_arguments AS process_command_line '
              'ComputerName AS device | search (process_command_line="*nbtstat *" process_command_line="* -n*") '
              'OR process_name IN ("nbtstat.exe", "ipconfig.exe")'},
    {"indicators": {"reg": [r"HKLM\SOFTWARE\Run\evil"]},
     "query": 'index=os sourcetype IN ("cef:windows", "cef:sysmon") | search cs3="*HKLM\\\\SOFTWARE\\\\Run\\\\evil*"'},
    {"indicators": {"api": ["AssumeRole"]}, "query": "index=aws | search act=AssumeRole"},
]


def test_learn_splunk_fields():
    learned = st.learn_splunk_fields(SPLUNK_DOCS)
    assert set(learned) == {"windows_prod", "os"}  # nothing learned for aws: not an endpoint kind
    win = learned["windows_prod"]
    assert set(win["kinds"]["cmd"]) == {"process_command_line_arguments"}  # the rename undone
    assert set(win["kinds"]["sw"]) == {"process_name"}
    assert win["host"] == "ComputerName"
    assert learned["os"]["kinds"] == {"reg": {"cs3": 1}}
    assert learned["os"]["sourcetypes"] == ["cef:windows", "cef:sysmon"]


def test_splunk_events(tmp_path):
    _, events = st.read_run(_run(tmp_path))
    by_index = st.splunk_events(events, st.learn_splunk_fields(SPLUNK_DOCS), "lab-run")
    first = by_index["windows_prod"][0]
    assert first["source"] == "shikari-lab" and first["index"] == "windows_prod"
    ev = first["event"]
    assert ev["process_command_line_arguments"] == "nbtstat -n"
    assert ev["process_name"] == "nbtstat.exe"  # a name field gets the file name, not the path
    assert ev["ComputerName"] == "LAB-WIN" and ev["shikari_technique"] == "T1016"
    [reg] = by_index["os"]
    assert reg["event"]["cs3"] == r"HKLM\SOFTWARE\Run\evil" and reg["sourcetype"] == "cef:sysmon"


def test_parent_fields_take_the_parent(tmp_path):
    _, events = st.read_run(_run(tmp_path))
    learned = {"mde": {"kinds": {"sw": {"properties.InitiatingProcessFileName": 1, "properties.FileName": 1},
                                 "cmd": {"properties.InitiatingProcessCommandLine": 1}},
                       "sourcetypes": [], "host": ""}}
    ev = st.splunk_events(events[:1], learned, "r")["mde"][0]["event"]["properties"]
    assert ev == {"InitiatingProcessFileName": "cmd.exe", "FileName": "nbtstat.exe",
                  "InitiatingProcessCommandLine": "cmd /c nbtstat -n"}


def test_put_nests_dotted_names():
    fields = {}
    st._put(fields, "properties.CommandLine", "x")
    st._put(fields, "properties.Image", "y")
    assert fields == {"properties": {"CommandLine": "x", "Image": "y"}}


def test_wazuh(tmp_path):
    _, events = st.read_run(_run(tmp_path))
    w = st.to_wazuh(events[0])
    assert w["win"]["system"]["eventID"] == "1" and w["win"]["system"]["providerName"] == st.SYSMON
    assert w["win"]["eventdata"]["commandLine"] == "nbtstat -n"
    assert w["win"]["eventdata"]["image"] == r"C:\Windows\System32\nbtstat.exe"
    assert st.to_wazuh(events[-1]) is None  # macOS


def _pack(tmp_path, siem):
    gdir = tmp_path / "groups"
    gdir.mkdir(parents=True, exist_ok=True)
    for i, d in enumerate(SPLUNK_DOCS):
        with open(gdir / f"s{i}.yaml", "w") as fh:
            yaml.safe_dump({"id": f"s{i}", "name": "n", "technique_id": "T1016",
                            "requiredDataConnectors": [{"connectorId": "Splunk"}], **d}, fh)
    with open(gdir / "e.yaml", "w") as fh:
        yaml.safe_dump({"id": "e", "name": "n", "technique_id": "T1016", "query": "FROM logs-endpoint.events.process-*",
                        "requiredDataConnectors": [{"connectorId": "Elastic"}]}, fh)
    data, manifest = siem_pack.build(siem, None, str(gdir), None, exclude_unavailable=False,
                                     wazuh_ids=str(tmp_path / "ids.json"), telemetry_run=_run(tmp_path))
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return {n: zf.read(n).decode() for n in zf.namelist() if not n.endswith(".tgz")}, manifest


def test_packs_with_telemetry(tmp_path):
    files, manifest = _pack(tmp_path / "e", "elastic")
    assert {"telemetry/events-001.ndjson", "telemetry/load.sh"} <= set(files)
    assert manifest["telemetry"]["events"] == 5 and manifest["telemetry"]["rebased"]
    assert "Lab telemetry: 5 events from lab-run, shifted" in files["README.txt"]

    files, manifest = _pack(tmp_path / "s", "splunk")
    assert {"telemetry/windows_prod-001.json", "telemetry/os-001.json", "telemetry/load.sh"} <= set(files)
    # the two Windows process creations (not the registry and DNS events, though they name a process);
    # the Mac's exec stays out of a Windows index, and os takes only the registry write
    assert manifest["telemetry"]["indexes"] == {"windows_prod": 2, "os": 1}

    files, manifest = _pack(tmp_path / "w", "wazuh")
    assert manifest["telemetry"]["events"] == 4  # Windows only
    assert len(files["telemetry/events.json"].splitlines()) == 4

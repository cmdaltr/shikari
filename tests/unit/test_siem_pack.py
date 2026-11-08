"""SIEM export packs (#41): Elastic rules NDJSON and the Splunk app."""

import io
import json
import os
import tarfile
import zipfile

import pytest

from shikari.export import siem_pack

ELASTIC_Q = """FROM logs-endpoint.events.process-*
| WHERE @timestamp >= NOW() - 1 day
| WHERE TO_LOWER(process.command_line) RLIKE ".*nbtstat.*"
| STATS Events = COUNT(*) BY host.name"""

SPLUNK_Q = """index=os earliest=-1d sourcetype="cef:sysmon"
| search cs1="*C:\\\\Windows\\\\System32\\\\nbtstat.exe*"
| stats count by dvc"""


def _write(gdir, name, connector, query, tid="T1016", **extra):
    doc = {"id": f"{name.lower()}-0000-1111-2222-333333333333", "name": name, "technique_id": tid,
           "description": "Finds it.\nOn two lines.", "severity": "High",
           "requiredDataConnectors": [{"connectorId": connector, "dataTypes": ["X"]}],
           "queryFrequency": "1d", "queryPeriod": "1d", "tactics": ["Discovery"],
           "tags": ["Sandworm Team (Group)"], "query": query, **extra}
    import yaml
    with open(os.path.join(gdir, f"{name}.yaml"), "w") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False)


def _lister(_group, gdir):
    return sorted(n for n in os.listdir(gdir) if n.endswith(".yaml"))


@pytest.fixture
def gdir(tmp_path):
    d = tmp_path / "groups"
    d.mkdir()
    _write(str(d), "FindDomain", "Elastic", ELASTIC_Q)
    _write(str(d), "FindDomainSpl", "Splunk", SPLUNK_Q)
    _write(str(d), "FindDomainMde", "MicrosoftThreatProtection", "DeviceProcessEvents")
    return str(d)


ATTACK = {"tactics": {"Discovery": {"id": "TA0007", "shortname": "discovery"}},
          "techniques": {"T1016": "System Network Configuration Discovery", "T1016.001": "Internet Connection Discovery"}}


def _unzip(data):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


def test_elastic_rule_shape():
    doc = {"id": "abc", "name": "Find Domain", "technique_id": "T1016.001", "severity": "High",
           "tactics": ["Discovery", "Not A Tactic"], "query": ELASTIC_Q + "\n", "queryFrequency": "1h",
           "queryPeriod": "1d", "description": ""}
    rule = siem_pack.elastic_rule(doc, ATTACK)
    assert rule["rule_id"] == "abc" and rule["type"] == "esql" and rule["language"] == "esql"
    assert rule["enabled"] is False
    assert (rule["severity"], rule["risk_score"]) == ("high", 73)
    assert (rule["interval"], rule["from"]) == ("60m", "now-24h")
    assert rule["query"] == ELASTIC_Q
    assert rule["description"] == "Find Domain"  # an empty description falls back to the name
    [threat] = rule["threat"]  # the unknown tactic is dropped, not invented
    assert threat["tactic"]["id"] == "TA0007"
    tech = threat["technique"][0]
    assert tech["id"] == "T1016" and tech["subtechnique"][0]["id"] == "T1016.001"
    assert tech["subtechnique"][0]["reference"].endswith("/T1016/001/")


def test_elastic_rule_without_bundle_keeps_going():
    rule = siem_pack.elastic_rule({"id": "x", "name": "n", "technique_id": "T1016", "query": "FROM a"},
                                  siem_pack.attack_lookup(None))
    assert rule["threat"] == [] and rule["severity"] == "medium"


def test_elastic_pack(gdir):
    data, manifest = siem_pack.build("elastic", "Sandworm Team", gdir, _lister, exclude_unavailable=False)
    files = _unzip(data)
    assert set(files) == {"rules.ndjson", "README.txt", "manifest.json"}
    rules = [json.loads(line) for line in files["rules.ndjson"].decode().splitlines()]
    assert [r["name"] for r in rules] == ["FindDomain (T1016)"]  # Splunk and MDE detections left out
    assert manifest["detections"] == 1 and manifest["group"] == "Sandworm Team"
    assert manifest["indexes"] == ["logs-endpoint.events.process-*"]
    assert "logs-endpoint.events.process-*" in files["README.txt"].decode()


def test_splunk_pack(gdir):
    data, manifest = siem_pack.build("splunk", None, gdir, _lister, exclude_unavailable=False)
    files = _unzip(data)
    assert manifest["group"] == "All" and manifest["indexes"] == ["os"]
    with tarfile.open(fileobj=io.BytesIO(files["shikari_detections.tgz"])) as tar:
        app = {m.name: tar.extractfile(m).read().decode() for m in tar.getmembers()}
    assert set(app) == {f"shikari_detections/{p}" for p in
                        ("default/app.conf", "default/savedsearches.conf", "default/indexes.conf",
                         "metadata/default.meta")}
    saved = app["shikari_detections/default/savedsearches.conf"]
    assert saved.startswith("[Shikari - T1016 - FindDomainSpl - finddoma]\n")
    search = next(line for line in saved.splitlines() if line.startswith("search = "))
    # one line, Windows path intact, no trailing backslash continuation
    assert search == ('search = index=os earliest=-1d sourcetype="cef:sysmon" | search '
                      'cs1="*C:\\\\Windows\\\\System32\\\\nbtstat.exe*" | stats count by dvc')
    assert "disabled = 1" in saved and "alert.severity = 5" in saved and "cron_schedule = 0 0 * * *" in saved
    assert "description = Finds it. On two lines." in saved
    assert "[os]\nhomePath = $SPLUNK_DB/os/db" in app["shikari_detections/default/indexes.conf"]


def test_splunk_indexes():
    qs = ['index=edr earliest=-1d', 'index="os" | x', 'index IN (proxy, "dns") | y', "index=main", "index=_internal"]
    assert siem_pack.splunk_indexes(qs) == ["dns", "edr", "os", "proxy"]


def test_stanza_strips_brackets():
    name, _ = siem_pack.splunk_saved_search({"id": "12345678abc", "name": "a [b]\nc", "technique_id": "T1",
                                             "query": "q"})
    assert name.startswith("Shikari - T1 - a ") and name.endswith(" - 12345678")
    assert "[" not in name and "]" not in name and "\n" not in name


def test_cron():
    assert siem_pack._cron("15m") == "*/15 * * * *"
    assert siem_pack._cron("6h") == "0 */6 * * *"
    assert siem_pack._cron("1d") == "0 0 * * *"
    assert siem_pack._cron("") == "0 0 * * *"


def test_missing_id_or_query_is_excluded(gdir):
    _write(gdir, "NoQuery", "Elastic", "")
    _, manifest = siem_pack.build("elastic", None, gdir, _lister, exclude_unavailable=False)
    assert manifest["detections"] == 1
    assert manifest["excluded"] == [{"file": "NoQuery.yaml", "reason": "no id or no query"}]


def test_unknown_siem():
    with pytest.raises(ValueError):
        siem_pack.build("qradar", None, "/nonexistent", _lister)


def test_filename():
    assert siem_pack.filename("splunk", "Sandworm Team") == "shikari-splunk-sandworm-team.zip"
    assert siem_pack.filename("elastic", None) == "shikari-elastic-all.zip"


def test_tactics_match_without_case_and_fall_back_to_attack():
    attack = {"tactics": {"Command and Control": {"id": "TA0011", "shortname": "command-and-control"}},
              "techniques": {"T1105": "Ingress Tool Transfer"},
              "technique_tactics": {"T1105": ["Command and Control"]}}
    doc = {"id": "x", "name": "n", "technique_id": "T1105", "query": "FROM a"}
    assert siem_pack.elastic_rule({**doc, "tactics": ["Command And Control"]}, attack)["threat"][0]["tactic"]["id"] == "TA0011"
    assert siem_pack.elastic_rule({**doc, "tactics": ["Sandworm Team (Group)"]}, attack)["threat"][0]["tactic"]["name"] == "Command and Control"


def test_splunk_dollar_is_escaped():
    _, keys = siem_pack.splunk_saved_search({"id": "x", "name": "n", "technique_id": "T1",
                                             "query": 'index=os cmd IN ("*$env:UserName*", "*C$*")'})
    assert keys["search"] == 'index=os cmd IN ("*$$env:UserName*", "*C$$*")'

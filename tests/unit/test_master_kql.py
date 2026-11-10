"""The master hunt query for Defender XDR: shikari.export.master_kql."""

import os
from datetime import datetime, timezone

import pytest
import yaml

from shikari.export import master_kql


def _write(d, fname, tid, table, connector="MicrosoftThreatProtection", where='ProcessCommandLine has "x"', tags=("APT29 (Group)",)):
    by = "DeviceName, InitiatingProcessAccountName" if table == "DeviceNetworkEvents" else "DeviceName, AccountName"
    query = f"{table}\n| where Timestamp > ago(1d)\n| where {where}\n| summarize count() by {by}"
    with open(os.path.join(d, fname), "w") as fh:
        yaml.safe_dump({"name": f"{tid} detection", "technique_id": tid, "tags": list(tags), "query": query,
                        "requiredDataConnectors": [{"connectorId": connector}]}, fh)


def _files(group, d):
    return sorted(os.path.join(d, f) for f in os.listdir(d)
                  if group.replace("_", " ") + " (Group)" in open(os.path.join(d, f)).read())


@pytest.fixture
def library(tmp_path):
    d = str(tmp_path)
    _write(d, "a_net.yaml", "T1016", "DeviceNetworkEvents", where='InitiatingProcessCommandLine has "nbtstat"')
    _write(d, "a_proc.yaml", "T1016", "DeviceProcessEvents", where='FileName has_any("nbtstat.exe", "ipconfig.exe")')
    _write(d, "b_proc.yaml", "T1033", "DeviceProcessEvents", where='ProcessCommandLine has "whoami"')
    _write(d, "c_splunk.yaml", "T1057", "index=x", connector="Splunk")
    _write(d, "d_other.yaml", "T1082", "DeviceProcessEvents", tags=("FIN7 (Group)",))
    return d


NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


@pytest.mark.unit
def test_one_function_per_technique_from_the_best_table_and_a_ranked_union(library):
    text, m = master_kql.build("APT29", library, _files, tlp="red", now=NOW)
    assert m["detections"] == 2 and m["techniques"] == ["T1016", "T1033"] and m["capped"] == 1
    assert "a_proc.yaml" in text and "a_net.yaml" not in text          # process events beat network events
    assert "c_splunk.yaml" not in text and "d_other.yaml" not in text  # not MDE; not this group
    assert "let StartTime = ago(30d);" in text and "ago(1d)" not in text
    assert text.count("Timestamp between (StartTime .. EndTime)") == 2
    assert "let D1 = () {" in text and "union isfuzzy=true D1(), D2()" in text
    assert '| extend Technique = "T1016", Detection = "T1016 detection"' in text
    assert "order by TechniqueCount desc" in text and "// TLP:RED" in text and "Scope     : APT29" in text


@pytest.mark.unit
def test_scoping_by_technique_and_taking_every_detection(library):
    _text, m = master_kql.build("APT29", library, _files, techniques=["t1016"], per_technique=0, now=NOW)
    assert m["detections"] == 2 and m["techniques"] == ["T1016"] and m["capped"] == 0
    _text, m = master_kql.build(None, library, _files, now=NOW)            # the whole library
    assert m["techniques"] == ["T1016", "T1033", "T1082"]


@pytest.mark.unit
def test_a_parent_technique_takes_in_its_sub_techniques(tmp_path):
    d = str(tmp_path)
    _write(d, "ps.yaml", "T1059.001", "DeviceProcessEvents")
    _text, m = master_kql.build("APT29", d, _files, techniques=["T1059"], now=NOW)
    assert m["techniques"] == ["T1059.001"]


@pytest.mark.unit
def test_a_query_that_fails_the_static_check_is_left_out_and_named(library):
    _write(library, "e_bad.yaml", "T1049", "DeviceProcessEvents", where='ProcessCommandLine has_any("a"')
    text, m = master_kql.build("APT29", library, _files, now=NOW)
    assert [e["file"] for e in m["excluded"]] == ["e_bad.yaml"]
    assert "Left out  : 1" in text and "e_bad.yaml" in text.split("// ====", 2)[1]


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["30", "1w", "30d; drop", ""])
def test_the_lookback_is_hours_or_days(library, bad):
    with pytest.raises(ValueError):
        master_kql.build("APT29", library, _files, lookback=bad)


@pytest.mark.unit
def test_nothing_to_combine_says_so(tmp_path):
    text, m = master_kql.build("APT29", str(tmp_path), _files, now=NOW)
    assert m["detections"] == 0 and "No Defender XDR detections" in text

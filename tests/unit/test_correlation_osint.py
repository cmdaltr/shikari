"""Correlations inherit their detections' OSINT enrichment, and say when they're out of date (#23)."""
from unittest.mock import patch

from shikari.build import correlation_osint as co

KQL = "DeviceProcessEvents\n| where Timestamp > ago(1d)\n| where ProcessCommandLine has \"runas\"\n| summarize by DeviceName"
YARAL = ('rule r {\n  events:\n    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
         '    (re.regex($e.target.process.command_line, `vssadmin`) nocase)\n  outcome:\n    $host = $e.principal.hostname\n'
         '  condition:\n    $e\n}')


def test_inherited_merges_and_tags_each_part():
    a = {"technique_id": "T1134", "osint_enhanced": True, "osint_sources": ["https://x/1", "https://x/2"],
         "known_false_positives": [{"source": "Splunk", "rule": "R1", "url": "u", "text": "Admins use runas"}],
         "lol_references": [{"source": "LOLBAS", "name": "runas.exe", "url": "https://lolbas/runas"}]}
    b = {"technique_id": "T1490", "osint_sources": ["https://x/2", "https://x/3"],
         "known_false_positives": [{"source": "Elastic", "rule": "R2", "url": "u", "text": "Backup software"},
                                   {"source": "Splunk", "rule": "R1", "url": "u", "text": "admins use RUNAS"}]}
    out = co.inherited([a, b])
    assert out["sources"] == ["https://x/1", "https://x/2", "https://x/3"] and out["enhanced"]
    assert [(f["technique"], f["text"]) for f in out["known_false_positives"]] == [
        ("T1134", "Admins use runas"), ("T1490", "Backup software")]  # the same text once
    assert out["lol_references"][0]["technique"] == "T1134"


def test_false_positives_fall_back_to_the_osint_index():
    d = {"technique_id": "T1134", "indicators": {"cmd": ["runas"]}}
    with patch("shikari.build.osint_index.known_false_positives", return_value=[{"text": "x", "url": "u"}]) as kfp:
        assert co.inherited([d])["known_false_positives"] == [{"text": "x", "url": "u", "technique": "T1134"}]
    kfp.assert_called_once_with("T1134", terms=["runas"])


def test_stale_parts():
    combined = ("let a = DeviceProcessEvents | where ProcessCommandLine has \"runas\";\n"
                "rule c { events: (re.regex($e1.target.process.command_line, `vssadmin`) nocase) }")
    parts = [{"name": "Runas", "query": KQL}, {"name": "Shadow copies", "query": YARAL}]
    assert co.stale_parts(combined, parts) == []  # $e renamed to $e1 still counts
    rewritten = {"name": "Shadow copies", "query": YARAL.replace("vssadmin", "wbadmin")}
    assert co.stale_parts(combined, [parts[0], rewritten]) == ["Shadow copies"]
    assert co.conditions(YARAL) == ["(re.regex($e.target.process.command_line, `vssadmin`) nocase)"]

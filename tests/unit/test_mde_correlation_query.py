"""Defender XDR correlations: whole where clauses, weak parts left out, each let checked against its table."""
from archer.ai.genai import engine
from archer.build.correlation_files import errors
from archer.validation.static_check import check_query

MULTILINE = """DeviceProcessEvents
  | where Timestamp > ago(1d)
  | where (ProcessCommandLine has_all("aws", "ec2", "create-key-pair") or
  InitiatingProcessCommandLine has_all("aws", "ec2")) or
  (FileName =~ "x.exe")
  | summarize count() by DeviceName"""
NETWORK = """DeviceNetworkEvents
  | where Timestamp > ago(1d)
  | where RemoteUrl has "evil.example"
  | summarize count() by DeviceName"""
PROTOCOL_ONLY = """DeviceNetworkEvents
  | where Timestamp > ago(1d)
  | where Protocol has "SSH"
  | summarize count() by DeviceName"""


def test_a_where_clause_runs_on_over_its_continuation_lines():
    assert engine._where_clauses(MULTILINE) == [
        '(ProcessCommandLine has_all("aws", "ec2", "create-key-pair") or InitiatingProcessCommandLine has_all("aws", "ec2")) or (FileName =~ "x.exe")']


def test_the_join_has_no_dangling_operator_and_passes_the_checks():
    q = engine._build_join_correlation_query({"vendor": "mde", "query_a": MULTILINE, "query_b": NETWORK,
                                              "techniques_involved": ["A", "B"]}, {})
    assert " or)" not in q and "or\n  )" not in q
    assert errors({"vendor": "mde", "combined_query": q}) == []


def test_a_protocol_only_part_is_left_out_and_an_empty_side_means_no_correlation():
    both = engine._build_join_correlation_query({"vendor": "mde", "query_a": MULTILINE,
                                                 "query_b": NETWORK + "\nUNION\n" + PROTOCOL_ONLY}, {})
    assert 'Protocol has "SSH"' not in both and "evil.example" in both
    assert engine._build_join_correlation_query({"vendor": "mde", "query_a": MULTILINE, "query_b": PROTOCOL_ONLY}, {}) == ""
    assert errors({"vendor": "mde", "combined_query": ""}) == ["no query"]


def test_each_let_is_checked_against_its_own_table():
    q = """let A = DeviceProcessEvents
| where ProcessCommandLine has "x"
| project Timestamp, DeviceName, AccountName=AccountName, *;
let B = DeviceNetworkEvents
| where RemoteUrl has "y"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, *;
A
| join kind=inner (B) on DeviceName, AccountName"""
    assert [f for f in check_query(q, "mde")["findings"] if f["check"] == "MDE-FIELD"] == []
    bad = q.replace('RemoteUrl has "y"', 'ProcessCommandLine has "y"')
    assert any("ProcessCommandLine isn't a column of DeviceNetworkEvents" in f["message"]
               for f in check_query(bad, "mde")["findings"])

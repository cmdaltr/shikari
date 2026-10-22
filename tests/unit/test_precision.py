"""Precision checks (#15): queries that parse but can't fire for the right reason."""

from archer.build.indicator_hygiene import clean_indicator
from archer.validation.precision import check, prune_kql
from archer.validation.static_check import check_query


def kql(where):
    return f"DeviceNetworkEvents\n| where Timestamp > ago(1d)\n| where {where}\n| summarize by DeviceName"


def codes(query, siem="kql", platforms=None):
    return {f["check"] for f in check(query, siem, platforms)}


def test_protocol_alone():
    assert codes(kql('Protocol has "DNS"')) == {"PREC-CONTEXT"}
    assert "PREC-CONTEXT" not in codes(kql('Protocol has "DNS" and InitiatingProcessFileName =~ "nslookup.exe"'))


def test_string_operator_on_a_port():
    assert "PREC-NUMERIC" in codes(kql('RemotePort has "135" or LocalPort has "135"'))
    assert codes(kql("RemotePort == 135")) == {"PREC-PORT"}


def test_placeholders():
    assert "PREC-PLACEHOLDER" in codes(kql('ProcessCommandLine has_all("mstsc.exe", "v:{hostname")'))
    assert "PREC-PLACEHOLDER" in codes(kql('FolderPath has "C:\\\\Users\\\\[Username]\\\\AppData"'))
    # bcdedit's {default} is real text
    assert not codes(kql('ProcessCommandLine has_all("bcdedit", "{default}", "recoveryenabled")'))


def test_generic_words_only_where_they_can_match_alone():
    assert "PREC-GENERIC" in codes(kql('ProcessCommandLine has_any("copy", "curl")'))
    assert "PREC-GENERIC" not in codes(kql('ProcessCommandLine has_all("dir", "/a")'))


def test_duplicates():
    q = kql('(ProcessCommandLine has "x.exe") or (ProcessCommandLine has "x.exe")')
    assert "PREC-DUPLICATE" in codes(q)


def test_table_the_technique_cannot_reach():
    q = "CloudAppEvents\n| where ActionType has \"Add member to role.\""
    assert "PREC-TABLE" in codes(q, platforms=["Windows"])
    assert "PREC-TABLE" not in codes(q, platforms=["SaaS", "Office Suite"])


def test_yaral():
    bare = 'rule r {\n  events:\n    $e.metadata.event_type = "PROCESS_LAUNCH"\n\n  condition:\n    $e\n}'
    assert codes(bare, "yara_l") == {"PREC-EMPTY"}
    proto = ('rule r {\n  events:\n    $e.metadata.event_type = "NETWORK_CONNECTION"\n'
             '    ($e.network.application_protocol = "SSH")\n  condition:\n    $e\n}')
    assert codes(proto, "yara_l") == {"PREC-CONTEXT"}
    # The same value on two fields isn't a duplicate
    two = ('rule r {\n  events:\n    (re.regex($e.target.process.command_line, `HKCU\\\\Run`) nocase or '
           're.regex($e.target.registry.registry_key, `HKCU\\\\Run`) nocase)\n  condition:\n    $e\n}')
    assert "PREC-DUPLICATE" not in codes(two, "yara_l")


def test_prune_keeps_what_can_fire():
    q = kql('(RemotePort has "135" or LocalPort has "135") or (Protocol has_any("HTTP")) '
            'or (ProcessCommandLine has_any("copy", "curl")) or (ProcessCommandLine has_any("copy", "curl")) '
            'or (ProcessCommandLine has "dir")')
    pruned, removed = prune_kql(q)
    assert '| where (ProcessCommandLine has_any("curl"))\n' in pruned
    assert {f["check"] for f in removed} == {"PREC-NUMERIC", "PREC-CONTEXT", "PREC-GENERIC", "PREC-DUPLICATE"}
    assert prune_kql(kql('Protocol has "DNS"'))[0] is None


def test_check_query_reports_them_as_errors():
    r = check_query(kql('Protocol has "DNS"'), "mde")
    assert r["ok"] is False and any(f["check"] == "PREC-CONTEXT" and f["severity"] == "error" for f in r["findings"])


def test_hygiene_leaves_a_gap_for_placeholders():
    assert clean_indicator("mstsc.exe /v:{hostname|ip}") == "mstsc.exe /v:"
    assert clean_indicator("C:\\Users\\[Username]\\AppData\\Roaming") == "C:\\Users\\\u2026\\AppData\\Roaming"
    assert clean_indicator("[IP address]") is None
    assert clean_indicator("bcdedit /set {default} recoveryenabled No") == "bcdedit /set {default} recoveryenabled No"
    assert clean_indicator("HKLM\\SYSTEM\\{4D36E972-E325-11CE-BFC1-08002BE10318}").endswith("10318}")


def test_a_built_in_binary_alone_is_bare():
    wmic = 'metadata.event_type = "PROCESS_LAUNCH" and (target.process.command_line = /wmic\\.exe/ nocase)'
    assert "PREC-BARE" in codes(wmic, "udm")
    assert "PREC-BARE" in codes('DeviceProcessEvents\n| where FileName =~ "wmic.exe"')
    # With what it was asked to do, or a tool that isn't built in, it says something
    assert "PREC-BARE" not in codes('DeviceProcessEvents\n| where FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete"')
    assert "PREC-BARE" not in codes('DeviceProcessEvents\n| where FileName =~ "AnyDesk.exe"')


def test_api_names_alone_on_a_command_line():
    apc = ('metadata.event_type = "PROCESS_LAUNCH" and (target.process.command_line = /QueueUserAPC/ nocase '
           'or target.process.command_line = /OpenThread/ nocase)')
    assert "PREC-API" in codes(apc, "udm")
    assert "PREC-API" not in codes('DeviceProcessEvents\n| where ProcessCommandLine has_all ("Add-Type", "QueueUserAPC")')

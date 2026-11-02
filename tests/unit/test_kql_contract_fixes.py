"""
Generator 3's KQL (shikari.build.queries, shikari.validation.mde_field_validator,
shikari.build.migrate_kql): one row per finding, verbatim paths, bracketed and/or, so
generated MDE detections pass the output contract's KQL lint.
"""
import hashlib

import pytest

from shikari.build import migrate_kql
from shikari.build.queries import _kql, compile_mde_queries
from shikari.contract.validator import Report, lint_kql, mixed_andor
from shikari.validation.mde_field_validator import (
    bracket_and_runs,
    format_mde_query,
    verbatim_backslash_literals,
)

SUMMARY = "\n| summarize by Timestamp, DeviceName, ActionType, AccountName, FolderPath, FileName, SHA256, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, RegistryKey"
MAPPING = {"cmd": {"MDE": {"DeviceProcessEvents": ["ProcessCommandLine", "InitiatingProcessCommandLine"]}}}


def lint(q):
    rep = Report()
    lint_kql(q, rep)
    mixed_andor(q, "kql", rep)
    return rep.gates()


def test_kql_literal_is_verbatim_only_with_a_backslash():
    assert _kql(r"C:\Windows\sethc.exe") == r'@"C:\Windows\sethc.exe"'
    assert _kql('say "hi"') == r'"say \"hi\""'


def test_windows_path_is_not_split_like_an_azure_operation():
    out = []
    compile_mde_queries(MAPPING, [r"C:\Windows\System32\sethc.exe", "Microsoft.Authorization/roleAssignments/write"], "cmd", out)
    q = out[0]
    assert r'has @"C:\Windows\System32\sethc.exe"' in q
    assert 'has_all("exe")' not in q


def test_generated_query_passes_the_contract_lint():
    out = []
    compile_mde_queries(MAPPING, [r"C:\Windows\System32\sethc.exe", "reg save",
                                  "Microsoft.Authorization/roleAssignments/write",
                                  "Microsoft.Authorization/elevateAccess/action"], "cmd", out)
    q = format_mde_query(out[0] + SUMMARY)
    assert lint(q) == []
    assert "summarize Events = count(), FirstSeen = min(Timestamp)" in q
    assert "arg_max(Timestamp," in q


def test_bracketing_keeps_strings_and_existing_groups():
    e = 'a has "x and y" and b == 1 or (c == 2 and d == 3 or e == 4)'
    assert bracket_and_runs(e) == '(a has "x and y" and b == 1) or ((c == 2 and d == 3) or e == 4)'
    assert bracket_and_runs("a == 1 or b == 2") == "a == 1 or b == 2"


def test_verbatim_conversion_keeps_the_value():
    assert verbatim_backslash_literals(r'x has "C:\\a \"b\""') == r'x has @"C:\a ""b"""'


def _detection(tmp_path, query, edited=False):
    block = "\n".join("  " + l for l in query.split("\n"))
    body = f"name: X\nrequiredDataConnectors:\n  - connectorId: MicrosoftThreatProtection\nquery: |\n{block}\nentityMappings:\n"
    digest = hashlib.sha256(block.rstrip().encode()).hexdigest()
    if edited:
        digest = "0" * 64
    path = tmp_path / "d.yaml"
    path.write_text(f"# shikari-generator: 2 query-sha256: {digest}\n{body}")
    return path


def test_migration_fixes_old_files_and_keeps_them_unedited(tmp_path):
    from shikari.build.yaml import file_state
    old = ('DeviceEvents\n| where Timestamp > ago(1d)\n'
           '| where AdditionalFields has_all("C:\\\\Windows\\\\sethc") and AdditionalFields has_all("exe") or AdditionalFields has "y"\n'
           '| summarize by Timestamp, DeviceName, ActionType, FileName,\n  FolderPath, RegistryKey')
    path = _detection(tmp_path, old)
    assert migrate_kql.migrate_file(str(path)) == "migrated"
    state = file_state(str(path))
    assert state["generator"] == 2 and not state["edited"]
    text = path.read_text()
    assert '(AdditionalFields has_all(@"C:\\Windows\\sethc") and AdditionalFields has_all("exe")) or' in text
    assert "summarize by Timestamp" not in text
    assert migrate_kql.migrate_file(str(path)) == "unchanged"


def test_migration_leaves_hand_edited_files(tmp_path):
    path = _detection(tmp_path, "DeviceEvents\n| summarize by Timestamp, DeviceName", edited=True)
    before = path.read_text()
    assert migrate_kql.migrate_file(str(path)) == "edited"
    assert path.read_text() == before

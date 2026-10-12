"""Unit tests for archer.contract (output contract v1.0).

The contract package is loaded by file path so these tests run without the web stack
(archer/__init__ imports requests, stix2 and friends). Needs only PyYAML and jsonschema.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PKG = ROOT / "archer" / "contract"


@pytest.fixture(scope="module")
def contract():
    if "archer.contract" in sys.modules:
        return sys.modules["archer.contract"]
    spec = importlib.util.spec_from_file_location("archer.contract", PKG / "__init__.py",
                                                  submodule_search_locations=[str(PKG)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules["archer.contract"] = mod
    spec.loader.exec_module(mod)
    return mod


EXEMPLARS = sorted((PKG / "exemplars").glob("EX-*.yaml"))


@pytest.mark.unit
@pytest.mark.parametrize("path", EXEMPLARS, ids=[p.stem for p in EXEMPLARS])
def test_exemplar_passes(contract, path):
    rep = contract.validate_file(path)
    assert rep.ok(), rep.fails


@pytest.mark.unit
def test_exemplar_mix(contract):
    assert len(EXEMPLARS) == 9
    yaral = [p for p in EXEMPLARS if "yaral" in p.name or "rejection" in p.name]
    assert len(yaral) * 3 >= len(EXEMPLARS) * 2, "at least two-thirds YARA-L"


def _mutate(path, old, new):
    text = path.read_text()
    assert old in text, f"anchor missing: {old[:40]}"
    return text.replace(old, new, 1)


EX = {p.name[:5]: p for p in EXEMPLARS}
MUTATIONS = [
    # (name, exemplar, old, new, expected gate prefix) — each maps to a workbook Low-row defect
    ("unused_event_var_Q007_Q018", "EX-01", "$setup and $payload", "$setup", "YL-5"),
    ("status_not_draft", "EX-01", "status: draft\n    detection_type", "status: production\n    detection_type", "STATUS"),
    ("parent_pid_join_Q054r2", "EX-02", "$cli.principal.asset_id = $device", "$cli.principal.asset_id = $device\n          $cli.principal.process.parent_process.pid = $device", "YL-18"),
    ("pid_int_compare_Q055", "EX-02", '$cli.target.process.command_line != ""\n          (', '$cli.target.process.command_line != ""\n          $cli.target.process.pid > 0\n          (', "YL-13"),
    ("placeholder_ioc_Q034", "EX-03", "value: 9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc", "value: evil.bat", "IOC-2"),
    ("uppercase_hash_Q032", "EX-03", "value: fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb", "value: FD3CA4007B225FDF8DE7AF4345A19179D5EFA8C4BB9205F88CDA806E5684B1EB", "IOC-6"),
    ("undeclared_reflist", "EX-03", "in %shai_hulud_payload_sha256", "in %undeclared_list", "YL-17"),
    ("mixed_andor_Q025_Q035", "EX-04", '$p.metadata.event_type = "PROCESS_LAUNCH"\n          $p.target.process.command_line != ""', '($p.metadata.event_type = "PROCESS_LAUNCH" or $p.metadata.event_type = "PROCESS_OPEN" and $p.target.process.command_line != "")', "LOGIC-andor"),
    ("regex_sample_mismatch_Q052", "EX-01", "must_match:\n          - 'node .vscode/setup.mjs'\n          - '/usr/local", "must_match:\n          - 'node setup.mjs'\n          - '/usr/local", "RX-5"),
    ("undeclared_regex", "EX-01", "re.regex($setup.target.process.file.full_path, `(^|[\\\\/])node(\\.exe)?$`)", "re.regex($setup.target.process.file.full_path, `node`)", "RX-1"),
    ("kql_contains_Q044", "EX-06", "InitiatingProcessFileName =~ FileName", "InitiatingProcessFileName contains FileName", "KQL-7"),
    ("kql_bad_literal_Q024_Q028", "EX-06", '@"\\Windows Defender\\"', '"\\Windows Defender\\"', "KQL-5"),
    ("kql_unused_let_Q007", "EX-06", "      let lookback = 2h;", '      let lookback = 2h;\n      let BenignSkypeProcesses = dynamic(["teams.exe"]);', "KQL-1"),
    ("kql_datetime_Q035", "EX-06", "| where Timestamp > ago(lookback)", "| where Timestamp > datetime(2025-07-21)", "KQL-6"),
    ("kql_failopen_Q022", "EX-06", "      | where ActionType ==", '      | where isempty(InitiatingProcessAccountName) or InitiatingProcessAccountName != "soc"\n      | where ActionType ==', "KQL-13"),
    ("kql_dropped_union_Q031", "EX-07", "union FileHits, ProcessHits, NetworkHits, ImageLoadHits, GenericHits", "union FileHits, ProcessHits, NetworkHits, ImageLoadHits", "KQL-3"),
    ("kql_dup_union_Q033", "EX-07", "union FileHits, ProcessHits, NetworkHits, ImageLoadHits, GenericHits", "union FileHits, ProcessHits, NetworkHits, ImageLoadHits, GenericHits, FileHits", "KQL-2"),
    ("hardcoded_user_Q014", "EX-06", "      | where ActionType ==", '      | where AccountUpn has "[USER_NAME]"\n      | where ActionType ==', "SCOPE-1"),
    ("lookback_vs_frequency_R13_2", "EX-06", "lookback: 2h", "lookback: 12h", "KQL-12"),
    ("query_not_block_scalar_Q043", "EX-06", "query: |", "query:", "LEX-2"),
    ("tactic_pre_v19_R11", "EX-06", "- privilege_escalation\n        - stealth", "- defense_evasion", "SCHEMA"),
    ("suppression_without_marker_R05_2", "EX-06", "// S2:", "// S9:", "SUP-1"),
]


@pytest.mark.unit
@pytest.mark.parametrize("name,ex,old,new,gate", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_mutation_is_caught(contract, name, ex, old, new, gate):
    rep = contract.validate_text(_mutate(EX[ex], old, new), name)
    assert any(f.startswith(gate) for f in rep.fails), f"expected {gate}, got {rep.fails}"


# ---------------------------------------------------------------------------
# Query-level lint on legacy (pre-contract) queries: the Archer rows Q036-Q049
# ---------------------------------------------------------------------------

Q044_KQL = """DeviceProcessEvents
| where Timestamp > ago(1d)
| where (ProcessCommandLine contains "runas" or InitiatingProcessCommandLine contains "runas")
| summarize by Timestamp, DeviceName, ActionType, AccountName, AccountUpn, FolderPath, FileName, SHA256, SHA1, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessParentFileName, InitiatingProcessVersionInfoCompanyName, InitiatingProcessVersionInfoProductName, IsProcessRemoteSession, AdditionalFields
"""

Q048_YARAL = """rule T1003_001 {
meta:
author = "Archer Detection Engineering"
description = "Detects LSASS Memory (T1003.001)"
severity = "MEDIUM"

events:
$e.metadata.event_type = "PROCESS_LAUNCH"
(re.regex($e.target.process.command_line, `comsvcs.dll`) nocase or re.regex($e.target.process.command_line, `rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump PID  lsass.dmp full`) nocase) and (re.regex($e.network.application_protocol, `HTTP`) nocase)

condition:
$e
}
"""

Q037_YARAL = """rule T1003_007 {
meta:
author = "Archer Detection Engineering"
severity = "MEDIUM"

events:
$e.metadata.event_type = "PROCESS_LAUNCH"
(re.regex($e.target.process.command_line, `and`) nocase or re.regex($e.target.process.command_line, `file shows how memory is mapped within the process virtual address space. And`) nocase)

condition:
$e
}
"""

Q042_KQL = """DeviceProcessEvents
| where Timestamp > ago(1d)
| where (ProcessCommandLine has_all("grep", "-E", ""^[0-9a-f-]*", "r"", "/proc/"$pid"/maps") or ProcessCommandLine has_any("/maps", "/mem"))
| summarize by Timestamp, DeviceName
"""


@pytest.mark.unit
def test_legacy_lint_q044(contract):
    rep = contract.lint_query(Q044_KQL)
    assert rep.siem == "kql"
    assert {"KQL-7", "KQL-14", "KQL-15"} <= set(rep.gates()), rep.fails


@pytest.mark.unit
def test_legacy_lint_q048(contract):
    rep = contract.lint_query(Q048_YARAL)
    assert rep.siem == "yara_l"
    gates = set(rep.gates())
    assert "YL-21" in gates, rep.fails   # network field on PROCESS_LAUNCH
    assert "YL-22" in gates, rep.fails   # unescaped Windows path in regex
    assert "YL-1" in gates, rep.fails    # rule name not snake_case


@pytest.mark.unit
def test_legacy_lint_q037_prose_indicators(contract):
    rep = contract.lint_query(Q037_YARAL)
    gates = set(rep.gates())
    assert "YL-23" in gates and "YL-24" in gates, rep.fails


@pytest.mark.unit
def test_legacy_lint_q042_unbalanced_quotes(contract):
    rep = contract.lint_query(Q042_KQL)
    assert "KQL-16" in rep.gates(), rep.fails


@pytest.mark.unit
def test_legacy_lint_spl_is_skipped(contract):
    rep = contract.lint_query('index=edr_events earliest=-1d "curl" "brew"')
    assert rep.siem == "spl" and rep.ok()


@pytest.mark.unit
def test_contract_exemplar_queries_are_clean_under_legacy_lint(contract):
    import yaml
    for p in EXEMPLARS:
        doc = yaml.safe_load(p.read_text())["archer_output"]
        if doc["kind"] != "rule":
            continue
        rep = contract.lint_query(doc["rule"]["query"], doc["rule"]["siem"])
        assert rep.ok(), (p.name, rep.fails)


@pytest.mark.unit
def test_gate_is_warn_only_by_default(contract, monkeypatch, capsys):
    monkeypatch.delenv("ARCHER_CONTRACT_STRICT", raising=False)
    allowed, rep = contract.gate_query(Q044_KQL, label="q044")
    assert allowed and rep.fails
    assert "[contract WARN]" in capsys.readouterr().out


@pytest.mark.unit
def test_gate_blocks_in_strict_mode(contract, monkeypatch):
    monkeypatch.setenv("ARCHER_CONTRACT_STRICT", "1")
    allowed, _ = contract.gate_query(Q044_KQL, label="q044")
    assert not allowed


@pytest.mark.unit
def test_pipeline_rule_round_trip(contract, tmp_path, monkeypatch):
    monkeypatch.setattr(contract.pipeline, "CONTRACT_DIR", tmp_path / "contract")
    text = EX["EX-01"].read_text()
    out = contract.handle_contract_response(text, technique_id="T1059.007", group_name="test")
    assert len(out) == 1 and out[0]["platform"] == "GoogleSecOps" and out[0]["detection_type"] == "scheduled_detection"
    assert (tmp_path / "contract" / "execution_t1059_007_udm_process_node_hook_setup_then_bun_payload.yaml").exists()


@pytest.mark.unit
def test_pipeline_rejection_and_failure(contract, tmp_path, monkeypatch):
    monkeypatch.setattr(contract.pipeline, "CONTRACT_DIR", tmp_path / "contract")
    assert contract.handle_contract_response(EX["EX-08"].read_text(), "T1059.007", "test") == []
    assert list((tmp_path / "contract" / "rejections").glob("*.yaml"))
    broken = _mutate(EX["EX-01"], "status: draft\n    detection_type", "status: production\n    detection_type")
    assert contract.handle_contract_response(broken, "T1059.007", "test") == []
    assert list((tmp_path / "contract" / "failed").glob("*.findings.txt"))


@pytest.mark.unit
def test_prompt_block_contains_contract_and_exemplars(contract):
    block = contract.contract_prompt_block("yara_l", "hunt")
    assert "archer_output" in block and "EX-01" in block and "PRE-OUTPUT CHECKLIST" in block
    kql = contract.contract_prompt_block("kql", "ioc_sweep")
    assert "EX-06" in kql and "EX-07" in kql


# ---------------------------------------------------------------------------
# Regressions: valid input the validator rejected or crashed on
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_kql_negation_operators_are_not_yaml_tags(contract):
    text = _mutate(EX["EX-06"], "      | where ActionType ==",
                   '      | where InitiatingProcessFileName !in~ ("svchost.exe") and FileName !has "x"\n      | where ActionType ==')
    assert "LEX-5" not in contract.validate_text(text).gates()


@pytest.mark.unit
def test_yaml_tag_outside_query_still_caught(contract):
    text = _mutate(EX["EX-06"], "    lookback: 2h", "    lookback: !!str 2h")
    assert "LEX-5" in contract.validate_text(text).gates()


@pytest.mark.unit
def test_short_kql_name_reports_instead_of_crashing(contract):
    text = _mutate(EX["EX-06"], "name: PrivilegeEscalation_T1055.004_DeviceEvents_RemoteApcQueued", "name: Execution_T1055")
    assert "NAME-1" in contract.validate_text(text).gates()


@pytest.mark.unit
def test_kql_live_schedule_reports_instead_of_crashing(contract):
    text = _mutate(EX["EX-06"], '      frequency: "1h"\n      grouping: DeviceId and InjectingProcess', "      mode: live")
    gates = contract.validate_text(text).gates()
    assert "KQL-12" not in gates and ("TYPE-2" in gates or "SCHEMA" in gates)


@pytest.mark.unit
def test_numeric_list_items_are_valid(contract):
    rep = contract.lint_query("DeviceNetworkEvents\n| where Timestamp > ago(1d)\n| where RemotePort in (445, 139) and ActionType !in~ (\"a\")\n")
    assert "KQL-16" not in rep.gates(), rep.fails


@pytest.mark.unit
def test_backslash_after_verbatim_string_is_caught(contract):
    rep = contract.lint_query('DeviceProcessEvents\n| where FolderPath startswith @"C:\\Users" and FileName == "a\\b.exe"\n')
    assert "KQL-5" in rep.gates(), rep.fails


@pytest.mark.unit
@pytest.mark.parametrize("wrap", [
    lambda t: f"```yaml\n{t}```\n",
    lambda t: f"Here is the rule:\n\n```yaml\n{t}```\n\nLet me know if you need changes.",
    lambda t: f"---\n{t}",
    lambda t: f"---\n{t}...\n",
], ids=["fenced", "fenced_with_prose", "leading_marker", "markers_both_ends"])
def test_pipeline_unwraps_chat_framing(contract, tmp_path, monkeypatch, wrap):
    monkeypatch.setattr(contract.pipeline, "CONTRACT_DIR", tmp_path / "contract")
    out = contract.handle_contract_response(wrap(EX["EX-06"].read_text()), technique_id="T1055.004", group_name="test")
    assert len(out) == 1, list((tmp_path / "contract" / "failed").glob("*.txt"))


@pytest.mark.unit
def test_empty_and_unbalanced_brackets_are_caught(contract):
    broken = 'DeviceEvents\n| where Timestamp > ago(1d)\n| where ())))))) or (ActionType has_any("CreateKeyPair"))\n'
    assert "KQL-17" in contract.lint_query(broken).gates()
    ok = 'DeviceEvents\n| where Timestamp > ago(1d) and FileName has ")("\n| summarize count() by DeviceName\n'
    assert "KQL-17" not in contract.lint_query(ok).gates(), contract.lint_query(ok).fails


BRANCHED_YARAL = r"""rule t1564_003 {
meta:
author = "Archer"

events:
($e.metadata.event_type = "PROCESS_LAUNCH" and re.regex($e.target.process.command_line, `powershell\.exe\s+-WindowStyle\s+Hidden`) nocase) or (($e.metadata.event_type = "REGISTRY_CREATION" or $e.metadata.event_type = "REGISTRY_MODIFICATION") and re.regex($e.target.registry.registry_key, `HKEY_CURRENT_USER\\Console`) nocase)

condition:
$e
}
"""


@pytest.mark.unit
def test_yl21_is_judged_per_branch(contract):
    # Each OR branch carries its own event type: command_line belongs to the PROCESS_LAUNCH branch
    assert "YL-21" not in contract.lint_query(BRANCHED_YARAL).gates()
    same_branch = BRANCHED_YARAL.replace("$e.target.registry.registry_key", "$e.target.process.command_line")
    assert "YL-21" in contract.lint_query(same_branch).gates()


@pytest.mark.unit
def test_kql16_allows_escaped_quotes_in_ordinary_strings(contract):
    ok = 'DeviceProcessEvents\n| where ProcessCommandLine has_all("SYSTEMD_UNIT_PATH=\\"", "lib")'
    assert "KQL-16" not in contract.lint_query(ok).gates()
    bad = 'DeviceProcessEvents\n| where ProcessCommandLine has_all("a\\"b, "c")'
    assert "KQL-16" in contract.lint_query(bad).gates()

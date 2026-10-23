"""
Chains: three techniques on one host within the window, built from a vendor's scored
pairs. Every pair stands on its own; a chain needs A-B and B-C to be pairs, and each
technique to bring a tactic the other two don't.
"""

from archer.ai.genai import engine
from archer.build import correlation_files
from archer.build.udm import build_chain
from archer.validation.static_check import check_query


def _udm(tid, name, expr):
    return f"// archer_{tid.replace('.', '_')}: {name} · ATT&CK {tid}\n{expr}"


PHISH = _udm("T1566", "Phishing", 'metadata.event_type = "PROCESS_LAUNCH" and target.process.command_line = /mshta/ nocase')
PWSH = _udm("T1059.001", "PowerShell", 'metadata.event_type = "PROCESS_LAUNCH" and target.process.command_line = /-enc/ nocase')
DUMP = _udm("T1003.001", "LSASS Memory", 'metadata.event_type = "PROCESS_LAUNCH" and target.process.command_line = /comsvcs/ nocase')
VALID = _udm("T1078", "Valid Accounts", 'metadata.event_type = "USER_LOGIN" and target.user.userid = /svc_/ nocase')


def test_udm_chain_binds_every_event_to_the_host():
    q = build_chain([PHISH, PWSH, DUMP])

    assert q.startswith("// archer_chain_t1566_t1059_001_t1003_001:")
    assert "Phishing, PowerShell and LSASS Memory on the same host within 1h" in q
    for i in (1, 2, 3):
        assert f"$e{i}.principal.hostname = $host" in q
    assert q.rstrip().endswith("match:\n  $host over 1h")
    assert not [f for f in check_query(q, "googlesecops")["findings"] if f["severity"] == "error"]


def test_udm_chain_refuses_a_side_that_is_not_udm():
    assert build_chain([PHISH, "DeviceProcessEvents | take 1", DUMP]) is None


def test_kql_chain_checks_each_part_against_its_table():
    nodes = [
        {"name": "PowerShell", "technique_id": "T1059.001", "queries": [
            'DeviceProcessEvents\n| where Timestamp > ago(1d)\n| where ProcessCommandLine has "-enc"']},
        {"name": "LSASS Memory", "technique_id": "T1003.001", "queries": [
            'DeviceProcessEvents\n| where ProcessCommandLine has "comsvcs"',
            'DeviceFileEvents\n| where FileName endswith ".dmp"']},
        {"name": "Create Account", "technique_id": "T1136", "queries": [
            'DeviceProcessEvents\n| where ProcessCommandLine has_all("net", "user", "/add")']},
    ]
    q = engine._kql_chain(nodes)

    assert "let T2_1 = DeviceProcessEvents" in q and "let T2_2 = DeviceFileEvents" in q
    assert "let T2 = union T2_1, T2_2" in q
    assert q.count("join kind=inner") == 2
    assert "abs(datetime_diff('minute', T1Time, T3Time)) <= 60" in q
    assert "ATT&CK T1059.001, T1003.001, T1136" in q.splitlines()[0]
    assert check_query(q, "mde")["findings"] == []


def _pairs(edges, tactics):
    """Scored pairs between techniques, with the file_info the engine would have."""
    queries = {"Phishing": PHISH, "PowerShell": PWSH, "LSASS Memory": DUMP, "Valid Accounts": VALID}
    info = {f"g/{n.replace(' ', '')}_UDM.yaml": {"name": n, "tactics": tactics[n], "query": queries[n]}
            for n in tactics}
    path = {v["name"]: p for p, v in info.items()}
    pairs = [{"vendor": "googlesecops", "a": path[a], "b": path[b], "query_a": queries[a], "query_b": queries[b],
              "combined_query": "x", "relevance_score": 0.9} for a, b in edges]
    return pairs, info


def test_three_techniques_each_with_their_own_tactic_make_a_chain():
    pairs, info = _pairs([("Phishing", "PowerShell"), ("PowerShell", "LSASS Memory")],
                         {"Phishing": ["Initial Access"], "PowerShell": ["Execution"],
                          "LSASS Memory": ["Credential Access"]})
    chains = engine._build_chains(pairs, info)

    assert len(chains) == 1
    chain = chains[0]
    assert chain["chain"] and sorted(chain["techniques_involved"]) == ["LSASS Memory", "Phishing", "PowerShell"]
    assert chain["tactics"] == ["Credential Access", "Execution", "Initial Access"]
    assert len([chain["a"]] + chain["b"]) == 3
    assert "$e3.principal.hostname = $host" in chain["combined_query"]


def test_a_technique_adding_no_tactic_of_its_own_is_no_chain():
    # Valid Accounts holds every tactic the other two have: the spread is its alone
    pairs, info = _pairs([("Valid Accounts", "PowerShell"), ("Valid Accounts", "LSASS Memory")],
                         {"Valid Accounts": ["Initial Access", "Execution", "Credential Access"],
                          "PowerShell": ["Execution"], "LSASS Memory": ["Credential Access"]})
    assert engine._build_chains(pairs, info) == []


def test_two_techniques_are_never_a_chain():
    pairs, info = _pairs([("Phishing", "PowerShell")], {"Phishing": ["Initial Access"], "PowerShell": ["Execution"]})
    assert engine._build_chains(pairs, info) == []


def test_chain_file_names_every_technique():
    corr = {"vendor": "googlesecops", "chain": True, "a": "g/PowerShell_UDM.yaml",
            "b": ["g/Phishing_UDM.yaml", "g/LSASSMemory_UDM.yaml"],
            "techniques_involved": ["LSASS Memory", "Phishing", "PowerShell"]}
    assert correlation_files.filename(corr) == "LSASSMemory_and_Phishing_and_PowerShell_UDM.yaml"
    assert correlation_files.title(corr) == "LSASS Memory, Phishing and PowerShell"
    assert correlation_files._window("// archer_chain_x: A, B and C on the same device within 2h") == "2h"


def test_a_run_keeps_a_chain_only_when_it_produced_every_part():
    from archer.app import _run_correlations

    chain = {"a": "g/A_UDM.yaml", "b": ["g/B_UDM.yaml", "g/C_UDM.yaml"]}
    assert _run_correlations([chain], {"A_UDM.yaml", "B_UDM.yaml", "C_UDM.yaml"}) == [chain]
    assert _run_correlations([chain], {"A_UDM.yaml", "B_UDM.yaml"}) == []

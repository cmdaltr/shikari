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


def test_a_hubs_extra_pairs_give_way_to_the_next_best(monkeypatch):
    # The hub's pairs score highest; past its limit, places go to pairs without it
    monkeypatch.setattr(engine, "PAIRS_PER_TECHNIQUE", 2)
    monkeypatch.setattr(engine, "_score_correlation", lambda corr, info: corr["score"])
    hub = [{"a": "g/Hub_UDM.yaml", "b": f"g/T{i}_UDM.yaml", "score": 140} for i in range(4)]
    rest = [{"a": f"g/T{i}_UDM.yaml", "b": f"g/U{i}_UDM.yaml", "score": 100} for i in range(3)]

    kept = engine._score_and_filter_correlations(hub + rest, {}, min_relevance=0.4, max_per_vendor=5)

    assert [c["a"] for c in kept].count("g/Hub_UDM.yaml") == 2
    assert len(kept) == 5


def test_a_pairs_per_table_variants_share_its_place(monkeypatch):
    # Defender XDR has a query per table: the same two techniques on three tables are one place
    monkeypatch.setattr(engine, "_score_correlation", lambda corr, info: corr["score"])
    variants = [{"a": f"g/A_{t}.yaml", "b": "g/B_DeviceProcessEvents.yaml", "score": 120}
                for t in ("DeviceProcessEvents", "DeviceFileEvents", "DeviceRegistryEvents")]
    others = [{"a": f"g/C{i}_DeviceProcessEvents.yaml", "b": "g/D_DeviceProcessEvents.yaml", "score": 100}
              for i in range(3)]

    kept = engine._score_and_filter_correlations(variants + others, {}, min_relevance=0.4, max_per_vendor=3)

    assert len(kept) == 5  # A-B's three variants, then C0-D and C1-D
    assert {c["a"] for c in kept[3:]} == {"g/C0_DeviceProcessEvents.yaml", "g/C1_DeviceProcessEvents.yaml"}


def _graph(tactics, edges, scores=None):
    """Pairs between made-up techniques, each a process launch, scoring 0.9 unless given."""
    q = {n: _udm("T1000", n, f'metadata.event_type = "PROCESS_LAUNCH" and target.process.command_line = /{n}/ nocase')
         for n in tactics}
    info = {f"g/{n}_UDM.yaml": {"name": n, "tactics": t, "query": q[n]} for n, t in tactics.items()}
    pairs = [{"vendor": "googlesecops", "a": f"g/{a}_UDM.yaml", "b": f"g/{b}_UDM.yaml", "query_a": q[a],
              "query_b": q[b], "combined_query": "x", "relevance_score": (scores or {}).get((a, b), 0.9)}
             for a, b in edges]
    return [set(c["techniques_involved"]) for c in engine._build_chains(pairs, info)]


def test_two_techniques_are_in_one_chain():
    # Hub and Spoke could take a third partner three times: they're together once, and the
    # partners left over make their own chain with Hub
    names = _graph({"Hub": ["Execution"], "Spoke": ["Persistence"], "Xa": ["Discovery"], "Xb": ["Collection"],
                    "Xc": ["Impact"]},
                   [("Hub", "Spoke"), ("Hub", "Xa"), ("Hub", "Xb"), ("Hub", "Xc")])
    assert sum({"Hub", "Spoke"} <= n for n in names) == 1
    assert all(len(set.intersection(a, b)) < 2 for a, b in zip(names, names[1:]))


def test_of_equal_chains_the_one_adding_a_tactic_comes_first():
    # Closed P-Q-R covers Execution, Credential Access, Persistence. S+T then take Acoll
    # (Collection, new) rather than Zcred (Credential Access, covered), though Zcred sorts last
    names = _graph({"P": ["Execution"], "Q": ["Credential Access"], "R": ["Persistence"], "S": ["Initial Access"],
                    "T": ["Discovery"], "Zcred": ["Credential Access"], "Acoll": ["Collection"]},
                   [("P", "Q"), ("Q", "R"), ("P", "R"), ("S", "T"), ("T", "Zcred"), ("T", "Acoll")])
    assert names == [{"P", "Q", "R"}, {"S", "T", "Acoll"}]


def test_kql_chain_parts_come_from_device_tables():
    nodes = [
        {"name": "Cloud Roles", "technique_id": "T1098.003", "queries": [
            'CloudAppEvents\n| where ActionType has "AttachUserPolicy"',
            'DeviceProcessEvents\n| where ProcessCommandLine has_all("aws", "iam", "attach-user-policy")']},
        {"name": "PowerShell", "technique_id": "T1059.001", "queries": [
            'DeviceProcessEvents\n| where ProcessCommandLine has "-enc"']},
        {"name": "Create Account", "technique_id": "T1136", "queries": [
            'DeviceProcessEvents\n| where ProcessCommandLine has_all("net", "user", "/add")']},
    ]
    q = engine._kql_chain(nodes)
    assert "CloudAppEvents" not in q and "let T1 = union T1_1\n" in q
    assert check_query(q, "mde")["findings"] == []


def test_a_chain_adding_a_tactic_goes_first():
    # After P-Q-R, S-T-U repeats its tactics at 0.9; Y-X-Q reaches Lateral Movement at 0.7.
    # With room for two, the one adding a tactic is kept; the list is best first
    tactics = {"P": ["Execution"], "Q": ["Credential Access"], "R": ["Persistence"],
               "S": ["Execution"], "T": ["Credential Access"], "U": ["Persistence"],
               "X": ["Lateral Movement"], "Y": ["Persistence"]}
    edges = [("P", "Q"), ("Q", "R"), ("P", "R"), ("S", "T"), ("T", "U"), ("X", "Y"), ("Y", "Q")]
    import pytest
    mp = pytest.MonkeyPatch()
    mp.setattr(engine, "CHAIN_MAX", 2)
    try:
        names = _graph(tactics, edges, {("X", "Y"): 0.7, ("Y", "Q"): 0.7})
    finally:
        mp.undo()
    assert names == [{"P", "Q", "R"}, {"X", "Y", "Q"}]


def test_each_tactic_is_sure_of_a_few_places(monkeypatch):
    # The Persistence pairs score highest, but Discovery's best pairs get places first
    monkeypatch.setattr(engine, "PAIRS_PER_TACTIC", 2)
    monkeypatch.setattr(engine, "_score_correlation", lambda corr, info: corr["score"])
    info = {f"g/P{i}_UDM.yaml": {"name": f"P{i}", "tactics": ["Persistence"]} for i in range(10)}
    info.update({f"g/D{i}_UDM.yaml": {"name": f"D{i}", "tactics": ["Discovery"]} for i in range(3)})
    persist = [{"a": f"g/P{i}_UDM.yaml", "b": f"g/P{i + 1}_UDM.yaml", "score": 140} for i in range(9)]
    discover = [{"a": f"g/D{i}_UDM.yaml", "b": f"g/P{i}_UDM.yaml", "score": 80} for i in range(3)]
    weak = [{"a": "g/D2_UDM.yaml", "b": "g/P9_UDM.yaml", "score": 30}]  # below the threshold

    kept = engine._score_and_filter_correlations(persist + discover + weak, info, min_relevance=0.4,
                                                 max_per_vendor=5)

    assert [c["a"] for c in kept].count("g/D0_UDM.yaml") + [c["a"] for c in kept].count("g/D1_UDM.yaml") == 2
    assert "g/D2_UDM.yaml" not in [c["a"] for c in kept] and len(kept) == 5


def test_sub_techniques_expanded_from_one_parent_are_not_paired():
    info = {"g/HTMLSmuggling_UDM.yaml": {"technique_id": "T1027.006"},
            "g/Steganography_UDM.yaml": {"technique_id": "T1027.003"},
            "g/PowerShell_UDM.yaml": {"technique_id": "T1059.001"},
            "g/LSASSMemory_UDM.yaml": {"technique_id": "T1003.001"},
            "g/DCSync_UDM.yaml": {"technique_id": "T1003.006"}}
    pair = lambda a, b: {"a": f"g/{a}_UDM.yaml", "b": f"g/{b}_UDM.yaml"}
    gallmaker = {"T1027", "T1059.001"}  # ATT&CK gives the parent only

    assert engine._expanded_siblings(pair("HTMLSmuggling", "Steganography"), info, gallmaker)
    assert not engine._expanded_siblings(pair("HTMLSmuggling", "PowerShell"), info, gallmaker)
    info["g/ObfuscatedFilesorInformation_UDM.yaml"] = {"technique_id": "T1027"}
    assert engine._expanded_siblings(pair("ObfuscatedFilesorInformation", "HTMLSmuggling"), info, gallmaker)
    # Attributed in their own right, siblings are two procedures
    assert not engine._expanded_siblings(pair("LSASSMemory", "DCSync"), info, {"T1003", "T1003.001"})
    # A report or CVE run has no attribution
    assert not engine._expanded_siblings(pair("HTMLSmuggling", "Steganography"), info, None)

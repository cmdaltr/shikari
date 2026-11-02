"""Cross-vendor correlation playbooks (#8)."""

from shikari.correlation.cross_vendor import build_cross_vendor_playbooks


def _file_info(records):
    # records: list of (path, vendor, technique_id, query, tactics)
    return {p: {"path": p, "vendor": v, "technique_id": t, "query": q, "tactics": ta, "name": t}
            for (p, v, t, q, ta) in records}


def _chain(techs, vendor="googlesecops", score=0.9):
    return {"vendor": vendor, "chain": True, "techniques_involved": techs,
            "tactics": [], "relevance_score": score, "time_window": "2h"}


def test_builds_playbook_when_two_vendors_cover_chain():
    fi = _file_info([
        ("a_udm.yaml", "googlesecops", "T1078", "principal.user.userid = x", ["Initial Access"]),
        ("a_mde.yaml", "mde", "T1078", "AccountName == 'x'", ["Initial Access"]),
        ("b_mde.yaml", "mde", "T1059.001", "DeviceProcessEvents | where DeviceName == y", ["Execution"]),
    ])
    pbs = build_cross_vendor_playbooks([_chain(["T1078", "T1059.001"])], fi)
    assert len(pbs) == 1
    pb = pbs[0]
    assert pb["type"] == "cross_vendor"
    assert pb["techniques_involved"] == ["T1078", "T1059.001"]
    assert set(pb["vendors"]) == {"googlesecops", "mde"}
    assert pb["attack_chain_length"] == 2
    # Stage order follows the chain, not tactic order
    assert [s["technique_id"] for s in pb["stages"]] == ["T1078", "T1059.001"]
    # The first stage has both SIEM queries
    assert set(pb["stages"][0]["vendors"]) == {"googlesecops", "mde"}


def test_single_vendor_chain_is_not_cross_vendor():
    fi = _file_info([
        ("a_mde.yaml", "mde", "T1078", "AccountName == x", ["Initial Access"]),
        ("b_mde.yaml", "mde", "T1059.001", "DeviceProcessEvents", ["Execution"]),
    ])
    assert build_cross_vendor_playbooks([_chain(["T1078", "T1059.001"])], fi) == []


def test_join_keys_detected_from_queries():
    fi = _file_info([
        ("a_udm.yaml", "googlesecops", "T1078", "principal.hostname = h and principal.user.userid = u", ["IA"]),
        ("a_mde.yaml", "mde", "T1078", "DeviceName == h and AccountName == u", ["IA"]),
        ("b_mde.yaml", "mde", "T1021", "DeviceName == h and AccountName == u", ["Lateral Movement"]),
    ])
    pb = build_cross_vendor_playbooks([_chain(["T1078", "T1021"])], fi)[0]
    entities = {k["entity"] for k in pb["join_keys"]}
    assert "host" in entities and "user" in entities
    # Each join key names the field per SIEM
    host = next(k for k in pb["join_keys"] if k["entity"] == "host")
    assert host["fields"]["mde"] == "DeviceName"
    assert host["fields"]["googlesecops"] == "principal.hostname"


def test_default_host_join_when_nothing_detected():
    fi = _file_info([
        ("a_udm.yaml", "googlesecops", "T1480", "metadata.event_type = GENERIC", ["Defense Evasion"]),
        ("a_mde.yaml", "mde", "T1480", "DeviceEvents | project Timestamp", ["Defense Evasion"]),
        ("b_el.yaml", "elastic", "T1497", "FROM logs | LIMIT 10", ["Discovery"]),
    ])
    pb = build_cross_vendor_playbooks([_chain(["T1480", "T1497"])], fi)[0]
    # mde query mentions DeviceEvents (host hint); still at least a host join key is present
    assert any(k["entity"] == "host" for k in pb["join_keys"])


def test_dedup_by_technique_set_keeps_highest_score():
    fi = _file_info([
        ("a_udm.yaml", "googlesecops", "T1078", "principal.hostname = h", ["IA"]),
        ("b_mde.yaml", "mde", "T1059", "DeviceName == h", ["Execution"]),
    ])
    low = _chain(["T1078", "T1059"], score=0.5)
    high = _chain(["T1059", "T1078"], vendor="mde", score=0.95)
    pbs = build_cross_vendor_playbooks([low, high], fi)
    assert len(pbs) == 1
    assert pbs[0]["relevance_score"] == 0.95


def test_non_chain_correlations_ignored():
    fi = _file_info([("a.yaml", "mde", "T1", "DeviceName x", ["X"]), ("b.yaml", "googlesecops", "T2", "principal.hostname y", ["Y"])])
    corr = {"vendor": "mde", "chain": False, "techniques_involved": ["T1", "T2"], "relevance_score": 1.0}
    assert build_cross_vendor_playbooks([corr], fi) == []

"""Elastic ES|QL detection generator (shikari.build.elastic)."""

from shikari.build.elastic import ElasticQueryGenerator


def gen():
    return ElasticQueryGenerator()


def test_basic_shape():
    r = gen().generate_query("T1003.001", "LSASS Memory", "Credential Access", "dump lsass",
                             indicators={"cmd": ["mimikatz"]})
    q = r["query"]
    assert q.startswith("FROM ")
    assert "| WHERE @timestamp >= NOW() - 1 day" in q
    assert "| STATS " in q and "| SORT " in q
    assert gen().validate_query(q) == (True, "")
    assert r["query_name"] == "T1003.001_LSASS_Memory"


def test_cmd_indicator_is_case_insensitive_substring():
    q = gen().generate_query("T1059", "Cmd", "Execution", "", indicators={"cmd": ["Mimikatz"]})["query"]
    # lower-cased pattern against TO_LOWER(field)
    assert 'TO_LOWER(process.command_line) RLIKE ".*mimikatz.*"' in q


def test_backslash_path_is_escaped_not_lost():
    q = gen().generate_query("T1003.001", "LSASS", "Credential Access", "",
                             indicators={"file": [r"C:\Windows\System32\lsass.exe"]})["query"]
    # one source backslash -> regex \\ -> ES|QL string \\\\, and the '.' is regex-escaped
    assert r".*c:\\\\windows\\\\system32\\\\lsass\\.exe.*" in q


def test_ip_and_port_are_exact_matches():
    q = gen().generate_query("T1071", "C2", "Command and Control", "",
                             indicators={"ip": ["10.0.0.5"], "port": ["445"]})["query"]
    assert 'destination.ip == "10.0.0.5"' in q
    assert "destination.port == 445" in q
    assert "RLIKE" not in q.split("| STATS")[0] or "10.0.0.5" not in q.split("RLIKE")[0:1]


def test_single_stream_uses_specific_index():
    r = gen().generate_query("T1059", "Cmd", "Execution", "", indicators={"cmd": ["x"], "sw": ["y.exe"]})
    assert r["index_pattern"] == "logs-endpoint.events.process-*"


def test_mixed_streams_use_broad_index():
    r = gen().generate_query("T1003.001", "LSASS", "Credential Access", "",
                             indicators={"cmd": ["mimikatz"], "ip": ["10.0.0.5"]})
    assert r["index_pattern"] == "logs-endpoint.events.*"


def test_no_indicators_still_valid():
    r = gen().generate_query("T1082", "Discovery", "Discovery", "", indicators={})
    assert gen().validate_query(r["query"]) == (True, "")


def test_validate_rejects_bad_queries():
    g = gen()
    assert g.validate_query("")[0] is False
    assert g.validate_query("WHERE x == 1")[0] is False          # no FROM
    assert g.validate_query("FROM logs")[0] is False             # no pipe
    assert g.validate_query('FROM logs | WHERE (a == "b"')[0] is False  # unbalanced paren


def test_correlation_query_valid():
    c = gen().generate_correlation_query(
        [{"indicators": {"cmd": ["mimikatz"]}}, {"indicators": {"reg": ["Run"]}}], "APT29")
    assert gen().validate_query(c["query"]) == (True, "")
    assert c["query_name"] == "APT29_correlation"
    assert "STATS" in c["query"]

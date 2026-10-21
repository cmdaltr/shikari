"""
Google SecOps correlations: two single-event UDM searches -> one two-event UDM join.

SecOps was skipped by the correlation engine entirely, and the grouping step that
merges correlations by technique pair ignored vendor, so it would have spliced SecOps
into KQL. Correlations are now Search joins (archer.build.udm), not YARA-L rules;
YARA-L inputs (detections written before the move) are converted first.
"""
import re

from archer.ai.genai import engine
from archer.build.udm import build_join, from_yaral


def _rule(tid, name, events):
    return f"""rule {tid.replace('.', '_')} {{
  meta:
    author = "Archer Detection Engineering"
    description = "Detects {name} ({tid})"
    mitre_attack_technique = "{tid}"
    severity = "MEDIUM"

  events:
  {events}

  condition:
  $e
  }}"""


PHISH = _rule("T1566", "Phishing", '$e.metadata.event_type = "PROCESS_LAUNCH"\n  re.regex($e.target.process.command_line, `mshta`) nocase')
PWSH = from_yaral(_rule("T1059.001", "PowerShell", '$e.metadata.event_type = "PROCESS_LAUNCH"\n  re.regex($e.target.process.command_line, `-enc`) nocase'))
RDP = from_yaral(_rule("T1021.001", "Remote Desktop Protocol", '$e.metadata.event_type = "NETWORK_CONNECTION"\n  $e.target.port = 3389'))


def test_two_searches_become_one_host_bound_join():
    q = build_join(PHISH, PWSH, "Phishing", "PowerShell")

    assert q.startswith("// archer_corr_t1566_then_t1059_001:")
    assert "$e." not in q and "re.regex" not in q and not q.lstrip().startswith("rule ")
    assert "$e1.principal.hostname = $host" in q and "$e2.principal.hostname = $host" in q
    assert "$e1.target.process.command_line = /mshta/ nocase" in q
    assert re.search(r"match:\s*\$host over 1h", q)
    # Search can't order events: no timestamp comparison, but each side's time is an outcome
    assert "event_timestamp.seconds <=" not in q and "condition:" not in q
    assert "$first_a = min($e1.metadata.event_timestamp.seconds)" in q
    assert "ATT&CK T1566, T1059.001" in q.splitlines()[0]


def test_merged_side_is_one_bracketed_line_of_alternatives():
    q = build_join(PHISH, [PWSH, RDP])

    alt = [l for l in q.splitlines() if "$e2.metadata.event_type" in l]
    assert len(alt) == 1  # statements are ANDed line by line; alternatives must share one
    assert alt[0].startswith("((") and ") or (" in alt[0] and alt[0].endswith("))")
    assert "PowerShell / Remote Desktop Protocol" in q
    assert q.startswith("// archer_corr_t1566_then_t1059_001_plus1:")


def test_regex_and_string_literals_are_not_rebound():
    q = build_join('// archer_x: X · ATT&CK T1\nmetadata.event_type = "target.x" and target.url = /principal\\.y/', PWSH)
    assert '$e1.metadata.event_type = "target.x"' in q and "$e1.target.url = /principal\\.y/" in q


def test_kql_or_a_join_is_refused():
    assert build_join("DeviceProcessEvents | take 1", PWSH) is None
    assert build_join(build_join(PHISH, PWSH), PWSH) is None


def test_engine_routes_secops_pairs_to_the_join_builder():
    out = engine._combine_queries("googlesecops", PHISH, PWSH, "a/Phishing_GoogleSecOps.yaml", "b/PowerShell_GoogleSecOps.yaml")
    assert out.startswith("// archer_corr_")
    assert "Phishing and PowerShell on the same host" in out


def test_grouping_never_mixes_vendors():
    corrs = [
        {"vendor": "mde", "a": "x/Phishing_DeviceProcessEvents.yaml", "b": "x/PowerShell_DeviceProcessEvents.yaml",
         "query_a": "DeviceProcessEvents | where 1", "query_b": "DeviceProcessEvents | where 2",
         "combined_query": "kql", "relevance_score": 0.9},
        {"vendor": "googlesecops", "a": "x/Phishing_GoogleSecOps.yaml", "b": "x/PowerShell_GoogleSecOps.yaml",
         "query_a": PHISH, "query_b": PWSH, "combined_query": "", "relevance_score": 0.8},
    ]
    info = {c[k]: {"name": n} for c in corrs for k, n in (("a", "Phishing"), ("b", "PowerShell"))}

    grouped = engine._apply_correlation_grouping(corrs, info)

    assert [c["vendor"] for c in grouped] == ["googlesecops", "mde"]  # SecOps first, not merged
    secops = grouped[0]["combined_query"]
    assert secops.startswith("// archer_corr_") and "DeviceProcessEvents" not in secops
    assert "archer_corr" not in grouped[1]["combined_query"]

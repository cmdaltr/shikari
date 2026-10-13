"""
Google SecOps correlations: two single-event YARA-L rules -> one multi-event rule.

SecOps was skipped by the correlation engine entirely, and the grouping step that
merges correlations by technique pair ignored vendor, so it would have spliced
YARA-L into KQL.
"""
import re

from archer.ai.genai import engine
from archer.build.secops import build_correlation_rule


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
PWSH = _rule("T1059.001", "PowerShell", '$e.metadata.event_type = "PROCESS_LAUNCH"\n  re.regex($e.target.process.command_line, `-enc`) nocase')
RDP = _rule("T1021.001", "Remote Desktop Protocol", '$e.metadata.event_type = "NETWORK_CONNECTION"\n  $e.target.port = 3389')


def _events(rule):
    return rule.split("events:")[1].split("match:")[0]


def test_two_rules_become_one_host_bound_ordered_rule():
    rule = build_correlation_rule(PHISH, PWSH, "Phishing", "PowerShell")

    assert rule.startswith("rule archer_corr_t1566_then_t1059_001 {")
    assert "$e." not in rule  # every single-event variable rebound
    assert "$e1.principal.hostname = $host" in rule and "$e2.principal.hostname = $host" in rule
    assert "$e1.metadata.event_timestamp.seconds <= $e2.metadata.event_timestamp.seconds" in rule
    assert re.search(r"match:\s*\$host over 1h", rule)
    assert re.search(r"condition:\s*\$e1 and \$e2", rule)
    assert 'mitre_attack_technique = "T1566, T1059.001"' in rule


def test_merged_side_is_one_line_of_alternatives():
    rule = build_correlation_rule(PHISH, [PWSH, RDP])

    alt = [l for l in _events(rule).splitlines() if "$e2.metadata.event_type" in l]
    assert len(alt) == 1  # separate lines in events are ANDed; alternatives must share one
    assert alt[0].strip().startswith("((") and ") or (" in alt[0]
    assert "PowerShell / Remote Desktop Protocol" in rule
    assert rule.startswith("rule archer_corr_t1566_then_t1059_001_plus1 {")


def test_non_rule_input_is_refused():
    assert build_correlation_rule("DeviceProcessEvents | take 1", PWSH) is None


def test_engine_routes_yaral_pairs_to_secops_builder():
    out = engine._combine_queries("googlesecops", PHISH, PWSH, "a/Phishing_GoogleSecOps.yaml", "b/PowerShell_GoogleSecOps.yaml")
    assert out.startswith("rule archer_corr_")
    assert "Phishing followed by PowerShell" in out


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
    assert secops.startswith("rule archer_corr_") and "DeviceProcessEvents" not in secops
    assert "rule " not in grouped[1]["combined_query"]

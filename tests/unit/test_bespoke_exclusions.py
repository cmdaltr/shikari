"""Bespoke exclusions for Elastic (ES|QL) and Google SecOps (YARA-L).

The MDE/KQL and Splunk/SPL paths predate these; here we cover the two added for
#37. get_exclusions/get_config are patched so the real bespoke/ dir is untouched.
"""

import pytest

from archer.build import bespoke


def _patch(monkeypatch, exclusions):
    full = {
        "process_exclusions": [],
        "user_exclusions": [],
        "host_exclusions": [],
        "ip_exclusions": [],
        "custom_exclusions": {},
    }
    full.update(exclusions)
    monkeypatch.setattr(bespoke, "get_exclusions", lambda: full)
    monkeypatch.setattr(bespoke, "get_config", lambda: {})


# A realistic two-event YARA-L rule, shaped like archer/contract/exemplars.
YARAL_RULE = """rule example_two_stage {
  meta:
    author = "Archer"
  events:
    $setup.metadata.event_type = "PROCESS_LAUNCH"
    $setup.target.process.command_line != ""
    $payload.metadata.event_type = "PROCESS_LAUNCH"
    $setup.principal.asset_id = $device
    $payload.principal.asset_id = $device
    $device != ""

  match:
    $device over 30m

  condition:
    $setup and $payload
}"""


# --- Elastic ES|QL -----------------------------------------------------------

def test_esql_appends_a_trailing_where_for_each_exclusion_type(monkeypatch):
    _patch(monkeypatch, {
        "user_exclusions": ["svc-backup"],
        "host_exclusions": ["JUMPHOST01"],
        "ip_exclusions": ["10.0.0.0/8", "198.51.100.5"],
    })
    q = "FROM logs-endpoint.events.*\n| WHERE process.name == \"rundll32.exe\""
    out = bespoke.apply_exclusions_to_esql(q)

    # Original query is kept, exclusions appended as one trailing | WHERE
    assert out.startswith(q)
    tail = out[len(q):]
    assert tail.count("| WHERE") == 1
    assert 'user.name != "svc-backup"' in out
    assert 'host.name != "JUMPHOST01"' in out
    # CIDR via the ES|QL function, plain IP via equality, both src and dest
    assert 'NOT CIDR_MATCH(source.ip, "10.0.0.0/8")' in out
    assert 'NOT CIDR_MATCH(destination.ip, "10.0.0.0/8")' in out
    assert 'source.ip != "198.51.100.5"' in out
    assert " AND " in tail


def test_esql_process_wildcard_uses_rlike_and_exact_uses_equality(monkeypatch):
    _patch(monkeypatch, {"process_exclusions": ["/opt/tanium/*", "/usr/bin/osqueryd"]})
    out = bespoke.apply_exclusions_to_esql("FROM logs | WHERE true")
    assert 'NOT process.executable RLIKE "/opt/tanium/.*"' in out
    assert 'process.executable != "/usr/bin/osqueryd"' in out


def test_esql_no_exclusions_leaves_the_query_untouched(monkeypatch):
    _patch(monkeypatch, {})
    q = "FROM logs | WHERE true"
    assert bespoke.apply_exclusions_to_esql(q) == q


def test_esql_disabled_by_config_is_a_noop(monkeypatch):
    monkeypatch.setattr(bespoke, "get_exclusions", lambda: {"user_exclusions": ["x"]})
    monkeypatch.setattr(bespoke, "get_config",
                        lambda: {"query_settings": {"apply_exclusions": False}})
    q = "FROM logs | WHERE true"
    assert bespoke.apply_exclusions_to_esql(q) == q


# --- Google SecOps YARA-L ----------------------------------------------------

def test_yaral_adds_negated_predicates_for_every_event_variable(monkeypatch):
    _patch(monkeypatch, {
        "user_exclusions": ["svc-backup"],
        "host_exclusions": ["JUMPHOST01"],
        "ip_exclusions": ["10.0.0.0/8"],
    })
    out = bespoke.apply_exclusions_to_yaral(YARAL_RULE)

    # Both event variables that the rule binds get the exclusions
    for var in ("$setup", "$payload"):
        assert f'not {var}.principal.user.userid = "svc-backup"' in out
        assert f'not {var}.principal.hostname = "JUMPHOST01"' in out
        assert f'not net.ip_in_range_cidr({var}.principal.ip, "10.0.0.0/8")' in out


def test_yaral_uses_not_equals_not_bang_equals_for_repeated_fields(monkeypatch):
    # principal.ip etc. are repeated; `field != x` is existential and wrong, so
    # the exclusion must be `not field = x` ("no element equals").
    _patch(monkeypatch, {"user_exclusions": ["svc-backup"]})
    out = bespoke.apply_exclusions_to_yaral(YARAL_RULE)
    assert "!=" not in out.split("// bespoke exclusions")[1]
    assert 'not $setup.principal.user.userid = "svc-backup"' in out


def test_yaral_inserts_inside_the_events_block_before_the_next_section(monkeypatch):
    _patch(monkeypatch, {"user_exclusions": ["svc-backup"]})
    out = bespoke.apply_exclusions_to_yaral(YARAL_RULE)
    # The inserted block sits after events: and before match:
    ev = out.index("events:")
    excl = out.index("// bespoke exclusions")
    match = out.index("match:")
    assert ev < excl < match


def test_yaral_ignores_bare_match_variables_like_device(monkeypatch):
    # $device is a match variable (no dotted field path); it must not be treated
    # as an event variable, or we'd emit predicates against an unbound var.
    _patch(monkeypatch, {"user_exclusions": ["svc-backup"]})
    out = bespoke.apply_exclusions_to_yaral(YARAL_RULE)
    assert "$device.principal" not in out


def test_yaral_non_rule_text_is_returned_unchanged(monkeypatch):
    _patch(monkeypatch, {"user_exclusions": ["svc-backup"]})
    assert bespoke.apply_exclusions_to_yaral("not a rule") == "not a rule"


def test_yaral_process_wildcard_uses_re_regex(monkeypatch):
    _patch(monkeypatch, {"process_exclusions": ["/opt/tanium/*"]})
    out = bespoke.apply_exclusions_to_yaral(YARAL_RULE)
    assert "not re.regex($setup.target.process.file.full_path, `/opt/tanium/.*`) nocase" in out


# --- dispatch ----------------------------------------------------------------

@pytest.mark.parametrize("platform", ["Elastic", "esql"])
def test_dispatch_routes_elastic(monkeypatch, platform):
    _patch(monkeypatch, {"user_exclusions": ["svc-backup"]})
    out = bespoke.apply_exclusions("FROM logs | WHERE true", platform)
    assert 'user.name != "svc-backup"' in out


@pytest.mark.parametrize("platform", ["GoogleSecOps", "secops", "yaral"])
def test_dispatch_routes_secops(monkeypatch, platform):
    _patch(monkeypatch, {"user_exclusions": ["svc-backup"]})
    out = bespoke.apply_exclusions(YARAL_RULE, platform)
    assert 'not $setup.principal.user.userid = "svc-backup"' in out

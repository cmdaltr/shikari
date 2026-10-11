"""Excluded MDE fields come out of where clauses a whole condition at a time."""

import pytest

from archer.validation.mde_field_validator import format_mde_query, strip_excluded_fields

BASE = "DeviceEvents\n| where Timestamp > ago(1d)\n| where "


def where(query):
    return query.split("\n")[-1] if query else query


@pytest.mark.unit
def test_has_all_condition_is_removed_whole():
    # The old regex stopped at has_all's first ")", leaving "where ())))) or ..."
    q = BASE + '(SHA1 has_all("aws", "create-key-pair") or ActionType has_any("CreateKeyPair"))'
    assert where(strip_excluded_fields(q)) == '| where (ActionType has_any("CreateKeyPair"))'


@pytest.mark.unit
def test_query_with_only_excluded_conditions_is_dropped():
    # An emptied where clause would match every event
    assert strip_excluded_fields(BASE + 'RemoteIP has_any("1.2.3.4")') == ""
    assert format_mde_query(BASE + 'RemoteIP has_any("1.2.3.4")') == ""


@pytest.mark.unit
def test_an_and_group_is_never_widened():
    q = BASE + '(RemoteIPType == "Public" and RemoteIP in~ ("1.1.1.1")) or RemoteUrl has "evil.com"'
    assert where(strip_excluded_fields(q)) == '| where RemoteUrl has "evil.com"'


@pytest.mark.unit
def test_trailing_comment_is_kept():
    q = BASE + '(ProcessCommandLine has "a") or SHA256 == "abc" // Emotet'
    assert where(strip_excluded_fields(q)) == '| where (ProcessCommandLine has "a") // Emotet'


@pytest.mark.unit
def test_field_names_sharing_a_prefix_are_kept():
    q = BASE + 'RemoteIPType == "Public" or RemoteUrl has "x"'
    assert where(strip_excluded_fields(q)) == '| where RemoteIPType == "Public" or RemoteUrl has "x"'


@pytest.mark.unit
def test_additional_fields_still_filter():
    # Left out of projections, but on DeviceEvents it is often the only field with the detail
    q = BASE + 'AdditionalFields has_all("aws", "create-key-pair") or SHA1 == "abc"\n| project Timestamp, AdditionalFields, DeviceName'
    out = strip_excluded_fields(q)
    assert '| where AdditionalFields has_all("aws", "create-key-pair")' in out
    assert out.endswith("| project Timestamp, DeviceName")

"""Generating for some SIEMs skips the others, in the keys construct_yaml checks."""
from archer.build.detections import ALL_SIEMS, excluded_for


def test_splunk_is_generated_again():
    assert "splunk" in ALL_SIEMS


def test_a_filter_excludes_secops_by_the_key_construct_yaml_checks():
    assert excluded_for({"splunk"}) == ["elastic", "googlesecops", "mde"]
    assert "googlesecops" not in excluded_for({"secops"})

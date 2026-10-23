"""A group's parent technique takes its expanded sub-techniques' indicators: one detection per family."""

import os

import pytest

from archer.mitre.retrieve import _merge_guidance

CACHE = os.path.join(os.path.dirname(__file__), "..", "..", "archer", "data", "cache", "enterprise-attack.json")


def test_indicators_merge_without_duplicates_and_descriptions_stay():
    parent = {"description": "parent", "cmd": ["certutil -decode", "Base64"]}
    _merge_guidance(parent, {"description": "sub", "cmd": ["base64", "steghide"], "reg": "HKCU\\Software\\x"})
    assert parent == {"description": "parent", "cmd": ["certutil -decode", "Base64", "steghide"],
                      "reg": ["HKCU\\Software\\x"]}


@pytest.fixture(scope="module")
def bundle():
    if not os.path.exists(CACHE):
        pytest.skip("no cached ATT&CK bundle")
    from archer.mitre.enterprise import get_stix_data
    return get_stix_data("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")


def test_gallmaker_gets_one_obfuscation_detection(bundle):
    from archer.mitre.retrieve import retrieve_group, retrieve_procedures, retrieve_techniques

    techs = retrieve_techniques(bundle, retrieve_group(bundle, "Gallmaker"))
    merged = retrieve_procedures(bundle, techs)
    expanded = retrieve_procedures(bundle, techs, merge_expanded=False)

    ids = [p[0] for p in merged]
    assert "T1027" in ids and not [t for t in ids if t.startswith("T1027.")]
    assert [t for t in (p[0] for p in expanded) if t.startswith("T1027.")]
    family = next(p for p in merged if p[0] == "T1027")
    assert "Includes the indicators of its sub-techniques" in family[3] and "Steganography (T1027.003)" in family[3]


def test_a_sub_technique_attributed_in_its_own_right_keeps_its_procedure(bundle):
    from archer.mitre.retrieve import retrieve_group, retrieve_procedures, retrieve_techniques

    techs = retrieve_techniques(bundle, retrieve_group(bundle, "FIN13"))
    ids = {p[0] for p in retrieve_procedures(bundle, techs)}
    assert "T1059.001" in ids  # PowerShell: ATT&CK attributes it to FIN13 directly

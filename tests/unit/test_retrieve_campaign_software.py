"""The run's ATT&CK walk follows the same paths as MITRESaw: group, campaigns, and software either uses."""
from types import SimpleNamespace

from shikari.mitre.retrieve import retrieve_techniques


def _uses(src, dst, desc=None):
    return {"type": "relationship", "relationship_type": "uses", "source_ref": src, "target_ref": dst, "description": desc}


def test_software_used_by_a_campaign_attributed_to_the_group_is_walked():
    bundle = SimpleNamespace(objects=[
        {"type": "intrusion-set", "id": "g"}, {"type": "campaign", "id": "c"}, {"type": "tool", "id": "impacket"},
        {"type": "attack-pattern", "id": "sniff"}, {"type": "attack-pattern", "id": "phish"},
        {"type": "relationship", "relationship_type": "attributed-to", "source_ref": "c", "target_ref": "g"},
        _uses("g", "phish"), _uses("c", "impacket", "C0027 used Impacket."), _uses("impacket", "sniff", "Impacket sniffs."),
    ])
    walked = dict((ref, desc) for desc, ref in retrieve_techniques(bundle, "g"))
    assert set(walked) == {"phish", "sniff"}
    assert walked["sniff"] == "C0027 used Impacket. Impacket sniffs."

"""Correlation progression pairs cover ATT&CK v18's Stealth and Defense Impairment as they do Defense Evasion."""
from archer.ai.genai.engine import _ATTACK_PROGRESSIONS


def test_v18_tactics_pair_like_defense_evasion():
    for a, b in [p for p in _ATTACK_PROGRESSIONS if "defense-evasion" in p]:
        for new in ("stealth", "defense-impairment"):
            pair = tuple(new if t == "defense-evasion" else t for t in (a, b))
            assert pair in _ATTACK_PROGRESSIONS

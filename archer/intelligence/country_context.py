"""
Classify country mentions in ATT&CK group descriptions as attribution or targeting.

"Iran" in "assessed to operate on behalf of Iran's MOIS" is attribution; in
"targeted victims in Russia, China, Sweden, Belgium, Iran" it is victimology.
A proximity window ("any attribution word within 200 chars") cannot tell these
apart because every description calls the actor a "threat group", so each
mention is classified from its own clause instead.
"""

import re
from typing import Iterable, List, Literal, Optional

Role = Literal["attributed", "targeted"]

# Right after the country: the country is describing the actor.
# Strong forms win over any preceding cue.
_STRONG_ATTR_AFTER = re.compile(
    # optional "(PRC)"-style aside between the country and the descriptor
    r"^(?:\s*\([^)]{1,25}\))?"
    r"(?:[\s\-–—]*(?:based|nexus|sponsored|linked|backed|aligned|affiliated|origins?)\b"
    r"|(?:['’]s)?\s+(?:ministry\s+of\s+(?:intelligence|state\s+security)|intelligence|military\s+intelligence"
    r"|general\s+staff|security\s+services?|irgc|mois|revolutionary\s+guard|reconnaissance\s+general\s+bureau"
    r"|main\s+intelligence|gru|fsb|svr|mss|pla|people['’]s\s+liberation\s+army)\b"
    r"|\s+state[\s-]sponsored\b)",
    re.IGNORECASE,
)

# ATT&CK markdown: [Name](https://attack.mitre.org/...) links and (Citation: ...) markers.
# Left in, "attack" in every URL reads as a targeting verb and citation titles add stray mentions.
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_CITATION = re.compile(r"\(Citation:[^)]*\)")


def clean_description(text: str) -> str:
    return _CITATION.sub("", _MD_LINK.sub(r"\1", text or ""))

# Weak adjective form ("an Iranian threat group"), used only when no preceding cue decides it
_WEAK_ATTR_AFTER = re.compile(
    r"^(?:['’]s\s+cyber\b|\s+(?:state\b|government[\s-](?:sponsored|backed|linked)\b|threat\s+(?:group|actor)s?\b"
    r"|(?:cyber\s+)?espionage\s+(?:group|actor)s?\b|apt\b|actors?\b|hackers?\b|hacking\s+group|intrusion\s+set|group\b))",
    re.IGNORECASE,
)

_ATTR_BEFORE = re.compile(
    # "attributed the SolarWinds Compromise to" counts as ending at "to"
    r"\b(?:attribut\w*\b[^.]{0,80}?\bto|align\w*\s+(?:closely\s+)?with|sponsored\s+by|backed\s+by|on\s+behalf\s+of|in\s+support\s+of|linked\s+to|tied\s+to"
    r"|affiliated\s+with|associated\s+with|working\s+for|operat\w*\s+(?:out\s+of|from)|based\s+(?:in|out\s+of)"
    r"|located\s+in|originat\w*\s+(?:from|in)|suspected|believed\s+to\s+be|assessed\s+(?:to\s+be|as|with)"
    r"|likely|part\s+of|(?:subordinate|element|unit)\s+(?:of|within)|conducted\s+by|serving)\b",
    re.IGNORECASE,
)

_TARGET_BEFORE = re.compile(
    r"\b(?:target\w*|victim\w*|against|attack\w*|compromis\w*|intrusions?|campaigns?|operations?\s+(?:in|against)"
    r"|organi[sz]ations?|entities|companies|institutions|individuals|users|dissidents|sectors?|industr\w+"
    r"|focus\w*\s+on|spying\s+on|interest\s+in|countries|regions?|governments?\s+(?:of|in))\b",
    re.IGNORECASE,
)

# Sentence boundary: ". " followed by a capital/bracket, avoiding "U.S." style abbreviations
_SENTENCE_END = re.compile(r"(?<![A-Z])[.!?](?=\s+[\[(A-Z])")


def _sentence_start(text: str, pos: int) -> int:
    # Scan the full text: with endpos=pos the lookahead could not see a sentence
    # that begins exactly at the mention ("... destructive.\n\nNorth Korean ...")
    start = 0
    for m in _SENTENCE_END.finditer(text):
        if m.end() > pos:
            break
        start = m.end()
    return start


def classify_mention(text: str, start: int, end: int) -> Optional[Role]:
    """Role of the country mention at text[start:end], or None if the clause gives no signal."""
    after = text[end:end + 60]
    if _STRONG_ATTR_AFTER.search(after):
        return "attributed"

    before = text[_sentence_start(text, start):start]
    last_attr = max((m.end() for m in _ATTR_BEFORE.finditer(before)), default=-1)
    last_target = max((m.end() for m in _TARGET_BEFORE.finditer(before)), default=-1)
    if last_attr > last_target:
        return "attributed"
    if last_target > last_attr:
        return "targeted"

    if _WEAK_ATTR_AFTER.search(after):
        return "attributed"
    return None


def country_roles(text: str, terms: Iterable[str]) -> List[Role]:
    """Classified roles of every whole-word mention of any of the terms."""
    text = clean_description(text)
    roles: List[Role] = []
    for term in terms:
        for m in re.finditer(rf"(?<!\w){re.escape(term)}(?!\w)", text, re.IGNORECASE):
            role = classify_mention(text, m.start(), m.end())
            if role:
                roles.append(role)
    return roles


def country_matches(text: str, terms: Iterable[str], scope: Role) -> bool:
    """True if the text mentions the country in the requested role."""
    return scope in country_roles(text, terms)

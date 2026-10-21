"""
Google SecOps queries as UDM Search, not YARA-L rules.

Archer's SecOps output is for hunting in Search, so every query is a UDM search:

- a single event is one boolean expression over UDM fields
  (``metadata.event_type = "PROCESS_LAUNCH" and target.process.command_line = /x/ nocase``)
- a correlation is a two-event join: ``$e1``/``$e2`` filters sharing a ``$host``
  placeholder, ``match: $host over 1h``, and an ``outcome`` with each side's timestamps.
  Search buckets by fixed windows and can't require $e1 before $e2 (rules only), so the
  order is shown in the outcome rather than enforced.

The indicator logic still builds YARA-L internally (archer.build.secops, ioc_sweep,
exploit_detection); from_yaral() turns it into UDM, and migrates stored rules the same way.
"""

import re
from typing import Dict, List, Optional, Tuple

# A UDM field path starts with one of the event's top-level nouns
_ROOTS = ("metadata", "principal", "target", "network", "security_result", "src", "intermediary",
          "observer", "about", "extensions", "additional")
_FIELD = re.compile(r"(?<![\w.$])(" + "|".join(_ROOTS) + r")\.")
_RE_REGEX = re.compile(r"re\.regex\(\s*(\$?[\w.]+)\s*,\s*`([^`]*)`\s*\)(\s+nocase)?")
_SECTION = re.compile(r"^\s*(meta|events|match|outcome|condition|options)\s*:\s*$", re.M)
# Search has fixed windows only: ordering on timestamps is a rules feature
_ORDERING = re.compile(r"^\s*\$e\d\.metadata\.event_timestamp\.seconds\s*[<>]=?\s*\$e\d\.metadata\.event_timestamp\.seconds\s*$")


def is_yaral(query: str) -> bool:
    return bool(re.match(r"\s*rule\s+\w+\s*\{", query or ""))


def is_udm(query: str) -> bool:
    """A UDM search as Archer writes it: an archer_ header, or a filter on UDM fields."""
    q = (query or "").lstrip()
    if q.startswith("// archer_"):
        return True
    first = next((l.strip() for l in q.splitlines() if l.strip() and not l.strip().startswith("//")), "")
    return bool(re.match(r"\(*(\$e\d*\.)?(" + "|".join(_ROOTS) + r")\.[\w.]+\s*(=|!=|<|>)", first))


def is_join(query: str) -> bool:
    return bool(re.search(r"^\s*match\s*:", query or "", re.M))


def slash_regex(pattern: str) -> str:
    """An RE2 pattern as a UDM /regex/ literal body: an unescaped / would end it. Escapes
    are followed pair by pair, so the / in [\\\\/] (a backslash, then a slash) is escaped too."""
    out, escaped = [], False
    for ch in pattern:
        if ch == "/" and not escaped:
            out.append("\\")
        out.append(ch)
        escaped = ch == "\\" and not escaped
    return "".join(out)


def _convert_regex(text: str) -> str:
    """re.regex($e.field, `p`) nocase -> $e.field = /p/ nocase"""
    return _RE_REGEX.sub(lambda m: f"{m.group(1)} = /{slash_regex(m.group(2))}/" + (" nocase" if m.group(3) else ""), text)


def _sections(rule: str) -> Dict[str, str]:
    body = rule.strip()
    body = body[body.find("{") + 1: body.rfind("}")] if "{" in body else body
    marks = list(_SECTION.finditer(body))
    return {m.group(1): body[m.end(): marks[i + 1].start() if i + 1 < len(marks) else len(body)].strip("\n")
            for i, m in enumerate(marks)}


def _meta(meta: str, key: str) -> Optional[str]:
    m = re.search(rf'^\s*{key}\s*=\s*"([^"]*)"', meta or "", re.M)
    return m.group(1) if m else None


def _statements(events: str) -> List[str]:
    """An events section's statements (ANDed), without comments or blank lines."""
    return [s.strip() for s in events.splitlines() if s.strip() and not s.strip().startswith("//")]


def _and(parts: List[str]) -> str:
    wrap = lambda p: p if len(parts) == 1 or not re.search(r"\sor\s", p) or (p.startswith("(") and _balanced(p)) else f"({p})"
    return " and ".join(wrap(p) for p in parts)


def _top_level_or(p: str) -> bool:
    """Whether p has an `or` outside any brackets (or /regex/ and "string" literals)."""
    text = re.sub(r'/(?:\\.|[^/\\])*/|"(?:\\.|[^"\\])*"', '""', p)
    depth = 0
    for i, ch in enumerate(text):
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0 and text.startswith(" or ", i):
            return True
    return False


def _balanced(p: str) -> bool:
    """Whether p's outer parentheses enclose all of it."""
    depth = 0
    for i, ch in enumerate(p):
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0 and i < len(p) - 1:
            return False
    return depth == 0


def header(name: str, description: str = "", technique: str = "", severity: str = "") -> str:
    """The comment line a UDM search starts with: name, what it finds, ATT&CK and severity."""
    bits = [b for b in (description, technique and f"ATT&CK {technique}", severity and f"severity {severity}") if b]
    return f"// {name}" + (": " + " · ".join(bits) if bits else "")


def from_yaral(rule: str) -> Optional[str]:
    """
    A YARA-L rule as a UDM search. Single-event rules become one expression on bare UDM
    fields; multi-event rules become a join (filters, match, outcome). Anything that isn't
    YARA-L is returned unchanged; None when the rule has no events.
    """
    if not is_yaral(rule):
        return rule
    sec = _sections(rule)
    events = sec.get("events")
    if not events:
        return None
    name = re.match(r"\s*rule\s+(\w+)", rule).group(1)
    meta = sec.get("meta", "")
    # "Detects Create Account (T1136)" -> "Create Account": the ATT&CK ID follows anyway
    desc = re.sub(r"^Detects (.+?) \(T\d{4}(?:\.\d{3})?\)$", r"\1", _meta(meta, "description") or "")
    if "match" in sec:
        desc = desc.replace(" followed by ", " and ")  # Search can't enforce the order a rule did
    head = header(name, desc, _meta(meta, "mitre_attack_technique") or "", _meta(meta, "severity") or "")
    if "match" not in sec:
        expr = _and([_convert_regex(s) for s in _statements(events)])
        return head + "\n" + re.sub(r"\$e\.", "", expr).strip()
    lines = [_convert_regex(line.rstrip()) for line in events.splitlines() if not _ORDERING.match(line)]
    out = [head, "\n".join(l[4:] if l.startswith("    ") else l.strip() for l in lines).strip("\n"),
           "", "match:", "  " + " ".join(sec["match"].split())]
    if sec.get("outcome"):
        out += ["", "outcome:"] + ["  " + l.strip() for l in sec["outcome"].splitlines() if l.strip()]
    return "\n".join(out)


# ── Correlation joins ──────────────────────────────────────────────────────

def _parts(query: str) -> Tuple[str, str]:
    """(header comment, expression) of a single-event UDM search."""
    query = from_yaral(query) or ""
    lines = [l for l in query.strip().splitlines()]
    head = lines[0] if lines and lines[0].startswith("//") else ""
    expr = " ".join(l.strip() for l in lines if l.strip() and not l.strip().startswith("//"))
    return head, expr


def bind(expr: str, var: str) -> str:
    """Prefix every UDM field in a search expression with an event variable ($e1.target...),
    leaving /regex/ literals and "strings" alone."""
    out, i = [], 0
    for m in re.finditer(r'/(?:\\.|[^/\\])*/|"(?:\\.|[^"\\])*"', expr):
        out.append(_FIELD.sub(lambda f: f"{var}.{f.group(1)}.", expr[i:m.start()]))
        out.append(m.group(0))
        i = m.end()
    out.append(_FIELD.sub(lambda f: f"{var}.{f.group(1)}.", expr[i:]))
    return "".join(out)


def _technique(head: str) -> Tuple[str, str]:
    """(technique ID, technique name) from a search's header comment."""
    tid = re.search(r"ATT&CK (T\d{4}(?:\.\d{3})?)", head or "")
    name = re.search(r"^//\s*\w+:\s*(?:Detects )?(.+?)(?: \(T\d[\d.]*\))? · ATT&CK", head or "")
    return (tid.group(1) if tid else "?"), (name.group(1) if name else "")


def build_join(queries_a, queries_b, label_a: str = "", label_b: str = "", window: str = "1h") -> Optional[str]:
    """
    Two-event UDM join: an A event and a B event on the same host within `window`.
    Each side takes one single-event search (or YARA-L rule) or a list, a list becoming
    alternatives for that event. None when a side has nothing to match on, or is
    itself a join.
    """
    sides = []
    for qs in (queries_a, queries_b):
        qs = [q for q in ([qs] if isinstance(qs, str) else qs or []) if q and q.strip()]
        if not qs or any(is_join(from_yaral(q) or "") for q in qs):
            return None
        parts = [_parts(q) for q in qs]
        # Each side must filter on UDM fields: KQL or SPL here is a caller's mistake
        if not all(expr and _FIELD.search(expr) for _, expr in parts):
            return None
        sides.append(parts)
    (a, b), labels = sides, []
    for parts, label in ((a, label_a), (b, label_b)):
        names = [n for n in dict.fromkeys(_technique(h)[1] for h, _ in parts) if n]
        tids = [t for t in dict.fromkeys(_technique(h)[0] for h, _ in parts)]
        labels.append(((" / ".join(names) or label or " / ".join(tids)).replace('"', "'"), tids))
    (la, tids_a), (lb, tids_b) = labels
    extra = len(tids_a) + len(tids_b) - 2
    name = re.sub(r"\W", "_", f"archer_corr_{tids_a[0]}_then_{tids_b[0]}" + (f"_plus{extra}" if extra else "")).lower()

    def side(parts, var):
        # Statements are ANDed line by line, so a side with alternatives is one bracketed line
        exprs = list(dict.fromkeys(bind(e, var) for _, e in parts))
        if len(exprs) > 1:
            return "(" + " or ".join(f"({e})" for e in exprs) + ")"
        return exprs[0] if not _top_level_or(exprs[0]) else f"({exprs[0]})"

    return f"""{header(name, f"{la} and {lb} on the same host within {window}", ", ".join(tids_a + tids_b), "HIGH")}
// {la}
{side(a, "$e1")}
$e1.principal.hostname = $host

// {lb}
{side(b, "$e2")}
$e2.principal.hostname = $host

$host != ""

match:
  $host over {window}

outcome:
  $first_a = min($e1.metadata.event_timestamp.seconds)
  $last_b = max($e2.metadata.event_timestamp.seconds)
  $users = array_distinct($e1.principal.user.userid)
  $commands_a = array_distinct($e1.target.process.command_line)
  $commands_b = array_distinct($e2.target.process.command_line)"""


# ── Back to YARA-L, for tools that parse rules ─────────────────────────────

_UDM_REGEX = re.compile(r"(\$?[\w.]+)\s*=\s*/((?:\\.|[^/\\])*)/(\s+nocase)?")


def to_yaral(query: str) -> str:
    """
    A single-event UDM search as the equivalent YARA-L rule, for the tools that parse
    rules: the local SecOps simulator, the precision checks and the contract lint. A
    YARA-L rule comes back unchanged; a join comes back as is (they don't take one).
    """
    if not query or is_yaral(query) or is_join(query):
        return query
    head, expr = _parts(query)
    name = (re.match(r"//\s*(\w+)", head) or re.match(r"(x)", "x")).group(1)
    name = name if name != "x" else "archer_search"
    events = _UDM_REGEX.sub(lambda m: f"re.regex({m.group(1)}, `{m.group(2).replace(chr(92) + '/', '/')}`)"
                            + (" nocase" if m.group(3) else ""), bind(expr, "$e"))
    return f"""rule {name} {{
  meta:
    description = "{(head.split(':', 1)[1].split(' · ')[0].strip() if ':' in head else name).replace('"', "'")}"

  events:
    {events}

  condition:
    $e
}}"""

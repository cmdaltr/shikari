"""
Google SecOps query generator: ATT&CK techniques as UDM searches for Search.

The indicator logic builds a single-event YARA-L rule internally (its tests and the
correlation builder were written against that form); archer.build.udm turns it into the
UDM search Archer writes, so no SecOps output is a rule.
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from archer.build.indicator_hygiene import clean_identifier_map
from archer.build.severity import RISK_SCORE, rate as rate_severity


class SecOpsGenerator:
    def __init__(self):
        """
        Initialize Google SecOps generator with schema mappings
        """
        # Load Google SecOps schema mappings
        self.schema = self._load_schema()

    def _load_schema(self) -> Dict:
        """Load Google SecOps UDM schema mappings"""
        schema_path = Path(__file__).parent.parent.parent / "bespoke" / "mappings" / "schemas" / "schemaGoogleSecOps.json"
        if schema_path.exists():
            with open(schema_path, 'r') as f:
                return json.load(f)
        return {}

    def generate_query(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        description: str,
        indicators: Optional[Dict] = None,
        osint_data: Optional[Dict] = None,
        group_name: Optional[str] = None,
        tactics: Optional[List[str]] = None,
    ) -> Dict[str, any]:
        """
        A UDM search for the technique, from its indicators.

        Returns:
            Dict with keys: rule_name (the search's name), query (UDM search, None when
            nothing to match on), description, severity, data_sources, event_types
        """
        from archer.build.udm import from_yaral

        rule_name = yaral_rule_name(technique_id)

        # The technique's kill-chain stage (archer.build.severity), as the YAML records it
        rating = rate_severity(tactics or [tactic])
        severity = rating.upper()

        yaral_code, event_types = self._build_yaral_query(
            technique_id=technique_id,
            technique_name=technique_name,
            indicators=clean_identifier_map(indicators or {}),
            severity=severity,
            risk_score=RISK_SCORE[rating],
        )

        return {
            "rule_name": rule_name,
            "query": from_yaral(yaral_code) if yaral_code else None,
            "description": f"Detects {technique_name} ({technique_id})",
            "severity": severity,
            "data_sources": event_types,
            "event_types": event_types,
        }

    def _build_yaral_query(
        self,
        technique_id: str,
        technique_name: str,
        indicators: Dict,
        severity: str = "MEDIUM",
        risk_score: int = RISK_SCORE["Medium"],
    ):
        """
        Build a single-event YARA-L rule from indicators. Returns (rule, event_types).

        Each indicator family matches only the UDM event type that carries its fields:
        command lines and binaries on PROCESS_LAUNCH, registry keys on registry events,
        ports/protocols/services on NETWORK_CONNECTION. Families become alternatives
        (one branch each) rather than being ANDed onto one event, which could never
        match (a process launch has no network.application_protocol).

        Network context only narrows a network event, so it gets its own branch only
        when there are no process or registry indicators; otherwise a lone protocol
        such as SSH would match every SSH connection. It is kept in meta as context.
        """
        branches, context = _indicator_branches(indicators)
        if not branches:
            # Nothing to match on: a bare event type would fire on every process launch
            return None, []

        event_types = list(dict.fromkeys(t for types, _ in branches for t in types))
        events = [_branch_expr(types, conds) for types, conds in branches]
        if len(events) == 1:
            types, conds = branches[0]
            event_lines = [_type_expr(types)] + conds
        else:
            # Lines in events are ANDed, so alternatives share one line
            event_lines = [" or ".join(events)]
        context_meta = "".join(f'\n    context_{k} = "{_meta_text(", ".join(v))}"' for k, v in context.items())
        outcome = "\n".join(f"    ${name} = {value}" for name, value in _outcome(risk_score, event_types))

        rule = f"""rule {yaral_rule_name(technique_id)} {{
  meta:
    author = "Archer Detection Engineering"
    description = "Detects {_meta_text(technique_name)} ({technique_id})"
    mitre_attack_technique = "{technique_id}"
    severity = "{severity}"{context_meta}

  events:
{chr(10).join("    " + line for line in event_lines)}

  outcome:
{outcome}

  condition:
    $e
}}"""
        return rule, event_types


# The entities an analyst triages first (contract R15.1), taken from the one event. Single
# values, not aggregates, so the rule needs no match section (R06.2). Only non-repeated UDM
# fields: a repeated one (target.ip, network.dns.questions) can't be assigned without match.
_OUTCOME_BY_TYPE = {
    "PROCESS_LAUNCH": [("process", "$e.target.process.file.full_path"),
                       ("command_line", "$e.target.process.command_line"),
                       ("parent_command_line", "$e.principal.process.command_line")],
    "NETWORK_CONNECTION": [("target_host", "$e.target.hostname"), ("target_port", "$e.target.port")],
    "NETWORK_HTTP": [("target_url", "$e.target.url")],
}
_REGISTRY_OUTCOME = [("registry_key", "$e.target.registry.registry_key"),
                     ("registry_value", "$e.target.registry.registry_value_name")]


def _outcome(risk_score: int, event_types: List[str]):
    """outcome variables: the risk score, the host and account, then each event type's own evidence."""
    rows = [("risk_score", str(risk_score)), ("hostname", "$e.principal.hostname"),
            ("user", "$e.principal.user.userid")]
    for et in event_types:
        extra = _REGISTRY_OUTCOME if et.startswith("REGISTRY_") else _OUTCOME_BY_TYPE.get(et, [])
        rows += [r for r in extra if r not in rows]
    return rows


def yaral_rule_name(technique_id: str) -> str:
    """archer_t1003_001: lowercase snake_case, as YARA-L names must be (validator YL-1),
    prefixed like the IOC sweeps (archer_ioc_sweep_*) and correlations (archer_corr_*)."""
    return "archer_" + re.sub(r"\W+", "_", technique_id).strip("_").lower()


# ── Indicator → UDM ────────────────────────────────────────────────────────

# RE2 metacharacters; everything else in an indicator is literal text
_RE2_META = re.compile(r"([\\.^$|?*+()\[\]{}])")
_REGISTRY_PATH = re.compile(r"^(HKLM|HKCU|HKU|HKCR|HKCC|HKEY_[A-Z_]+)\\", re.I)
_PER_TYPE_LIMIT = 5
# UDM ApplicationProtocol enum values that indicators commonly name
_UDM_PROTOCOLS = {"DNS", "HTTP", "HTTPS", "SSH", "RDP", "SMB", "LDAP", "SMTP", "SNMP", "NTP", "DHCP",
                  "KRB5", "QUIC", "TOR", "NFS", "SIP", "MQTT", "GRPC", "RPC", "DCERPC"}
_PROTOCOL_ALIASES = {"KERBEROS": "KRB5"}


def _re_literal(value: str) -> Optional[str]:
    """
    An indicator as an RE2 pattern matching it literally; runs of spaces match any
    whitespace, and a placeholder's gap (indicator_hygiene.GAP) matches anything.
    """
    if "`" in value:  # cannot appear inside a YARA-L regex literal
        return None
    return ".*?".join(r"\s+".join(_RE2_META.sub(r"\\\1", part) for part in piece.split())
                      for piece in value.split("\u2026"))


def _regex_any(field: str, values: List[str]) -> List[str]:
    pats = [p for p in (_re_literal(v) for v in values[:_PER_TYPE_LIMIT]) if p]
    return [f"re.regex($e.{field}, `{p}`) nocase" for p in pats]


def _type_expr(types: List[str]) -> str:
    exprs = [f'$e.metadata.event_type = "{t}"' for t in types]
    return exprs[0] if len(exprs) == 1 else "(" + " or ".join(exprs) + ")"


def _branch_expr(types: List[str], conds: List[str]) -> str:
    return "(" + " and ".join([_type_expr(types)] + conds) + ")"


def _meta_text(value: str) -> str:
    return str(value).replace("\\", "/").replace('"', "'")


def _indicator_branches(indicators: Dict):
    """[(event_types, [conditions])] per indicator family, plus unused network context."""
    from archer.validation.precision import is_generic

    # An ordinary word ("copy", "dir") as a whole value matches far more than the behaviour
    cmds = [c for c in indicators.get("cmd", []) if not is_generic(str(c))]
    reg_keys = list(indicators.get("reg", [])) + [c for c in cmds if _REGISTRY_PATH.match(c)]
    binaries = [b for b in indicators.get("sw", []) if not is_generic(str(b))]

    branches = []
    process = _regex_any("target.process.command_line", cmds) + _regex_any("target.process.file.full_path", binaries)
    if process:
        branches.append((["PROCESS_LAUNCH"], ["(" + " or ".join(process) + ")"]))
    registry = _regex_any("target.registry.registry_key", reg_keys)
    if registry:
        branches.append((["REGISTRY_CREATION", "REGISTRY_MODIFICATION"], ["(" + " or ".join(registry) + ")"]))

    ports = [p for p in (str(x).strip() for x in indicators.get("port", [])) if p.isdigit() and 0 < int(p) < 65536]
    protocols, unknown = [], []
    for proto in indicators.get("protocol", []):
        name = _PROTOCOL_ALIASES.get(str(proto).upper(), str(proto).upper())
        (protocols if name in _UDM_PROTOCOLS else unknown).append(name)
    services = list(indicators.get("service", []))
    context = {k: v for k, v in (("ports", ports), ("protocols", protocols + unknown), ("services", services)) if v}

    # A protocol only narrows: alone it matches every SSH or DNS connection
    if not branches and (ports or services):
        network = []
        if ports:
            network.append("(" + " or ".join(f"$e.target.port = {p}" for p in ports[:_PER_TYPE_LIMIT]) + ")")
        if protocols:
            network.append("(" + " or ".join(f'$e.network.application_protocol = "{p}"' for p in protocols[:_PER_TYPE_LIMIT]) + ")")
        svc = _regex_any("target.application", services)
        if svc:
            network.append("(" + " or ".join(svc) + ")")
        branches.append((["NETWORK_CONNECTION"], network))
        context = {}
    return branches, context


# ── Multi-event correlation ────────────────────────────────────────────────

_SECTION = re.compile(r"^\s*(meta|events|match|outcome|condition|options)\s*:\s*$", re.M)


def _rule_sections(rule: str) -> Dict[str, str]:
    """Split a YARA-L rule body into its sections (meta, events, condition, ...)."""
    body = rule.strip()
    body = body[body.find("{") + 1: body.rfind("}")] if "{" in body else body
    marks = list(_SECTION.finditer(body))
    return {m.group(1): body[m.end(): marks[i + 1].start() if i + 1 < len(marks) else len(body)].strip("\n")
            for i, m in enumerate(marks)}


def _meta_value(meta: str, key: str) -> Optional[str]:
    m = re.search(rf'^\s*{key}\s*=\s*"([^"]*)"', meta, re.M)
    return m.group(1) if m else None


def _event_block(events: str, var: str, grouped: bool) -> str:
    """
    Rebind a single-event rule's $e to `var`. Lines in an events section are ANDed;
    `grouped` folds them into one parenthesised expression so blocks can be ORed.
    """
    lines = [re.sub(r"\$e\b", var, line.strip()) for line in events.splitlines()
             if line.strip() and not line.strip().startswith("//")]
    if not grouped:
        return "\n".join(f"    {line}" for line in lines)
    return "    (" + " and ".join(lines) + ")"


def _event_types(events: str) -> List[str]:
    return re.findall(r'metadata\.event_type\s*=\s*"([A-Z_]+)"', events)


def _side(rules, var: str):
    """events text, technique IDs and event types for one side ($e1 or $e2) of a correlation."""
    rules = [r for r in ([rules] if isinstance(rules, str) else rules) if r and r.strip()]
    parsed = [_rule_sections(r) for r in rules]
    if not parsed or any(not p.get("events") or re.search(r"\$e\d", p["events"]) for p in parsed):
        return None
    tids = [_meta_value(p.get("meta", ""), "mitre_attack_technique") or "?" for p in parsed]
    names = [_technique_name(p.get("meta", "")) for p in parsed]
    blocks = [_event_block(p["events"], var, grouped=len(parsed) > 1) for p in parsed]
    # Alternatives stay on one line: separate statements in events are ANDed
    events = blocks[0] if len(blocks) == 1 else "    (" + " or ".join(b.strip() for b in blocks) + ")"
    types = [t for p in parsed for t in _event_types(p["events"])]
    return events, list(dict.fromkeys(tids)), types, [n for n in dict.fromkeys(names) if n]


def _technique_name(meta: str) -> Optional[str]:
    """'Detects Access Token Manipulation (T1134)' -> 'Access Token Manipulation'."""
    m = re.match(r"Detects (.+?) \(T\d", _meta_value(meta, "description") or "")
    return m.group(1) if m else None


def build_correlation_rule(rules_a, rules_b, label_a: str = "", label_b: str = "",
                           window: str = "1h") -> Optional[str]:
    """
    Combine single-event YARA-L rules into one multi-event correlation rule.

    Mirrors the MDE correlation (same device within an hour): both events must come
    from the same host (principal.hostname, bound to the $host match variable) within
    `window`, and the A event must not be later than the B event. Each side takes one
    rule or a list; a list becomes alternatives (A1 or A2 ...) for that event.
    Returns None when an input isn't a single-event rule this can rebind.
    """
    a, b = _side(rules_a, "$e1"), _side(rules_b, "$e2")
    if not (a and b):
        return None
    events_a, tids_a, types_a, names_a = a
    events_b, tids_b, types_b, names_b = b
    clean = lambda s: s.replace('"', "'")
    # Technique names from each rule's own meta; the caller's label (from the filename) is the fallback
    label_a = clean(" / ".join(names_a) or label_a or " / ".join(tids_a))
    label_b = clean(" / ".join(names_b) or label_b or " / ".join(tids_b))
    extra = len(tids_a) + len(tids_b) - 2
    name = re.sub(r"\W", "_", f"archer_corr_{tids_a[0]}_then_{tids_b[0]}" + (f"_plus{extra}" if extra else "")).lower()

    return f"""rule {name} {{
  meta:
    author = "Archer Detection Engineering"
    description = "{label_a} followed by {label_b} on the same host within {window}"
    mitre_attack_technique = "{', '.join(tids_a + tids_b)}"
    event_types = "{', '.join(sorted(set(types_a + types_b)))}"
    severity = "HIGH"

  events:
    // {label_a}
{events_a}
    $e1.principal.hostname = $host

    // {label_b}
{events_b}
    $e2.principal.hostname = $host

    $host != ""
    $e1.metadata.event_timestamp.seconds <= $e2.metadata.event_timestamp.seconds

  match:
    $host over {window}

  outcome:
    $first_seen = min($e1.metadata.event_timestamp.seconds)
    $last_seen = max($e2.metadata.event_timestamp.seconds)
    $users = array_distinct($e1.principal.user.userid)
    $commands_a = array_distinct($e1.target.process.command_line)
    $commands_b = array_distinct($e2.target.process.command_line)

  condition:
    $e1 and $e2
}}"""

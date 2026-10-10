# Archer output contract v1.0 — schema

The contract is a single YAML document validated against `archer-output.schema.json` (JSON Schema draft 2020-12) and the additional rules in `validate.py`. This document is the normative description; the schema file and the validator are its enforcement.

## Why YAML, and the lexical rules that make it strict

JSON was rejected because the query would have to be a single escaped string. Every regex backslash becomes `\\`, every quote `\"`, and the two most frequent Archer syntax failures in the workbook (Q042, Q043, Q048: unbalanced quotes and lost backslashes) are escaping failures. YAML's literal block scalar carries the query byte-for-byte with no escaping at all. The Q043 YAML failure was a flow-style quoted scalar with an embedded newline, which the lexical rules below forbid.

YAML's own ambiguities are closed by rule:

| Rule | Requirement | Validator gate |
|---|---|---|
| L1 | No tab characters anywhere | LEX-1 |
| L2 | `query` is a literal block scalar: `query: \|` followed by the query indented two spaces deeper than the key | LEX-2 |
| L3 | Block style only; the sole flow collections allowed are the empty `[]` and `{}` | LEX-3 |
| L4 | No anchors, aliases or tags | LEX-4, LEX-5 |
| L5 | No document markers (`---`) | LEX-6 |
| L6 | `contract_version`, `attack_version`, `version`, `created`, `modified`, `measured_on`, `first_reported`, `accessed`, `frequency` are quoted strings so they cannot be parsed as numbers or dates | schema patterns |
| L7 | `pattern` in `regexes[]` is a `\|-` block scalar; sample strings are single-quoted unless they contain a single quote | RX-7 (pattern must appear verbatim in the query) |
| L8 | Keys appear in the fixed order below; a key out of order is a validation failure | ORDER-* |
| L9 | `query` is the last key of `rule`, so metadata is written before logic | ORDER-rule |
| L10 | Parsing is YAML 1.2 `safe_load`; bare `yes`, `no`, `on`, `off` never appear as values | enumerations |

## Top level

```yaml
archer_output:
  contract_version: "1.0"         # const
  kind: rule | rejection
  request_ref: <string>           # the request envelope identifier
  rule: {...}                     # exactly one of rule / rejection, matching kind
  rejection: {...}
```

## `rule` — fixed key order and requirements

Every key is required for every `detection_type` unless the Type column says otherwise. "Null allowed" means the key must be present with the value `null`.

| # | Key | Type | Detection | Hunt | Sweep | Rejection condition if violated |
|---|---|---|---|---|---|---|
| 1 | `rule_id` | UUID v4 | req | req | req | SCHEMA_VALIDATION_FAILED. Stable across versions; a revision request supplies it. |
| 2 | `name` | string, convention R07 | req | req (`_hunt`/`Hunt` suffix) | req (`_sweep`/`Sweep` suffix) | SCHEMA_VALIDATION_FAILED (NAME-1..4) |
| 3 | `author` | string | req | req | req | — |
| 4 | `created` | ISO date, quoted | req | req | req | — |
| 5 | `modified` | ISO date, quoted | req | req | req | — |
| 6 | `version` | `major.minor.patch`, quoted | req | req | req | — |
| 7 | `status` | `draft` | `draft` | `draft` | `draft` | Any other value from the model: STATUS. `test` and `production` are set by the harness. |
| 8 | `detection_type` | enum | `scheduled_detection` | `hunt` | `ioc_sweep` | SCHEMA_VALIDATION_FAILED |
| 9 | `siem` | `yara_l` \| `kql` | req | req | req | SYNTAX_UNSUPPORTED for anything else |
| 10 | `target_os` | list of `windows`, `macos`, `linux`, `cloud` | req | req | req | — |
| 11 | `log_sources[]` | see below | ≥1 | ≥1 | ≥1 | SOURCE_NOT_STATED, SOURCE_NOT_INGESTED, FIELD_NOT_POPULATED |
| 12 | `attack` | see below | req | req | req | MAPPING_TOO_COARSE, TACTIC_OUT_OF_SCOPE |
| 13 | `lookback` | `<n>m\|h\|d` | = match window (YARA-L, ≤ 48h) or within the KQL platform window | ≤ 90d | ≤ 90d | SCHEMA_VALIDATION_FAILED (YL-9b, KQL-12, TYPE-1) |
| 14 | `schedule` | object or null | `{mode: live}` (YARA-L) or `{frequency, grouping}` (KQL) | `null` | `null` | SCHEMA_VALIDATION_FAILED |
| 15 | `confidence` | `{rating, rationale ≥ 40 chars}` | req | req | req | — |
| 16 | `severity` | `{rating, rationale ≥ 40 chars}` | req | req | req | — |
| 17 | `false_positives[]` | see below | ≥1, at least one `suppression` or `structural` | ≥1 | ≥1 | SCHEMA_VALIDATION_FAILED (FP-1..3) |
| 18 | `tuning_notes` | see below | req; baseline numbers before production | req | req | — |
| 19 | `references[]` | ≥1 | req | req | req | IOC_NO_PROVENANCE if an indicator's reference is missing |
| 20 | `indicators[]` | list, may be `[]` | any hardcoded value listed | same | ≥1, complete | IOC_PLACEHOLDER, INDICATORS_UNUSABLE |
| 21 | `reference_lists[]` | list, may be `[]` | every `%list` declared | same | same | SCHEMA_VALIDATION_FAILED (YL-17) |
| 22 | `entity_output` | see below | req | req | req, plus matched indicator and source | — |
| 23 | `correlation` | see below | req | req | req | JOIN_NOT_PORTABLE |
| 24 | `regexes[]` | list, may be `[]` | every regex literal declared | same | same | SCHEMA_VALIDATION_FAILED (RX-1..7) |
| 25 | `complexity` | counted values | ≤ ceilings | ≤ ceilings | ≤ ceilings | COMPLEXITY_EXCEEDED |
| 26 | `validation` | see below | req | req | req | — |
| 27 | `query` | literal block scalar, last key | req | req | req | LEX-2 |

### `log_sources[]`

```yaml
- id: LS1                                  # LS<n>, referenced by correlation.events[].source_id
  siem_source: PROCESS_LAUNCH              # UDM event type(s) or Advanced Hunting table
  product: Microsoft Defender for Endpoint
  udm_log_type: WINDOWS_DEFENDER_ATP       # or null for KQL
  ingestion:
    status: confirmed | unverified | not_ingested   # not_ingested must be a rejection
    profile_ref: <environment profile id or null>
  fields:                                  # every field path used from this source
    - path: target.process.command_line
      population: known_populated | unknown | known_empty   # known_empty must be a rejection
      os: [windows, macos, linux]          # block style in the document; shown inline here only
      note: <optional>
  coverage_gaps: [...]                     # known holes, may be []
```

### `attack`

```yaml
attack_version: "19.2"                     # const
bundle_ref: <STIX bundle id> | null        # tactic membership is taken from the bundle, not memory
tactics: [v19 names]                       # tactics[0] is the name's tactic
technique_ids: [T1234.001, ...]            # technique_ids[0] is the name's technique
mapping_rationale: <≥ 40 chars; names the field and value that evidences each technique>
```

Tactic enumeration: `initial_access`, `execution`, `persistence`, `privilege_escalation`, `stealth`, `defense_impairment`, `credential_access`, `discovery`, `lateral_movement`, `collection`, `command_and_control`, `exfiltration`, `impact`. `defense_evasion`, `reconnaissance` and `resource_development` are schema violations.

### `false_positives[]`

```yaml
- id: FP1
  scenario: <≥ 20 chars; a specific process, tool, team, population or workflow>
  population: <who or what produces it>
  distinguishing_fields:
    - field: <field path>
      benign_pattern: <value or pattern that separates it>
  handled_by: suppression | structural | triage | accepted
  suppression_id: S<n> | null              # required when handled_by is suppression, null otherwise
```

`structural` means the rule's anchor condition already excludes the scenario (for example, the initiating-process re-check excludes a developer running the same CLI from a shell).

### `tuning_notes`

```yaml
baseline:
  window_days: <int ≥ 1>
  before_tuning: <int> | null
  after_tuning: <int> | null
  alerts_per_day_after_aggregation: <number> | null   # ≤ 5 required for production detections
  measured_on: <date> | null
  measurement_procedure: <≥ 40 chars; the query or steps>
suppressions:
  - id: S1
    logic_ref: "// S1:"                    # the marker comment that precedes the clause in the query
    reason: <≥ 20 chars>
    depends_on_enrichment: true | false
    fails_closed_how: <≥ 20 chars>
dependencies:
  - type: reference_list | lookup | macro | function | allow_list | enrichment | watchlist | externaldata
    name: <name as used in the query>
    declared_in: <where the definition lives>
    definition_ref: <definition or owner>
first_parameter_to_adjust: <≥ 20 chars; one knob and a direction>
known_limitations: [...]
split_from:
  - rule_id: <sibling uuid>
    relationship: sequential | independent | correlation_consumer
```

### `references[]`, `indicators[]`, `reference_lists[]`

```yaml
references:
  - id: REF1
    title: <string>
    locator: <URL, report id, ticket, workbook row>
    accessed: <date>
    used_for: [<what in the rule depends on it>]
indicators:
  - id: IOC1
    type: sha256 | sha1 | md5 | ipv4 | ipv6 | domain | url | filename | path | user_agent | command_fragment | package_version
    value: <normalised: lowercase hashes and domains, no port on IPs>
    reference_id: REF1
    first_reported: <date>
reference_lists:
  - name: <snake_case; used as %name in YARA-L>
    type: string | regex | cidr
    purpose: match | allow
    indicator_ids: [IOC1, ...]             # [] permitted for allow-lists whose members are not indicators
```

### `entity_output`

Maps each required projection to the output column (KQL) or outcome variable (YARA-L). `parent_command_line` and `source_table` may be `null` when the source cannot carry them, and `known_limitations` must then say so.

```yaml
timestamp_first: $first_seen
timestamp_last: $last_seen
device: $hostnames
account: $accounts
process: $payload_processes, $payload_commands
parent_command_line: $payload_parent_commands | null
evidence_value: $setup_commands, $payload_commands
source_table: $event_types | DeviceEvents | null
```

### `correlation`

```yaml
events:
  - var: setup                             # YARA-L event variable name; KQL let or table name
    source_id: LS1
    role: anchor | evidence | single
join_keys:                                 # required when events has more than one entry
  - key: principal.asset_id
    holds_on: [macos, linux, windows]      # every OS in target_os must appear, or mitigation must be set
    mitigation: <how the join is made to hold> | null
ordering: <the timestamp inequality> | null
window: <duration>                         # YARA-L match window; KQL bin or join window; equals lookback for detections
```

### `regexes[]`

```yaml
- id: RX1
  field: <field(s) the regex is applied to>
  pattern: |-
    <regex exactly as it appears in the query>
  engine: re2
  literal_encoding: yara_l_backtick | kql_verbatim
  must_match: [<≥ 1 realistic value>]
  must_not_match: [<≥ 1 near-miss>]
```

### `complexity`

```yaml
lines: <non-blank query lines, ≤ 150>
event_variables_or_joins: <YARA-L event variables, ≤ 4; KQL joins, ≤ 5>
union_branches: <≤ 6>
nesting_depth: <≤ 2>
```

The validator recounts every value; a mismatch is a failure.

### `validation`

```yaml
fidelity_basis: logic_review | positive_control
compile:
  status: not_run                          # harness sets pass | fail
field_existence:
  schema_ref: <catalogue used>
  status: checked | unchecked
field_population:
  status: known_populated | unknown | known_empty
  evidence: <≥ 20 chars; the sample or the sample query to run>
ingestion:
  status: confirmed | unverified | not_ingested
  profile_ref: <profile id> | null
join_portability:
  status: pass | fail | not_applicable
  notes: <string>
regex_checks:
  status: not_run                          # harness sets pass | fail after running samples in the target engine
positive_control:
  status: not_run | passed | failed | failed_to_observe
  procedure: <≥ 40 chars; the command, the expected single result, the negative case>
  evidence_ref: REF<n> | null
  date: <date> | null
```

## Promotion rules (harness, not model)

| `status` | Requires |
|---|---|
| `draft` | Model output. All emission gates pass. |
| `test` | `compile.status: pass`; `ingestion.status: confirmed`; `field_population.status: known_populated`; `regex_checks.status: pass` in the target engine. |
| `production` | `test`, plus `positive_control.status: passed` with `evidence_ref` and `date`; for `scheduled_detection`, `baseline.window_days ≥ 7` and `alerts_per_day_after_aggregation ≤ 5`; `join_portability.status` is `pass` or `not_applicable`. |

A `hunt` or `ioc_sweep` never reaches `production` as an alerting rule; `production` for those types means "approved for analyst use".

## `rejection` — fixed key order

```yaml
archer_output:
  contract_version: "1.0"
  kind: rejection
  request_ref: <string>
  rejection:
    reason_code: <one code>
    secondary_codes: [<codes>]             # may be []
    detection_type_requested: scheduled_detection | hunt | ioc_sweep
    siem_requested: <string as requested, even if unsupported>
    technique_ids_requested: [<ids>]       # may be []
    blocking_criteria: [R02.8, G1.3]       # rubric test ids and/or checklist gate ids, ≥ 1
    evidence:
      - check: <what was tested>
        observed: <what was found>
        expected: <what would have passed>
    remediation: [<≥ 1 concrete action>]
    nearest_viable_alternative:            # or null
      detection_type: ...
      siem: yara_l | kql
      log_source: <source>
      summary: <≥ 20 chars>
```

### Reason codes

| Code | Meaning | Rubric |
|---|---|---|
| `SOURCE_NOT_STATED` | No exact source, or a wildcard source | R02.1, R09.1 |
| `SOURCE_NOT_IN_SCHEMA` | Source is not in the catalogue and not declared as a tenant function | R02.2 |
| `SOURCE_NOT_INGESTED` | Environment profile does not list the source as ingested for the target estate | R02.8, R09.2 |
| `FIELD_NOT_IN_SCHEMA` | Field path does not exist on that source | R02.3 |
| `FIELD_NOT_POPULATED` | Field exists but cannot carry the value for that event type | R02.4, R14.5, R14.6 |
| `SINGLE_WEAK_INDICATOR` | Strongest available term is generic, with no correlating anchor | R09.4 |
| `MAPPING_TOO_COARSE` | Tactic only, or parent where sub-techniques exist and the intent does not disambiguate | R01, R09.5 |
| `TACTIC_OUT_OF_SCOPE` | Reconnaissance or Resource Development | R11.3 |
| `HARDCODED_SCOPE_REQUIRED` | Precision would depend on a named user, host or absolute date | R18, R09.6 |
| `IOC_PLACEHOLDER` | Placeholder indicator value | R16.3 |
| `IOC_NO_PROVENANCE` | Hardcoded indicator with no reference | R16.1 |
| `INDICATORS_UNUSABLE` | Indicators are prose, malformed or unescapable | R16.4, R16.6 |
| `JOIN_NOT_PORTABLE` | Join key empty on a target OS with no identity re-check possible | R14.10 |
| `COMPLEXITY_EXCEEDED` | Over a ceiling and cannot be split | R12 |
| `TYPE_MISMATCH` | Requested type cannot be met by the achievable logic | R13.7 |
| `SYNTAX_UNSUPPORTED` | SPL, Sigma, EQL or anything other than yara_l and kql | R06.1 |
| `SCHEMA_VALIDATION_FAILED` | Draft fails a gate and cannot be repaired | R08.1, R09.13 |

## Request envelope (input)

The contract's gates depend on these inputs. The model records their absence in `validation`; it never guesses them.

```yaml
request:
  request_ref: <id>
  intent: <technique id, log source, or hunt hypothesis in one paragraph>
  detection_type: scheduled_detection | hunt | ioc_sweep
  siem: yara_l | kql
  target_os: [...]
  technique_records:                       # from the pinned ATT&CK v19.2 STIX bundle (MITRESaw)
    - id: T1059.007
      name: JavaScript
      parent: T1059
      has_subtechniques: false
      tactics: [execution]
      deprecated: false
  attack_bundle_ref: <bundle id>
  environment_profile:
    id: ENVPROFILE-B-secops-observed-2026-10-09
    siem: yara_l
    ingested:
      - product: Microsoft Defender for Endpoint
        tables: [DeviceEvents, DeviceFileEvents, DeviceRegistryEvents]
        udm_event_types: [FILE_CREATION, FILE_MODIFICATION, FILE_MOVE, FILE_DELETION, REGISTRY_CREATION, ...]
        notes: "PROCESS_LAUNCH present from DeviceEvents on 59 hosts only"
    not_ingested: [DeviceProcessEvents, DeviceNetworkEvents]
    reference_lists_available: [...]
    known_coverage_gaps: [...]
  indicators: [...]                        # with reference ids
  references: [...]
  prior_validation: {...} | null           # for revisions: baseline numbers, positive-control results
  rule_id: <uuid> | null                   # for revisions
```

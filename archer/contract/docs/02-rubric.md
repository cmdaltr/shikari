# Archer fidelity rubric — pass/fail tests

Every Include criterion from the Fidelity Criteria tab is expressed below as numbered tests. A test is either **PASS** or **FAIL**; there is no partial credit. Where a test depends on something the generating model cannot know (ingestion state, field population in the tenant, baseline volume), the rubric says what input carries that fact and what happens when the input is absent.

Three words are used with fixed meaning:

- **Reject**: do not emit a rule; emit the rejection shape with the named reason code.
- **Cap**: emit the rule, but `status` may not exceed the named value until the gate is satisfied by the harness or a human.
- **Fail**: the draft does not pass; the model must repair it before emitting. If it cannot, reject.

Output types: **SD** = scheduled_detection, **H** = hunt, **IS** = ioc_sweep. A test marked "all" applies identically to every type.

## Inputs the rubric assumes

The request envelope that Archer passes to the model carries:

| Input | Used by | If absent |
|---|---|---|
| `technique_records[]` from the pinned ATT&CK STIX bundle: id, name, parent id, `has_subtechniques`, tactics (v19 names), `is_deprecated` | R01, R11 | R01.4 and R11.2 cannot run; cap at `draft` and record `attack.bundle_ref: null` |
| `environment_profile`: siem, ingested products and tables or UDM event types, target OS list, known reference lists, known coverage gaps | R02, R09, R10 | Ingestion state is `unverified`; cap at `draft`; never reject for ingestion |
| `schema_ref`: the UDM field catalogue or the Defender XDR Advanced Hunting table catalogue, with per-event-type population notes | R02 | Model falls back to the field tables in this rubric; cap at `draft` |
| `indicators[]` with `reference_id` for each | R16, IS logic | Any hardcoded indicator without a reference: reject `IOC_NO_PROVENANCE` |
| `prior_validation` (for revisions): baseline numbers, positive-control results, compile results | R10, R05, status | All validation blocks are `not_run` |

## R01 — ATT&CK mapping granularity

- **R01.1 (all)** At least one technique ID is present in `attack.technique_ids`. Tactic-only mapping: reject `MAPPING_TOO_COARSE`.
- **R01.2 (all)** For every technique ID: if the technique record has `has_subtechniques: true`, the ID is a sub-technique (`Tnnnn.nnn`). A parent ID where sub-techniques exist: FAIL. If the intent does not identify which sub-technique the logic observes, reject `MAPPING_TOO_COARSE`.
- **R01.3 (all)** A parent ID is acceptable only when `has_subtechniques: false`, and `attack.mapping_rationale` must say so explicitly ("T1546 has no sub-technique for repository-local hooks").
- **R01.4 (all)** Every technique in `technique_ids` belongs to every tactic in `tactics` per the bundle. T1611 under lateral_movement: FAIL. A tactic the technique does not belong to: FAIL.
- **R01.5 (all)** The mapping describes the observed behaviour in the query, not the campaign's goal. Test: for each technique, `mapping_rationale` names the field and value in the query that evidences it. A rule whose logic is `docker run kali` mapped to T1611 fails; mapped to T1610 passes.
- **R01.6 (SD)** The primary technique (first in the list, used in the name) is the one the anchor event evidences. **(H)** A hunt with several signal classes lists one technique per class. **(IS)** A sweep maps to the technique the indicator type evidences (payload hash present on disk = delivery technique; C2 IP contacted = C2 technique), taken from the indicator's reference.

Ground truth: Q008, Q010, Q012, Q018, Q040, Q044 (parent only or wrong tactic); Q050–Q055 (no IDs).

## R02 — Log source field validation

- **R02.1 (all)** Every log source is named exactly. YARA-L: `metadata.event_type` value(s) and, where the product matters, `metadata.log_type` or `metadata.vendor_name`/`product_name`. KQL: the table name. Wildcarded, implied or `index=*` sources: reject `SOURCE_NOT_STATED`.
- **R02.2 (all)** Every source is in the schema catalogue (for Defender XDR, the published Advanced Hunting table list, which includes `IdentityInfo` and `IdentityAccountInfo`). A table or function not in the catalogue: reject `SOURCE_NOT_IN_SCHEMA` unless the request declares it as a tenant function with its definition.
- **R02.3 (all)** Every field path exists in the schema for that source. YARA-L: the path exists in UDM. KQL: the column exists on that table (not on a sibling table; `DeviceEvents` has no `InitiatingProcessParentCommandLine`). Nonexistent: reject `FIELD_NOT_IN_SCHEMA`.
- **R02.4 (all)** Every field is populated for the declared event type or ActionType, using three states:
  - `known_populated`: the catalogue or a tenant sample says so. PASS.
  - `known_empty`: the catalogue says the field is never carried for that event type (examples: `network.application_protocol` on PROCESS_LAUNCH; `InitiatingProcessVersionInfo*` for non-PE images; Win32 API names in any command-line field; cloud control-plane operation names in endpoint fields; HTTP body content in `RemoteUrl`; a script's hash in `DeviceProcessEvents.SHA256`; `principal.process.parent_process.pid` on MDE PROCESS_LAUNCH in UDM). Reject `FIELD_NOT_POPULATED`.
  - `unknown`: emit, record `validation.field_population.status: unknown` and the sample query that would confirm it; cap at `draft`.
- **R02.5 (all)** Coalescing: at most two candidate fields per logical value, and each must be mapped to a named source in `log_sources[].field_map`. A third candidate: FAIL.
- **R02.6 (YARA-L)** Every reference list is named in `reference_lists[]` with its type and the indicator IDs it contains. A `%list` in the query with no declaration: FAIL.
- **R02.7 (KQL, SPL reference)** Every macro, function, lookup or `externaldata` source is declared in `tuning_notes.dependencies[]` with a definition reference. Undeclared: FAIL. SPL `mde_clean` is the canonical example.
- **R02.8 (all)** Declared source is ingested in the target environment. Test against `environment_profile`: the table (KQL) or the product-plus-event-type pair (YARA-L) is listed as ingested for the target estate. Not listed: reject `SOURCE_NOT_INGESTED` with the profile evidence. Profile absent: cap at `draft`, `validation.ingestion.status: unverified`. This is the first of the three explicit gates.
- **R02.9 (all)** Every target OS the rule claims is one on which the source emits the event. Record `log_sources[].coverage_gaps[]` for known holes (macOS MDE: file events for script writes not observed; network events intermittent, `RemoteUrl` often empty).

Ground truth: Q001, Q004–Q006 (coalescing), Q009, Q011, Q013 (raw text, macro), Q022, Q023, Q034, Q038, Q039, Q045–Q049 (field cannot carry value), Q052–Q055 (not ingested).

## R03 — False-positive condition stated

- **R03.1 (all)** `false_positives[]` has at least one entry.
- **R03.2 (all)** Each entry names a specific scenario: a process image, a tool, a team or role, a host population or a workflow. "May be benign", "legitimate admin activity", "normal developer behaviour": FAIL.
- **R03.3 (all)** Each entry lists at least one `distinguishing_fields[]` item: the field path and the benign value or pattern that separates it from the malicious case (`principal.process.file.full_path` ends with `/git`; `InitiatingProcessFileName == FileName and InitiatingProcessFolderPath == FolderPath`).
- **R03.4 (all)** Each entry says how it is handled: `suppression` (and names the suppression ID in `tuning_notes.suppressions`), `structural` (the rule's anchor condition already excludes it, and the rationale names the condition), `triage` (left in, analyst decides, with the triage question stated) or `accepted` (volume stated).
- **R03.5 (SD)** At least one FP entry is handled by `suppression` or the rationale states why no suppression is needed (volume demonstrated at or below ceiling without one). **(H, IS)** `triage` is acceptable for every entry.

Ground truth: Q002 (FP in prose only), Q005 (identified FP never became a suppression), Q051/Q052 (exclusions present, reasons absent), Q036–Q049 (no FP field).

## R04 — Confidence and severity rating

- **R04.1 (all)** `confidence.rating` ∈ {High, Medium, Low} and `severity.rating` ∈ {Critical, High, Medium, Low}. Both present, both separate fields. One field or a combined score: FAIL.
- **R04.2 (all)** `confidence.rationale` names the indicator specificity and the number of correlated stages. Rule: one stage with a generic indicator cannot be High; two ordered stages with campaign-specific indicators cannot be Low.
- **R04.3 (all)** `severity.rationale` names the kill-chain stage and the asset or credential exposure. Rule: credential or token retrieval, lateral movement or impact cannot be Low; a delivery-only artefact cannot be Critical.
- **R04.4 (all)** Neither rating may be a template default. Test: the rationale references at least one field or condition in the query. A rationale that could be attached to any rule: FAIL.
- **R04.5 (SD)** Severity drives routing; the rule emits it as `meta.severity` (YARA-L) or the custom detection severity (KQL) and the two must match the contract field. **(H)** Confidence may be computed per row (as Q025 does) but the contract field is the maximum the hunt can reach. **(IS)** Confidence is set by the indicator type: hash High, URL or FQDN Medium to High, IP Medium, filename Low unless path-anchored.

Ground truth: Q036–Q049 (`MEDIUM` hardcoded; Q041 computed HIGH and emitted MEDIUM); Q053 "should be tiered above Q3".

## R05 — Tuning notes present

- **R05.1 (all)** `tuning_notes.baseline` states `window_days`, `before_tuning`, `after_tuning` and `measurement_procedure`. The numbers may be null on first emission; the procedure may not be. Missing procedure: FAIL.
- **R05.2 (all)** Every suppression in the query appears in `tuning_notes.suppressions[]` with `id`, `logic_ref` (the line or clause), `reason`, and `fails_closed_how`. A suppression in the query with no entry, or an entry with no matching logic: FAIL.
- **R05.3 (all)** Every environment dependency is in `tuning_notes.dependencies[]`: reference lists, lookups, macros, functions, allow-lists, enrichment tables, with `declared_in` and `definition_ref`. Undeclared dependency used in the query: FAIL.
- **R05.4 (all)** `tuning_notes.first_parameter_to_adjust` names one concrete knob (a threshold, a window, a list) and the direction to move it.
- **R05.5 (all)** `tuning_notes.known_limitations[]` lists each coverage gap the author knows about (Q052: `node setup.mjs` from inside `.vscode` is missed).
- **R05.6 (SD)** `baseline.after_tuning` is populated before `status: production`. **(H, IS)** Baseline numbers may remain null; the procedure must still be present.

Ground truth: Q007 (inline reasons, the model to follow), Q025 (narrative disagrees with code), Q036–Q049 (none).

## R06 — SIEM syntax correctness

- **R06.1 (all)** `siem` ∈ {yara_l, kql}. A request for SPL, Sigma or EQL: reject `SYNTAX_UNSUPPORTED`.
- **R06.2 (YARA-L)** The rule has `rule <name> {`, `meta:`, `events:`, `condition:` and closing `}`. Any rule with more than one event variable, or any aggregation in `outcome`, has `match:`. `outcome:` is present for every SD and IS (it carries the entity output).
- **R06.3 (YARA-L)** Every event variable bound in `events:` appears in `condition:`. Every placeholder variable (`$device`) is bound to at least one event field. Unused variable: FAIL.
- **R06.4 (YARA-L)** `meta` values are quoted strings. Regex literals are backtick-delimited and contain no backtick. `nocase` follows the closing parenthesis of `re.regex(...)`, not the pattern.
- **R06.5 (YARA-L)** Type discipline: `process.pid` is a string in UDM and is never compared with an integer; `event_timestamp.seconds` is an integer and is only compared with another `.seconds`. Q055's `$payloadpid > 0`: FAIL.
- **R06.6 (KQL)** Every `let` is consumed by a later statement. Every table-valued `let` built for a union appears in that union; the union lists every branch and no branch twice. Count of `let <name> = <Table>` branches equals count of names in `union`. Unused `let` or missing branch: FAIL.
- **R06.7 (KQL)** String literals that contain a backslash use verbatim form `@"..."` with any internal `"` doubled. An ordinary literal containing `\"`, `\t`, `\.` or `\\`: FAIL (Q024, Q028, Q042, Q043).
- **R06.8 (KQL, SD)** The final projection includes `Timestamp`, `ReportId` and `DeviceId` (or the identity entity columns `AccountObjectId`/`AccountUpn` for identity sources), because the custom detection platform requires them. After `summarize`, carry them with `arg_max(Timestamp, ReportId)`.
- **R06.9 (all)** Comments are in the language's comment syntax (`//`). Triple-backtick fences or prose outside a comment: FAIL (Q006).
- **R06.10 (all)** `validation.compile.status` is `not_run` on model emission. The harness sets `pass` or `fail`. `pass` in model output: FAIL (the model cannot have compiled it).

Ground truth: Q006, Q024, Q028, Q042, Q043, Q048, Q055.

## R07 — Naming convention

- **R07.1 (KQL)** `name` matches `^[A-Z][A-Za-z]+_T\d{4}(\.\d{3})?_[A-Za-z]+_[A-Z][A-Za-z0-9]+$`. Tactic in PascalCase from the v19 list (`CredentialAccess`, `Stealth`, `DefenseImpairment`), technique ID of the primary technique, the primary table name, PascalCase descriptor, no spaces.
- **R07.2 (YARA-L)** The rule name in the query and `name` in the contract are identical and match `^[a-z][a-z_]+_t\d{4}(_\d{3})?_udm_[a-z_]+_[a-z0-9_]+$`. Log-source token is the UDM family: `udm_process`, `udm_file`, `udm_network`, `udm_registry`, `udm_cloud_audit`, `udm_user_auth`, `udm_generic`.
- **R07.3 (all)** The technique ID in the name equals `technique_ids[0]`. The tactic in the name equals `tactics[0]`. Mismatch: FAIL.
- **R07.4 (all)** The descriptor names the behaviour, not the campaign alone (`NodeHookSetupThenBunPayload` passes; `ShaiHulud` alone fails).
- **R07.5 (IS)** Descriptor ends with `Sweep` (KQL) or `_sweep` (YARA-L). **(H)** Descriptor ends with `Hunt` or `_hunt`. **(SD)** no suffix.

Ground truth: Q036–Q049 (named by technique ID alone).

## R08 — Metadata completeness

- **R08.1 (all)** Every field in the schema's required list for the declared `detection_type` is present and non-empty. The required list is in `03-schema.md`. Missing or empty: reject `SCHEMA_VALIDATION_FAILED` (self-rejection: the model must not emit a rule that fails its own schema).
- **R08.2 (all)** `rule_id` is a UUID v4 and is carried unchanged across versions (a revision request supplies it; the model must not mint a new one).
- **R08.3 (all)** `created` and `modified` are ISO dates; `version` is semantic (`major.minor.patch`) and increments on every revision.
- **R08.4 (all)** `status` is `draft` on every model emission. Any other value: FAIL.
- **R08.5 (SD)** `schedule` is present. **(H, IS)** `schedule` is `null`.
- **R08.6 (all)** `references[]` has at least one entry, and every `indicators[].reference_id` resolves to one.

Ground truth: all ground-truth rows (bare queries); Q036–Q049 (blank fields).

## R09 — Rejection condition

The model must emit the rejection shape, with no query, when any of the following holds. Reason codes are defined in `03-schema.md`.

- **R09.1** Source not stated or not in schema: `SOURCE_NOT_STATED`, `SOURCE_NOT_IN_SCHEMA`.
- **R09.2** Source not ingested per the environment profile: `SOURCE_NOT_INGESTED`.
- **R09.3** Any referenced field nonexistent or `known_empty` for the event type: `FIELD_NOT_IN_SCHEMA`, `FIELD_NOT_POPULATED`.
- **R09.4** Intent can only be met with a single weak indicator and no correlating anchor: `SINGLE_WEAK_INDICATOR`. Test: the strongest available term is a generic string (`runas`, `$HOME`, `.txt`, `and`), a common binary name, or a substring match, and no second field, second event or ordering can be added from the same source.
- **R09.5** Mapping cannot go beyond tactic level, or cannot reach a sub-technique where one exists: `MAPPING_TOO_COARSE`.
- **R09.6** Precision would depend on hardcoded users, hosts or absolute dates: `HARDCODED_SCOPE_REQUIRED`.
- **R09.7** Indicators are placeholders or lack provenance: `IOC_PLACEHOLDER`, `IOC_NO_PROVENANCE`. Indicators are prose, unescapable or malformed for their type: `INDICATORS_UNUSABLE`.
- **R09.8** A join key needed for correlation is empty on a target OS and no identity re-check is possible: `JOIN_NOT_PORTABLE`.
- **R09.9** Logic cannot be brought under the complexity ceiling and cannot be split: `COMPLEXITY_EXCEEDED`.
- **R09.10** Requested type is `scheduled_detection` but the logic cannot meet R10/R13 bounds: `TYPE_MISMATCH` with `nearest_viable_alternative: hunt`.
- **R09.11** Requested syntax is not yara_l or kql: `SYNTAX_UNSUPPORTED`.
- **R09.12** Tactic is Reconnaissance or Resource Development: `TACTIC_OUT_OF_SCOPE`.
- **R09.13** The draft fails any gate in `04-checklist.md` and cannot be repaired: `SCHEMA_VALIDATION_FAILED`, with the failed gate IDs in `blocking_criteria`.

A rejection is a successful output. A best-effort rule in any of these conditions is a failure.

Ground truth: Q020 (R09.1), Q052–Q055 in tenant (R09.2), Q038, Q039, Q049 (R09.3), Q040, Q044 (R09.4, R09.5), Q014–Q019, Q035 (R09.6), Q034, Q037 (R09.7), Q054 rev 2 (R09.8), Q007, Q034 (R09.9), Q008 (R09.10).

## R10 — False-positive rate ceiling

- **R10.1 (SD)** `tuning_notes.baseline.alerts_per_day_after_aggregation` ≤ 5 across the monitored estate, measured over `window_days` ≥ 7, before `status: production`. Not measured: cap at `test`. Measured above 5: cap at `test` and `first_parameter_to_adjust` must name the fix.
- **R10.2 (SD)** Entity aggregation is present: YARA-L `match:` on a device or account placeholder; KQL `summarize ... by` a device or account key with a time bin, or the custom-detection platform's per-entity grouping stated in `schedule.grouping`. A rule that alerts per raw event (`summarize by` 20 columns, `triggerThreshold 0`): FAIL.
- **R10.3 (SD)** `baseline.measurement_procedure` is the exact query or steps to count alerts per day after aggregation over 7 days. Absent: FAIL.
- **R10.4 (H, IS)** Exempt from the ceiling. `baseline.before_tuning` or `after_tuning` is stated where known (Q025: 912 to 1), otherwise the procedure is stated.
- **R10.5 (SD)** A two-day estate baseline (Q053) is recorded as `window_days: 2` and does not satisfy R10.1.

Ground truth: Q008 (18,355/30d), Q044 (every event), Q053 (0 FP over 2 days).

## R11 — ATT&CK version and scope

- **R11.1 (all)** `attack.attack_version` equals the pinned version in the request (`19.2`). Any other value: FAIL.
- **R11.2 (all)** Tactic names come from the v19 enumeration: `initial_access`, `execution`, `persistence`, `privilege_escalation`, `stealth`, `defense_impairment`, `credential_access`, `discovery`, `lateral_movement`, `collection`, `command_and_control`, `exfiltration`, `impact`. `defense_evasion`: FAIL.
- **R11.3 (all)** `reconnaissance` and `resource_development`: reject `TACTIC_OUT_OF_SCOPE`.
- **R11.4 (all)** `attack.bundle_ref` records the bundle the technique records came from. The model takes tactic membership from the bundle, not from memory. Where the bundle is absent, the model records `bundle_ref: null`, uses the v19 names above, and caps at `draft`.
- **R11.5 (all)** Deprecated or revoked techniques per the bundle: FAIL, with the replacement ID in `mapping_rationale`.

Ground truth: Q012, Q018 (wrong tactic), Q036–Q049 (pre-v19 labels).

## R12 — Query complexity ceiling

- **R12.1 (all)** `complexity.lines` ≤ 150 (counting non-blank lines of the query). Over: split or reject `COMPLEXITY_EXCEEDED`.
- **R12.2 (KQL)** `complexity.joins` ≤ 5. **(YARA-L)** event variables ≤ 4 (each additional event variable is a join).
- **R12.3 (KQL)** `complexity.union_branches` ≤ 6.
- **R12.4 (KQL)** `complexity.nesting_depth` ≤ 2: a `let` that feeds a join may itself contain at most one further `let` or subquery.
- **R12.5 (all)** Every expression that mixes `and` and `or` at the same level is fully parenthesised so that no sub-expression relies on operator precedence. Test: for every `or`, both operands are either atomic or parenthesised; for every `and` whose sibling is an `or`, it is parenthesised. Q025, Q035: FAIL.
- **R12.6 (all)** Inline indicator lists ≤ 50 values per list; larger lists go to a reference list (YARA-L) or `externaldata`/watchlist (KQL) declared under dependencies.
- **R12.7 (all)** Where splitting is required, `tuning_notes.split_from` names the sibling `rule_id`s and the composition (sequential, independent, correlation-consumer).

Ground truth: Q007 (23k chars), Q034 (23 joins), Q054 (250 lines).

## R13 — Detection type declared

- **R13.1 (all)** `detection_type` ∈ {scheduled_detection, hunt, ioc_sweep}. Absent: reject `SCHEMA_VALIDATION_FAILED`.
- **R13.2 (SD)** Lookback is relative and matched to schedule. YARA-L: `lookback` equals the `match` window and is ≤ 48h; `schedule.mode: live`. KQL: `schedule.frequency` ∈ {1h, 3h, 12h, 24h}; `lookback` ≥ frequency and ≤ the platform-checked window for that frequency (1h→4h, 3h→12h, 12h→48h, 24h→30d); the query bounds `Timestamp` with `ago(lookback)` explicitly.
- **R13.3 (SD)** No `index=*`, no `_raw`-only matching, no absolute dates, no `datetime(...)` literals.
- **R13.4 (SD)** The logic has an anchor: a campaign-specific or behaviour-specific condition that is sufficient on its own, or an ordered correlation of two or more events. A rule whose every condition is a weak signal: `TYPE_MISMATCH`, alternative `hunt`.
- **R13.5 (H)** `lookback` ≤ 90d. Scoring, weak-signal correlation and analyst-triage output are permitted. The contract field `detection_type: hunt` and the rule name suffix `Hunt`/`_hunt` make it impossible to deploy as a detection by accident; a harness that schedules a `hunt` as an alerting rule is in breach.
- **R13.6 (IS)** `lookback` ≤ 90d, every match term is a typed indicator from `indicators[]`, no behavioural logic beyond field binding and entity aggregation.
- **R13.7 (all)** The model never changes the requested type silently. If the request asks for SD and the logic only reaches H, the output is a rejection with `nearest_viable_alternative`, not a hunt labelled as a detection and not a detection with hunt logic.

Ground truth: Q008, Q020, Q021, Q030, Q044.

## R14 — Logic integrity

- **R14.1 (all)** Every defined variable is consumed: KQL `let`, YARA-L event and placeholder variables, SPL `eval` fields (reference only). Unused: FAIL (Q005, Q007, Q018).
- **R14.2 (all)** Every numeric literal in a comment adjacent to a comparison agrees with the operator and value in the code. "more than 5" with `< 5`: FAIL (Q035). This also covers `tuning_notes` and `false_positives` text: a stated threshold must equal the coded one (Q025).
- **R14.3 (all)** Time ranges are ordered older-to-newer: KQL `between (ago(20d) .. ago(10d))`, never the reverse (Q022). YARA-L `$older.metadata.event_timestamp.seconds <= $newer.metadata.event_timestamp.seconds` with the anchor on the left.
- **R14.4 (all)** Timestamps projected in output come from the detecting event. KQL: after `summarize`, `Timestamp` must be an explicit aggregate (`min`, `max`, `arg_max`) of the event table, never a column surviving from an enrichment join (Q018). YARA-L: `min($anchor.metadata.event_timestamp.seconds)`, never an entity-graph timestamp.
- **R14.5 (all)** No two conditions on one event variable are mutually exclusive. Test: for each event variable, the set of `metadata.event_type` or `ActionType` values it is constrained to must carry every field it is tested on (Q048).
- **R14.6 (all)** No dead branch: every `or` branch can be true for at least one real event of the declared type (Q022 body strings in URL fields; Q023 script hashes on process table; Q034 PE version fields for scripts).
- **R14.7 (all)** Windowing claimed in the description is implemented in the code. "12-hour sessions" requires `bin(_time, 12h)` or a `match` window (Q004, Q006).
- **R14.8 (all)** Substring operators are not used where token or anchored matching is required. KQL `contains "runas"` for a binary name: FAIL; `=~`, `has`, `in~` or an anchored regex passes. YARA-L unanchored `re.regex(x, "runas")` for an image name: FAIL.
- **R14.9 (all)** Regex literals escape metacharacters that are meant literally: `.` in extensions, `\` in Windows paths, `(` `)` in `(x86)`. Test: every regex has at least one `must_match` sample in `regexes[]` that is a realistic value, and no `must_not_match` sample that matches.
- **R14.10 (YARA-L, two or more events)** The join is on a key that is populated on every target OS (`principal.asset_id`, `principal.hostname`). A PID-based join on MDE-sourced events with macOS in `target_os` requires an identity re-check on the evidence event's `principal.process` (image path and command line), and `correlation.join_keys[].holds_on` lists every OS with the mitigation. `principal.process.parent_process.pid` as a join key for MDE: FAIL (`known_empty`). This is the second explicit gate.
- **R14.11 (all)** Mixed `and`/`or` fully parenthesised (shared with R12.5).

Ground truth: Q004–Q007, Q018, Q022, Q023, Q025, Q031–Q035, Q048, Q054 rev 2, Q055.

## R15 — Entity output

- **R15.1 (all)** The output projects: first timestamp, last timestamp, device, account, process, parent command line (endpoint sources), and the matched evidence value. Each is mapped in `entity_output` to the exact output column (KQL) or outcome variable (YARA-L).
- **R15.2 (SD)** `stats BY _raw`, `summarize by` with more than 8 keys, bare `count()`, or no aggregation: FAIL.
- **R15.3 (all)** Where the source does not carry a parent command line (`DeviceEvents`, `DeviceNetworkEvents`, `DeviceFileEvents` carry the initiating process's command line but not its parent's), `entity_output.parent_command_line` is `null` and `tuning_notes.known_limitations[]` says so; the parent image name is projected instead.
- **R15.4 (IS)** Output additionally projects `MatchedIndicator`, `MatchedField` and `SourceTable` (KQL) or `$matched_indicator`, `$matched_field`, `$event_types` (YARA-L). `dcount(DeviceName) by hash` with no device names: FAIL (Q031–Q034).
- **R15.5 (YARA-L)** `outcome` variables use `array_distinct` for multi-valued evidence and `count_distinct($e.metadata.id)` for event counts. `$risk_score` is set for SD.
- **R15.6 (H)** Scored hunts project the score, the signal set and the reason (Q007's `AlertReason` pattern).

Ground truth: Q002, Q009, Q020, Q021, Q031–Q034, Q044, Q036–Q049 (no outcome).

## R16 — Indicator provenance

- **R16.1 (all)** Every hardcoded indicator value in the query (hash, IP, domain, URL, path, filename, user agent, command-line literal taken from intel) has an entry in `indicators[]` with `type`, `value`, `reference_id`, `first_reported`.
- **R16.2 (all)** Every `reference_id` resolves to `references[]` with a locator (URL, report ID, ticket, workbook row).
- **R16.3 (all)** Placeholder detection: values matching `evil`, `malware`, `example.com`, `test.exe`, `1.2.3.4`, `0.0.0.0`, `127.0.0.1`, `attacker`, `badguy`, `foo`, `bar`, or any hash that is not the right length and hex: reject `IOC_PLACEHOLDER`.
- **R16.4 (all)** Format validation per type: `sha256` is 64 lowercase hex; `sha1` 40; `md5` 32; `ipv4` dotted quad with no port and not RFC 1918, loopback or link-local unless the reference says it is an internal back-office indicator; `ipv6` parses; `domain` has no scheme or path; `url` has a scheme; `filename` has no directory; `path` is anchored. Malformed: reject `INDICATORS_UNUSABLE` (Q033 port suffixes).
- **R16.5 (all)** Indicator values are normalised: hashes lowercased, domains lowercased, duplicates removed. Duplicates in the list: FAIL.
- **R16.6 (all)** Indicators derived from ATT&CK technique descriptions, citations or example text are not indicators. Any match term that is a sentence fragment, contains `(Citation:`, or is a stop-word: reject `INDICATORS_UNUSABLE` (Q037, Q046).
- **R16.7 (IS)** The sweep's `indicators[]` is the complete list used; the query contains no indicator that is not in the list and vice versa.

Ground truth: Q020 (no citation), Q031–Q034 (no provenance, placeholder, malformed), Q037, Q045, Q046 (prose and lifted values).

## R17 — Suppression fails closed

- **R17.1 (all)** Every suppression that depends on enrichment (identity, asset, department, HR, CMDB) is listed in `tuning_notes.suppressions[]` with `depends_on_enrichment: true` and `fails_closed_how`.
- **R17.2 (KQL)** The enrichment lookup's time window is ≥ the detection lookback. `IdentityInfo | where Timestamp > ago(10d)` against `lookback = 30d`: FAIL (Q023, Q030).
- **R17.3 (KQL)** The idiom `where isempty(<enrichment>) or <enrichment> != <value>` is forbidden. Required pattern: `extend EnrichmentPresent = isnotempty(<enrichment>)`, `extend SuppressionApplied = EnrichmentPresent and <condition>`, `where not(SuppressionApplied)`, and `EnrichmentPresent` projected in the output. Rows with missing enrichment are kept and visibly marked; they are never silently suppressed and never silently passed as if checked.
- **R17.4 (KQL)** Run-level health: `extend EnrichmentRows = toscalar(<lookup> | count)` and `EnrichmentRows` projected, so that an empty enrichment set is visible in every alert from that run.
- **R17.5 (SPL reference)** A role or population filter inside the subsearch of a left join does not suppress results (Q011) and a `search field=*` after a left join silently drops unenriched rows (Q006). Both are FAIL patterns the KQL and YARA-L outputs must not reproduce.
- **R17.6 (YARA-L)** Suppressions use reference lists or literal conditions, which fail closed by construction (a missing list is a compile error). Entity-graph enrichment (`graph.entity.*`) used for suppression requires the same `EnrichmentPresent` outcome variable projected.

Ground truth: Q006, Q010, Q011, Q022, Q023, Q030.

## R18 — Hardcoded scope

- **R18.1 (SD)** No user ID, user name, UPN, email, hostname, device ID or absolute date appears in the query. Test: any literal matching a UPN or email pattern, a `[USER_*]` or `[SOC_*]` token, a `datetime(` literal, or a value in the request's `known_entities` list: reject `HARDCODED_SCOPE_REQUIRED`.
- **R18.2 (SD)** Role-, department- or team-based filters are permitted only as declared dependencies (a reference list or watchlist named in `tuning_notes.dependencies`), never as inline string lists (Q010 job titles).
- **R18.3 (H, IS)** Entity scoping is permitted only when the request is explicitly a validation search, in which case `detection_type` is still `hunt` and `name` descriptor ends with `ValidationHunt`. The default is the same prohibition as SD.
- **R18.4 (all)** Absolute dates are never used for windowing. Relative `ago()` or a `match` window only. An `ioc_sweep` for a bounded incident window uses `lookback` and records the incident dates in `references`, not in the query.
- **R18.5 (all)** `[SOC_DEPARTMENT]`-style suppressions are declared dependencies and subject to R17.

Ground truth: Q014–Q019, Q035, Q022–Q030 (`[SOC_DEPARTMENT]`).

## Type bounds at a glance

| Bound | scheduled_detection | hunt | ioc_sweep |
|---|---|---|---|
| Lookback | = schedule-matched; YARA-L ≤ 48h | ≤ 90d | ≤ 90d |
| Schedule | required | null | null |
| FP ceiling | ≤ 5 alerts/day after aggregation, 7-day baseline | exempt; baseline stated | exempt; baseline stated |
| Anchor | required (specific condition or ordered correlation) | not required; scoring allowed | indicators are the anchor |
| Entity aggregation | required | required | required, plus matched indicator and source |
| Suppression | at least one or justified | triage allowed | triage allowed |
| Hardcoded entities | reject | reject unless ValidationHunt | reject |
| Indicators | provenance for any hardcoded value | same | complete typed list, provenance for all |
| Status on emission | draft | draft | draft |

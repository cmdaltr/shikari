# Shikari output contract — rationale

Why each schema field and each checklist stage exists, with the workbook row that motivated it. Written so the framework can be defended and maintained without its author.

## Design decisions

**The model always emits `draft`.** The three gates the brief asked for (source ingested, join holds on every OS, positive control fired) split into two kinds. Ingestion and join portability can be decided at generation time from the environment profile and the known-hazard table, so they are emission gates with rejection codes. A positive control cannot be run by the model, so it is a promotion gate: the schema has a `validation` block whose states the harness or a human advances, and `status` cannot leave `draft` until they are. The alternative, letting the model write `status: production` or `positive_control: passed`, recreates the exact failure the workbook documents: Q050, Q051 and Q055 carry High labels for logic that has never been seen to fire.

**YAML with a literal block scalar for the query.** Escaping is the dominant syntax failure in Shikari output (Q042, Q043, Q048, and the Q024/Q028 KQL literals). A JSON contract would require every regex backslash doubled and every quote escaped inside the query string, which multiplies that failure. A block scalar carries the query verbatim. The YAML risks (flow-style strings with embedded newlines, type coercion of `19.2` or `1.0`, anchors) are closed by lexical rules L1 to L10 and checked by the validator.

**Fixed key order, query last.** Metadata before logic forces the model to decide source, fields, type, mapping and FP handling before it writes a single condition. The workbook's Shikari rows show the reverse: a template with a query slot and a wrapper filled in afterwards with defaults (`severity = "MEDIUM"` in every YARA-L rule; Q041 computed HIGH and emitted MEDIUM).

**Mechanical validation, not instruction.** A Sonnet-class model will drift under prompt pressure. Everything that can be counted is counted by `validate.py`: key order, line count, event-variable count, union branches, `let` consumption, regex declaration and samples, indicator format, suppression markers, naming, lookback against schedule. The model is told the gates so it can pre-empt them; the harness enforces them.

**Rejection is a successful output.** The rubric's R09 and the `rejection` shape exist because the alternative is Q036 to Q049: 659 files, every one emitted, none fit to deploy. A rejection with a reason code, evidence, remediation and a nearest viable alternative is more useful than any of them.

## Schema fields

| Field | Why it exists | Motivating rows |
|---|---|---|
| `contract_version`, `kind`, `request_ref` | Versioned contract; one of two shapes; traceability to the request that supplied the technique records, profile and indicators | — |
| `rule_id` | Stable identity across revisions so baselines, suppressions and positive-control evidence attach to the same rule; a model that mints a new UUID on every revision orphans the evidence | Q010/Q016 (two revisions with no link), Q054 revisions 1 to 3 |
| `name` | The convention encodes tactic, technique, source and behaviour; a name is the first thing a reviewer reads and the Shikari rows were named by technique ID alone | Q036–Q049 |
| `author`, `created`, `modified`, `version` | Change control; `version` increments on every revision so a baseline measured against 1.0.0 is not quoted for 1.2.0 | Q054 (rev 2 PID join, rev 3 without) |
| `status` | Carries the promotion state; the model may only write `draft` | Q050, Q051, Q055 (High without a fired control) |
| `detection_type` | Hunt logic scheduled as a detection alerts on every event; sweeps need indicators; each type has different bounds. The suffix in the name makes the type visible in the SIEM too | Q008, Q020, Q021, Q030, Q044 |
| `siem` | SPL is reference only; Sigma and EQL are out of scope; the validator's lint is per syntax | Q045–Q047 |
| `target_os` | Joins and fields behave differently per OS; the macOS parent-PID finding is only expressible if the rule says which OS it targets | Q054 |
| `log_sources[].siem_source`, `product`, `udm_log_type` | Exact source, not a wildcard; `index=*` and `*_proxy` cannot be validated | Q002, Q020 |
| `log_sources[].ingestion` | The first explicit gate; a rule on an un-ingested source is unfireable regardless of logic | Q052–Q055 |
| `log_sources[].fields[].population` | Three states instead of a boolean: `known_empty` rejects, `unknown` caps, `known_populated` passes. Fields that exist in the schema but cannot carry the value are the largest single failure class in Shikari output | Q022, Q023, Q034, Q038, Q039, Q045–Q049, Q048 |
| `log_sources[].coverage_gaps` | Known holes travel with the rule so an analyst does not re-discover them | Q050–Q052, Q055 |
| `attack.attack_version`, `bundle_ref` | Pinned version; tactic membership from the bundle, not from memory, because the model cannot be trusted to know the v19 split | Q012, Q018 (wrong tactic), Q036–Q049 (pre-v19 labels) |
| `attack.tactics`, `technique_ids` | Sub-technique required; multi-technique allowed; first entries feed the name | Q008, Q010, Q040, Q044 |
| `attack.mapping_rationale` | Forces the mapping to name the field and value that evidences the technique, which is how T1611 for `docker run kali` gets caught | Q012 |
| `lookback`, `schedule` | Relative windows matched to the schedule; absolute dates and hunt-length lookbacks on a detection are the R13 failures | Q035, Q008 |
| `confidence`, `severity` | Two fields, two rationales, each citing a condition in the query; a template default is detectable because its rationale could attach to any rule | Q036–Q049, Q041, Q053 ("should be tiered above Q3") |
| `false_positives[]` | A named scenario with a field-level discriminator and a handling mode; generic statements fail. `structural` exists because the best FP handling is an anchor that excludes the scenario without a suppression clause | Q002, Q005, Q051/Q052 |
| `tuning_notes.baseline` | Numbers may be null on first emission; the procedure may not. A 2-day baseline is recorded as 2, not rounded up to the 7 the ceiling needs | Q053, Q025, Q026 |
| `tuning_notes.suppressions[]` with `// S<n>:` markers | Every suppression in the query is tied to a reason and a fail-closed statement; a suppression with no entry, or an entry with no clause, is detectable mechanically | Q007 (inline reasons, the model), Q005 (identified FP never suppressed), Q010 (unused suppression) |
| `tuning_notes.dependencies[]` | Macros, lookups, functions and lists are environment-specific; undeclared ones make the rule un-reviewable | Q001, Q011, Q013 (`mde_clean`) |
| `tuning_notes.first_parameter_to_adjust` | The on-call engineer needs one knob, not a design document | Q007 |
| `tuning_notes.known_limitations`, `split_from` | Coverage gaps and decomposition are recorded, so a split rule can be reassembled and a known miss is not re-reported as a bug | Q052 (hook path required), Q054 (split) |
| `references[]`, `indicators[]`, `reference_lists[]` | Provenance for every hardcoded value; typed indicators so format can be checked; reference lists declared so a `%list` resolves and allow-lists are explicit | Q020, Q031–Q034, Q033 (malformed), Q037/Q046 (prose) |
| `entity_output` | Maps the rubric's required projections to actual column or outcome names, so "entity output present" is checkable rather than asserted | Q021 (`stats BY _raw`), Q031–Q034 (`dcount` only), Q044 (20-column `summarize by`) |
| `correlation` | Events, roles, join keys per OS with mitigation, ordering and window. This is where the macOS PID finding lives and where the second explicit gate is checked | Q054 rev 2, Q053 |
| `regexes[]` with samples | Validity is not evidence that a regex fires in the target engine; a must-match set that the harness runs in that engine is. Also catches unescaped dots and paths | Q052, Q036, Q041, Q048 |
| `complexity` | Self-reported and recounted; over-ceiling rules are split, not trimmed | Q007, Q034, Q054 |
| `validation` | The promotion ledger: compile, field existence, field population, ingestion, join portability, regex checks, positive control, and the basis of the fidelity claim | Q050–Q055 Notes |
| `query` last | Metadata before logic; block scalar; verbatim | Q042, Q043 |
| `rejection.*` | Reason code for routing, evidence for audit, remediation and nearest viable alternative so the rejection moves the work forward | Q038, Q039, Q040, Q049, Q052–Q055 |

## Checklist stages

| Stage | Why it is where it is |
|---|---|
| 0 Request | Syntax, type, tactic scope and sub-technique can be decided before any logic exists; failing them early costs nothing. |
| 1 Source and ingestion | Nothing downstream matters if the source is wrong or absent. Ingestion is checked here, before fields, because a rule can be field-perfect and still never fire (Q052–Q055). |
| 2 Fields | Existence, then population. The three-state population model is here because "field exists" was true for every Low row in Q038–Q049 and still wrong. |
| 3 Indicators | Provenance, placeholders, format, prose. Sweeps are only as good as their list; Q033's port suffixes and Q034's `evil.bat` would have passed any logic check. |
| 4 Anchor and type | The single-weak-indicator test and the hardcoded-scope test decide whether a detection is possible at all. Deciding this before writing correlation logic prevents a hunt being dressed as a detection (Q008, Q044) or a validation search leaking into production (Q014–Q019). |
| 5 Logic integrity | The mechanical lints: consumed variables, complete unions, ordered ranges, parenthesised and/or, comment-threshold agreement, no contradictory conditions, event-side timestamps, implemented windows, no substring operators, type discipline. Each maps to a named row (Q007, Q018, Q022, Q025, Q031–Q035, Q048, Q055). |
| 6 Correlation and joins | The second explicit gate. Also the enrichment rules, because enrichment-driven suppression is the most common silent failure (Q006, Q010, Q011, Q022, Q023, Q030) and the fix is a projected `SuppressionApplied`, not a comment. |
| 7 Regex and escaping | Separate from logic because the failure is engine-specific and invisible to review (Q052). Sample sets are the only evidence the contract accepts. |
| 8 Entity output | Checked after logic so the projections reflect the final shape; `ReportId`/`DeviceId` for KQL custom detections is a platform requirement that review does not catch. |
| 9 Metadata and bounds | Name, ratings, FP, suppressions, baseline, schedule and version are checked once the logic is settled, because several of them (suppression markers, FP discriminators, lookback) reference it. |
| 10 Complexity | Last among the content gates because splitting is the remedy and splitting changes everything above. |
| 11 Positive control and status | The third explicit gate, framed as a promotion gate: the model writes the procedure, the harness records the result. |
| 12 Emit | The lexical and validator pass. A draft that fails here is repaired or becomes a `SCHEMA_VALIDATION_FAILED` rejection; it is never emitted as a rule. |

## What the framework does not do

- It does not verify ATT&CK v19.2 tactic membership itself. That comes from the pinned STIX bundle supplied in the request (`technique_records`), which MITRESaw can produce. Where the bundle is absent the model records `bundle_ref: null` and the rule stays `draft`.
- It does not run regex samples in RE2 or in Defender. `validate.py` runs them with Python's `re` as a first filter; the harness must repeat them in the target engine before `regex_checks.status: pass`.
- It does not compile YARA-L or parse KQL. `compile.status` is a harness field. The YARA-L outcome arithmetic in EX-04 (sum of `if()` terms inside `max()`) is derived from the UDM outcome syntax and is flagged in its positive-control procedure as needing a compile check.
- It does not measure baselines. `tuning_notes.baseline.measurement_procedure` is the query the harness runs; the numbers come back through `prior_validation` on revision.

## Maintaining the framework

- A new failure pattern becomes a rubric test (R-number), a checklist gate (G-number), a validator rule (gate ID string), and, where possible, a mutation case in the harness's test set. All four should land together.
- A new SIEM syntax requires: a `siem` enum value, a naming pattern, a lint function in `validate.py`, a `literal_encoding` value for regexes, and at least two exemplars (one emitted, one rejection).
- A new ATT&CK version changes `attack_version` (schema const), the tactic enumeration if tactics changed, and the bundle reference in every request. Exemplars are regenerated, not edited.
- Promotion thresholds (5 alerts per day, 7-day baseline, 48-hour match window, 150 lines, 5 joins, 6 branches) are schema maxima and validator constants; change them in both places and record the change in `contract_version`.

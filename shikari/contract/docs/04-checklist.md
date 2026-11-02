# Shikari pre-output self-verification checklist

Run against the draft, in order, before emitting anything. Every gate is a yes/no question. The action on "no" is fixed: **repair** (fix the draft and re-run from gate 1), **reject** (emit the rejection shape with the named reason code and stop), or **cap** (emit, but record the named validation state; `status` stays `draft`). The gate IDs are referenced by `validate.py` and by `blocking_criteria` in rejections.

The model emits `status: draft` always. Gates marked **harness** are re-run mechanically by `validate.py` or by the Shikari harness after emission; the model still answers them, because a draft that fails them is wasted.

## Stage 0 — request

- **G0.1** Is the requested syntax `yara_l` or `kql`? No: reject `SYNTAX_UNSUPPORTED`.
- **G0.2** Is the requested `detection_type` one of `scheduled_detection`, `hunt`, `ioc_sweep`? No: reject `SCHEMA_VALIDATION_FAILED` (R13.1).
- **G0.3** Is every requested tactic outside Reconnaissance and Resource Development? No: reject `TACTIC_OUT_OF_SCOPE` (R11.3).
- **G0.4** Does the request supply at least one technique ID, and is it a sub-technique wherever the bundle record says the parent has sub-techniques? No, and the intent does not say which sub-technique is observed: reject `MAPPING_TOO_COARSE` (R01.1, R01.2).

## Stage 1 — source and ingestion

- **G1.1** Is every log source named exactly (UDM event type plus log type, or the Advanced Hunting table)? No: reject `SOURCE_NOT_STATED` (R02.1).
- **G1.2** Is every source in the schema catalogue? No, and the request does not declare it as a tenant function: reject `SOURCE_NOT_IN_SCHEMA` (R02.2).
- **G1.3** Is the declared source listed as ingested for the target estate in `environment_profile`? No: reject `SOURCE_NOT_INGESTED` with the profile evidence (R02.8). Profile absent: cap `ingestion.status: unverified`. **This is the first explicit gate.**
- **G1.4** Does the source emit the event on every OS in `target_os`? No: record the gap in `coverage_gaps` and remove the OS from `target_os`, or keep the OS and record the gap if the rule is still useful on the others (R02.9).

## Stage 2 — fields

- **G2.1** Does every field path in the draft exist in the schema for that exact source (not a sibling table)? No: reject `FIELD_NOT_IN_SCHEMA` (R02.3).
- **G2.2** Can the field actually carry the value being matched on this event type? Answer no for: API names in command lines; cloud control-plane operations in endpoint fields; a script's hash on a process-launch table; `network.application_protocol` on PROCESS_LAUNCH; `VersionInfo*` for non-PE files; HTTP body strings in URL fields; `principal.process.parent_process.pid` on MDE-sourced UDM. No: reject `FIELD_NOT_POPULATED` (R02.4, R14.5, R14.6).
- **G2.3** Is population confirmed by the catalogue or a tenant sample? Unknown: cap `field_population.status: unknown` and write the sample query into `evidence`.
- **G2.4** Does any logical value coalesce more than two candidate fields? Yes: repair (R02.5).
- **G2.5** Is every reference list, macro, function, lookup, watchlist or `externaldata` source declared with a definition reference? No: repair (R02.6, R02.7, R05.3).

## Stage 3 — indicators

- **G3.1** Is every hardcoded indicator in the draft present in `indicators[]` with a `reference_id` that resolves? No: reject `IOC_NO_PROVENANCE` (R16.1, R16.2).
- **G3.2** Is any indicator a placeholder (`evil.bat`, `example.com`, `1.2.3.4`, `attacker`, a hash of the wrong length)? Yes: reject `IOC_PLACEHOLDER` (R16.3).
- **G3.3** Is every indicator well-formed for its type (hash length and hex, no port on an IP, no scheme on a domain, no directory on a filename) and normalised to lowercase with no duplicates? No: repair, or reject `INDICATORS_UNUSABLE` if the source list cannot be cleaned (R16.4, R16.5).
- **G3.4** Is any match term a sentence fragment, a citation, a stop-word, or text lifted from an ATT&CK description? Yes: drop it; if nothing specific remains, reject `INDICATORS_UNUSABLE` (R16.6).
- **G3.5** For `ioc_sweep`: does the query contain exactly the indicators in `indicators[]`, no more and no fewer? No: repair (R16.7).

## Stage 4 — anchor and type

- **G4.1** For `scheduled_detection`: is there an anchor, meaning a campaign- or behaviour-specific condition sufficient on its own, or an ordered correlation of two or more events? No: reject `TYPE_MISMATCH` with `nearest_viable_alternative: hunt`, or `SINGLE_WEAK_INDICATOR` if no hunt would be useful either (R13.4, R09.4).
- **G4.2** Is the strongest term more specific than a generic string (`runas`, `$HOME`, `.txt`, `and`), a common binary name, or a substring? No: reject `SINGLE_WEAK_INDICATOR` (R09.4, R14.8).
- **G4.3** Does the query contain any user ID, UPN, email, hostname, device ID, `[USER_*]`/`[SOC_*]` token or absolute date? Yes: reject `HARDCODED_SCOPE_REQUIRED` unless the request is an explicit validation hunt (R18).
- **G4.4** Is every role, team or department filter a declared dependency rather than an inline string list? No: repair (R18.2).
- **G4.5** Does the requested type match what the logic can deliver, without silently changing it? No: reject `TYPE_MISMATCH` (R13.7).

## Stage 5 — logic integrity (**harness**)

- **G5.1** Is every defined variable consumed: every KQL `let`, every YARA-L event and placeholder variable, every `extend`ed flag? No: repair (R14.1).
- **G5.2** Does the `union` list every table-valued `let` exactly once, and does the branch count equal `complexity.union_branches`? No: repair (R06.6).
- **G5.3** Is every time range ordered older-to-newer (`between (ago(20d) .. ago(10d))`; `$older.seconds <= $newer.seconds`)? No: repair (R14.3).
- **G5.4** Does every expression that mixes `and` and `or` at one level carry full parentheses? No: repair (R12.5, R14.11).
- **G5.5** Does every numeric literal in a comment, in `false_positives` and in `tuning_notes` agree with the operator and value in the code ("more than 5" is `> 5`, never `< 5`)? No: repair (R14.2).
- **G5.6** Are two conditions on the same event variable ever mutually exclusive, or is any `or` branch impossible for a real event of that type? Yes: repair or reject `FIELD_NOT_POPULATED` (R14.5, R14.6).
- **G5.7** Does every timestamp in the output come from the detecting event (`min`/`max`/`arg_max` of the event table), never from an enrichment join? No: repair (R14.4).
- **G5.8** Is every window the description promises ("12-hour sessions", "within 30 minutes") implemented as a `match` window, `bin()`, or a bounded join? No: repair (R14.7).
- **G5.9** Is every substring operator (`contains`, unanchored `re.regex` on an image name) replaced by a token, equality or anchored match? No: repair (R14.8).
- **G5.10** YARA-L: is `process.pid` only ever compared with another string, and `event_timestamp.seconds` only with another `.seconds`? No: repair (R06.5).

## Stage 6 — correlation and joins

- **G6.1** For every join key, does the key hold on every OS in `target_os`? A PID join on MDE-sourced events with macOS in scope: no. No: add an identity re-check on the evidence event's `principal.process` image and command line and record it in `correlation.join_keys[].mitigation`; if no re-check is possible, reject `JOIN_NOT_PORTABLE` (R14.10). **This is the second explicit gate.**
- **G6.2** Does the draft use `principal.process.parent_process.pid` as a join key for MDE-sourced UDM? Yes: repair; it is empty on every event (R02.4).
- **G6.3** Does the enrichment lookup's time window cover the whole detection lookback? No: repair (R17.2).
- **G6.4** Does any enrichment-dependent suppression use `isempty(x) or x != y`, or filter inside a left-join subsearch, or `search field=*` after a left join? Yes: repair with `EnrichmentPresent` and `SuppressionApplied` projected (R17.3, R17.5).
- **G6.5** Is `EnrichmentRows` (run-level health) projected wherever enrichment drives suppression? No: repair (R17.4).

## Stage 7 — regex and escaping (**harness**)

- **G7.1** Is every regex literal in the query listed in `regexes[]` with at least one realistic `must_match` and one `must_not_match` sample? No: repair (R14.9).
- **G7.2** Does every `must_match` sample match and every `must_not_match` sample fail under RE2 semantics? No: repair (R14.9).
- **G7.3** Are literal dots, backslashes and parentheses escaped (`\.doc`, `C:\\Windows`, `\(x86\)`)? No: repair (R14.9).
- **G7.4** KQL: is every string containing a backslash a verbatim literal `@"..."` with internal `"` doubled? No: repair (R06.7).
- **G7.5** YARA-L: is every regex backtick-delimited with no backtick inside, and does `nocase` follow the closing parenthesis? No: repair (R06.4).
- **G7.6** Is `regex_checks.status` `not_run`? It must be; the model cannot have run them in the target engine. The Q052 finding (valid RE2 evaluated false in Defender) is why a sample set, not validity, is the evidence.

## Stage 8 — entity output and aggregation

- **G8.1** Does the output project first and last timestamp, device, account, process, parent command line (or `null` with a stated limitation), and the matched evidence value, each mapped in `entity_output`? No: repair (R15.1, R15.3).
- **G8.2** For `scheduled_detection`: is there entity aggregation (`match:` on a device or account placeholder; `summarize ... by` ≤ 8 keys), and is `$risk_score` set (YARA-L)? `summarize by` 20 columns, `stats BY _raw`, bare counts: no. No: repair (R10.2, R15.2, R15.5).
- **G8.3** For `ioc_sweep`: are the matched indicator, matched field and source table projected, with device names (not just `dcount`)? No: repair (R15.4).
- **G8.4** KQL `scheduled_detection`: does the final statement carry `Timestamp`, `ReportId` and `DeviceId`? No: repair (R06.8).

## Stage 9 — metadata and bounds

- **G9.1** Is `name` in the convention, with the tactic and technique equal to `tactics[0]` and `technique_ids[0]`, the log-source token a declared source, and the `Hunt`/`Sweep` suffix where required? No: repair (R07).
- **G9.2** Are `confidence` and `severity` separate, each with a rationale that cites a condition in this query, neither a template default? No: repair (R04).
- **G9.3** Does `false_positives[]` name at least one specific scenario with a field-level distinguishing pattern and a handling mode? "May be benign" or "legitimate admin activity": no. No: repair (R03).
- **G9.4** Is every suppression in the query preceded by a `// S<n>:` marker that appears as `logic_ref` in `tuning_notes.suppressions[]` with a reason and a `fails_closed_how`? No: repair (R05.2).
- **G9.5** Does `tuning_notes.baseline` state the window and a measurement procedure, with numbers where the request supplied them and `null` otherwise? No: repair (R05.1).
- **G9.6** Is `first_parameter_to_adjust` one concrete knob with a direction? No: repair (R05.4).
- **G9.7** `scheduled_detection`: is `lookback` relative and matched to `schedule` (YARA-L: equals the match window, ≤ 48h, `mode: live`; KQL: frequency ∈ {1h, 3h, 12h, 24h}, lookback between the frequency and the platform window, `ago(lookback)` in the query)? No: repair (R13.2).
- **G9.8** `hunt` and `ioc_sweep`: is `schedule` null and `lookback` ≤ 90d? No: repair (R13.5, R13.6).
- **G9.9** Is `attack_version` `19.2`, every tactic from the v19 list (no `defense_evasion`), and `bundle_ref` recorded or `null`? No: repair (R11).

## Stage 10 — complexity

- **G10.1** Non-blank query lines ≤ 150, YARA-L event variables ≤ 4 or KQL joins ≤ 5, union branches ≤ 6, nesting depth ≤ 2, inline lists ≤ 50 values? No: split into composable rules recorded in `split_from`, or reject `COMPLEXITY_EXCEEDED` (R12).
- **G10.2** Do the self-reported `complexity` numbers equal the counted values? No: repair.

## Stage 11 — positive control and status

- **G11.1** Is `validation.positive_control.procedure` a concrete, repeatable test naming the command to run, the expected single result, and a negative case that must not alert? No: repair (R05.1 analogue for validation).
- **G11.2** Is `positive_control.status` `not_run` unless the request carried prior evidence, in which case is `evidence_ref` and `date` populated? Model output may never claim `passed` without an evidence reference. **This is the third explicit gate; it is a promotion gate, not an emission gate.** A rule is promoted beyond `draft` only when the harness or a human records a passed positive control in the target engine and a 7-day baseline inside the ceiling.
- **G11.3** Is `status: draft` and `compile.status: not_run`? No: repair.

## Stage 12 — emit

- **G12.1** Is the output a single YAML document with `shikari_output` at the root, keys in the fixed order, `query` as the last key and a literal block scalar (`query: |`), no flow collections except `[]`, no anchors, no tags, no tabs? No: repair.
- **G12.2** Does the document pass `validate.py` with no findings? No: repair; if it cannot be repaired, reject `SCHEMA_VALIDATION_FAILED` with the failing gate IDs in `blocking_criteria`.
- **G12.3** If any gate above produced a rejection, is the rejection the only thing emitted, with no query, and with `remediation` and `nearest_viable_alternative` filled in? No: repair.

# SIEM mappings: editor + live test — implementation plan

**Issue:** #12 (remainder) · **Blocked on:** a SIEM tenant (test step) + your field/index values · **Shares infra with:** #16

The data-source **availability** half of #12 is shipped (flag at generation, exclude at deploy; MDE tables + SecOps UDM event types; admin UI). What's left is the **field-name mapping editor** and the **live connectivity test**.

## Already done

- `schema_overrides.load_active_schema()` — every SIEM now honours `schema<SIEM>_custom.json` (SecOps and Elastic ignored it before).
- Availability gating + badge + deploy-exclusion + config UI (`docs/guide/24-siem-data-sources.md`).
- Splunk and Elastic field/index names are consumed from the bespoke custom schema files today; they're just hand-edited rather than edited in-app.

## Part A — Setup you provide

Two separate needs:

1. **For the field-mapping editor** — your estate's real values, which only you have:
   - **Splunk:** the index names, sourcetypes, and field names for command-line, file, registry and network activity (CIM/CEF is encouraged but not enforced, so these can't be assumed).
   - **Elastic:** the index patterns (`logs-*`, `winlogbeat-*`, …) and any non-ECS field overrides.
   These live in `bespoke/mappings/schemas/schema{Splunk,Elastic}_custom.json` (gitignored). The editor just writes those files from a form instead of by hand — so it needs you to know the values, not a live connection.
2. **For the live "test" step** — the same read-only SIEM API access as #16 (see that plan's Part A). The test answers "does this index/table actually exist?" and "does a sample query parse?" against the real SIEM, which can't be faked.

**Expected outcome:** for the editor — your field/index values to hand (or confirmation the current bespoke files are authoritative); for the test — read-only SIEM credentials configured (the #16 SIEM-connections config).

## Part B — Implementation plan (Archer)

**Editor (offline — needs only your values)**
1. Under **Profile → Config → SIEM field mapping**, per SIEM: load the active schema (base or custom via `schema_overrides`), present the index/sourcetype/field values (Splunk) and index patterns + ECS overrides (Elastic) as an editable form, and save to `schema<SIEM>_custom.json`. For a large/complex Splunk schema, also allow paste/upload of the whole file rather than field-by-field.
2. Flag existing runs for regeneration when a field mapping changes (it changes generated query text, unlike availability which only re-badges).
3. Validate on save: well-formed JSON and the expected shape per SIEM. Unit-tested (save/load roundtrip, validation, regeneration flag).

**Live test (needs Part A's credentials, shared with #16)**
4. Reuse #16's read-only client: given a mapping, check each named index/table exists and that a sample generated query parses (dry-run/validate endpoint where the SIEM offers one). Report per-source pass/fail in the config UI.
5. Unit-test the request building and result parsing with fixtures; the HTTP layer mocked. **Live validation** against your tenant.

**Build order:** the editor first (it only needs your values and is fully testable offline); the live test second, alongside #16, since they share the SIEM-connections config and read-only clients.

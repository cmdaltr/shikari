# VECTR integration — implementation plan

**Issue:** #26 · **Blocked on:** a running VECTR instance + API key

Integrate with VECTR rather than rebuild it: push Archer's threat-library test cases into a VECTR assessment, then read campaign outcomes back as coverage. Archer stays the upstream content engine; VECTR owns the campaign lifecycle.

## Already done

- The threat library exports **MACATable TOML**, which imports into VECTR by hand today. This issue replaces the manual import with a live connector.
- Decisions captured on the issue: keep the Threat library; once read-back (phase 2) lands, demote the in-app assessment tracker (it's the part that duplicates VECTR); MACATable stays on the Threat library, not the intel-interchange page.

## Part A — Setup you provide

1. **Stand up VECTR** — the SecurityRiskAdvisors/VECTR docker-compose, reachable on a URL (the homelab is fine; it's Tomcat + MongoDB, a couple of GB).
2. **Create an API key** in VECTR's admin UI, scoped to the environment/DB you'll push into.
3. **Confirm the GraphQL surface** — this is the real unknown. VECTR's GraphQL schema shifts between releases, so before I write mutations I need, from *your* instance: the GraphQL endpoint path, the VECTR version, and (via introspection or the docs for that version) the mutations for creating/selecting an assessment and loading test cases, plus the queries for reading test-case outcomes. An introspection dump from the running instance is ideal.
4. **A target** — an environment/assessment (or DB) to push into, and agreement on how an Archer run maps to it (one assessment per group? per campaign?).

**Expected outcome:** a reachable VECTR, an API key, the confirmed GraphQL endpoint + version + the relevant mutation/query shapes, and a target to push into.

## Part B — Implementation plan (Archer)

**Phase 1 — push**
1. **Connector config** — `archer/integrations/vectr_config.py`: base URL + API key, gitignored under `bespoke/`, admin-only `GET/POST /api/vectr/config` + a read-only `…/test` (a GraphQL introspection or `__typename` ping). Credentials never returned to the client or logged. Mirrors `repo_config.py`.
2. **GraphQL client** — `archer/integrations/vectr.py` over `requests`: a thin `query(document, variables)` with the API key header, pinned to the version you confirm.
3. **Map + push** — Archer threat-library test cases → the create-assessment / load-test-case mutations from Part A. A "Push to VECTR" button on the Threat library, reporting what was created/updated.
4. **Tests (offline)** — the mutation/variable builders unit-tested against fixtures from your introspection dump; the HTTP client mocked. **Live validation** against your instance.

**Phase 2 — read back**
5. Query test-case outcomes (detected / blocked / not detected) and map them onto Archer detections, surfaced on Results/Coverage: "you have a detection for T1059.001" × "it fired last campaign". Builders unit-tested; live-validated.
6. Once this works, demote the in-app assessment tracker per the issue decision.

**Risk to manage:** GraphQL schema churn — pin the version, keep the mutations in one module, and fail loudly with a clear "VECTR schema mismatch" if introspection diverges from what we built against.

**Stays deferred until Part A:** everything touching the live GraphQL. The config module and the builder/mapping logic ship and are tested against your introspection fixtures before anything hits the instance.

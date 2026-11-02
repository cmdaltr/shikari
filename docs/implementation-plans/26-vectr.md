# VECTR integration — implementation plan

**Issue:** #26 · **Blocked on:** a running VECTR instance + API key

Integrate with VECTR rather than rebuild it: push Shikari's threat-library test cases into a VECTR assessment, then read campaign outcomes back as coverage. Shikari stays the upstream content engine; VECTR owns the campaign lifecycle.

## Already done

- The threat library exports **MACATable TOML**, which imports into VECTR by hand today. This issue replaces the manual import with a live connector.
- Decisions captured on the issue: keep the Threat library; once read-back (phase 2) lands, demote the in-app assessment tracker (it's the part that duplicates VECTR); MACATable stays on the Threat library, not the intel-interchange page.

## Part A — Setup you provide

1. **Stand up VECTR** — run `scripts/deployment/install-vectr.sh` on an **x86-64** Docker host (ARM is unsupported, so the Intel Mac Mini homelab or a Linux VM, not the ARM MacBook; 8 GB+ RAM, 100 GB+ SSD). It fetches VECTR CE, generates the `.env` secrets, and brings the stack up over HTTPS (default `:8081`). Then change the `admin` password.
2. **Create an API key** — Profile → API Key → Create. Copy the ID and Secret (the secret shows once). Shikari will send `Authorization: VEC1 <id>:<secret>`.
3. **Confirm the mutation/query shapes** — the endpoint and auth are known: GraphQL at `https://<host>:<port>/sra-purpletools-rest/graphql`, each operation takes a `db` argument (e.g. `FS_THREAT_INDEX`). What still varies by version is the exact mutations/queries. From your running instance, give me an **introspection dump** (GET the endpoint, or the version's schema docs) so I build against the real schema rather than guess.
4. **A target** — an environment/DB and assessment to push into, and how an Shikari run maps to it (one assessment per group? per campaign?).

**Expected outcome:** a reachable VECTR (via the script), an API key, an introspection dump of its GraphQL schema, and a target DB/assessment to push into. (Note: the archived `_archive/vectr/` client assumed a REST `/api/v1/` API — that was wrong; the real API is GraphQL, so it's reference only.)

## Part B — Implementation plan (Shikari)

**Phase 1 — push**
1. **Connector config** — `shikari/integrations/vectr_config.py`: base URL + API key, gitignored under `bespoke/`, admin-only `GET/POST /api/vectr/config` + a read-only `…/test` (a GraphQL introspection or `__typename` ping). Credentials never returned to the client or logged. Mirrors `repo_config.py`.
2. **GraphQL client** — `shikari/integrations/vectr.py` over `requests`: a thin `query(document, variables)` with the API key header, pinned to the version you confirm.
3. **Map + push** — Shikari threat-library test cases → the create-assessment / load-test-case mutations from Part A. A "Push to VECTR" button on the Threat library, reporting what was created/updated.
4. **Tests (offline)** — the mutation/variable builders unit-tested against fixtures from your introspection dump; the HTTP client mocked. **Live validation** against your instance.

**Phase 2 — read back**
5. Query test-case outcomes (detected / blocked / not detected) and map them onto Shikari detections, surfaced on Results/Coverage: "you have a detection for T1059.001" × "it fired last campaign". Builders unit-tested; live-validated.
6. Once this works, demote the in-app assessment tracker per the issue decision.

**Risk to manage:** GraphQL schema churn — pin the version, keep the mutations in one module, and fail loudly with a clear "VECTR schema mismatch" if introspection diverges from what we built against.

**Stays deferred until Part A:** everything touching the live GraphQL. The config module and the builder/mapping logic ship and are tested against your introspection fixtures before anything hits the instance.

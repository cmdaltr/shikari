# Hit counts — implementation plan

**Issue:** #16 · **Blocked on:** a SIEM tenant with read-only API access · **Shares infra with:** #12 live test

Run a saved detection read-only against the real SIEM to measure how noisy it is (hit count over a window → false-positive signal), without deploying it.

## Already done

Nothing in the engine yet — this is net-new, and deliberately so: it's outward-facing and can't be validated without a tenant. The query-to-count transform and response parsing *can* be built and unit-tested offline (Part B), but the HTTP calls can't.

## Part A — Setup you provide

Per SIEM you want hit counts for, a **read-only** API identity and endpoint. Read-only is the whole point — Archer must never write a rule or change state here.

- **Microsoft Defender XDR (KQL)**
  - An Entra ID app registration (client-credentials flow): tenant ID, client ID, client secret.
  - Application permission `ThreatHunting.Read.All` (Microsoft Graph `POST /security/runHuntingQuery`, or the Defender Advanced Hunting API), with admin consent granted.
  - Note the per-tenant Advanced Hunting rate limits (requests/min and /hour) — hit counts must stay well under them.
- **Google SecOps (YARA-L / UDM)**
  - A service identity with read access to the SecOps search/stats API (service account key, or workforce/BYOID per your tenant's auth), the customer/instance ID, and the region.
  - Confirm the search-or-stats endpoint your instance exposes (the SecOps API has changed shape across releases — give me the one your tenant uses).
- **Elastic (ES|QL)** — the `_query` endpoint URL and a read-only API key.
- **Splunk** — off for now; skip unless you re-enable it, then a REST search endpoint + a read-only token.

Where the credentials live: a new admin-only **SIEM connections** config (same pattern as the detections-as-code repo config — stored gitignored, never in git, never logged). Don't put secrets in the repo.

**Also provide:** a non-production/test index or tenant with known, bounded data, and one or two detections whose expected hit count you already know, so I can confirm the counts are right rather than just plausible.

**Expected outcome:** for at least one SIEM, read-only API credentials + endpoint configured in Archer, reachable from the host, plus a known-good dataset to validate against.

## Part B — Implementation plan (Archer)

1. **SIEM connection config** — `archer/siem/connections.py`: load/save per-SIEM `{endpoint, auth_ref}` to a gitignored JSON under `bespoke/`; admin routes `GET/POST /api/siem/connections` and a read-only `…/test`. Credentials referenced, never echoed back to the client. Mirrors `archer/export/repo_config.py`.
2. **Read-only clients** — `archer/siem/clients/{mde,secops,elastic}.py`, each exposing `run_count(query, window) -> {count, scanned, took_ms}`. They **only** count: the saved query is wrapped to a count/aggregation (KQL `| count`, YARA-L stats/count, ES|QL `| STATS COUNT(*)`), time-boxed to a configurable window (default 24h, max 7d), and the client refuses anything that isn't a read/aggregation. No rows returned, nothing written.
3. **Hit-count action** — per detection on Results, an on-demand "measure hits" call → the client → a count chip ("37 hits / 7d"), plus a crude FP signal (count vs a threshold band). Cache the last result with the run so it isn't re-run on every page load.
4. **Guardrails** — strict read-only, aggregation-only, per-run and per-window caps, client-side rate limiting under the tenant limits, timeouts, and a kill switch. Never log query results or credentials.
5. **Tests (offline)** — unit-test the query→count wrapping and the response parsing per SIEM with fixtures; mock the HTTP layer; assert the client rejects a non-read query. **Live validation** (against your test index) confirms the counts match the known-good numbers.

**Stays deferred until Part A:** the actual API calls and the count-accuracy validation. Everything above the HTTP boundary ships and is tested without a tenant.

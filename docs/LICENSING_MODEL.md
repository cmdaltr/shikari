# Shikari licensing model — what's free, what's paid

Source of truth for the open-core split, so the licence model stays consistent across the codebase,
`COMMERCIAL-LICENSE.md`, and `shikari/licensing.py`. If you're updating the licence model, reconcile
it against this document (and update this document if the decision changes).

## Principle

Shikari's core is AGPL-3.0 and must stay that way: the detection-generation engine is the adoption
funnel, so anything that makes someone try Shikari — and keep using it solo — is free. The commercial
licence charges an **organisation** for **brand, scale and governance**: features a single
self-hoster never needs but a team or a consultancy does. Free for individuals, paid for orgs.

A corollary: never gate the thing that earns the upsell. The reports must be good for free so people
see the branding upsell; the SIEM export must be free so people wire Shikari into their own SIEM at
all.

## Free (AGPL core — never gated)

- Detection generation across all SIEMs, ATT&CK coverage, correlation, MITRESaw traversal.
- The three report products themselves (assessment, campaign-intelligence, detection/hunt),
  unbranded.
- SIEM export packs (Elastic / Splunk / Wazuh) and the Defender XDR master hunt query.
- Lab / emulation basics, the exposure map, the catalogue, the threat feed.
- Ask Shikari, agents, AI-written queries and briefings — **with the user's own API key**. AI is
  opt-in and BYO-key; it is not a paid tier.
- Single-user self-hosting, the CLI, the desktop app.

## Paid (commercial licence — reserved feature ids)

Entitlements are per-feature ids in the signed licence's `features` list; `pro` / `all` is a wildcard
that grants everything (see `shikari/licensing.py`). Keep ids short, kebab-case, and stable.

| Feature id | Status | Gates |
|---|---|---|
| `report-branding` | **shipped** | Custom logos + colour palette on all three reports (chrome + accent only; severity colours stay semantic; co-brand unless turned off). |
| `teams` | **shipped (seats)** — rest drafted | Anything past a single admin. **Enforced now:** the seat limit — one account on the free tier, more need `teams` (`licensing.FREE_SEATS`, `can_add_user()`, gated where accounts are created). **Reserved for the same id, not yet gated:** RBAC / operator roles, JIT elevation, SSO / OIDC, audit-log export. |
| `automation` | proposed | Scheduled / routine runs, detections-as-code repo **push** + CI, webhooks, API-driven bulk generation. |

`pro` = all reserved features. "No licence installed" = the full single-user AGPL build.

**Priority:** `teams` is live as the seat gate — the highest revenue per unit of adoption cost, since a
solo self-hoster never hits the limit so nothing the free build needs moves behind the paywall, but
every multi-analyst organisation does. The other `teams` entitlements (RBAC, JIT, SSO, audit export)
are reserved under the same id and can be gated behind `licensing.has_feature("teams")` as they're
hardened — do it at the point of use, like the seat check and `active_theme()`, not at config time.
`automation` follows; it monetises the orgs wiring Shikari into a pipeline.

## Edge calls (tempting to gate — deliberately not)

- **SIEM export packs: free.** The "try it against my own Elastic/Splunk" hook. Gating it kills the
  thing that drives adoption.
- **AI features: free (BYO key).** Charging for them fights the "avoid AI where possible, don't waste
  tokens" stance and annoys the people most likely to buy.
- **Reports: free; only the *branding* is paid.** The report has to be good in the free tier for the
  branding upsell to exist.
- **Lab / CALDERA: free for now.** A managed or multi-node lab could be paid later (`lab-scale`), but
  basic emulation is a major adoption draw — keep it free.

## Suggested tiers (packaging, not new mechanism)

- **Individual** — no licence; the AGPL build. Free.
- **Pro** — `report-branding` + `automation`. For consultancies and solo pros who white-label and
  automate.
- **Team / Enterprise** — `pro` (adds `teams`). Plus support / SLA, which is where the real
  enterprise revenue is and is sold as a contract, not a code feature.

## How the gate works (for consistency)

- A feature checks `licensing.has_feature("<id>")` at the point of use, not at config time, so editing
  the stored config/profile can't bypass it (see `shikari/reports/theme.py:active_theme()` for the
  pattern to copy).
- Licences are Ed25519-signed, verified offline against the public key embedded in
  `shikari/licensing.py`. No call home. Signature + validity window are both checked.
- Licensor tooling: `scripts/admin/sign_licence.py` and `scripts/admin/issue-pro.sh`. The signing
  private key is never committed.

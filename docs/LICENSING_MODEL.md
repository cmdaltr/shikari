# Licensing model

ostraka, Shikari and Rowanholt share one licensing model (Ben, 11 November 2026). The first part of
this file is that shared specification, kept identical in each product's `docs/LICENSING_MODEL.md`;
the second is this product's own split (Shikari, below). ostraka is the reference implementation.

## Shared across ostraka, Shikari and Rowanholt

### Code licence and notices

- **Elastic License 2.0** for all three (`LICENSE`: the ELv2 text, after a line naming the licensor,
  Ben Smith (cmdaltr)). Free to use, copy and change; no providing it to others as a hosted or
  managed service; no getting around the licence key. Not open core: the key's protection is in the
  code licence itself, not goodwill.
- **`COMMERCIAL-LICENSE.md`** adds the Pro and Services terms, governed by the law of England and
  Wales, marked for legal review. Services is where ELv2's managed-service restriction is lifted for
  work done for the licensee's own clients.
- Copyright **cmdaltr**; a ™ notice for each product's name and logo; outside contributions need a
  contributor licence agreement.
- Releases already published under another licence (Rowanholt's MIT, Shikari's AGPL) keep it; ELv2
  applies from the first release that ships it.

### Editions

| Edition | For | Seats | Always includes |
|---|---|---|---|
| **Free** | Individuals and small teams | The product's own free number | The whole core product, unbranded |
| **Pro** | Organisations using it for themselves | As the licence states, or unlimited | The product's Pro features |
| **Services** | MSSPs and consultancies working for clients | As the licence states, or unlimited | Pro's features, the product's Services features, and the `managed-service` right |

What each edition unlocks is decided per product (below, for ostraka).

### The licence

One line: `<product>-licence-1.<payload>.<signature>`.

- `payload` is base64url (no padding) of canonical JSON: sorted keys, compact separators.
- `signature` is Ed25519, base64url, over the ASCII bytes of `<product>-licence-1.<payload>`, so
  the product and format version are signed too.
- Payload fields: `licence_id`, `product`, `licensee`, `edition` (`pro` or `services`), `seats` (a
  number, or `null` for unlimited), `issued`, `expires` (a date, or `null` for perpetual), and
  optionally `email`, `features` (extra feature ids, or `*` for all) and `not_before`. Dates are
  `YYYY-MM-DD`.
- A licence for another product, another format version, or with a bad signature is refused with a
  reason an admin can act on.

### Terms and accepting them

- `COMMERCIAL-LICENSE.md` states its version on the line after its title (`**Version 1.0**, date`).
  The licensor is "Ben Smith, trading as cmdaltr (cmdaltr.com)" until there's a company. An order
  wins over the terms, the terms over ELv2.
- The product ships a copy of the terms where its server can read them (ostraka:
  `backend/ostraka/legal/`), and a test keeps the copy identical to the root file.
- **Installing a licence needs an admin to accept the current terms on the licensee's behalf.** The
  admin page checks the licence first (showing the licensee, edition, seats and dates), shows the
  terms, and installs only once "I accept the <product> Commercial Licence, version x.y, on behalf
  of <licensee>, and I have authority to do so" is ticked. The API refuses an install without
  `accept_terms` (422) or with a `terms_version` that isn't current (409).
- The installed licence keeps the terms version, who accepted (the account, and "Name <email>" as
  written) and when; the admin page shows it, and the install's audit entry carries the version.
  The CLI needs `--accept-terms "Name <email>"`.
- Every version a customer has accepted is filed in the licensing repo under
  `terms/<product>/COMMERCIAL-LICENSE-v<version>.md`. A new version applies from the next key a
  customer installs.

### Keys and tooling

- **One signing key per product**, so a leak affects one product only. Only the public half ships,
  as hex in `PUBLIC_KEYS` (a tuple, so a key can be rotated by adding the new one). Licences are
  checked offline; nothing calls home.
- `scripts/admin/sign_licence.py` with `keygen PATH`, `public` and `sign`, reading the private key
  from `<PRODUCT>_LICENCE_KEY` (a file path or the key itself; PEM, or the seed as hex).
- `scripts/admin/issue-licence.sh "Licensee" <pro|services> <seats|unlimited> [email|-]
  [YYYY-MM-DD|perpetual] [features]`.
- **The ledger:** with `LICENCE_LEDGER_DIR` set to the licensing repo, `sign` writes the licence to
  `issued/<product>/<licence_id>.licence` and appends a row to `ledger.csv` (licence_id, product,
  licensee, email, edition, seats, features, issued, not_before, expires, terms_version, order,
  file, notes). Without it, the licence goes to a git-ignored `licences/`. The signed order form for
  a sale goes in the licensing repo's `orders/`.
- `.gitignore` covers `licences/`, `*licence-signing-key*`, `*licence-signing.key`, `*.lic.key` and
  `*.licence`. Never commit a private key or an issued licence.

### Behaviour

- **Entitlements:** the edition's own features, plus any the licence lists; `*` grants every
  feature. Code asks `has(feature)`, never the edition name.
- **Check at the point of use**, never at configuration time, so editing stored settings can't get
  around it.
- **Seats** count accounts that can sign in plus open invitations that would add one, and are
  checked only when someone is added (invited, re-enabled, given access). Never retroactively.
- **Validity:** from the start of `not_before` (if any) to the end of `expires`. Before
  `not_before`: Free, shown as pending. After `expires`: the edition carries on for **30 days'
  grace** with a warning to admins, then the installation is Free again.
- **Nobody is ever locked out.** A licence ending, being removed or failing to verify never
  deactivates anyone or deletes anything; it only stops new additions past the free limit and turns
  paid features off.
- **Admin surface:** an admin-only page to see the edition, places taken and who accepted the terms,
  and to check, accept and install or remove a licence; `<product> licence show|install FILE
  --accept-terms NAME|remove`. Installs and removals are recorded where the
  product keeps its security log.
- **Tests** sign with a throwaway key (patching `PUBLIC_KEYS`) and cover: valid, tampered, another
  key, another product, not-yet-valid, grace then lapse, perpetual, wildcard, edition features, the
  seat limit, install refused without acceptance or with a stale terms version, acceptance recorded,
  and the shipped terms identical to `COMMERCIAL-LICENSE.md`.

### Individual to each product

Where the licence is stored (ostraka: its database; a product without one: a file); the free seat
number; feature ids and what each edition unlocks; how "an admin" is spotted for the seat rule.

## Shikari's split

Confirmed by Ben, 11 November 2026.

| Feature id | Free | Pro | Services | Gated at |
|---|---|---|---|---|
| (seats) | 2 (for example an operator and a reviewer) | Licence | Licence | `licensing.can_add_user`, at account creation: public registration and admin create-user |
| `report-branding` | — | Yes | Yes | `reports/theme.py:active_theme()`, and the licence/brand writes in `app.py` |
| `teams` | — | Yes | Yes | reserved; the seat limit is live, the rest (RBAC, SSO, audit export) not yet gated |
| `automation` | — | Yes | Yes | reserved; not yet gated |
| `managed-service` | — | — | Yes | A right in COMMERCIAL-LICENSE.md, not a switch |

`EDITION_FEATURES` gives Pro and Services the three paid features and Services the managed-service
right; `FREE_SEATS` is 2. Raising the free limit from 1 deactivated nobody; it only lets a second
account be added. Gates for `teams` and `automation` arrive with the features they protect.

### Where the licence and its acceptance are stored

Shikari has no licence table, so the licence lives in a file: `data/licence.json` under
`paths.DATA`, or the path in `SHIKARI_LICENCE`. Installing writes `{"licence": "<line>",
"terms_version", "accepted_by" (the account id, or null from the CLI), "accepted_by_name" ("Name
<email>"), "accepted_at"}` there, so the acceptance can't be separated from the licence it was given
for. A file holding only the bare line (from earlier builds) still reads, with no acceptance shown.
The terms the server reads are the packaged copy, `shikari/legal/COMMERCIAL-LICENSE.md`; a test keeps
it identical to the root file. Installs and removals are in the audit log (`licence_installed`, with
`terms_version`, and `licence_removed`).

Free on purpose: the detection-generation engine and everything that drives solo adoption — detection
generation across all SIEMs, ATT&CK coverage, correlation, MITRESaw, the three reports unbranded, the
SIEM export packs and the Defender XDR master hunt query, the lab, the exposure map, the catalogue and
feed, and AI with the user's own key. The reports must be good unbranded for branding to be worth
buying.

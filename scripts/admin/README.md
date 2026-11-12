# Admin scripts

Operator tools for a Shikari deployment and, separately, for the licensor. They are not part of the
running app and are never invoked by it.

| Script | Purpose |
|---|---|
| `create_admin.py` | Create the initial admin account |
| `reset_password.py` | Reset an existing admin account's password |
| `regenerate.py` | Regenerate hunted ATT&CK groups one at a time, as the Results page's Regenerate button does |
| [`WEB_APP.md`](WEB_APP.md) | Notes on the web-app admin scripts |
| `sign_licence.py`, `issue-licence.sh` | **Licence issuing — licensor only** (see below) |

## Licence issuing (licensor only)

`sign_licence.py` and `issue-licence.sh` mint Pro/Services licences. They are in the public repo on
purpose and expose no secret:

- The licence format is signed, not encrypted, and the signing primitive (`sign()`) lives in the
  shipped `shikari/licensing.py` alongside `verify()` — one module so the two can't drift, and one
  round-trip test (`tests/test_licensing.py`) proves they stay compatible. These scripts are thin
  CLI wrappers over that function.
- The only secret is the **private key**, which never lives in the repo. It is read from
  `SHIKARI_LICENCE_KEY` (a path or the key itself), defaulting to `~/.config/shikari/licence-signing-key.pem`
  (keep it `chmod 600`). The matching public key is embedded in `shikari/licensing.PUBLIC_KEYS`, so
  the product verifies offline with no phone-home.
- Issued licences and the ledger are recorded in the **private licensing repo** (set
  `LICENCE_LEDGER_DIR`, or use its `scripts/licences.py` front end), not here.

So the product verifies; the licensor signs with a key that stays on the licensor's machine. A copy of
these scripts in the public tree lets the one compatibility test run in CI; it hands an attacker
nothing they couldn't already derive from the public verifier.

```bash
# issue one (licensor, with the key in place)
export SHIKARI_LICENCE_KEY=~/.config/shikari/licence-signing-key.pem
export LICENCE_LEDGER_DIR=~/path/to/licensing          # records the ledger row + issued file there
./scripts/admin/issue-licence.sh "Northwind Ltd" services 25 ops@northwind.example 2027-12-31
```

The cross-product front end (`licences.py` in the licensing repo) wraps this for all products and is
the usual way to issue, list and verify. See that repo's `README.md`.

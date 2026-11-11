# Shikari Commercial Licence

Shikari's source is published under the GNU Affero General Public License v3.0 (`LICENSE`). That
licence governs the software itself and is all most users need. A small number of features are
**reserved** — they ship in the source but stay inactive until unlocked by a commercial licence
granted by the Licensor. This document sets out the terms on which such a licence is granted.

> This is a plain-language commercial agreement, not legal advice. Have it reviewed by a solicitor
> before relying on it in a sale.

**Licensor:** Ben Smith (@cmdaltr) ("the Licensor").
**Software:** Shikari, and the reserved features listed below.
**Licence key:** the signed licence file the Licensor issues to a Licensee under these terms.

---

## 1. Reserved features

The following features are reserved and require a valid commercial licence to activate. Without one
they remain inactive and the software behaves as the stock open-source build.

| Feature id | What it unlocks |
|---|---|
| `report-branding` | Custom logos and colour palette on the assessment, campaign-intelligence and detection/hunt reports |

`pro` (or `all`) in a licence unlocks every reserved feature. The Licensor may add features to this
list in later versions; a licence grants only the feature ids named in it (or a wildcard).

## 2. Grant

On payment of the applicable fee, the Licensor grants the Licensee a non-exclusive,
non-transferable, non-sublicensable licence to activate and use the reserved features named in the
Licensee's licence key, for the Licensee's own internal business use (including delivering reports
to the Licensee's own clients), for the term of the licence.

This commercial licence is **in addition to**, and does not replace, the AGPL-3.0 terms that govern
the Software itself. The Licensee's obligations under the AGPL (including source availability for
modified network-served copies) are unchanged.

## 3. Licence key

The reserved features are gated by a cryptographically signed licence key. The Licensee may install
the key on the systems it operates to run the Software. The Licensee must not:

- share, publish, resell or redistribute the licence key, or make it available to any third party;
- modify, remove, or circumvent the licensing or feature-gating mechanism, or activate a reserved
  feature other than by a valid key issued by the Licensor;
- extract or attempt to recover any signing key.

Removing or bypassing the gate to use a reserved feature without a valid key is a breach of this
licence and an infringement of the Licensor's rights, notwithstanding that the source is available
under the AGPL. The AGPL grants rights in the Software's source; it does not grant the right to
activate features the Licensor has reserved and offered only under this commercial licence.

## 4. Term, renewal and termination

A licence key may be perpetual or carry an expiry date, as stated in the key. A key with an expiry
date stops activating the reserved features after that date until renewed. The Licensor may
terminate this licence if the Licensee materially breaches it and does not remedy the breach within
30 days of written notice. On termination the Licensee must stop using the reserved features and
remove the licence key.

## 5. Fees

Fees, the billing period, and whether a key is perpetual or time-limited are as agreed in the order
or invoice between the parties. Fees are non-refundable except as required by law.

## 6. Support and updates

Unless separately agreed in writing, a commercial licence does not include support, maintenance, or
any commitment to provide updates. Updates to the Software remain available under the AGPL.

## 7. Warranty and liability

The reserved features are provided "as is", without warranty of any kind, to the fullest extent
permitted by law. To the fullest extent permitted by law, the Licensor's total liability arising out
of or in connection with this licence shall not exceed the fees paid by the Licensee for the licence
in the 12 months before the event giving rise to the claim, and the Licensor shall not be liable for
any indirect or consequential loss, loss of profit, or loss of data. Nothing in this licence limits
liability that cannot be limited by law.

## 8. Governing law

This licence is governed by the laws of England and Wales, and the parties submit to the exclusive
jurisdiction of the courts of England and Wales.

---

## Obtaining or installing a licence

To obtain a licence, contact the Licensor at <https://github.com/cmdaltr/shikari>.

To install one: open **Assessments → Report branding** (admin) and install the licence file under
**Licence**, or save it as `data/licence.json` on the server (or point `SHIKARI_LICENCE` at it). The
key verifies offline against the public key built into the product; no call home is made.

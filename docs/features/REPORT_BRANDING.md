# Report branding

Custom logos and a colour palette on the three report products — the adversary-emulation
assessment, the campaign-intelligence report and the detection/hunt report. It's a commercial (Pro)
feature: the controls are always present, but the branding only applies once a valid licence is
installed (see `COMMERCIAL-LICENSE.md`). Without one, reports render in the stock Shikari look.

The setting is install-wide and admin-only. Find it at **Assessments → Report branding**, or at
`/settings/report-branding`.

## What it changes, and what it deliberately doesn't

The override is chrome only. Your palette drives the cover lead, the running header, the section and
heading rules, the table-header fill and the accent. Up to three logos lead the cover and the header.

Severity and risk-rating colours (Critical / High / Medium / Low) and the bateleur are left alone. A
"Critical" badge recoloured to a house teal stops reading as critical, and that costs the reader more
than the branding gains — so those stay fixed.

Shikari keeps a co-brand line on the cover and a back cover, so a report never hides where it came
from. Turn that off per install with the co-brand switch if your agreement allows a full white-label.

## Palette

Four chrome colours, each mapped onto the role it replaces:

| Slot | Drives | Shikari default |
|---|---|---|
| Accent | Header and section rules, labels, callouts, query accent | `#f59e0b` (gold) |
| Secondary | The cover title underline | `#df514e` (red) |
| Headings | Sub-headings and the "prepared for" line | `#8f5742` (chestnut) |
| Dark | Table headers, the cover title, body text | `#1a2028` (ink) |

Pick a dark colour for the Dark slot — table-header text is light, and a pale value there won't read.

## Logos

Up to three, PNG or SVG with transparency works best. They're normalised to one height and laid out
in a row as the cover and header mark. If no logo is uploaded but colours are set, the Shikari
wordmark stays as the lead and only the palette changes.

## Licence

Report branding needs a signed commercial licence. Install it under **Licence** on the settings page
(paste it or upload the file), or save it as `data/licence.json` on the server, or point
`SHIKARI_LICENCE` at it. The licence is an Ed25519-signed token that verifies offline against the
public key built into the product — no call home. Verification covers the signature and the validity
window; a tampered or expired licence is rejected and branding stays off.

## How it's wired

- `shikari/reports/theme.py` — the `ReportTheme`, the install-wide profile under `data/branding/`,
  and the drawn cover panel and logo strip. `active_theme()` is the single gate: it returns the stock
  theme unless branding is enabled **and** the licence grants `report-branding`.
- `shikari/reports/branded.py` and `shikari/reports/generator.py` take the theme and recolour the
  chrome; the branded `render()` resolves `active_theme()` automatically, so every report download is
  branded without the call sites changing.
- `shikari/licensing.py` — offline licence verification and the entitlement check.

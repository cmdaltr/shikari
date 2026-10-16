# Company profile

**Home → Profile** starts from a company instead of a threat. Enter its primary domain (`rolls-royce.com`; `https://` and paths are stripped) and Archer works out who is likely to target it, then generates detections for the groups you choose.

## How it works

1. **Look the company up.** Archer reads Wikidata, the company's homepage and OSINT sources to establish its name, sector, where it operates and where its site is hosted. It also looks at its technology stack for relevant CVEs.
   Wikidata lists a company's industries with its main one first, and the sector follows that order: Rolls-Royce's "aerospace industry, energy industry, weapons industry" is defence. The other sectors are noted in the profile's evidence ("Also in: energy") but don't choose the groups.
2. **Recommend threat groups.** Groups whose ATT&CK descriptions say they target that sector or region are ranked, and the profile gets a risk score.
3. **Choose.** A window shows the profile summary (company, industry, location, hosting, source, risk score) and the recommended groups, the top three ticked. Tick or untick any. If the profile saw products (the web server banner, WordPress, the email provider from the MX records), **Add to my technology stack** adds them to Profile → [Technology stack](16-profile-and-settings.md#technology-stack). Use it only when the company is your own.
4. **Generate.** Archer runs a [Hunt](02-hunt.md) for each ticked group. Each gets its own [Results](06-results.md) page.

## Options

| Option | Default | What it does |
|---|---|---|
| Supply Chain | Off | Also identifies the company's vendor dependencies |
| AI Enhancement | Off | A model analyses the company too. Needs an AI provider in Profile → API Keys |

Industry, geography and technology stack are always included.

## OSINT API keys

Most sources need no key. Shodan, SecurityTrails and a GitHub token add coverage (internet-facing assets, DNS history, code search). The page shows which are set; set them in Profile → API Keys → OSINT Sources, or in `.env` in the project root.

## Limits

- Group recommendations come from ATT&CK's descriptions of who each group targets. ATT&CK reflects what western vendors and governments publish, so some sectors and regions are better covered than others.
- A domain that resolves to a parent company, a CDN or a hosting provider can give the wrong sector. Check the profile summary before generating.

# Company profile

**Home → Profile** starts from a company instead of a threat. Enter its primary domain (`rolls-royce.com`; `https://` and paths are stripped) and Archer works out who is likely to target it, then generates detections for the groups you choose.

## How it works

1. **Look the company up.** Profiling runs in the background with a progress page of its seven stages (domain, OSINT, industry, geography, technology, supply chain, recommendations), the same as a hunt. Archer reads Wikidata, the company's homepage and OSINT sources to establish its name, sector, where it operates and where its site is hosted. It also looks at its technology stack for relevant CVEs.
   Wikidata lists a company's industries with its main one first, and the sector follows that order: Rolls-Royce's "aerospace industry, energy industry, weapons industry" is defence. The other sectors are noted in the profile's evidence ("Also in: energy") but don't choose the groups.
2. **Recommend threat groups.** Groups whose ATT&CK descriptions say they target that sector or region are ranked, and the profile gets a risk score.
3. **Review.** When profiling finishes it opens a **Review** page: the company's branding, the profile summary (company, industry, location, hosting, source, risk score), the [exposure map](#exposure-map), and the recommended groups laid out in columns — each with a **likelihood** of targeting this organisation (how strongly its sector and region match the group's known targeting), the top three ticked. Tick or untick any. If the profile saw products (the web server banner, WordPress, the email provider from the MX records), **Add to my technology stack** adds them to Environment → [Technology stack](16-profile-and-settings.md#technology-stack). Use it only when the company is your own.
4. **Generate.** Archer runs a [Hunt](02-hunt.md) for each ticked group. Each gets its own [Results](06-results.md) page.

The profile is saved, so the same company doesn't have to be re-run; the Review page, exposure map and catalogue entry are all built from it. Open the Review page again any time from the [Catalogue](#companies-catalogue).

## Exposure map

The **Organisation Exposure Map** is shown on the Review page (and standalone at `/exposure?domain=…`) — a node-and-link graph, in the same style as the attack anatomy on a Results page, of everything profiling surfaced from public sources and how each piece links back to the domain. It answers "what can a threat actor see before they act", and nothing is harvested to build it.

Two hops out from the organisation:

- **Off the domain:** resolved IP addresses, nameservers, mail (MX) with its provider, subdomains (from certificate transparency), the technology fingerprint (server, CDN, cloud, TLS grade, missing security headers) and historical snapshots (Wayback).
- **Off those:** the networks behind the IPs (ASNs, announced ranges, hosting country), certificates issued for the subdomains, exposed services (open ports and software from Shodan InternetDB), **known CVEs** on those services, and the **breach & leak surface** — HIBP breach *metadata* for the email domain (names, dates and counts only, never accounts or credentials), plus any GitHub leaks.

The Mail node also carries email **spoofability**: whether SPF, DMARC and DKIM are published and enforced. A domain is flagged spoofable unless SPF hard/soft-fails unknown senders *and* DMARC is set to quarantine/reject.

Select any node or link for the detail behind it; the CVE node links each CVE to its NVD entry, and the breach node links out to HIBP.

## Companies Catalogue

**Intel → Catalogue** (`/catalogue`, top of the Intel menu) lists every organisation profiled so far, newest first — a Library for companies. Each card opens that company's exposure map.

## Options

| Option | Default | What it does |
|---|---|---|
| Supply Chain | Off | Also identifies the company's vendor dependencies |
| AI Enhancement | Off | A model analyses the company too. Needs an AI provider in Profile → API Keys |

Industry, geography and technology stack are always included.

## OSINT sources and keys

Most sources need no key: DNS, crt.sh certificate transparency, the Wayback Machine, **Team Cymru** (IP→ASN, announced ranges and hosting country), **Shodan InternetDB** (open ports, software and known CVEs per IP) and **HIBP**'s public domain-breach endpoint (breach metadata only). SPF/DMARC/DKIM come straight from DNS.

Optional keys add coverage: **Shodan** (internet-facing assets), **SecurityTrails** (DNS history), **HIBP** (breach metadata, higher rate limits) and a **GitHub** token (code/secret search). The home Profile tab lists each one with a toggle — add a key in place from a small modal, or switch a saved key off without deleting it (kept in the vault, just not applied). You can also manage them in Profile → API Keys → OSINT Sources, or set them in `.env` in the project root. A disabled or absent key simply means that source is skipped.

## Limits

- Group recommendations come from ATT&CK's descriptions of who each group targets. ATT&CK reflects what western vendors and governments publish, so some sectors and regions are better covered than others.
- A domain that resolves to a parent company, a CDN or a hosting provider can give the wrong sector. Check the profile summary before generating.

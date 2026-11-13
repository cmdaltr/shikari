# Threat Feed

**Intel → Threat Feed** is a wall of the last seven days of technical threat research from vendor and government sources, one card per post, each tagged with the industries targeted, the attacker's nation and whether the activity is opportunistic or financially motivated. No AI is involved.

## Using the wall

| Control | What it does |
|---|---|
| Search box | Matches titles and descriptions on the wall |
| Your industries | Posts about groups that target your industries |
| Your stack | Posts that name a product in your [technology stack](16-profile-and-settings.md#technology-stack) |
| Opportunistic / financial | Posts about opportunistic or financially motivated activity, which can land in any industry |
| Both | Any of the above (the default), leaving out posts aimed only at products you don't run |
| All | Every technical post of the week |
| Refresh now | Collect again (only new posts are fetched, so it's usually quick) |
| Analyse in Shikari | Open the post on Home → [Analyse](03-analyse.md) |

Set your industries in Environment → Threat Feed industries.

A card shows the source, date, title, a two-to-three sentence description, and its tags:

| Tag | Comes from |
|---|---|
| Industry | The targeting in ATT&CK of any group the post names; the industries most of a nation's groups target, when the post attributes activity to that nation; industries the post itself names twice or in its title. Yours are highlighted |
| Nation | Attribution in the post ("China-nexus", "DPRK", "Russian GRU", "<country>-nexus") and the nation of each named group. Any nation the IISS assesses as a cyber power counts, plus Pakistan, Belarus, Lebanon and South Korea |
| Opportunistic | Supply-chain or package compromise, mass exploitation, ransomware-as-a-service, infostealers, botnets, malvertising, initial access brokers |
| Financially motivated | Ransomware, extortion, BEC, crypto theft or mining, banking trojans, carding, or a named group whose ATT&CK objective is financial |
| Product | A product in your technology stack that the post names |
| Not your stack | The post names products you don't run and none you do (MOVEit exploitation when you have no MOVEit). It stays under All |

Groups are recognised by their ATT&CK names and aliases, and by vendor naming schemes ATT&CK doesn't have yet: Microsoft's weather names (… Typhoon, Storm-NNNN), CrowdStrike's animals (… Spider, … Panda), Unit 42's constellations, and UNC, FIN, TA and UAT numbers.

Tags only come from the title and the post's technical paragraphs: ones with a technique ID, hash, IP, domain, file name, command, registry key or command-line switch, and the paragraphs either side. A passing mention in a policy piece doesn't count. Posts with no technical content (product news, webinars, newsletters) aren't shown.

## Search all research

The **Search all research** card (collapsed by default; click its title) finds a campaign, tool or actor at any date: `GhostAction`, `RedSun`, `Salt Typhoon`.

| Where it searches | What it matches |
|---|---|
| Shikari's sources | Every post the sources' feeds have carried since Shikari started collecting, back to 2016 for some sources: title, summary, and the analysed description |
| MITRE ATT&CK | Groups, software and campaigns whose name, aliases or description mention it. Name and alias matches come first |
| Web news (optional) | Google News and Bing News: English only, de-duplicated, and only stories that read as security news |

Every word of the search must appear, as a whole word or the start of one. Results are kept for an hour, so repeating a search is instant.

**Include web news** sends your keyword to Google and Bing. Untick it for a search that stays on your machine.

## Watchlists

The **Watchlists** card saves a search, for example `Scattered Spider`, `RedSun`, a CVE or a vendor. Each collection then flags posts that match it. The search is the same as Search all research's: Shikari's sources, plus web news if you tick **Include web news**, which sends the keyword to Google and Bing at every collection. No AI is involved.

When you save a watchlist, everything it matches already counts as seen, so only posts that arrive afterwards are new. The number of new matches shows on the card, and on **Intel** and **Threat Feed** in the menu bar. **Mark seen** clears a watchlist's new matches. A **Watch** button under each Search all research result saves that search.

While any watchlist exists, Shikari collects by itself, so new matches don't wait for someone to open the Threat Feed. Each user sets how often under **Profile → Environment → Watchlist checks**: every 1, 4, 6, 12 or 24 hours, six by default. One collection serves everyone, so Shikari collects at the shortest interval chosen by anyone with a watchlist; hourly is there for a major incident. **Email me** sends one email per collection listing the new matches. It needs email configured (`EMAIL_ENABLED=true` and the `SMTP_*` settings in `.env`); without that, the box is greyed out.

Watchlists, and each user's check interval, are per user, in `data/feed/watchlists/` (not in git).

## Sources

The **Sources** section at the foot of the page lists each source and the result of its last collection: posts this week, or why it failed.

Built in: Microsoft Threat Intelligence, Google Threat Intelligence (Mandiant), Unit 42, Cisco Talos, CrowdStrike, SentinelLABS, Kaspersky Securelist, ESET WeLiveSecurity, Proofpoint, The DFIR Report, Red Canary, Huntress, Elastic Security Labs, CISA, NCSC (UK), Recorded Future, Trend Micro Research, Rapid7, FortiGuard Labs, Symantec Threat Hunter, Volexity, Zscaler ThreatLabz, Sekoia, Group-IB, Bitdefender Labs and JPCERT/CC.

An administrator can add any RSS or Atom feed (name and URL) and remove ones they added. Shikari checks the feed reads before adding it, and only accepts public addresses. Added sources are this installation's own (`data/feed/sources.json`, not in git).

## Limits

- Collection happens on start-up, on **Refresh now**, and when the page is opened six hours or more after the last collection. While any watchlist exists, Shikari also collects by itself, at the shortest interval any watchlist owner has chosen (six hours by default).
- Tags are pattern matches, not reading comprehension. A post that discusses a group without naming it, or attributes in unusual wording, can go untagged.
- The research archive only holds what the feeds carried. Some feeds carry ten posts, some hundreds, so older coverage varies by source.

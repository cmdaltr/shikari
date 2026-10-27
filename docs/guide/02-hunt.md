# Hunt

**Home → Hunt** generates detections for one of three things: a threat group, one or more CVEs, or a list of ATT&CK techniques. Fill in one field and press **Generate**.

## Threat group

Type a group's ATT&CK name or any of its aliases: `APT29`, `Cozy Bear`, `Scattered Spider`, `UNC3944`. Archer finds the group in ATT&CK, collects every technique it's documented as using (directly, through its campaigns, and through the software it uses), and builds detections for each. When ATT&CK attributes a parent technique (Gallmaker's **T1027** Obfuscated Files or Information), its sub-techniques' indicators go into the parent's detection, which says which sub-techniques it includes; a sub-technique ATT&CK attributes to the group in its own right keeps its own detection.

A name ATT&CK doesn't know opens the [Manual](13-manual.md) page instead, so you can enter the group's techniques yourself.

When you've set a [technology stack](16-profile-and-settings.md#technology-stack), a note under the field says so. The hunt then leaves out techniques and procedures that can't happen in your estate. Tick **Ignore it for this hunt** to use all of ATT&CK.

## CVE

Enter one CVE or several, separated by commas: `CVE-2024-3400, CVE-2021-44228`. Each must look like `CVE-20YY-NNNN`. A CVE from the last 30 days is read from Archer's recent-CVE cache, and one in CISA's Known Exploited Vulnerabilities or naming a product in your technology stack has usually been researched already, so the hunt starts at once.

**Browse the last 30 days** under the field lists the CVEs published in that time with an ID from this year (an older ID published now, such as CVE-2013-10076, is a backlog reaching an old bug), newest first: search by ID, product or phrase, and filter to **Exploited (KEV)**, **My technology stack** or **CVSS 7+**. Each shows its CVSS score (or *Not scored yet*: NVD analyses new CVEs days or weeks after they're published), whether it's in KEV and used by ransomware, the stack products it affects, and **Researched** when its hunt will start at once. Picking a CVE adds it to the field; picking it again takes it out. NVD hasn't listed the affected products for most CVEs of the last few weeks, so for those the products are the ones the description names.

Archer reads the CVE's record from the NVD, the advisories and write-ups it links to, and the READMEs of public proof-of-concept exploits on GitHub. It builds four kinds of query:

| Query | From | What it matches |
|---|---|---|
| Exploit request (**T1190**) | The PoCs' HTTP requests | Requests to the vulnerable path in HTTP logs: Defender XDR's inspected inbound HTTP on an onboarded server, Google SecOps `NETWORK_HTTP` events from a proxy, WAF or the appliance. When the payload (`../`, `${jndi:`) travels in a cookie or the body, which these logs don't keep, the query also matches normal use of that path: its description says so |
| Exploitation detections | ATT&CK and the write-ups | The behaviour of exploiting it, including the shell the write-ups show running afterwards (`wget -qO- http://… \| bash`) |
| Runtime shell (**T1190**) | The CVE's products and description | For a code-execution CVE in PHP, a Java application server, IIS (Exchange, SharePoint) or Node.js: its worker process (`php-fpm`, `java`, `w3wp.exe`, `node`) starting recon tools, or a shell whose command line runs recon or a download. It holds however the exploit is delivered, including in a request body HTTP logs don't keep. A bare shell isn't enough: PHP's `exec()` starts one for every call |
| IOC sweeps | The references | The hashes, IPs and domains the advisories and write-ups publish. A domain seen only in an email address or a mailing list's Message-ID (`…@mail.gmail.com` on oss-security) isn't one |

For an appliance (PAN-OS, Ivanti, Citrix) no EDR runs where the exploit lands, so the exploit request and the sweep are the queries that can see it.

The exploit request, runtime shell and IOC sweep queries are the CVE's own, so they're rated **High** whatever the tactic, and their files, titles and the run's correlations start with the CVE and the exploit's name when it has one: `CVE-2026-109618_PHP2Shell_RuntimeShell_KQL.yaml`. The name is what researchers call it, taken from the proof-of-concept repositories' names and the write-ups' URLs: it needs two sources, one of them a write-up off the vendor's own site, or three repository owners. Product names (Magento, NetScaler) and advisory IDs don't count. With no name, the label is the CVE alone (`CVE-2024-3400_Exploit_UDM.yaml`); several CVEs list their IDs and then each name once.

## ATT&CK techniques

Enter technique IDs separated by commas: `T1003, T1021.001, T1078`. Archer hunts each technique across every group that uses it, building queries from the indicators in ATT&CK's procedure examples; a parent technique (`T1003`) also takes its sub-techniques' examples, since its own are often vague. A **Research** bar shows the ATT&CK lookups before detections are built. The same hunt runs from the console (`hunt/technique`) and the API: see [Console, API and MCP](17-console-api-mcp.md). On a group's page, **Hunt techniques** fills this field with the group's techniques.

## Options

| Option | Default | What it does |
|---|---|---|
| Merge by Parent Technique | Off | Folds sub-techniques into their parent (T1003.001, T1003.002 → T1003) before correlating, so correlations are by technique rather than by sub-technique |
| Auto-validate | Off | Runs each query against sample events in containerised SIEMs. Needs Docker running; the box is greyed out and says why when it isn't |
| LOL datasets | On | Adds what LOLBAS, LOLDrivers and LOLRMM document about the binaries, drivers and RMM tools the group is seen using: command lines, hashes and paths go into the queries, and each detection links to the entries |
| OSINT Enhancement | On | Merges indicators from public detection rules (Google SecOps, Sentinel, Splunk and Elastic repositories) into the queries, and adds their known false positives to each detection |
| OSINT Comparison | Off | Scores each detection against the public rules for the same technique, and records how well they agree. Also builds detections from the public rules when ATT&CK gives a technique no indicators |

Correlations are always built. Which SIEMs get queries is set in Environment → SIEM platforms.

## The AI question

After **Generate**, Archer asks whether to use AI for this hunt. **No** runs the standard pipeline only. **Yes** also has a model write queries, one call per procedure, using the provider set in Profile → API Keys. Tick **Remember this choice** to stop being asked; change it later under Profile → API Keys → Hunt prompt.

## What happens next

The progress page shows detections and then correlations being built. A CVE or technique hunt first has a **Research** bar: for each CVE, the NVD record, proofs of concept, ATT&CK mapping, advisories and exploit requests, then the IOC sweeps; for techniques, each ATT&CK lookup. When the run finishes, its [Results](06-results.md) page opens.

## Limits

- About 318 of ATT&CK's 697 techniques name no command, file, registry key or other indicator anywhere in ATT&CK (**T1190**, **T1566.001**, much of Reconnaissance and Resource Development). Without AI or OSINT, those produce nothing. The Results page lists them with the reason.
- A technique hunt where every technique is on that list, run without AI or OSINT, is refused with the reason instead of producing an empty run.
- Generated queries are a starting point. Review them and tune them to your environment before you deploy them: the Results page's Validation section walks you through it.

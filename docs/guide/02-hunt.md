# Hunt

**Home → Hunt** generates detections for one of three things: a threat group, one or more CVEs, or a list of ATT&CK techniques. Fill in one field and press **Generate**.

## Threat group

Type a group's ATT&CK name or any of its aliases: `APT29`, `Cozy Bear`, `Scattered Spider`, `UNC3944`. Archer finds the group in ATT&CK, collects every technique it's documented as using (directly, through its campaigns, and through the software it uses), and builds detections for each.

A name ATT&CK doesn't know opens the [Manual](13-manual.md) page instead, so you can enter the group's techniques yourself.

When you've set a [technology stack](16-profile-and-settings.md#technology-stack), a note under the field says so. The hunt then leaves out techniques and procedures that can't happen in your estate. Tick **Ignore it for this hunt** to use all of ATT&CK.

## CVE

Enter one CVE or several, separated by commas: `CVE-2024-3400, CVE-2021-44228`. Each must look like `CVE-20YY-NNNN`. Archer reads the CVE's record from the NVD, the advisories and write-ups it links to, and the READMEs of public proof-of-concept exploits on GitHub. It builds three kinds of query:

| Query | From | What it matches |
|---|---|---|
| Exploit request (**T1190**) | The PoCs' HTTP requests | Requests to the vulnerable path in HTTP logs: Defender XDR's inspected inbound HTTP on an onboarded server, Google SecOps `NETWORK_HTTP` events from a proxy, WAF or the appliance. High severity when the payload (`../`, `${jndi:`) is in the URL; low when it travels in a cookie or the body, which these logs don't keep, so the query also matches normal use of that path |
| Exploitation detections | ATT&CK and the write-ups | The behaviour of exploiting it, including the shell the write-ups show running afterwards (`wget -qO- http://… \| bash`) |
| IOC sweeps | The references | The hashes, IPs and domains the advisories and write-ups publish |

For an appliance (PAN-OS, Ivanti, Citrix) no EDR runs where the exploit lands, so the exploit request and the sweep are the queries that can see it.

## ATT&CK techniques

Marked **Coming soon** in the page. The same hunt is available now from the console (`hunt/technique`) and the API: see [Console, API and MCP](17-console-api-mcp.md). It hunts the techniques across every group that uses them.

## Options

| Option | Default | What it does |
|---|---|---|
| Merge by Parent Technique | Off | Folds sub-techniques into their parent (T1003.001, T1003.002 → T1003) before correlating, so correlations are by technique rather than by sub-technique |
| Auto-validate | Off | Runs each query against sample events in containerised SIEMs. Needs Docker running; the box is greyed out and says why when it isn't |
| LOL datasets | On | Adds what LOLBAS, LOLDrivers and LOLRMM document about the binaries, drivers and RMM tools the group is seen using: command lines, hashes and paths go into the queries, and each detection links to the entries |
| OSINT Enhancement | On | Merges indicators from public detection rules (Google SecOps, Sentinel, Splunk and Elastic repositories) into the queries, and adds their known false positives to each detection |
| OSINT Comparison | Off | Scores each detection against the public rules for the same technique, and records how well they agree. Also builds detections from the public rules when ATT&CK gives a technique no indicators |

Correlations are always built. Which SIEMs get queries is set in Profile → SIEM platforms.

## The AI question

After **Generate**, Archer asks whether to use AI for this hunt. **No** runs the standard pipeline only. **Yes** also has a model write queries, one call per procedure, using the provider set in Profile → API Keys. Tick **Remember this choice** to stop being asked; change it later under Profile → API Keys → Hunt prompt.

## What happens next

The progress page shows detections and then correlations being built. A CVE or technique hunt first has a **Research** bar: for each CVE, the NVD record, proofs of concept, ATT&CK mapping, advisories and exploit requests, then the IOC sweeps; for techniques, each ATT&CK lookup. When the run finishes, its [Results](06-results.md) page opens.

## Limits

- About 318 of ATT&CK's 697 techniques name no command, file, registry key or other indicator anywhere in ATT&CK (**T1190**, **T1566.001**, much of Reconnaissance and Resource Development). Without AI or OSINT, those produce nothing. The Results page lists them with the reason.
- A technique hunt where every technique is on that list, run without AI or OSINT, is refused with the reason instead of producing an empty run.
- Generated queries are a starting point. Review them and tune them to your environment before you deploy them: the Results page's Validation section walks you through it.

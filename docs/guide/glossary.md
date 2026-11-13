# Glossary

| Term | Meaning in Shikari |
|---|---|
| ATT&CK | MITRE ATT&CK Enterprise: the catalogue of attacker tactics, techniques, groups, software and campaigns Shikari works from |
| Tactic | The attacker's goal at a stage of an attack (Initial Access, Persistence, Lateral Movement…) |
| Technique, sub-technique | How a tactic is achieved: **T1003** OS Credential Dumping; **T1003.001** its LSASS Memory variant |
| Procedure | A documented instance of a group using a technique, in ATT&CK's words. Shikari takes its indicators from these |
| Group | A threat actor ATT&CK tracks (APT29, Scattered Spider), with aliases |
| Campaign, software | ATT&CK's records of an operation and of malware or tools. A group's techniques can reach it through either |
| TTPs | Tactics, techniques and procedures |
| IOC | Indicator of compromise: a hash, IP address, domain, URL, file name or registry key |
| IOC sweep | A query that looks for a report's or CVE's IOCs across your data |
| Indicator | Anything a query can match: a command line, file path, registry key, process name, hash or address |
| Detection | One query (per SIEM) for one technique, saved as YAML with its metadata |
| Correlation | Several detections chained into one query that fires when their steps happen together within a time window |
| Attack flow | A group's techniques laid out by tactic, marked detected or not |
| Threat briefing | A run's coverage, its weakest stage and the gaps to close first |
| OSINT Enhancement | Merging indicators and known false positives from public detection rules into Shikari's queries |
| OSINT Comparison | Scoring Shikari's queries against public rules, and building from those rules where ATT&CK has no indicators |
| LOL datasets | LOLBAS (Windows binaries), LOLDrivers (vulnerable and malicious drivers) and LOLRMM (remote management tools) |
| Reference queries | Your own production-tested queries in `bespoke/llm_references/`, used as templates and examples |
| Bespoke | Your organisation's own prompts, templates, mappings and reference queries, kept out of git |
| MITRESaw | The tool that walks ATT&CK into a table of procedures and indicators |
| KQL | Kusto Query Language: Defender XDR advanced hunting |
| YARA-L | Google SecOps's rule language |
| SPL | Splunk's Search Processing Language |
| EQL, ES\|QL | Elastic's event and piped query languages |
| UDM | Google SecOps's Unified Data Model: the field names YARA-L rules use |
| Recording | One attack (a tool or Atomic Red Team test) run in a lab with logging on, and the events it produced. Emulate's evidence |
| Native logs | Logging the operating system has built in: Windows Security, System and PowerShell logs; Linux auditd and the journal; the macOS unified log. Sysmon and EDR agents are extra, and less widely deployed |
| Atomic Red Team | Red Canary's library of small tests, one or more per ATT&CK technique, used to produce recordings |
| GUIDE | Microsoft's dataset of Defender XDR alerts from thousands of organisations, with triage grades; Emulate's source for Defender's own alerting |
| True, benign, false positive | Customers' triage grades in GUIDE: a real attack; real activity that wasn't malicious; a wrong alert |
| IISS | The International Institute for Strategic Studies, whose cyber power tiers the Cyber Powers map uses |
| MCP | Model Context Protocol: how AI clients such as Claude Code call Shikari's tools |

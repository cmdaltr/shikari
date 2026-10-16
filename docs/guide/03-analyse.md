# Analyse

**Home → Analyse** builds detections from a threat report. Give it either a URL or a file.

| Input | Accepts |
|---|---|
| URL | A blog post or advisory: `https://thedfirreport.com/2024/...` |
| File | PDF, TXT, MD, JSON, CSV, XLSX, DOCX, YARA (drag it onto the box, or **Select File**) |

**Analyse in Archer** on a Threat Feed or research-search result opens this tab with the URL already filled in.

## How it works

1. **Extraction.** Archer reads the report and pulls out ATT&CK technique IDs and the behaviour they describe (TTPs), and indicators of compromise (IOCs): hashes, IP addresses, domains, URLs, file names, registry keys and similar. Defanged indicators such as `evil[.]com` are recognised.
2. **Review.** A window lists every TTP and IOC found, each with a tick box. Untick anything you don't want hunted, such as a vendor's own domain or a technique that was only mentioned in passing.
3. **Generate.** Archer builds detections for the ticked techniques and sweeps for the ticked IOCs, then opens the [Results](06-results.md) page.

If the report is about a threat group, the run is linked to it under its ATT&CK name. Archer recognises every ATT&CK group by its name or any alias (a report on Midnight Blizzard is APT29), as whole words, and goes by the group the report mentions most, a mention in the title counting most. Otherwise the run is named after the article: `Report_Nightmare-Eclipse_Tooling_Seen_in_Real-World_Intrusion`.

Commands come from the report's code blocks and its text. A sentence that starts with a program's name ("the flaws remain unpatched", "net group occurring near…") isn't taken as a command. Where a report shows commands but no technique IDs, Archer maps each command to the technique ATT&CK's procedures cite it under most (`whoami /priv` to **T1033**, `nltest /domain_trusts` to **T1482**), without AI.

### What the IOC sweep leaves out or narrows

| Indicator | In the sweep |
|---|---|
| A path with a blanked-out folder: `c:\users\[redacted]\downloads\z.exe`, `<user>`, `%username%` | Any one folder there |
| A file in a system folder: `C:\Windows\System32\…`, `/usr/bin/…`, `/System/…` | Only when it's written (created, modified or renamed). The genuine file runs on every host; a malicious copy has to be put there |
| A Windows binary LOLBAS lists, by name alone: `comsvcs.dll` | Left out: it matches every host that loads it. The report's hashes still find a malicious copy |
| A domain only the platform itself can create: `login.microsoftonline.com`, `github.com` | Left out |
| A shared-hosting platform's bare domain: `s3.amazonaws.com`, `pages.dev` | Left out. Subdomains stay (`evil.s3.amazonaws.com` is whoever registered it) |
| Public DNS resolvers (`8.8.8.8`, `1.1.1.1`) and the empty file's hashes | Left out |
| Cloud provider IP ranges | Kept: a lot of C2 runs on rented cloud servers |

The known-good list is `archer/mappings/known_good.json`. To add your own, such as internal domains, put a file with the same keys at `bespoke/mappings/known_good.json`.

IPs and domains expire 90 days after Archer first saw them in that run; the sweep's description gives the first expiry date. **Regenerate** drops the expired ones. Hashes and files don't expire.

## Options

The options are the same as on the Hunt tab: Merge by Parent Technique, Auto-validate, LOL datasets (on), OSINT Enhancement (on) and OSINT Comparison (off). [Hunt → Options](02-hunt.md#options) explains each.

## Limits

- A report that names behaviour but no technique IDs or commands gives fewer TTPs without AI. A command maps to a technique only when ATT&CK's procedures cite it at least three times, mostly under one technique.
- Some sites block automated fetches or load their text with JavaScript. If a URL gives nothing, save the page as PDF or text and upload it.
- IOCs are taken as written. Check the review list for benign infrastructure the report mentions (vendor domains, sinkholes, public DNS resolvers).

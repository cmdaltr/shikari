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

The IOC sweep treats a path segment the report blanked out (`c:\users\[redacted]\downloads\z.exe`, `<user>`, `%username%`) as any one folder. It leaves out files in Windows' system folders and binaries LOLBAS lists (`comsvcs.dll`): their names match every host, and the report's hashes find a malicious copy.

## Options

The options are the same as on the Hunt tab: Merge by Parent Technique, Auto-validate, LOL datasets (on), OSINT Enhancement (on) and OSINT Comparison (off). [Hunt → Options](02-hunt.md#options) explains each.

## Limits

- A report that names behaviour but no technique IDs or commands gives fewer TTPs without AI. A command maps to a technique only when ATT&CK's procedures cite it at least three times, mostly under one technique.
- Some sites block automated fetches or load their text with JavaScript. If a URL gives nothing, save the page as PDF or text and upload it.
- IOCs are taken as written. Check the review list for benign infrastructure the report mentions (vendor domains, sinkholes, public DNS resolvers).

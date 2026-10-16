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

If the report names a threat group, the run is linked to it. Otherwise it gets a name made from the report.

## Options

The options are the same as on the Hunt tab: Merge by Parent Technique, Auto-validate, LOL datasets (on), OSINT Enhancement (on) and OSINT Comparison (off). [Hunt → Options](02-hunt.md#options) explains each.

## Limits

- A report that names behaviour but no technique IDs gives fewer TTPs without AI. The extraction looks for technique IDs and known behaviour patterns, not every way a report can describe an attack.
- Some sites block automated fetches or load their text with JavaScript. If a URL gives nothing, save the page as PDF or text and upload it.
- IOCs are taken as written. Check the review list for benign infrastructure the report mentions (vendor domains, sinkholes, public DNS resolvers).

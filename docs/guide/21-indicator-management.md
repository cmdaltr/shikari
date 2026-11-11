# Indicator Management

**Intel → Indicator Management** is one page for indicators, in two collapsible sections: searching reputable reporting for an indicator, and importing or exporting threat intelligence as STIX, TAXII or MISP. No AI is involved.

## Search indicators

Enter an IP, domain, URL, file hash, email or CVE and Shikari searches the reputable vendor, CERT/government, news and aggregator sources' reporting from the last 7 days for it — and its common defanged forms (`hxxp`, `[.]`, `(dot)`, `[@]`). The tier chips (Vendor TI, CERT/Gov, News, Aggregator) filter which sources it searches. Each hit shows the source, a tier badge, the date and a highlighted snippet, and links to the original; results are cached for the 7-day window, and recent searches sit as chips to re-run. The deep link `/ioc?q=<indicator>` runs a search directly — the Investigation agent and the `ioc_search` console/MCP tool use the same engine.

## Import

Four ways in, all producing the same result as analysing a report — techniques and IOCs you review before generating:

- **File upload** — drag a file onto the box or choose one: a STIX 2.1 bundle (`.json` with an `objects` list) or a MISP event (`.json` with an `Event`). Shikari detects which.
- **Paste JSON** — the same, pasted in.
- **TAXII collection** — the collection's `…/collections/<id>/` URL, with a username and password if the server needs them (used for that request only, never stored). Shikari polls the collection, following pagination, and imports every object. Redirects aren't followed, so the credentials only go to the URL you give: use the collection's final address.
- **MISP instance** — a MISP base URL and an API key. Shikari queries `/events/restSearch` for recently-published events (default the last 30 days) and merges their techniques and IOCs. The key is used for that request only, never stored.

From a STIX bundle, `attack-pattern` objects map to ATT&CK techniques (via their `mitre-attack` external reference), indicator patterns and cyber-observables map to IOCs, and an `intrusion-set` or `threat-actor` names the group. From a MISP event, attributes map to IOCs by type (including composites such as `filename|md5`), and MITRE galaxies and tags map to techniques.

After import you get the technique and IOC counts, the OSINT and correlation toggles, and **Generate detections** — the same pipeline a report runs through.

## Export

Pick a saved run and download it as either format.

**STIX 2.1 bundle** —

- an `identity` for Shikari, the TLP 2.0 marking (AMBER) carried by every object, and an `intrusion-set` for the group,
- an `attack-pattern` per technique, with its ATT&CK external reference,
- an `indicator` per IOC, with its cyber observables (IPv4 or IPv6, and the hash's own algorithm),
- the detections themselves as `x-shikari-detection` custom objects carrying the SIEM and the query,
- a `report` referencing them all,

tied together with `uses`, `detects` and `indicates` relationships. Ids are stable, so exporting the same run again gives the same ids.

**MISP event** — the group as a `threat-actor` galaxy, each technique as a `mitre-attack-pattern` galaxy cluster (and a tag, so simple parsers pick it up too), and the IOCs as attributes typed by kind. MISP carries intel rather than detection logic, so the queries aren't embedded — the event summarises what the run is about.

Both round-trip: importing either back recovers the techniques and IOCs. (For emulation test cases rather than intel interchange, use the MACATable TOML export on the Threat library — that's the format VECTR imports.)

## Notes

- STIX, TAXII and MISP are read and written by samarkand (`samarkand.stix`, `.taxii`, `.misp`), the package Shikari shares with Ostraka and Rowanholt, as plain JSON: parsing reads the raw JSON rather than a strict loader, so MISP- and vendor-exported bundles with custom properties import cleanly, and escaped quotes and backslashes in STIX patterns are read correctly. No python-stix2 or pymisp is involved.
- The TAXII client is samarkand's (standard library); the MISP instance query is built on `requests`. Recurring polling as a standing Threat Feed source is a later addition — for now a collection or instance is polled on demand.

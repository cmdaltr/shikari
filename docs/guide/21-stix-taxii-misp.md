# STIX / TAXII & MISP

Threat intelligence arrives as STIX bundles, TAXII collections and MISP events as often as it does blog posts. **Intel → STIX/TAXII & MISP** takes those as a hunt input and exports a finished run back out as STIX or a MISP event. No AI is involved.

## Import

Four ways in, all producing the same result as analysing a report — techniques and IOCs you review before generating:

- **File upload** — drag a file onto the box or choose one: a STIX 2.1 bundle (`.json` with an `objects` list) or a MISP event (`.json` with an `Event`). Archer detects which.
- **Paste JSON** — the same, pasted in.
- **TAXII collection** — the collection's `…/collections/<id>/` URL, with a username and password if the server needs them (used for that request only, never stored). Archer polls the collection, following pagination, and imports every object.
- **MISP instance** — a MISP base URL and an API key. Archer queries `/events/restSearch` for recently-published events (default the last 30 days) and merges their techniques and IOCs. The key is used for that request only, never stored.

From a STIX bundle, `attack-pattern` objects map to ATT&CK techniques (via their `mitre-attack` external reference), indicator patterns and cyber-observables map to IOCs, and an `intrusion-set` or `threat-actor` names the group. From a MISP event, attributes map to IOCs by type (including composites such as `filename|md5`), and MITRE galaxies and tags map to techniques.

After import you get the technique and IOC counts, the OSINT and correlation toggles, and **Generate detections** — the same pipeline a report runs through.

## Export

Pick a saved run and download it as either format.

**STIX 2.1 bundle** —

- an `identity` for Archer and an `intrusion-set` for the group,
- an `attack-pattern` per technique, with its ATT&CK external reference,
- `indicator` objects built from each detection's IOCs,
- the detections themselves as `x-archer-detection` custom objects carrying the SIEM and the query,

tied together with `uses`, `detects` and `indicates` relationships.

**MISP event** — the group as a `threat-actor` galaxy, each technique as a `mitre-attack-pattern` galaxy cluster (and a tag, so simple parsers pick it up too), and the IOCs as attributes typed by kind. MISP carries intel rather than detection logic, so the queries aren't embedded — the event summarises what the run is about.

Both round-trip: importing either back recovers the techniques and IOCs. (For emulation test cases rather than intel interchange, use the MACATable TOML export on the Threat library — that's the format VECTR imports.)

## Notes

- Parsing reads the raw JSON rather than python-stix2's strict loader, so MISP- and vendor-exported bundles with custom properties import cleanly. STIX export uses python-stix2 to produce a valid 2.1 bundle; MISP export and import are plain JSON, no pymisp dependency.
- The TAXII and MISP clients are built on `requests` (no extra dependency). Recurring polling as a standing Threat Feed source is a later addition — for now a collection or instance is polled on demand.

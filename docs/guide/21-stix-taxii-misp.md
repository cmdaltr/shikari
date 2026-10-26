# STIX / TAXII & MISP

Threat intelligence arrives as STIX bundles, TAXII collections and MISP events as often as it does blog posts. **Intel → STIX/TAXII & MISP** takes those as a hunt input and exports a finished run back out as STIX. No AI is involved.

## Import

Three ways in, all producing the same result as analysing a report — techniques and IOCs you review before generating:

- **File** — a STIX 2.1 bundle (`.json` with an `objects` list) or a MISP event (`.json` with an `Event`). Archer detects which.
- **Paste JSON** — the same, pasted in.
- **TAXII collection** — the collection's `…/collections/<id>/` URL, with a username and password if the server needs them (used for that request only, never stored). Archer polls the collection, following pagination, and imports every object.

From a STIX bundle, `attack-pattern` objects map to ATT&CK techniques (via their `mitre-attack` external reference), indicator patterns and cyber-observables map to IOCs, and an `intrusion-set` or `threat-actor` names the group. From a MISP event, attributes map to IOCs by type (including composites such as `filename|md5`), and MITRE galaxies and tags map to techniques.

After import you get the technique and IOC counts, the OSINT and correlation toggles, and **Generate detections** — the same pipeline a report runs through.

## Export

Pick a saved run and download it as a STIX 2.1 bundle:

- an `identity` for Archer and an `intrusion-set` for the group,
- an `attack-pattern` per technique, with its ATT&CK external reference,
- `indicator` objects built from each detection's IOCs,
- the detections themselves as `x-archer-detection` custom objects carrying the SIEM and the query,

tied together with `uses`, `detects` and `indicates` relationships. The bundle round-trips: importing it back recovers the techniques and IOCs.

## Notes

- Parsing reads the raw JSON rather than python-stix2's strict loader, so MISP- and vendor-exported bundles with custom properties import cleanly. Export uses python-stix2 to produce a valid 2.1 bundle.
- The TAXII client is built on `requests` (no extra dependency); recurring TAXII polling as a standing Threat Feed source is a later addition — for now a collection is polled on demand.

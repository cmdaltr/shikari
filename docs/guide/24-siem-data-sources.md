# SIEM data sources

A detection can only fire if the estate ingests the data it reads. An MDE→SecOps feed, for instance, might carry file and registry events but not process launches, so a process-based detection would sit in the SIEM and never trigger. **Profile → Config → SIEM data sources** records what the estate actually ingests, so Archer flags the detections that can't fire and keeps them out of what you deploy. No AI is involved.

## What varies, and what doesn't

Field names are vendor-fixed and documented — MDE's Advanced Hunting columns, SecOps' UDM paths — so there's nothing to map there. What varies per tenant is **availability**: which tables or event types the estate collects. That's all this configures. (Per-tenant field and index names, where they genuinely differ — Splunk especially — stay in the bespoke schema files, `bespoke/mappings/schemas/schema<SIEM>_custom.json`.)

Each detection already names what it needs in `requiredDataConnectors.dataTypes`: an MDE table (`DeviceProcessEvents`) or a SecOps UDM event type (`PROCESS_LAUNCH`). The gate is simply whether the estate ingests every source a detection lists.

## Configure it

Admin only, under **Profile → Config → SIEM data sources**:

- **Microsoft Defender XDR** — tick the Advanced Hunting tables the estate ingests (the documented set of twelve).
- **Google SecOps** — tick the UDM event types the estate receives. The list is drawn from what your runs actually emit.

Tick only what you ingest. A SIEM you leave untouched is not gated — every source counts as ingested — so with nothing configured, nothing is flagged and behaviour is unchanged. The config lives gitignored at `bespoke/mappings/availability.json`.

## What the flag does

The flag is derived live from the config, so changing what you ingest re-badges existing runs without regenerating them.

- **On Results** — a detection that needs a source you don't ingest carries a **Source not ingested** badge naming the missing table or event type. It's shown rather than hidden, so the telemetry gap is visible: these are the detections your collection is blinding you to.
- **At deploy** — the two deployment paths leave flagged detections out. **Detections → Detections as code** doesn't commit them (they're listed under `excluded`), and the **Push to a SIEM** plan skips them. A rule that can't fire is never pushed into the SIEM.

So the full picture stays on Results and in Coverage, and only deployable detections reach git or the SIEM.

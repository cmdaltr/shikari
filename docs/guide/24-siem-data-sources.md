# SIEM data sources

A detection can only fire if the estate ingests the data it reads. An MDE→SecOps feed, for instance, might carry file and registry events but not process launches, so a process-based detection would sit in the SIEM and never trigger. **Profile → Config → SIEM data sources** records what the estate actually ingests, so Shikari flags the detections that can't fire and keeps them out of what you deploy. No AI is involved.

## What varies, and what doesn't

Field names are vendor-fixed and documented — MDE's Advanced Hunting columns, SecOps' UDM paths — so there's nothing to map there. What varies per tenant is **availability**: which tables or event types the estate collects. That's all this configures. (Per-tenant field and index names, where they genuinely differ — Splunk especially — stay in the bespoke schema files, `bespoke/mappings/schemas/schema<SIEM>_custom.json`.)

Each detection already names what it needs in `requiredDataConnectors.dataTypes`: an MDE table (`DeviceProcessEvents`) or a SecOps UDM event type (`PROCESS_LAUNCH`). The gate is simply whether the estate ingests every source a detection lists.

## Configure it

Admin only, under **Profile → Config → SIEM data sources**:

- **Microsoft Defender XDR** — tick the Advanced Hunting tables the estate ingests (the documented set of twelve).
- **Google SecOps** — tick the UDM event types the estate receives. The list is the documented UDM `metadata.event_type` set, unioned with whatever your runs emit (so nothing in use is missing). To use your own authoritative list, drop a JSON array of event-type strings at `bespoke/mappings/udm_event_types.json` and it replaces the built-in default.

Tick only what you ingest. A SIEM you leave untouched is not gated — every source counts as ingested — so with nothing configured, nothing is flagged and behaviour is unchanged. The config lives gitignored at `bespoke/mappings/availability.json`.

## What the flag does

The flag is derived live from the config, so changing what you ingest re-badges existing runs without regenerating them.

- **On Results** — a detection that needs a source you don't ingest carries a **Source not ingested** badge naming the missing table or event type. It's shown rather than hidden, so the telemetry gap is visible: these are the detections your collection is blinding you to.
- **At deploy** — the two deployment paths leave flagged detections out. **Detections → Detections as code** doesn't commit them (they're listed under `excluded`), and the **Push to a SIEM** plan skips them. A rule that can't fire is never pushed into the SIEM.

So the full picture stays on Results and in Coverage, and only deployable detections reach git or the SIEM.

## Field mapping

Availability is about *which* sources you collect; field mapping is about *what they're called*. **Profile → Config → SIEM field mapping** edits the per-environment schema a SIEM's queries are generated from — index, sourcetype and field names — and saves it as `schema<SIEM>_custom.json` (gitignored), which the generator reads in place of the base.

This matters for **Splunk** (index/sourcetype/field names vary by deployment; CIM/CEF is encouraged but not enforced) and **Elastic** (index patterns, non-ECS overrides). MDE columns and SecOps UDM paths are vendor-fixed, so overriding those is rarely needed — they're offered for completeness. Edit the schema, **Save override** to apply it, or **Reset to base** to drop it. Because a field mapping changes the generated query text (unlike availability, which only re-badges), regenerate affected runs after a change.

The live "does this index/table exist, does this query parse" test against the real SIEM is a later addition — it needs a tenant (see the [hit counts](../implementation-plans/16-hit-counts.md) plan, which it shares credentials with).

# VECTR integration — stand-up and schema probe (#26)

Shikari's job is upstream: turning MITRE ATT&CK / MITRESaw group and campaign data into a threat
library and detections. [VECTR](https://docs.vectr.io) owns the downstream lifecycle — running
emulation campaigns and recording detect/prevent outcomes. The plan ([#26](https://github.com/cmdaltr/shikari/issues/26))
is to **integrate, not rebuild**:

- **Phase 1 — push:** load the threat library's test cases into a VECTR assessment over its GraphQL API.
- **Phase 2 — read back:** pull detect/block/not-detected outcomes and surface them as coverage against
  Shikari's detections.

VECTR's GraphQL schema shifts between releases, so the exact mutations and queries have to be confirmed
against a running instance **before** the connector is written. This directory is that Phase 0: stand up
VECTR, authenticate, and print its real GraphQL surface.

## Files

| File | What it does |
| --- | --- |
| `up.sh` | Fetches the pinned VECTR CE release bundle (via `gh`), unpacks it and brings its own docker compose up. |
| `vectr_gql.py` | Minimal GraphQL client: `VEC1 keyId:secret` auth, POST queries, introspection, self-signed TLS. |
| `probe_schema.py` | Read-only. Authenticates, then prints the mutations/queries for assessments, campaigns and test cases. |

The archived `_archive/vectr/` code assumed a REST `/api/v1` surface that VECTR does not expose; it is
kept only for reference. The real API is GraphQL at `…/sra-purpletools-rest/graphql`.

## Run it

> ⚠ **sbx recommended** — this stands up a third-party Docker stack and makes outbound network
> connections. If you want the agent to run it rather than running it yourself, use `sbx run claude`
> first to isolate the agent in a microVM. Running the bundle yourself on the homelab is fine.

Needs `docker` (with the compose plugin) and `gh` (authenticated). ~2 GB of images on first pull.

```bash
scripts/vectr/up.sh                 # fetch + start (override version with VECTR_VERSION=ce-9.13.1)
# open https://localhost:8081, complete first-login, create an API key in Administration (shown once)

export VECTR_API_KEY='keyId:secret'
.venv/bin/python scripts/vectr/probe_schema.py          # relevant mutations + queries
.venv/bin/python scripts/vectr/probe_schema.py --json > /tmp/vectr-schema.json   # full surface

scripts/vectr/up.sh down            # stop (keeps data volumes)
```

## Status — parked in favour of export (decision 2026-11-05)

**The live GraphQL integration is not being built.** Shikari already exports the threat library and
emulation plans as **MACATable TOML** (`shikari/assessments/macat.py`), which is VECTR's native import
format — a file contract with zero runtime coupling, where VECTR owns its own lifecycle. A live
connector would replace "export once, import once" with a version-pinned GraphQL dependency that breaks
whenever VECTR's schema shifts: a lot of fragility for marginal convenience over the export we already
have. The clean seam between two independently-versioned tools is the **format, not the API**.

The only part of #26 with genuinely new value is the Phase 2 read-back (coverage informed by real
campaign outcomes). If that is ever wanted, do it as a **results import** — ingest VECTR's exported
outcomes as a file — not a live poll, keeping both directions file-based and uncoupled.

This bundle (`up.sh`, `vectr_gql.py`, `probe_schema.py`) is kept only as the Phase-0 starting point
**if** a live, bidirectional integration is ever deliberately chosen. It is off the critical path.
Recommended issue outcome: close #26 as "export covers push", and track read-back separately as an
optional file import.

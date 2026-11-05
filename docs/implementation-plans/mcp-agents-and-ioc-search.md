# Plan — MCP tools, agents, functions, and IOC search

Scope: four related pieces of work. Guiding principle throughout (Shikari's house rule): **deterministic,
offline, no-AI where possible**; AI and agents only where the task is genuinely open-ended. The verdict
up front, so the rest is detail:

| Piece | Verdict | Why |
|---|---|---|
| MCP tools for every component | **No — curate ~8–10** | An MCP server already exists; blanket-wrapping every helper duplicates the HTTP API and creates auth/schema upkeep for tools nobody calls |
| Agents per component | **No — 2, maybe 3** | Agents earn their cost only on open-ended synthesis/investigation; deterministic components are better as functions |
| New shared functions | **Yes — a small set** | A few genuinely cross-cutting helpers (IOC handling, source registry) that MCP/agents/UI all reuse |
| IOC search | **Build — feed-first, no-AI core** | Reputable-by-construction from a curated source set; deterministic; optional AI only for an opt-in summary |

---

## Part 1 — MCP tools

Shikari **already ships an MCP server**: `shikari mcp` (`shikari/mcp_server.py`), a stdio server built
over `ShikariClient`, exposing the server-side console agent tools (`hunt_report`, `analyse_report`,
`hunt_cve`, `intel_company`, …). So this is **curate + extend**, not build-from-scratch.

**Do not** add a tool per component. The test for a tool: *would an external LLM/agent actually call
this?* Rendering paths, CRUD on internal rows, and one-off helpers fail it.

### Curated surface (target ~8–10)

| Tool | Maps to | New? | Notes |
|---|---|---|---|
| `hunt_group` | `/generate` (orchestrator) | exists | group → detections |
| `hunt_cve` | `/generate_cve` | exists | CVE → detections, NVD-enriched |
| `hunt_technique` | `/hunt/technique` | exists | technique(s) → detections |
| `hunt_report` / `analyse_report` | report pipeline | exists | report/URL → TTPs + detections |
| `profile_company` | `_launch_company_profile` | **add** | domain → background profile |
| `rank_adversaries` | `adversary_ranking.rank_adversaries` | **add** | domain → top-10 likely actors (no AI) |
| `coverage` | `/api/coverage/*` | **add** | saved detections vs ATT&CK/cloud |
| `mitresaw_traverse` | `shikari.mitre.procedures` | **add** | group → procedures/evidence (3 attribution paths) |
| `emulate_plan` | CALDERA plan (read-only) | **add** | target+group → operation plan; **execute stays out of MCP** (live detonation is a deliberate UI action) |
| `ioc_search` | Part 4 | **add after P4** | IOC → reputable recent reporting |

### Build notes
- Extend the existing tool registry behind `ShikariClient`/`mcp_server.py`; keep one server, two transports (stdio for Claude Code; the HTTP API already exists for everything else).
- Auth: reuse `SHIKARI_TOKEN` (Profile → Security → API Tokens), same as the console server modules.
- Safety: read/plan tools are safe to expose; anything that **executes** (CALDERA detonation, SIEM writes, deletes) stays out of the tool set or is hard-gated — never a one-call side effect from an agent.
- Mark long-running tools (profile, hunt) as async/background and return a job id + poll tool, mirroring the web flow.

---

## Part 2 — Agents (truly useful only)

An agent earns its keep when the task is **open-ended** (synthesis, multi-step investigation with
branching), not when it wraps a deterministic function. Two solid ones, a third maybe:

### A. Threat Briefing agent *(solid)*
- **Job:** for a group or an org, produce a practitioner briefing — who they are, likely TTPs against *this* org, coverage gaps, recommended next hunts.
- **Beats a function because:** it synthesises across `rank_adversaries` + `mitresaw_traverse` + `coverage` + the profile, and writes prose. There's already a `threat_briefing` endpoint (`shikari/chat.py`) to graduate into this.
- **Tools:** `rank_adversaries`, `mitresaw_traverse`, `coverage`, `profile_company` (read).
- **Guardrail:** the inputs stay deterministic/no-AI; the agent only does the synthesis layer.

### B. Investigation agent *(solid)*
- **Job:** start from an IOC or a domain and pivot — `ioc_search` → `profile_company`/`rank_adversaries` → `mitresaw_traverse` → draft findings — deciding the next pivot each step.
- **Beats a function because:** the pivot path is genuinely open-ended and data-dependent.
- **Tools:** `ioc_search`, `profile_company`, `rank_adversaries`, `mitresaw_traverse`.
- **Guardrail:** read-only; proposes hunts/detections, never auto-executes.

### C. Detection-tuning agent *(maybe — defer)*
- **Job:** given validation failures (grade < threshold, FP risk), iterate a detection and re-validate.
- **Why maybe:** validation is already deterministic (A–F grade, FP risk); the loop is narrow. Worth it only if query authoring proves to need iteration. Defer until asked.

**Not agents:** rank adversaries, build a Sigma/YARA-L rule, normalise an IOC, compute coverage — all deterministic, keep as functions/tools.

---

## Part 3 — Truly useful shared functions

Small, cross-cutting, reused by Part 1/2/4 and the UI:

| Function/module | Purpose | Reused by |
|---|---|---|
| `shikari/intelligence/ioc.py` | classify (ip/domain/url/hash/email/cve/…), normalise, **defang/refang** (`hxxp`, `[.]`, `(dot)`) | IOC search, Investigation agent, MCP |
| `shikari/data/intel_sources.yaml` + loader | the curated ~100 reputable sources (name, RSS, tier, tags) | IOC search, Threat Feed (could share) |
| `rank_adversaries` | already built (`adversary_ranking`) | exposure/review, MCP, briefing agent |
| `incident_sources` | already built (feeds) | adversary ranking, (future) IOC enrichment |

Deliberately **not** adding a generic "pivot everything" function — speculative; let the Investigation
agent compose the specific tools instead.

---

## Part 4 — IOC search

> **Goal:** given an IOC, search the ~100 most reputable cyber-intelligence / public cyber-reporting
> **web pages** (not full PDF reports) from the **past 7 days** for that IOC.

### Approach — feed-first, no-AI core (recommended)
Reputable *by construction* (we own the source list), deterministic, cacheable, no paid search key.

1. **Source registry** — `shikari/data/intel_sources.yaml`, ~100 curated sources, each: `name`, `homepage`, `rss` (one or more Atom/RSS URLs), `tier`, `tags`. Tiers:
   - **T1 vendor TI research:** Mandiant/Google TAG, Microsoft MSTIC, Talos, Unit 42, CrowdStrike, SentinelOne, ESET, Securelist, Check Point Research, Trend Micro, Sophos X-Ops, FortiGuard, Proofpoint, Secureworks CTU, Volexity, Group-IB, Dragos (OT), Red Canary, Huntress, The DFIR Report …
   - **T2 CERT/gov:** CISA (+ KEV alerts), NCSC-UK, CERT-EU, ACSC, JPCERT …
   - **T3 reputable news/community:** BleepingComputer, The Hacker News, The Record, DarkReading, SecurityWeek, Krebs, Malwarebytes Labs …
   - **T4 structured/aggregators (web pages):** abuse.ch (URLhaus/MalwareBazaar entries), OTX pulses …
2. **Fetch feeds** — concurrent, polite (per-host rate limit, timeout, conditional GET via ETag/Last-Modified, UA), cached to `data/cache/intel_feeds/`. Keep entries published in the **last 7 days**.
3. **Match** — normalise the IOC (`ioc.py`) and search each candidate for it **and its defanged variants** (reports routinely defang: `1.2.3.4` ↔ `1[.]2[.]3[.]4`, `hxxp`). Use the feed's `content`/`summary`; when the IOC type is likely only in the body (hashes, URLs), fetch the page and search its extracted text.
4. **Rank & return** — by source tier then recency. Each hit: `{source, tier, title, url, published, snippet (IOC highlighted)}`.

### IOC handling (`ioc.py`)
- Classify: ipv4/ipv6, domain, url, md5/sha1/sha256, email, cve, filename, registry key, mutex.
- Refang on input, search defanged + plain forms in page text.

### Architecture
- `shikari/intelligence/ioc.py` — classify/normalise/defang.
- `shikari/intelligence/ioc_search.py` — engine (feed fetch + match + rank); reads the source registry + feed cache.
- API: `GET /api/ioc/search?ioc=…` (auth; background for slow page fetches, poll for results); `POST /api/ioc/feeds/refresh` (admin) to warm the feed cache.
- UI: **Intel → IOC Search** — input + results with **tier badges** and highlighted snippets; a **pivot** button from the exposure map (an exposed CVE/IP → IOC search).
- Caching keeps render fast; the live fetch is the only networked step.

### Tradeoffs (flagged)
- **Feed-first vs search API:** feed-first is reputable-by-construction and key-free, but only sees what the feeds surface in 7 days, and a few sources lack RSS. Mitigation: a lightweight index-page fetch for RSS-less sources, and an **optional** search-API fallback (Brave/Google PSE/Bing: `"<ioc>" site:domain` + date filter) behind a key, opt-in.
- **Coverage vs noise:** T4 aggregators are high-recall but noisier — tier badges + a tier filter let the analyst weight them.
- **Politeness/legal:** respect robots.txt, cap concurrency, cache aggressively; ~100 sources × weekly windows is light.
- ⚠ **sbx:** the live feed/page fetch makes **outbound connections to ~100 sites** — run the refresh/search under `sbx run claude` if isolating; render-time stays on cache.
- **AI:** none in the core. Optional opt-in: an AI summary of the hit corpus ("what are these reports saying about this IOC?") — a layer, never the mechanism.

### Phasing
- **P1:** `ioc.py` + source registry (~100) + feed fetch + match + `/api/ioc/search` + basic UI. No AI, no page-body fetch.
- **P2:** page-body fetch for body-only IOCs; exposure-map pivot; tier filter.
- **P3:** search-API fallback for RSS-less sources; optional AI summary; share the source registry with the Threat Feed.

---

## Suggested order
1. Part 3 `ioc.py` + source registry (foundation, small).
2. Part 4 P1 (IOC search core) — the feature you asked for.
3. Part 1 — add `rank_adversaries`, `profile_company`, `coverage`, `mitresaw_traverse`, `emulate_plan`, `ioc_search` to the existing MCP server.
4. Part 2 A (Briefing) then B (Investigation).
5. Part 4 P2/P3 and Part 2 C as demand shows.

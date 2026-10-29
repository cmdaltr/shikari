# How Archer Compares

Where Archer sits in the detection-engineering tooling landscape, measured honestly against the free and paid tools that overlap with it. This is a positioning document, not marketing — the limitations section is as important as the rest.

## What Archer actually does

Archer turns threat intelligence into high-fidelity SIEM detections. You give it a MITRE ATT&CK group, a CVE, or a threat report; it generates queries for four SIEMs, with extra granularity when a technique is attributed to a known adversary. It also maps coverage, finds gaps, correlates techniques into attack chains, and (via CALDERA) closes the loop by emulating an adversary and checking whether the generated detections fire.

The important distinction up front: most tools in this space either **translate** rules you already wrote, or hand you a **library** of pre-written rules. Archer **generates** detections from intelligence. That is a different category, and it is where the comparison gets interesting.

## The landscape, by category

| Category | What it means | Representative tools |
|---|---|---|
| Format + translation | A generic rule format and converters between SIEM dialects — you still author the logic | Sigma / pySigma, Uncoder |
| Vendor-native content | Curated rule packs for one SIEM, mapped to ATT&CK | Splunk ESCU, Elastic Detection Rules, Microsoft Sentinel/Defender content, Google SecOps content |
| Detection marketplace | A large curated library plus translation and coverage tooling | SOC Prime Platform |
| Enterprise detection platforms | Managed detection posture, coverage and (some) generation across SIEMs | CardinalOps, Anvilogic, SnapAttack |
| Threat-informed defence | ATT&CK coverage mapping and prioritisation (not generation) | Tidal Cyber, DeTT&CT |
| Adversary emulation | Run techniques to test detections (not generation) | CALDERA, Atomic Red Team |
| **Intelligence-to-detection generation** | **Generate detections from ATT&CK/CVE/report + actor attribution, multi-SIEM** | **Archer** |

Archer overlaps with several of these but lives primarily in the last row, which is thinly populated and dominated by expensive enterprise platforms.

## Feature comparison

Columns group comparators by category so the matrix stays readable. "~" means partial or indirect support.

| Capability | Archer | Sigma + Uncoder (free, DIY) | Vendor-native content (free, single-SIEM) | SOC Prime (freemium → paid) | Enterprise platforms (CardinalOps / Anvilogic / SnapAttack, paid) |
|---|:---:|:---:|:---:|:---:|:---:|
| Generate detections **from threat intel** (group/CVE/report) | ✓ | ✗ | ✗ | ~ (library, not generation) | ✓ |
| **Threat-actor attribution granularity** (direct / software / campaign) | ✓ | ✗ | ✗ | ~ | ~ |
| Multi-SIEM output | ✓ SecOps, MDE, Splunk, Elastic | ✓ (translate many) | ✗ (one SIEM) | ✓ (translate many) | ✓ |
| Targets newer dialects (ES\|QL, YARA-L/UDM) | ✓ | ~ | ~ | ~ | ~ |
| SIEM query translation between dialects | ~ (generates per-SIEM) | ✓ | ✗ | ✓ | ~ |
| Curated detection **library** at scale | ✗ | ✗ | ✓ | ✓ (large) | ✓ |
| ATT&CK coverage + **gap analysis** | ✓ | ✗ | ~ | ✓ | ✓ |
| Cross-technique **correlation / attack chains** | ✓ | ✗ | ~ | ~ | ✓ |
| **Emulation → detection validation** loop | ✓ (CALDERA) | ✗ | ✗ | ~ | ✓ (SnapAttack) |
| Works **without AI** (deterministic mode) | ✓ | ✓ | ✓ | ~ | ✗ (AI-centric) |
| **Self-hosted / data stays local** | ✓ | ✓ (CLI) | ✓ | ✗ (SaaS) | ✗ (SaaS) |
| Desktop app / offline use | ✓ | ✗ | ✗ | ✗ | ✗ |
| Org-specific tuning (exclusions, mappings) | ✓ | ✗ | ~ | ✓ | ✓ |
| Managed content updates + support | ✗ | ✗ | ✓ (vendor) | ✓ | ✓ |
| Cost | Free for individuals | Free | Free | Freemium → enterprise | Enterprise ($$$) |

Competitor capabilities and pricing reflect what is publicly documented at the time of writing and will change; verify before relying on any single cell.

## Category-by-category assessment

**Sigma + Uncoder (free, DIY).** The honest free baseline for multi-SIEM work. Sigma is an excellent portable rule format and Uncoder translates between dialects well. But both assume you have *already written* the detection logic. They answer "convert my rule to SPL"; Archer answers "give me detections for APT29 across my four SIEMs." Different jobs. Archer complements Sigma more than it competes with it.

**Vendor-native content (Splunk ESCU, Elastic Detection Rules, Sentinel/Defender, Google SecOps).** High quality and free, but locked to one platform. A shop running three SIEMs needs three separate content pipelines with three mental models. Archer's value is precisely the cross-SIEM generation these cannot offer, and it targets the newer dialects (ES|QL, YARA-L) that have thinner community coverage.

**SOC Prime.** The strongest freemium comparator. Its marketplace of curated detections is far larger than anything Archer ships, and Uncoder is a mature translator. Where Archer differs: it generates from intelligence rather than serving a library, it runs entirely self-hosted with no data leaving the environment, and it works without AI or a cloud account.

**Enterprise platforms (CardinalOps, Anvilogic, SnapAttack).** These are the closest in *ambition* — automated, multi-SIEM, ATT&CK-driven detection engineering, and SnapAttack adds the emulation loop Archer also has. They are also enterprise SaaS with enterprise pricing, cloud-hosted, and generally AI-dependent. Archer delivers a meaningful slice of the same workflow as a free, self-hosted, AI-optional tool. It will not match their breadth, integrations, managed content, or scale — but it puts the core capability within reach of an individual or a team that cannot justify a six-figure platform.

## Where Archer stands on its own

Three things, combined, describe a position no other tool in the table occupies at once:

1. **It generates detections from intelligence, not from rules you already have** — and does so for four SIEMs, including the newer ES|QL and YARA-L dialects where ready-made content is scarce.
2. **It is self-hosted and AI-optional.** The deterministic path produces detections with no LLM call and no data leaving the environment. Everything works offline, from a desktop app. The enterprise platforms that match its generation ambition are all cloud SaaS and AI-centric.
3. **It is free for individuals.** The only other free options are translators and single-SIEM libraries — none of which generate cross-SIEM detections from threat intelligence.

## Unique selling points

| USP | Why it matters |
|---|---|
| **Attribution granularity** | When a technique is tied to a known actor (directly, via their software, or via a campaign — through MITRESaw), Archer generates more specific detections than a generic ATT&CK rule. Nothing else in the free tier does this. |
| **Intelligence → detection, multi-SIEM** | One input (group, CVE, report) yields detections for SecOps, MDE, Splunk and Elastic at once. |
| **AI-optional, deterministic** | Detections are generated from evidence without a mandatory cloud LLM — important for air-gapped, regulated and privacy-sensitive environments, and it keeps the tool useful with no AI budget. |
| **Data sovereignty** | Fully self-hosted; a desktop app that runs locally. Threat intel and detection logic never leave the environment — unlike every SaaS comparator. |
| **Closed validation loop** | Generate detections, emulate the adversary with CALDERA, confirm what fired. Only the priciest platforms offer this. |
| **Cost** | The generation capability of an enterprise platform, free for individuals and affordable for teams. |

## Where Archer does not lead (the honest part)

A credible comparison has to state the gaps:

- **Library scale.** Archer generates; it does not ship a large curated, continuously updated detection catalogue the way SOC Prime or the vendor content packs do.
- **Enterprise integrations.** No deep connector ecosystem, ticketing/SOAR integrations, or multi-tenant managed service.
- **Managed content + support.** No vendor SLA, no team pushing tuned content to you weekly. You run it yourself.
- **Scale and certifications.** It is an independent project, not a platform with SOC 2, enterprise onboarding and 24/7 support behind it.
- **Breadth of SIEM coverage.** Four targets, chosen deliberately (SecOps, MDE, Splunk, Elastic) — not the long tail that mature translators cover.

These are the trade-offs of a focused, self-hosted, independent tool. For an individual practitioner, a small team, or an air-gapped environment, they are often acceptable — which is exactly the gap Archer fills.

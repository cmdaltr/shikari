# Shikari Documentation Index

Single-page index of all project documentation.

---

## User Guide (start here)

Plain-language guide to every part of Shikari, one page each: what it's for, how to use it, every option, where its data comes from, and its limits.

| Page | Covers |
|------|--------|
| [Overview](guide/README.md) | What Shikari does, where everything is, which SIEMs, what uses AI |
| [Running Shikari](guide/01-running-shikari.md) | `shikari start/stop/status`, signing in, what happens at start-up |
| [Hunt](guide/02-hunt.md) | Threat group, CVE and technique hunts; every option |
| [Analyse](guide/03-analyse.md) | Detections from a report URL or file |
| [Company profile](guide/04-company-profile.md) | Who targets a company, then their detections |
| [Research](guide/05-research.md) | Find groups by keyword, compare their techniques, export |
| [Results](guide/06-results.md) | Detections, correlations, attack flow, briefing, buttons |
| [Library](guide/07-library.md) | Saved detections: search, filter, tag, export |
| [Coverage](guide/08-coverage.md) | Reference and detection coverage across ATT&CK |
| [Flows](guide/09-flows.md) | Attack flows: what you can and can't detect |
| [Threat Feed](guide/10-threat-feed.md) | The week's research, tags, search all research, sources |
| [Cyber Powers](guide/11-cyber-powers.md) | The map's three views and how attribution is read |
| [MITRESaw](guide/12-mitresaw.md) | Procedures, rebuilds, OSINT repositories, exclusions |
| [Manual](guide/13-manual.md) | Detections from your own TTPs |
| [Regex](guide/14-regex.md) | Regex tester and per-SIEM checks (RE2, PCRE, Lucene) |
| [Agents and Ask Shikari](guide/15-agents-and-ask-shikari.md) | The AI features |
| [Profile and settings](guide/16-profile-and-settings.md) | Account, SIEMs, industries, keys, MFA, tokens, users |
| [Console, API and MCP](guide/17-console-api-mcp.md) | `shikari console`, the Python client, REST, `shikari mcp` |
| [Data and updates](guide/18-data-and-updates.md) | What's downloaded, when, and where everything is kept |
| [Emulate](guide/19-emulate.md) | Which logs record each technique (native, Sysmon, EDR; Windows, Linux, macOS, ESXi, cloud), detections checked against lab recordings, Defender XDR's own alerting |
| [Recording a lab](guide/20-recording-a-lab.md) | **Coming soon**: Atomic Red Team on your own VMs, with Defender for Endpoint's rows, into Emulate |
| [CALDERA operations](guide/25-caldera.md) | Plan and run CALDERA operations on lab agents, collect each step, optionally capture its endpoint logs over the agent's own C2, check detections and correlations against it statically |
| [Glossary](guide/glossary.md) | The terms used throughout |

---

## Getting Started

| Document | Description |
|----------|-------------|
| [README.md](../README.md) | Project overview, features, shikari console usage |
| [GETTING_STARTED.md](../GETTING_STARTED.md) | Installation, setup, first run |
| [USAGE.md](USAGE.md) | Where each task is done, and `shikari offline` |
| [desktop/README.md](../desktop/README.md) | Desktop installers: connecting to an organisation's server (MDM, Group Policy), running locally, building releases |
| [scripts/video/README.md](../scripts/video/README.md) | Remaking the in-app guide's pictures and the narrated walkthrough video |
| [Deployment comparison](architecture/deployment-comparison.svg) | Web, desktop client, desktop local and checkout: where users, detections and mappings live |

---

## Interactive Console (shikari console)

| Document | Description |
|----------|-------------|
| [README.md — shikari console](../README.md#-interactive-console-shikari-console) | Commands, modules, example session |

---

## Bespoke Configuration

| Document | Description |
|----------|-------------|
| [bespoke/README.md](../bespoke/README.md) | Bespoke directory structure, mapping files, reference queries |
| [shikari/mappings/defaults/README.md](../shikari/mappings/defaults/README.md) | The default mappings a new install starts with; Splunk's CEF indexes, sourcetypes and custom-string convention |
| [LLM_CONFIGURATION.md](features/LLM_CONFIGURATION.md) | LLM provider setup — Anthropic, OpenAI, ChatGPT Enterprise, Azure OpenAI, Copilot, local LLMs |
| [bespoke/config.yaml.example](../bespoke/config.yaml.example) | Config file template with all LLM provider options |

---

## Features

| Document | Description |
|----------|-------------|
| [API_INTEGRATION_GUIDE.md](features/API_INTEGRATION_GUIDE.md) | REST API reference — authentication, endpoints, code examples |
| [LLM_CONFIGURATION.md](features/LLM_CONFIGURATION.md) | Configure LLM providers for `--llm` mode |
| [CVE_ENRICHMENT.md](features/CVE_ENRICHMENT.md) | CVE-based detection generation with NVD enrichment |
| [DETECTION_VALIDATION.md](features/DETECTION_VALIDATION.md) | Pre-generation validation (cross-platform contamination prevention) |
| [RUNTIME_VALIDATION.md](features/RUNTIME_VALIDATION.md) | Runtime detection testing in containerised SIEMs |
| [OSINT_INTEGRATION.md](features/OSINT_INTEGRATION.md) | OSINT repository integration for indicator enrichment |
| [PARENT_TECHNIQUE_OPTION.md](features/PARENT_TECHNIQUE_OPTION.md) | Automatic sub-technique expansion |
| [REPORT_GENERATION.md](features/REPORT_GENERATION.md) | Export detections as Word, PDF, HTML reports |
| [REPORT_BRANDING.md](features/REPORT_BRANDING.md) | Custom logos + palette on reports (commercial/Pro, signed licence) |
| [LICENSING_MODEL.md](LICENSING_MODEL.md) | Elastic License 2.0 and the editions — the shared model, and what Free/Pro/Services each unlock |
| [RESPONSE_ACTIONS.md](features/RESPONSE_ACTIONS.md) | Automated response action recommendations |
| [CALDERA_WINDOWS_CAPTURE.md](features/CALDERA_WINDOWS_CAPTURE.md) | CALDERA endpoint-log capture on a Windows host — how it integrates with Shikari and where each capture's results land |
| [SIEM_EXPORT_PACKS.md](features/SIEM_EXPORT_PACKS.md) | Export packs for your own Elastic, Splunk or Wazuh: contents, tested versions, known limits |
| [SECURITY_FEATURES.md](features/SECURITY_FEATURES.md) | Authentication, encryption, MFA, audit logging |
| [DOCKER.md](features/DOCKER.md) | Docker deployment guide |

---

## Architecture

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](architecture/ARCHITECTURE.md) | System architecture overview |
| [CORRELATION_ENGINE.md](architecture/CORRELATION_ENGINE.md) | Correlation generation — scoring, filtering, JOIN queries |
| [CORRELATION_QUICK_REFERENCE.md](architecture/CORRELATION_QUICK_REFERENCE.md) | Correlation tuning parameters |
| [PERFORMANCE_ARCHITECTURE.md](architecture/PERFORMANCE_ARCHITECTURE.md) | Performance and optimisation |
| [SCHEMA_NORMALIZATION.md](architecture/SCHEMA_NORMALIZATION.md) | Field normalisation and schema design |
| [Architecture Diagrams](architecture/mermaid/) | 13 Mermaid diagrams — end-to-end flow, component map, decision map, data flow |
| [deployment-comparison.svg](architecture/deployment-comparison.svg) | The four ways to run Shikari, side by side |

---

## AI and RAG

| Document | Description |
|----------|-------------|
| [AI_TRAINING.md](ai/AI_TRAINING.md) | AI query training and generation |
| [LLM_DETECTION_GENERATION.md](ai/LLM_DETECTION_GENERATION.md) | LLM-powered detection generation internals |
| [MODEL_CONFIGURATION.md](ai/MODEL_CONFIGURATION.md) | AI model configuration |
| [TRAIN_AI.md](ai/TRAIN_AI.md) | Training data preparation |
| [RAG README](rag/README.md) | RAG system overview |
| [RAG_USER_GUIDE.md](rag/RAG_USER_GUIDE.md) | Quick start for RAG fidelity enhancement |
| [FIDELITY_SYSTEM_SUMMARY.md](rag/FIDELITY_SYSTEM_SUMMARY.md) | RAG implementation summary |
| [FIDELITY_IMPLEMENTATION_GUIDE.md](rag/FIDELITY_IMPLEMENTATION_GUIDE.md) | Comprehensive RAG implementation guide |

---

## Scripts

| Document | Description |
|----------|-------------|
| [SCRIPTS.md](SCRIPTS.md) | Command-line scripts and utilities overview |
| [scripts/admin/WEB_APP.md](../scripts/admin/WEB_APP.md) | Web application admin scripts |
| [scripts/ai/LOCAL_LLM.md](../scripts/ai/LOCAL_LLM.md) | Local LLM setup scripts |
| [scripts/data/DATA_SCRIPTS.md](../scripts/data/DATA_SCRIPTS.md) | Data management scripts |
| [scripts/deployment/DEPLOY.md](../scripts/deployment/DEPLOY.md) | Deployment scripts |
| [scripts/validation/VALIDATION.md](../scripts/validation/VALIDATION.md) | Validation scripts |

---

## Testing

| Document | Description |
|----------|-------------|
| [tests/README.md](../tests/README.md) | Test suite — categories, running tests |

---

## Bespoke Prompts and Templates

| Document | Description |
|----------|-------------|
| [bespoke/prompts/CloudLLM_Master.md](../bespoke/prompts/CloudLLM_Master.md) | Cloud LLM master prompt for detection generation |
| [bespoke/prompts/LocalLLM_Master.md](../bespoke/prompts/LocalLLM_Master.md) | Local LLM master prompt (smaller context) |
| [bespoke/query_templates/DetectionGeneration_Templates.md](../bespoke/query_templates/DetectionGeneration_Templates.md) | Per-telemetry query templates (AWS, Windows, MDE, Unix, Proxy, etc.) |
| [bespoke/llm_references/README.md](../bespoke/llm_references/README.md) | Reference query format and examples |

---

## Status and Roadmap

| Document | Description |
|----------|-------------|
| [UNTESTED.md](other/UNTESTED.md) | Implemented but not validated features |
| [QUERY_EXECUTION.md](features/QUERY_EXECUTION.md) | Running generated SPL against Splunk and reading results back |
| [Feature requests](https://github.com/cmdaltr/shikari/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement) | Planned features: tracked only as GitHub issues labelled `enhancement` |

## Output contract

- [shikari/contract/README.md](../shikari/contract/README.md) — strict output contract v1.0: validator, legacy lint gate, LLM pipeline hook, exemplars and rationale (`shikari/contract/docs/`).

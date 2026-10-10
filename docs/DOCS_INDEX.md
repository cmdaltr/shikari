# Archer Documentation Index

Single-page index of all project documentation.

---

## Getting Started

| Document | Description |
|----------|-------------|
| [README.md](../README.md) | Project overview, features, adfconsole usage |
| [GETTING_STARTED.md](../GETTING_STARTED.md) | Installation, setup, first run |
| [USAGE.md](USAGE.md) | Web UI, CLI (`archer.py`), and API usage |

---

## Interactive Console (adfconsole)

| Document | Description |
|----------|-------------|
| [README.md — adfconsole](../README.md#-interactive-console-adfconsole) | Commands, modules, example session |

---

## Bespoke Configuration

| Document | Description |
|----------|-------------|
| [bespoke/README.md](../bespoke/README.md) | Bespoke directory structure, mapping files, reference queries |
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
| [RESPONSE_ACTIONS.md](features/RESPONSE_ACTIONS.md) | Automated response action recommendations |
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
| [bespoke/prompts/PROMPT_Interactive_Console.md](../bespoke/prompts/PROMPT_Interactive_Console.md) | Reusable prompt for creating interactive CLI consoles |
| [bespoke/query_templates/DetectionGeneration_Templates.md](../bespoke/query_templates/DetectionGeneration_Templates.md) | Per-telemetry query templates (AWS, Windows, MDE, Unix, Proxy, etc.) |
| [bespoke/llm_references/README.md](../bespoke/llm_references/README.md) | Reference query format and examples |

---

## Status and Roadmap

| Document | Description |
|----------|-------------|
| [UNTESTED.md](other/UNTESTED.md) | Implemented but not validated features |
| [FUTURE.md](other/FUTURE.md) | Planned features and roadmap |

## Output contract

- [archer/contract/README.md](../archer/contract/README.md) — strict output contract v1.0: validator, legacy lint gate, LLM pipeline hook, exemplars and rationale (`archer/contract/docs/`).

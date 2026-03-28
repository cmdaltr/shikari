# Archer Documentation

Complete documentation for the Archer threat detection automation platform.

---

## 🚀 Quick Start

- **[GETTING_STARTED.md](../GETTING_STARTED.md)** - Complete setup and configuration guide
- **[USAGE.md](USAGE.md)** - Web UI, CLI, and API usage guide
- **[BESPOKE.md](BESPOKE.md)** - Organization-specific customization (exclusions, mappings)
- **[README.md](../README.md)** - High-level project overview
- **[UNTESTED.md](UNTESTED.md)** - Features implemented but not validated
- **[FUTURE.md](FUTURE.md)** - Planned features and roadmap

---

## 📁 Documentation Structure

### 🏗️ [`architecture/`](architecture/)
Technical architecture and design documentation:
- **[CORRELATION_ENGINE.md](architecture/CORRELATION_ENGINE.md)** - Complete correlation generation system (scoring, filtering, JOIN queries)
- **[PERFORMANCE_ARCHITECTURE.md](architecture/PERFORMANCE_ARCHITECTURE.md)** - System performance and optimization
- **[SCHEMA_NORMALIZATION.md](architecture/SCHEMA_NORMALIZATION.md)** - Field normalization and schema design

### 📖 [`guides/`](guides/)
User guides and setup instructions:
- **[USAGE.md](USAGE.md)** - Web UI, CLI, and API usage guide
- **[CORRELATION_GUIDE.md](guides/CORRELATION_GUIDE.md)** - Correlation query builder guide
- **[CVE_HUNTING_GUIDE.md](guides/CVE_HUNTING_GUIDE.md)** - CVE-based detection generation
- **[EMULATION_GUIDE.md](guides/EMULATION_GUIDE.md)** - Adversary emulation and remote execution
- **[QUERY_API_GUIDE.md](guides/QUERY_API_GUIDE.md)** - MDE and Splunk API integration
- **[TESTING_GUIDE.md](guides/TESTING_GUIDE.md)** - Testing and validation workflows
- **[IMPORT_TRAINING_QUERIES.md](guides/IMPORT_TRAINING_QUERIES.md)** - Import existing detection queries
- **[MAPPINGS_README.md](guides/MAPPINGS_README.md)** - Mapping system overview
- **[MAPPINGS_INTEGRATION_GUIDE.md](guides/MAPPINGS_INTEGRATION_GUIDE.md)** - Schema normalization integration
- **[MAPPING_SETUP_GUIDE.md](guides/MAPPING_SETUP_GUIDE.md)** - Configure mapping files for your environment
- **[MAPPING_FILES_GUIDE.md](guides/MAPPING_FILES_GUIDE.md)** - Detailed mapping file reference

### 📚 Technical References
- **[Scripts Documentation](SCRIPTS.md)** - Command-line scripts and utilities
- **[Usage Guide](USAGE.md)** - Complete Web UI, CLI, and API reference
- **[API Integration Guide](guides/API_INTEGRATION_GUIDE.md)** - REST API integration with code examples
- **[Auto-Generated API Docs](http://localhost:8000/docs)** - Interactive Swagger UI (requires running server)

### 🧠 [`rag/`](rag/)
RAG (Retrieval-Augmented Generation) fidelity enhancement:
- **[README.md](rag/README.md)** - RAG system overview
- **[RAG_USER_GUIDE.md](rag/RAG_USER_GUIDE.md)** - Quick start guide for RAG enhancement
- **[FIDELITY_SYSTEM_SUMMARY.md](rag/FIDELITY_SYSTEM_SUMMARY.md)** - Implementation summary
- **[FIDELITY_IMPLEMENTATION_GUIDE.md](rag/FIDELITY_IMPLEMENTATION_GUIDE.md)** - Comprehensive implementation guide

### 📂 Data Directory Structure
```
data/
├── external/                    # External/community content
│   ├── repos/                   # Cloned git repos (Sigma, Splunk, Elastic)
│   └── detections/              # Processed detection examples + embeddings
├── bespoke/                     # Legacy org-specific content (gitignored)
├── validation/                  # Test samples and results
└── ml_training/                 # ML training data
```

Organization-specific configuration now lives in the root-level `bespoke/` directory:
```
bespoke/
├── prompts/            # LLM prompt templates for query generation
├── query_templates/    # SIEM query templates per log source
└── mappings/           # Environment-specific field and index mappings
```
Directories are committed empty; files within are gitignored. See **[docs/BESPOKE.md](BESPOKE.md)** for details.

### ✨ [`features/`](features/)
Feature-specific documentation:
- **[AI_TRAINING.md](ai/AI_TRAINING.md)** - AI query training and generation
- **[DETECTION_VALIDATION.md](features/DETECTION_VALIDATION.md)** - Pre-generation validation (cross-platform contamination prevention)
- **[RUNTIME_VALIDATION.md](features/RUNTIME_VALIDATION.md)** - Runtime detection testing in containerized SIEMs
- **[DOCKER.md](features/DOCKER.md)** - Docker deployment guide
- **[OSINT_INTEGRATION.md](features/OSINT_INTEGRATION.md)** - OSINT repository integration
- **[PARENT_SUBTECHNIQUE_EXPANSION.md](features/PARENT_SUBTECHNIQUE_EXPANSION.md)** - Automatic subtechnique generation
- **[SECURITY_FEATURES.md](features/SECURITY_FEATURES.md)** - Authentication, encryption, audit logging

### 🛡️ Threat Briefing
Grounded threat actor prioritisation:
- **[USAGE.md — Threat Briefing](USAGE.md#threat-briefing)** - Web UI walkthrough
- **[API Integration Guide — Workflow 8](guides/API_INTEGRATION_GUIDE.md#workflow-8-threat-briefing)** - API endpoint reference and code examples

### 🔬 Research Tab
Actor technique consolidation and threat landscape analysis:
- **[USAGE.md — Research Tab](USAGE.md#research-tab)** - Keyword/country filtering, actor consolidation, XLSX export, Hunt buttons

### 💬 Ask Archer
Conversational Q&A powered by your configured LLM:
- **[USAGE.md — Ask Archer](USAGE.md#ask-archer)** - Chat interface for ATT&CK questions and SIEM queries

### 🎭 Adversary Emulation
Atomic Red Team integration:
- **[USAGE.md — Adversary Emulation](USAGE.md#adversary-emulation)** - Simulate and execute techniques
- **[Emulation Guide](guides/EMULATION_GUIDE.md)** - Detailed emulation workflows

### 🧪 Testing
Comprehensive test suite:
- **[Test Suite README](../tests/README.md)** - Test categories, running tests, screenshot documentation

### 📝 [`notion/`](notion/)
Notion-formatted versions of documentation (for Notion import)

### 🎨 [`flow/`](flow/)
Architecture diagrams and flow charts

### 🔮 Status Documentation
- **[UNTESTED.md](UNTESTED.md)** - Implemented but unvalidated features (Adversary Emulation, Query Execution)
- **[FUTURE.md](FUTURE.md)** - Planned features and roadmap (VECTR, CALDERA, MACAT)

---

## 📚 Documentation by Task

### Getting Started
1. **New to Archer?** Start with [GETTING_STARTED.md](../GETTING_STARTED.md)
2. **Using Archer?** See [USAGE.md](USAGE.md) for Web UI, CLI, and API guides
3. **Using custom log sources?** Read [Mapping Setup Guide](guides/MAPPING_SETUP_GUIDE.md)
4. **Want to tune correlation quality?** See [Correlation Quick Reference](architecture/CORRELATION_QUICK_REFERENCE.md)

### Integration & Advanced Usage
1. **Need API integration?** Check [API Integration Guide](guides/API_INTEGRATION_GUIDE.md)
2. **CLI workflows?** See [USAGE.md](USAGE.md#command-line-interface-cli)
3. **Exploring untested features?** See [UNTESTED.md](UNTESTED.md)
4. **Planning future deployments?** Review [FUTURE.md](FUTURE.md)

---

## 📊 Key Documentation by Use Case

### For SOC Analysts
- [Getting Started Guide](../GETTING_STARTED.md) - Basic setup
- [Usage Guide](USAGE.md) - Web UI, CLI, and API reference
- [Research Tab](USAGE.md#research-tab) - Threat landscape analysis, actor consolidation, XLSX export
- [Threat Briefing](USAGE.md#threat-briefing) - Grounded detection prioritisation for a threat group
- [Ask Archer](USAGE.md#ask-archer) - Conversational Q&A for ATT&CK and SIEM queries
- [Correlation Guide](guides/CORRELATION_GUIDE.md) - Using the correlation builder
- [CVE Hunting Guide](guides/CVE_HUNTING_GUIDE.md) - CVE-based detection

### For Security Engineers
- [Usage Guide](USAGE.md) - Complete usage reference
- [Correlation Quick Reference](architecture/CORRELATION_QUICK_REFERENCE.md) - Tune correlation parameters
- [Detection Validation](features/DETECTION_VALIDATION.md) - Validate detection quality
- [Testing Guide](guides/TESTING_GUIDE.md) - Testing workflows

### For Platform Administrators
- [Mapping Setup Guide](guides/MAPPING_SETUP_GUIDE.md) - Configure for your environment
- [API Integration Guide](guides/API_INTEGRATION_GUIDE.md) - REST API integration
- [Security Features](features/SECURITY_FEATURES.md) - User management and security

### For Developers
- [Usage Guide](USAGE.md#api-integration) - API usage and workflows
- [Correlation Engine](architecture/CORRELATION_ENGINE.md) - Engine internals and per-technique query output
- [Performance Architecture](architecture/PERFORMANCE_ARCHITECTURE.md) - System design
- [Schema Normalization](architecture/SCHEMA_NORMALIZATION.md) - Field mapping
- [API Integration Guide](guides/API_INTEGRATION_GUIDE.md) - REST API workflows and examples
- [Threat Briefing API](guides/API_INTEGRATION_GUIDE.md#workflow-8-threat-briefing) - `/api/threat-briefing` endpoint
- [RAG Implementation](rag/FIDELITY_IMPLEMENTATION_GUIDE.md) - RAG fidelity enhancement system

---

## 🔗 External Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---

**Version**: 1.3
**Last Updated**: March 22, 2026

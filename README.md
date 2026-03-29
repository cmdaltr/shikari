<div align="center">
<a href="https://github.com/cmdaltr/archer">
<img src="static/images/archer_banner.png" alt="Archer - Automated Multi-Vendor Threat HUNTING & DETECTION SUITE" width="600px" height="600px">
</a>
</div>

<br>

Archer is a modular Python service for automated threat hunting with optional adversary emulation and hunt tracking integrations. Generate detection queries, validate with real attack execution, and track hunts with VECTR integration.

## 🛠️ Setup and Usage

**📖 Setup instructions: [GETTING_STARTED.md](GETTING_STARTED.md)**

**⌨️ Usage instructions and guidance: [USAGE.md](docs/USAGE.md)**

---
<br>

## ✨ Features

### Core Capabilities
- 🎯 **MITRE ATT&CK Integration** - Automated detection generation from threat group TTPs
- 📤 **File Upload & Intelligence Extraction** - Upload threat intel files (PDF, TXT, JSON, CSV, XLSX, YARA, DOCX) for automatic TTP/IOC extraction
- 🌐 **Blog Analysis** - Paste a threat intel blog URL and extract TTPs/IOCs automatically
- 🔍 **Multi-Platform Support** - Splunk (SPL), KQL (Microsoft Defender/Sentinel), Google SecOps (YARA-L) and Elastic (DSL) queries
- 🧠 **Heuristic and AI-Powered Correlations** - Semantic analysis and query correlation with per-technique chained queries
- 🛡️ **Threat Briefing** - Grounded ATT&CK prioritisation grounded in real MITRE data and your detection coverage gaps
- 🔬 **Research Tab** - Actor technique consolidation with keyword/country filtering, tactic filtering, and professional XLSX export
- 💬 **Ask Archer** - Conversational Q&A panel for ATT&CK questions and SIEM query generation
- 🌐 **Web UI & CLI** - VirusTotal-inspired tabbed interface plus command-line tools
- 🖥️ **Interactive Console (`adfconsole`)** - Metasploit-style interactive shell with module selection, options, tab-completion
- 🎯 **RAG Fidelity Enhancement** - Improve query quality using 4,800+ community detection examples ([docs](docs/rag/README.md))
- 🏢 **Organization-Specific Customization** - Bespoke sample searches and global exclusions for your environment

### Additional Features

- **Detection Validation** - Test queries against containerized SIEMs with sample events ([docs](docs/features/RUNTIME_VALIDATION.md))
- **Detection Library** - Save, search, tag, share, and export your generated detections
- **Adversary Emulation** - Atomic Red Team integration for simulate/execute modes
- **Company Profiling** - Industry-aware threat landscape analysis for targeted detection
- **CVE Hunting** - Generate detections from CVE IDs with NVD enrichment
- **Query Execution** - MDE/Splunk API integration (code implemented, see [UNTESTED.md](docs/UNTESTED.md))
- **VECTR, CALDERA, MACAT** - Planned integrations (see [FUTURE.md](docs/other/FUTURE.md))

### Security & User Management
- 🔐 **Enterprise Authentication** - Bcrypt password hashing, session management, MFA support (TOTP)
- 🛡️ **Security Features** - Rate limiting, CSRF protection, account lockout, audit logging
- 👥 **Admin User Management** - Complete CRUD API for user accounts (create, read, update, deactivate)
- 📧 **Email Integration** - SMTP-based password reset with secure token delivery
- 🔑 **API Key Encryption** - Fernet encryption for stored SIEM/AI API credentials
- 📊 **Comprehensive Audit Logs** - Track all authentication events and admin actions
- 🔒 **Role-Based Access Control** - Admin and Standard user roles with granular permissions

---
<br>

## 📚 Documentation & Resources

### Archer Documentation

**📖 [Complete Documentation Index](docs/DOCS.md)** - Browse all documentation by category

**Quick Links:**
- **Getting Started:** [GETTING_STARTED.md](GETTING_STARTED.md) | [Mapping Setup](docs/guides/MAPPING_SETUP_GUIDE.md)
- **Interactive Console:** [adfconsole Guide](#-interactive-console-adfconsole)
- **Usage:** [Web UI, CLI & API](docs/USAGE.md) | [Auto-Generated API Docs](http://localhost:8000/docs)
- **Research Tab:** [Actor Consolidation & XLSX Export](docs/USAGE.md#research-tab)
- **Threat Briefing:** [Usage Guide](docs/USAGE.md#threat-briefing) | [API Reference](docs/guides/API_INTEGRATION_GUIDE.md#workflow-8-threat-briefing)
- **Ask Archer:** [Conversational Q&A](docs/USAGE.md#ask-archer)
- **API Integration:** [API Integration Guide](docs/guides/API_INTEGRATION_GUIDE.md)
- **Correlation Tuning:** [Correlation Engine](docs/architecture/CORRELATION_ENGINE.md) | [Quick Reference](docs/architecture/CORRELATION_QUICK_REFERENCE.md)
- **Features:** [Security](docs/features/SECURITY_FEATURES.md) | [AI Training](docs/ai/AI_TRAINING.md) | [OSINT](docs/features/OSINT_INTEGRATION.md)
- **RAG Enhancement:** [RAG User Guide](docs/rag/RAG_USER_GUIDE.md) | [Implementation Guide](docs/rag/FIDELITY_IMPLEMENTATION_GUIDE.md)
- **Testing:** [Test Suite](tests/README.md) | [Run Tests](tests/run_all_tests.sh)
- **Architecture:** [Performance](docs/architecture/PERFORMANCE_ARCHITECTURE.md) | [Schema Normalization](docs/architecture/SCHEMA_NORMALIZATION.md)

### External Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [VECTR](https://vectr.io/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---
<br>

## 🖥️ Interactive Console (adfconsole)

`adfconsole` is a Metasploit-style interactive shell for building detection queries, running correlations, hunting techniques, and executing adversary emulations.

### Launch

```bash
./adfconsole
```

### Modules

| Module | Description |
|--------|-------------|
| `generate` | Generate detection queries for a MITRE ATT&CK threat group |
| `correlate` | Build correlation queries from existing detection YAMLs |
| `hunt` | Hunt for a specific technique and generate detections |
| `emulate` | Execute adversary emulation tests |

### Commands

| Command | Description |
|---------|-------------|
| `use <module>` | Select a module |
| `show modules` | List available modules |
| `show options` | Display current module's configurable options |
| `set <OPT> <val>` | Set a module option |
| `unset <OPT>` | Clear a module option |
| `run` | Execute the selected module |
| `info` | Show module details |
| `back` | Deselect current module |
| `exit` | Exit the console |

Tab-completion is supported for commands, module names, option names, and option values.

### Example Session

```
$ ./adfconsole

adfconsole > use generate
adfconsole (generate) > set GROUP APT29
  GROUP => APT29
adfconsole (generate) > set MODE llm
  MODE => llm
adfconsole (generate) > set CORRELATE true
  CORRELATE => True
adfconsole (generate) > show options

  Module options (generate):

  Name                 Current Value             Required   Description
  ----                 -------------             --------   -----------
  GROUP                APT29                     yes        Threat group name
  MODE                 llm                       no         Query generation mode
  CORRELATE            True                      no         Run correlation after generation
  HYPOTHESIS                                     no         Optional hypothesis
  OSINT                False                     no         Enable OSINT enhancement
  OSINT_COMPARE        False                     no         Enable OSINT comparison

adfconsole (generate) > run
[*] Generating detections for APT29 (mode: llm)
...
```

### Query Generation Modes

The `generate` module supports three modes via `set MODE <mode>`:

| Mode | Description |
|------|-------------|
| `standard` | Default — uses Archer's built-in indicator extraction and platform validation |
| `llm` | Sends bespoke prompt templates + technique data to an LLM for high-fidelity query generation (requires `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `LLM_ENDPOINT`) |
| `fallback` | Template-based query builder — maps MITRESaw evidence indicators to SIEM fields using bespoke mapping files, no LLM needed |

---
<br>

## 🤝 Contributing

Feel free to open issues or submit pull requests to improve Archer.

---
<br>

## 📝 License

This project is licensed under the MIT License. See the LICENSE file for details.

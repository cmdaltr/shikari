# Archer Documentation

Comprehensive documentation for the Archer threat hunting application.

## Quick Start

- **[GETTING_STARTED.md](GETTING_STARTED.md)** 🚀 - **START HERE**: Setup guide & troubleshooting
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture overview
- **[CORRELATION_GUIDE.md](CORRELATION_GUIDE.md)** - Correlation query builder guide
- **[EMULATION_GUIDE.md](EMULATION_GUIDE.md)** - Adversary emulation and remote execution
- **[QUERY_API_GUIDE.md](QUERY_API_GUIDE.md)** - MDE and Splunk API integration
- **[VECTR_INTEGRATION.md](VECTR_INTEGRATION.md)** - VECTR hunt tracking integration

---

## Main Documentation

### GETTING_STARTED.md 🚀
**Setup, configuration, and troubleshooting guide**

- Quick setup (5 steps)
- Virtual environment setup
- Common commands (venv, running, Docker, development)
- Directory structure
- Troubleshooting common issues
- Configuration and environment variables
- Quick reference tables

### ARCHITECTURE.md
**System architecture and optional module integration**

- Core architecture overview
- Optional feature modules:
  - **Emulation** - Local and remote execution (SSH/WinRM)
  - **Query Execution** - MDE and Splunk API clients
  - **VECTR** - Hunt tracking integration
- Plugin-based design principles
- Configuration management
- Integration workflows (5 complete examples)
- Security considerations
- Future enhancements roadmap

### CORRELATION_GUIDE.md
**Complete guide to the correlation query builder system**

- Overview and features
- Usage examples (CLI, programmatic, standalone)
- Configuration options
- Output structure and format
- How the relevance scoring works
- Platform-specific query generation (MDE/KQL and Splunk)
- Advanced usage and customization
- Module reference and API
- **Appendix A**: Local AI model setup
- **Appendix B**: Semantic overlap algorithm

### EMULATION_GUIDE.md
**Adversary emulation with Atomic Red Team**

- Setup and configuration
- Local execution (simulation and live)
- **Remote execution** (SSH/WinRM):
  - SSH key authentication
  - WinRM HTTPS/HTTP support
  - Cross-platform testing
  - Remote artifact collection
- Single technique emulation
- Threat group emulation (bulk testing)
- Evidence collection and enrichment
- Safety modes and best practices
- Troubleshooting

### QUERY_API_GUIDE.md
**MDE and Splunk API integration**

- **Microsoft Defender for Endpoint (MDE)**:
  - Azure AD App Registration
  - OAuth2 authentication
  - KQL query execution
  - Advanced Hunting API
- **Splunk**:
  - REST API setup
  - Session authentication
  - SPL query execution
  - Job-based search
- Security best practices
- Troubleshooting and optimization
- Future CLI integration

### VECTR_INTEGRATION.md
**VECTR integration for hunt tracking**

- Setup and configuration
- Export detections to campaigns
- Import test results
- Bidirectional sync
- Coverage reporting
- Purple team collaboration

---

## Documentation Structure

```
docs/
├── README.md                     # This file - documentation index
├── GETTING_STARTED.md            # Setup & troubleshooting 🚀
├── ARCHITECTURE.md               # System architecture
├── CORRELATION_GUIDE.md          # Correlation builder guide (with AI appendices)
├── EMULATION_GUIDE.md            # Adversary emulation (local + remote)
├── QUERY_API_GUIDE.md            # MDE/Splunk API integration
├── VECTR_INTEGRATION.md          # Hunt tracking integration
├── archive/                      # Historical documents
│   ├── README.md
│   ├── CLEANUP_REPORT.md
│   └── GENAI_RESTRUCTURE.md
└── flow/                         # Architecture diagrams
    ├── archer_flow.pdf
    ├── archer_flow.png
    └── archer_flow.dot
```

---

## Finding What You Need

**I want to...**

- **Get Archer running** → [GETTING_STARTED.md](GETTING_STARTED.md) 🚀
- **Troubleshoot setup issues** → [GETTING_STARTED.md](GETTING_STARTED.md)
- **Understand the architecture** → [ARCHITECTURE.md](ARCHITECTURE.md)
- **Build correlation queries** → [CORRELATION_GUIDE.md](CORRELATION_GUIDE.md)
- **Set up adversary emulation** → [EMULATION_GUIDE.md](EMULATION_GUIDE.md)
- **Run emulations remotely via SSH/WinRM** → [EMULATION_GUIDE.md](EMULATION_GUIDE.md)
- **Execute queries via MDE/Splunk APIs** → [QUERY_API_GUIDE.md](QUERY_API_GUIDE.md)
- **Integrate with VECTR** → [VECTR_INTEGRATION.md](VECTR_INTEGRATION.md)
- **Set up local AI models** → [CORRELATION_GUIDE.md - Appendix A](CORRELATION_GUIDE.md#appendix-a-local-ai-model-setup)
- **Understand semantic overlap** → [CORRELATION_GUIDE.md - Appendix B](CORRELATION_GUIDE.md#appendix-b-semantic-overlap-algorithm)
- **See architecture diagrams** → [flow/](flow/)
- **Review past changes** → [archive/](archive/)

---

## Key Features Documentation

### Core Features
- **Detection Generation** - [GETTING_STARTED.md](GETTING_STARTED.md)
- **Correlation Building** - [CORRELATION_GUIDE.md](CORRELATION_GUIDE.md)
- **System Architecture** - [ARCHITECTURE.md](ARCHITECTURE.md)

### Optional Modules
- **Local Emulation** - [EMULATION_GUIDE.md](EMULATION_GUIDE.md)
- **Remote Emulation (SSH/WinRM)** - [EMULATION_GUIDE.md - Remote Execution](EMULATION_GUIDE.md#2-remote-execution)
- **Query Execution (MDE/Splunk)** - [QUERY_API_GUIDE.md](QUERY_API_GUIDE.md)
- **VECTR Integration** - [VECTR_INTEGRATION.md](VECTR_INTEGRATION.md)

### Advanced Features
- **AI-Powered Correlations** - [CORRELATION_GUIDE.md](CORRELATION_GUIDE.md)
- **Local LLM Support** - [CORRELATION_GUIDE.md - Appendix A](CORRELATION_GUIDE.md#appendix-a-local-ai-model-setup)
- **Semantic Analysis** - [CORRELATION_GUIDE.md - Appendix B](CORRELATION_GUIDE.md#appendix-b-semantic-overlap-algorithm)

---

## Contributing

When adding new documentation:

1. **User guides** go in the main `docs/` directory
2. **Historical records** go in `docs/archive/`
3. **Diagrams and visuals** go in appropriate subdirectories (e.g., `flow/`)
4. Update this README with new document links
5. Keep documents focused and concise
6. Use descriptive filenames (e.g., `FEATURE_GUIDE.md` not `FEATURE.md`)

---

## Related Documentation

- **[../README.md](../README.md)** - Main project README
- **[../archer/genai/](../archer/genai/)** - Source code for correlation engine
- **[../archer/emulation/](../archer/emulation/)** - Source code for emulation module
- **[../archer/query/](../archer/query/)** - Source code for query execution module

---

**Last Updated**: October 6, 2025

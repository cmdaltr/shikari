# Archer Documentation

Comprehensive documentation for the Archer threat hunting application.

## Quick Start

- **[GETTING_STARTED.md](GETTING_STARTED.md)** 🚀 - **START HERE**: Setup guide & troubleshooting
- **[SCHEMA_CUSTOMIZATION.md](SCHEMA_CUSTOMIZATION.md)** 🔧 - **CRITICAL**: Configure log source field mappings
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture overview
- **[QUERY_LEARNING_SYSTEM.md](QUERY_LEARNING_SYSTEM.md)** - AI-powered query generation system
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

### SCHEMA_CUSTOMIZATION.md 🔧
**Configure log source field mappings for your environment**

- Why schema customization is required
- Understanding schemaSplunk.json and schemaMDE.json
- Step-by-step customization guide
- Real-world examples (ES with CIM, Splunk Cloud, custom fields)
- Common pitfalls and solutions
- Validation and testing
- Adding new log sources (AWS CloudTrail, Azure AD, etc.)

### QUERY_LEARNING_SYSTEM.md
**AI-powered query generation with few-shot learning**

- Query learning system overview
- Supported query repositories (Splunk Security Content, Sigma, MDE)
- Architecture and flow
- Setup and configuration
- Schema integration with AI generation
- How few-shot learning works
- Real-world examples and best practices

---

## Documentation Structure

```
docs/
├── README.md                          # This file - documentation index
├── GETTING_STARTED.md                 # Setup & troubleshooting 🚀
├── SCHEMA_CUSTOMIZATION.md            # Log source field mapping guide 🔧
├── ARCHITECTURE.md                    # System architecture
├── QUERY_LEARNING_SYSTEM.md           # AI-powered query generation
├── QUICK_START_QUERY_LEARNING.md      # Query learning quick start
├── HOW_QUERY_LEARNING_WORKS.md        # Query learning technical details
├── ADDING_QUERY_REPOSITORIES.md       # Adding new query sources
├── CORRELATION_GUIDE.md               # Correlation builder guide
├── EMULATION_GUIDE.md                 # Adversary emulation (local + remote)
├── QUERY_API_GUIDE.md                 # MDE/Splunk API integration
├── VECTR_INTEGRATION.md               # Hunt tracking integration
├── UPLOAD_FEATURE.md                  # File upload & extraction guide
├── DIRECTORY_STRUCTURE.md             # Project organization
├── SECURITY.md                        # Security best practices
├── DISABLED_FEATURES.md               # Disabled features reference
├── TESTING_GUIDE.md                   # Testing procedures
├── PLAYWRIGHT_TESTING.md              # UI testing with Playwright
├── TEST_RESULTS.md                    # Test results documentation
├── archive/                           # Historical documentation
│   ├── implementation/                # Implementation notes & fixes
│   │   ├── IOC_EXTRACTION_EVOLUTION docs (7 files)
│   │   ├── IMPLEMENTATION milestones (4 files)
│   │   └── OTHER fixes and updates (5 files)
│   └── ui_changes/                    # UI change history
│       ├── BANNER_IMPLEMENTATION.md
│       ├── LOGO_UPDATE_COMPLETE.md
│       └── OTHER design updates (3 files)
├── architecture/                      # Architecture diagrams
│   ├── cli_diagram.png
│   ├── cli_diagram.dot
│   ├── web_diagram.png
│   └── web_diagram.dot
└── flow/                              # Flow diagrams
    ├── archer_flow.pdf
    ├── archer_flow.png
    └── archer_flow.dot
```

---

## Finding What You Need

**I want to...**

- **Get Archer running** → [GETTING_STARTED.md](GETTING_STARTED.md) 🚀
- **Configure my log source field names** → [SCHEMA_CUSTOMIZATION.md](SCHEMA_CUSTOMIZATION.md) 🔧
- **Troubleshoot setup issues** → [GETTING_STARTED.md](GETTING_STARTED.md)
- **Understand the architecture** → [ARCHITECTURE.md](ARCHITECTURE.md)
- **Enable AI-powered query generation** → [QUERY_LEARNING_SYSTEM.md](QUERY_LEARNING_SYSTEM.md)
- **Build correlation queries** → [CORRELATION_GUIDE.md](CORRELATION_GUIDE.md)
- **Set up adversary emulation** → [EMULATION_GUIDE.md](EMULATION_GUIDE.md)
- **Run emulations remotely via SSH/WinRM** → [EMULATION_GUIDE.md](EMULATION_GUIDE.md)
- **Execute queries via MDE/Splunk APIs** → [QUERY_API_GUIDE.md](QUERY_API_GUIDE.md)
- **Integrate with VECTR** → [VECTR_INTEGRATION.md](VECTR_INTEGRATION.md)
- **Upload threat reports for TTP extraction** → [UPLOAD_FEATURE.md](UPLOAD_FEATURE.md)
- **Add new query example repositories** → [ADDING_QUERY_REPOSITORIES.md](ADDING_QUERY_REPOSITORIES.md)
- **Set up local AI models** → [CORRELATION_GUIDE.md - Appendix A](CORRELATION_GUIDE.md#appendix-a-local-ai-model-setup)
- **Understand semantic overlap** → [CORRELATION_GUIDE.md - Appendix B](CORRELATION_GUIDE.md#appendix-b-semantic-overlap-algorithm)
- **See architecture diagrams** → [architecture/](architecture/) and [flow/](flow/)
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

**Last Updated**: October 15, 2025

---

## Recent Documentation Updates

### October 15, 2025
- ✅ **NEW**: [SCHEMA_CUSTOMIZATION.md](SCHEMA_CUSTOMIZATION.md) - Comprehensive guide for configuring log source field mappings
- 🗂️ **Organized**: Moved 16 implementation notes and 5 UI change documents to `archive/` for better organization
- 📊 **Reduced clutter**: Main docs directory now contains only active, user-facing documentation
- 🔗 **Updated links**: All references to archived documents updated
- 📈 **Better navigation**: Enhanced "Finding What You Need" section with new guides

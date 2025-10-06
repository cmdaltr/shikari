# Archer Documentation

Comprehensive documentation for the Archer threat hunting application.

## Quick Start

- **[SUPPORT.md](SUPPORT.md)** 🚀 - **START HERE**: Setup guide & troubleshooting
- **[CORRELATIONS.md](CORRELATIONS.md)** - Main guide for correlation query builder (opt-in)
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture, emulation & VECTR integration
- **[EMULATION.md](EMULATION.md)** - Adversary emulation guide (Atomic Red Team)
- **[VECTR.md](VECTR.md)** - VECTR integration guide for hunt tracking
- **[MODELS.md](MODELS.md)** - Setup guide for local AI models
- **[SEMANTICS.md](SEMANTICS.md)** - Technical reference for semantic overlap scoring

## Main Documentation

### SUPPORT.md 🚀
**Setup, configuration, and troubleshooting guide**

- Quick setup (5 steps)
- Virtual environment setup
- Common commands (venv, running, Docker, development)
- Directory structure
- Troubleshooting common issues
- Configuration and environment variables
- Quick reference tables

### CORRELATIONS.md
**The complete guide to the correlation query builder system (opt-in)**

- Overview and features
- Usage examples (CLI with `--correlate` flag, programmatic, standalone)
- Configuration options
- Output structure and format
- How the relevance scoring works
- Platform-specific query generation (MDE/KQL and Splunk)
- Advanced usage and customization
- Module reference and API

### ARCHITECTURE.md
**System architecture and optional module integration**

- Core architecture overview
- Optional feature modules (emulation, VECTR)
- Plugin-based design principles
- Configuration management
- Integration workflows (4 complete examples)
- Security considerations

### EMULATION.md
**Adversary emulation with Atomic Red Team**

- Setup and configuration
- Single technique emulation
- Threat group emulation (bulk testing)
- Evidence collection and enrichment
- Safety modes (simulate vs. live)

### VECTR.md
**VECTR integration for hunt tracking**

- Setup and configuration
- Export detections to campaigns
- Import test results
- Bidirectional sync
- Coverage reporting

### MODELS.md
**Setup guide for running local AI models with llama.cpp**

- Prerequisites and installation (macOS M1/M2)
- Model download and configuration
- Environment variables
- Running the smoke test
- Troubleshooting tips

### SEMANTICS.md
**Technical explanation of the semantic overlap algorithm**

- How overlap percentage is calculated
- What counts toward overlap
- What's ignored (common KQL keywords)
- Interpreting the percentage
- Limitations and caveats

## Additional Resources

### Flow Diagrams
The `flow/` directory contains architecture diagrams:
- `archer_flow.pdf` - Visual workflow diagram
- `archer_flow.png` - PNG version
- `archer_flow.dot` - Graphviz source

### Archive
The `archive/` directory contains historical documentation:
- `CLEANUP_REPORT.md` - Codebase cleanup (Oct 2025)
- `GENAI_RESTRUCTURE.md` - Module reorganization (Oct 2025)

## Documentation Structure

```
docs/
├── README.md                     # This file
├── SUPPORT.md                    # Setup & troubleshooting (300+ lines) 🚀
├── CORRELATIONS.md        # Main user guide (400+ lines)
├── MODELS.md                # AI setup guide (61 lines)
├── SEMANTICS.md           # Technical reference (48 lines)
├── archive/                      # Historical documents
│   ├── README.md
│   ├── CLEANUP_REPORT.md
│   └── GENAI_RESTRUCTURE.md
└── flow/                         # Architecture diagrams
    ├── archer_flow.pdf
    ├── archer_flow.png
    └── archer_flow.dot
```

## Finding What You Need

**I want to...**

- **Get Archer running** → [SUPPORT.md](SUPPORT.md) 🚀
- **Troubleshoot setup issues** → [SUPPORT.md](SUPPORT.md)
- **Build correlation queries** → [CORRELATIONS.md](CORRELATIONS.md)
- **Understand the architecture** → [ARCHITECTURE.md](ARCHITECTURE.md)
- **Set up adversary emulation** → [EMULATION.md](EMULATION.md)
- **Integrate with VECTR** → [VECTR.md](VECTR.md)
- **Set up local AI models** → [MODELS.md](MODELS.md)
- **Understand semantic overlap** → [SEMANTICS.md](SEMANTICS.md)
- **See architecture diagrams** → [flow/](flow/)
- **Review past changes** → [archive/](archive/)

## Contributing

When adding new documentation:

1. **User guides** go in the main `docs/` directory
2. **Historical records** go in `docs/archive/`
3. **Diagrams and visuals** go in appropriate subdirectories (e.g., `flow/`)
4. Update this README with new document links
5. Keep documents focused and concise

## Related Documentation

- **[../README.md](../README.md)** - Main project README
- **[../archer/genai/](../archer/genai/)** - Source code for correlation engine

---

**Last Updated**: October 4, 2025

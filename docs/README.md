# Archer Documentation

Comprehensive documentation for the Archer threat hunting application.

## Quick Start

- **[SUPPORT.md](SUPPORT.md)** 🚀 - **START HERE**: Setup guide & troubleshooting
- **[CORRELATION_BUILDER.md](CORRELATION_BUILDER.md)** - Main guide for correlation query builder
- **[LOCAL_LLAMA.md](LOCAL_LLAMA.md)** - Setup guide for local AI models
- **[semantic-overlap.md](semantic-overlap.md)** - Technical reference for semantic overlap scoring

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
**The complete guide to the correlation query builder system**

- Overview and features
- Usage examples (CLI, programmatic, standalone)
- Configuration options
- Output structure and format
- How the relevance scoring works
- Platform-specific query generation (MDE/KQL and Splunk)
- Advanced usage and customization
- Module reference and API

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
├── CORRELATION_BUILDER.md        # Main user guide (400+ lines)
├── LOCAL_LLAMA.md                # AI setup guide (61 lines)
├── semantic-overlap.md           # Technical reference (48 lines)
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
- **Build correlation queries** → [CORRELATION_BUILDER.md](CORRELATION_BUILDER.md)
- **Set up local AI models** → [LOCAL_LLAMA.md](LOCAL_LLAMA.md)
- **Understand semantic overlap** → [semantic-overlap.md](semantic-overlap.md)
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
- **[../gorgon/genai/](../gorgon/genai/)** - Source code for correlation engine

---

**Last Updated**: October 4, 2025

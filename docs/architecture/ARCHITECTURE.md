# Architecture Documentation

Complete architecture and design documentation for Archer.

## Architecture Documents

### Core Architecture
- **[CORRELATION_ENGINE.md](CORRELATION_ENGINE.md)** - Correlation engine design and scoring system
- **[PERFORMANCE_ARCHITECTURE.md](PERFORMANCE_ARCHITECTURE.md)** - Performance optimization and scaling
- **[SCHEMA_NORMALIZATION.md](SCHEMA_NORMALIZATION.md)** - YAML schema standardization

### System Diagrams

#### Flow Diagrams
Located in `diagrams/flow/`:
- `archer_flow.dot` - System flow (GraphViz source)
- `archer_flow.pdf` - System flow (PDF)
- `archer_flow.png` - System flow (PNG)

#### Component Diagrams
Located in `diagrams/components/`:
- `cli_diagram.dot/pdf/png` - CLI architecture
- `web_diagram.dot/pdf/png` - Web interface architecture

### Updating Diagrams

To regenerate diagrams from .dot files:

```bash
# Flow diagrams
cd docs/architecture/diagrams/flow
python update.py

# Component diagrams
cd docs/architecture/diagrams/components
python update.py
```

## Quick Links

### For Developers
- [Correlation Engine](CORRELATION_ENGINE.md) - Understanding correlation generation
- [Performance](PERFORMANCE_ARCHITECTURE.md) - Optimization strategies
- [Schema](SCHEMA_NORMALIZATION.md) - YAML schema design

### For Architects
- [System Flow Diagram](diagrams/flow/archer_flow.pdf) - Overall system flow
- [CLI Architecture](diagrams/components/cli_diagram.pdf) - Command-line interface
- [Web Architecture](diagrams/components/web_diagram.pdf) - Web application structure

## Directory Structure

```
docs/architecture/
├── README.md                      # This file
├── CORRELATION_ENGINE.md          # Correlation system design
├── PERFORMANCE_ARCHITECTURE.md    # Performance documentation
├── SCHEMA_NORMALIZATION.md        # Schema design
└── diagrams/
    ├── flow/                      # System flow diagrams
    │   ├── archer_flow.dot
    │   ├── archer_flow.pdf
    │   ├── archer_flow.png
    │   └── update.py
    └── components/                # Component diagrams
        ├── cli_diagram.dot/pdf/png
        ├── web_diagram.dot/pdf/png
        └── update.py
```


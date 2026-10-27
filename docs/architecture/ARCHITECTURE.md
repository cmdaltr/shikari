# Architecture Documentation

Complete architecture and design documentation for Archer.

## Architecture Documents

### Core Architecture
- **[CORRELATION_ENGINE.md](CORRELATION_ENGINE.md)** - Correlation engine design and scoring system
- **[PERFORMANCE_ARCHITECTURE.md](PERFORMANCE_ARCHITECTURE.md)** - Performance optimization and scaling
- **[SCHEMA_NORMALIZATION.md](SCHEMA_NORMALIZATION.md)** - YAML schema standardization

### System Diagrams

The component architecture (web UI and `archer-cli`) is now a single
theme-aware inline HTML/SVG diagram at `static/diagrams/architecture.html`,
rendered on the Help page. The old Graphviz `cli_diagram`/`web_diagram`
DOT pipeline has been retired.

#### Flow Diagrams
Located in `diagrams/flow/`:
- `archer_flow.dot` - System flow (GraphViz source)
- `archer_flow.pdf` - System flow (PDF)
- `archer_flow.png` - System flow (PNG)

### Updating Diagrams

To regenerate the flow diagram from its .dot file:

```bash
cd docs/architecture/diagrams/flow
python update.py
```

## Quick Links

### For Developers
- [Correlation Engine](CORRELATION_ENGINE.md) - Understanding correlation generation
- [Performance](PERFORMANCE_ARCHITECTURE.md) - Optimization strategies
- [Schema](SCHEMA_NORMALIZATION.md) - YAML schema design

### For Architects
- [System Flow Diagram](diagrams/flow/archer_flow.pdf) - Overall system flow
- [Component Architecture](../../static/diagrams/architecture.html) - Web UI and `archer-cli` (inline, on the Help page)
- [Generation Flow](../../static/diagrams/pipeline.html) - Step-by-step input → MITRESaw → queries → correlation → artefacts (light)
- [The Archer Machine](../../static/diagrams/machine.html) - Interactive 3D isometric view of the runtime (three.js; drag/zoom/click)

## Directory Structure

```
docs/architecture/
├── README.md                      # This file
├── CORRELATION_ENGINE.md          # Correlation system design
├── PERFORMANCE_ARCHITECTURE.md    # Performance documentation
├── SCHEMA_NORMALIZATION.md        # Schema design
└── diagrams/
    └── flow/                      # System flow diagrams
        ├── archer_flow.dot
        ├── archer_flow.pdf
        ├── archer_flow.png
        └── update.py
```

The component architecture (web UI and `archer-cli`) lives at
`static/diagrams/architecture.html`. Two companion views sit beside it:
`static/diagrams/pipeline.html` (a light, top-to-bottom generation flow) and
`static/diagrams/machine.html` (an interactive 3D isometric runtime scene). All
three are linked from the Architecture tab on the Help page.


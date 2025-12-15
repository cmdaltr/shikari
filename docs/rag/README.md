# RAG Fidelity Enhancement Documentation

This directory contains documentation for the RAG (Retrieval-Augmented Generation) fidelity enhancement system.

## Documents

| Document | Description | Audience |
|----------|-------------|----------|
| [RAG_USER_GUIDE.md](RAG_USER_GUIDE.md) | Quick start guide for using RAG enhancement | End users |
| [FIDELITY_SYSTEM_SUMMARY.md](FIDELITY_SYSTEM_SUMMARY.md) | Implementation summary and status | Developers |
| [FIDELITY_IMPLEMENTATION_GUIDE.md](FIDELITY_IMPLEMENTATION_GUIDE.md) | Comprehensive implementation guide | Developers |

## Quick Start

```bash
# 1. Build embeddings (one-time setup)
python3 scripts/build_embeddings.py

# 2. Test retrieval
python3 scripts/test_retrieval.py --technique T1003.001 --platform Splunk

# 3. RAG is now active for query generation
```

## Data Directory Structure

```
data/
├── external/
│   ├── repos/           # Cloned community repos (Sigma, Splunk, Elastic)
│   └── detections/      # Processed detection examples + embeddings
├── bespoke/             # Organization-specific content (gitignored)
│   ├── sample_searches/ # Custom search examples
│   └── exclusions.yaml  # Global query exclusions
└── ml_training/         # ML training data
```

## See Also

- Main documentation: [docs/USAGE.md](../USAGE.md)
- Scripts documentation: [docs/SCRIPTS.md](../SCRIPTS.md)

# Query Examples Repository

> **Status (2026-10-16):** some of what this document names was never built: `scripts/manage_query_examples.py` and `docs/QUERY_LEARNING_SYSTEM.md`; the examples are loaded by `shikari/ai/genai/query_examples.py` from `data/query_examples.json`. What exists: `scripts/config/` (`setup_knowledge_base.py`, `import_community_rules.py`, `build_embeddings.py`, `search_similar_detections.py`, `validate_detections.py`, `quickstart_rag.py`), `scripts/ai/` (`setup_local_llm.py`, `train_ai.py`), `scripts/data/` and `scripts/validation/`: see [SCRIPTS.md](../../../docs/SCRIPTS.md).

This directory contains downloaded query examples from open source security repositories, used to enhance detection query generation through few-shot learning.

## Contents

When populated, this directory contains:

- **splunk_security_content/** - Splunk Security Content repository
- **defender_hunting/** - Microsoft Defender hunting queries repository
- **index.json** - Search index mapping techniques to examples

## Setup

To download and index query examples:

```bash
# Download repositories (~300MB)
python scripts/manage_query_examples.py update

# Build search index
python scripts/manage_query_examples.py rebuild

# View statistics
python scripts/manage_query_examples.py stats
```

## Why These Repositories?

- **Splunk Security Content**: Production-ready queries from Splunk's Enterprise Security team
- **Defender Hunting**: Real-world threat hunting patterns from Microsoft security researchers

## Storage Requirements

- Total size: ~300MB (repositories)
- Index size: ~50MB (index.json)
- This directory is excluded from Git (see .gitignore)

## Documentation

See docs/QUERY_LEARNING_SYSTEM.md for complete documentation.

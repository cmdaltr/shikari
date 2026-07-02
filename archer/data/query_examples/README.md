# Query Examples Repository

This directory contains downloaded query examples from open source security repositories, used to enhance detection query generation through few-shot learning.

## Contents

When populated, this directory contains:

- **splunk_security_content/** - Splunk Security Content repository
- **sigma/** - SigmaHQ Sigma rules repository
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
- **SigmaHQ Sigma**: Vendor-agnostic rules used by security teams worldwide
- **Defender Hunting**: Real-world threat hunting patterns from Microsoft security researchers

## Storage Requirements

- Total size: ~300MB (repositories)
- Index size: ~50MB (index.json)
- This directory is excluded from Git (see .gitignore)

## Documentation

See [docs/QUERY_LEARNING_SYSTEM.md](../../../docs/QUERY_LEARNING_SYSTEM.md) for complete documentation.

# Bespoke Organization-Specific Configuration

This directory contains **organization-specific** content. The `mappings/` subdirectory contains core schema files that ARE tracked in git. Other files (exclusions, config, custom searches) are gitignored.

## Directory Structure

```
bespoke/
  mappings/                 # Schema and indicator mapping files (tracked in git)
    members.json            # Team member assignments (LAN ID to team mapping)
    schemaSplunk.json       # Splunk field schema mappings
    schemaMDE.json          # Microsoft Defender field mappings
    schemaElastic.json      # Elastic field mappings
    schemaGoogleSecOps.json # Google SecOps field mappings
    indicatorMapping.json   # Indicator type to field mappings
    entityMappings.json     # Entity type mappings for KQL
    dataSources.json        # MITRE data source mappings
    platforms.json          # Platform definitions
    logSourceCategories.json # Log source categories
    techniquePlatformIndicators.json # Technique validation matrix
  exclusions.yaml           # Global exclusions (gitignored)
  config.yaml               # Organization settings (gitignored)
  searches/                 # Custom detection examples (gitignored)
```

## Quick Start

1. **Copy the example files:**
   ```bash
   cp exclusions.yaml.example exclusions.yaml
   cp config.yaml.example config.yaml
   ```

2. **Edit the files** with your organization's specific exclusions and settings

3. **Reload the configuration** via API or restart the server:
   ```bash
   curl -X POST http://localhost:8000/api/bespoke/reload
   ```

## Mapping Files

The `mappings/` directory contains core schema and configuration files:

| File | Purpose |
|------|---------|
| `schemaSplunk.json` | Splunk index/sourcetype to field mappings |
| `schemaMDE.json` | Microsoft Defender table mappings |
| `schemaElastic.json` | Elastic index mappings |
| `schemaGoogleSecOps.json` | Google SecOps UDM mappings |
| `indicatorMapping.json` | Maps indicator types (cmd, file, reg) to platform fields |
| `entityMappings.json` | KQL entity type mappings |
| `dataSources.json` | MITRE ATT&CK data source definitions |
| `platforms.json` | Platform configuration |
| `members.json` | Team member LAN ID to team assignments |
| `techniquePlatformIndicators.json` | Technique validation matrix |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status/bespoke` | GET | Get bespoke configuration status |
| `/api/bespoke/sample-searches` | GET | Get custom sample searches |
| `/api/bespoke/reload` | POST | Reload configuration from disk |

## Git Tracking

- `mappings/` directory - **Tracked** (structure only)
- `mappings/*.json` - **Gitignored** (all mapping files are org-specific)
- `exclusions.yaml`, `config.yaml` - **Gitignored** (org-specific)
- `searches/` contents - **Gitignored** (org-specific)

New users must populate `mappings/` with schema files from a reference install or create their own.

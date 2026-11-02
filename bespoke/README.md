# Bespoke Organization-Specific Configuration

This directory contains **organisation-specific** content. Everything in it except the `.example` files, this README and `.gitkeep` placeholders is gitignored, including the mapping files. A new install's `mappings/` is filled from the generic defaults in `shikari/mappings/defaults/`; your own replacements can't be regenerated from the repository, so keep a copy somewhere safe.

## Directory Structure

```
bespoke/
  mappings/                                  # gitignored; all files below are required for query generation
    indicatorMapping.json                    # Indicator types (cmd, reg, evt, sw, port, protocol, service, api, network) to fields
    techniquePlatformIndicators.json         # Technique validation matrix
    schemas/
      schemaSplunk.json                      # Splunk index/sourcetype field schemas
      schemaMDE.json                         # Microsoft Defender table/field definitions
      schemaElastic.json                     # Elastic field definitions
      schemaGoogleSecOps.json                # Google SecOps UDM field definitions
    sources/
      platforms.json                         # Platform to index compatibility matrix
      dataSources.json                       # Log source definitions
      entityMappings.json                    # KQL entity extraction patterns
      logSourceCategories.json               # Log source to category mapping
      members.json                           # Team member LAN ID to team assignments (optional)
  exclusions.yaml                            # Global exclusions
  config.yaml                                # Organisation settings
  searches/                                  # Custom detection examples
```

A new install starts with generic mappings from `shikari/mappings/defaults/` (CEF-aligned Splunk indexes and sourcetypes; see its README): Shikari copies in whatever is missing at startup and never overwrites a file that's here. The server lists any missing required files at startup ("N required bespoke mapping file(s) absent"), and detection generation fails with a message naming the missing piece.

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

New installs get the generic defaults (`shikari/mappings/defaults/README.md`): the six files that name Splunk indexes are copied in together, and only into an empty `mappings/`, so they never mix with your own index names. Replace them with your organisation's files when you have them.

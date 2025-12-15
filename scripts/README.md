# Archer Scripts

Utility scripts organized by functionality.

## Quick Navigation

| Category | Documentation | Purpose |
|----------|--------------|---------|
| **AI & LLM** | [ai/LOCAL_LLM.md](ai/LOCAL_LLM.md) | AI model configuration and training |
| **Admin** | [admin/WEB_APP.md](admin/WEB_APP.md) | User administration |
| **Deployment** | [deployment/DEPLOY.md](deployment/DEPLOY.md) | Server operations |
| **Validation** | [validation/VALIDATION.md](validation/VALIDATION.md) | SIEM configuration and schema validation |
| **Data** | [data/DATA_SCRIPTS.md](data/DATA_SCRIPTS.md) | OSINT and MITRE data management |

## Directory Structure

```
scripts/
├── ai/              # AI and LLM configuration scripts
├── admin/           # User administration scripts
├── deployment/      # Deployment and server management scripts
├── validation/      # Schema validation and mapping scripts
└── data/            # Data import and OSINT scripts
```

## Quick Start Examples

### AI Setup
```bash
# Auto-configure local LLM based on your system
python scripts/ai/setup_local_llm.py
```

### Admin Tasks
```bash
# Create admin user
python scripts/admin/create_admin.py

# Reset password
python scripts/admin/reset_password.py user@example.com
```

### Initial Configuration
```bash
# Configure SIEM mappings
python scripts/validation/setup_mappings.py
```

### Data Updates
```bash
# Update OSINT repositories
python scripts/data/update_osint.py
```

## Documentation

For comprehensive script documentation, see:
- **[docs/SCRIPTS.md](../docs/SCRIPTS.md)** - Complete scripts reference with detailed examples

For category-specific documentation, see the README files in each subdirectory above.

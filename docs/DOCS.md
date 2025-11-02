# Archer Documentation

Complete documentation for the Archer threat detection automation platform.

## 📁 Documentation Structure

### 🏗️ [`architecture/`](architecture/)
Technical architecture and design documentation:
- **[CORRELATION_ENGINE.md](architecture/CORRELATION_ENGINE.md)** - Complete correlation generation system (scoring, filtering, JOIN queries)
- **[PERFORMANCE_ARCHITECTURE.md](architecture/PERFORMANCE_ARCHITECTURE.md)** - System performance and optimization
- **[SCHEMA_NORMALIZATION.md](architecture/SCHEMA_NORMALIZATION.md)** - Field normalization and schema design

### 📖 [`guides/`](guides/)
User guides and setup instructions:
- **[GETTING_STARTED.md](guides/GETTING_STARTED.md)** - Setup and troubleshooting
- **[CORRELATION_GUIDE.md](guides/CORRELATION_GUIDE.md)** - Correlation query builder guide
- **[CVE_HUNTING_GUIDE.md](guides/CVE_HUNTING_GUIDE.md)** - CVE-based detection generation
- **[EMULATION_GUIDE.md](guides/EMULATION_GUIDE.md)** - Adversary emulation and remote execution
- **[QUERY_API_GUIDE.md](guides/QUERY_API_GUIDE.md)** - MDE and Splunk API integration
- **[TESTING_GUIDE.md](guides/TESTING_GUIDE.md)** - Testing and validation workflows
- **[IMPORT_TRAINING_QUERIES.md](guides/IMPORT_TRAINING_QUERIES.md)** - Import existing detection queries
- **[MAPPINGS_README.md](guides/MAPPINGS_README.md)** - Mapping system overview
- **[MAPPINGS_INTEGRATION_GUIDE.md](guides/MAPPINGS_INTEGRATION_GUIDE.md)** - Schema normalization integration
- **[MAPPING_SETUP_GUIDE.md](guides/MAPPING_SETUP_GUIDE.md)** - Configure mapping files for your environment
- **[MAPPING_FILES_GUIDE.md](guides/MAPPING_FILES_GUIDE.md)** - Detailed mapping file reference

### 📚 [`reference/`](reference/)
API documentation and technical references:
- **[API_DOCUMENTATION.md](reference/API_DOCUMENTATION.md)** - Complete REST API documentation with examples
- **[API_REFERENCE.md](reference/API_REFERENCE.md)** - Authentication and user management API reference
- **[CORRELATION_QUICK_REFERENCE.md](reference/CORRELATION_QUICK_REFERENCE.md)** ⚙️ **Tunable parameters** (threshold, per-vendor, tech frequency)
- **[MITRE_PROCEDURES.md](reference/MITRE_PROCEDURES.md)** - MITRE ATT&CK procedure extraction
- **[SCRIPTS.md](reference/SCRIPTS.md)** - Command-line scripts reference

### ✨ [`features/`](features/)
Feature-specific documentation:
- **[AI_TRAINING.md](features/AI_TRAINING.md)** - AI query training and generation
- **[DETECTION_VALIDATION.md](features/DETECTION_VALIDATION.md)** - Detection quality validation
- **[DOCKER.md](features/DOCKER.md)** - Docker deployment guide
- **[OSINT_INTEGRATION.md](features/OSINT_INTEGRATION.md)** - OSINT repository integration
- **[PARENT_SUBTECHNIQUE_EXPANSION.md](features/PARENT_SUBTECHNIQUE_EXPANSION.md)** - Automatic subtechnique generation
- **[SECURITY_FEATURES.md](features/SECURITY_FEATURES.md)** - Authentication, encryption, audit logging

### 📝 [`notion/`](notion/)
Notion-formatted versions of documentation (for Notion import)

### 🎨 [`flow/`](flow/)
Architecture diagrams and flow charts

---

## 🚀 Quick Start

1. **New to Archer?** Start with [Getting Started Guide](guides/GETTING_STARTED.md)
2. **Want to tune correlation quality?** See [Correlation Quick Reference](reference/CORRELATION_QUICK_REFERENCE.md)
3. **Need API integration?** Check [API Documentation](reference/API_DOCUMENTATION.md)
4. **Using custom log sources?** Read [Mapping Setup Guide](guides/MAPPING_SETUP_GUIDE.md)

---

## 📊 Key Documentation by Use Case

### For SOC Analysts
- [Getting Started Guide](guides/GETTING_STARTED.md) - Basic setup
- [Correlation Guide](guides/CORRELATION_GUIDE.md) - Using the correlation builder
- [CVE Hunting Guide](guides/CVE_HUNTING_GUIDE.md) - CVE-based detection

### For Security Engineers
- [Correlation Quick Reference](reference/CORRELATION_QUICK_REFERENCE.md) - Tune correlation parameters
- [Detection Validation](features/DETECTION_VALIDATION.md) - Validate detection quality
- [Testing Guide](guides/TESTING_GUIDE.md) - Testing workflows

### For Platform Administrators
- [Mapping Setup Guide](guides/MAPPING_SETUP_GUIDE.md) - Configure for your environment
- [API Documentation](reference/API_DOCUMENTATION.md) - API integration
- [Security Features](features/SECURITY_FEATURES.md) - User management and security

### For Developers
- [Correlation Engine](architecture/CORRELATION_ENGINE.md) - Engine internals
- [Performance Architecture](architecture/PERFORMANCE_ARCHITECTURE.md) - System design
- [Schema Normalization](architecture/SCHEMA_NORMALIZATION.md) - Field mapping

---

## 🔗 External Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---

**Version**: 1.0  
**Last Updated**: November 2, 2024

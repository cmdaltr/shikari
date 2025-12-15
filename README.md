<div align="center">
<a href="https://github.com/cmdaltr/archer">
<img src="static/images/archer_banner.png" alt="Archer - Automated Multi-Vendor Threat Hunting & Detection Framework" width="600px" height="600px">
</a>
</div>

<br>

Archer is a modular Python service for automated threat hunting with optional adversary emulation and hunt tracking integrations. Generate detection queries, validate with real attack execution, and track hunts with VECTR integration.

## 🛠️ Setup and Usage

**📖 Setup instructions: [GETTING_STARTED.md](GETTING_STARTED.md)**

**⌨️ Usage instructions and guidance: [USAGE.md](docs/USAGE.md)**

---
<br>

## ✨ Features

### Core Capabilities
- 🎯 **MITRE ATT&CK Integration** - Automated detection generation from threat group TTPs
- 📤 **File Upload & Intelligence Extraction** - Upload threat intel files (PDF, TXT, JSON, CSV, YARA) for automatic TTP/IOC extraction
- 🔍 **Multi-Platform Support** - Splunk (SPL), KQL (Microsoft Defender/Sentinel), Google SecOps (YARA-L) and Elastic (DSL) queries
- 🧠 **Heuristic and AI-Powered Correlations** - Semantic analysis and query correlation
- 🌐 **Web UI & CLI** - VirusTotal-inspired tabbed interface plus command-line tools
- 🎯 **RAG Fidelity Enhancement** - Improve query quality using 4,800+ community detection examples ([docs](docs/rag/README.md))
- 🏢 **Organization-Specific Customization** - Bespoke sample searches and global exclusions for your environment

### Additional Features

- 💥 **Adversary Emulation** - Atomic Red Team integration (code implemented, see [UNTESTED.md](docs/UNTESTED.md))
- 🔍 **Query Execution** - MDE/Splunk API integration (code implemented, see [UNTESTED.md](docs/UNTESTED.md))
- 📊 **VECTR, CALDERA, MACAT** - Planned integrations (see [FUTURE.md](docs/FUTURE.md))

### Security & User Management
- 🔐 **Enterprise Authentication** - Bcrypt password hashing, session management, MFA support (TOTP)
- 🛡️ **Security Features** - Rate limiting, CSRF protection, account lockout, audit logging
- 👥 **Admin User Management** - Complete CRUD API for user accounts (create, read, update, deactivate)
- 📧 **Email Integration** - SMTP-based password reset with secure token delivery
- 🔑 **API Key Encryption** - Fernet encryption for stored SIEM/AI API credentials
- 📊 **Comprehensive Audit Logs** - Track all authentication events and admin actions
- 🔒 **Role-Based Access Control** - Admin and Standard user roles with granular permissions

---
<br>

## 📚 Documentation & Resources

### Archer Documentation

**📖 [Complete Documentation Index](docs/DOCS.md)** - Browse all documentation by category

**Quick Links:**
- **Getting Started:** [GETTING_STARTED.md](GETTING_STARTED.md) | [Mapping Setup](docs/guides/MAPPING_SETUP_GUIDE.md)
- **API Integration:** [API Integration Guide](docs/guides/API_INTEGRATION_GUIDE.md) | [Auto-Generated Docs](http://localhost:8000/docs)
- **Correlation Tuning:** [Correlation Engine](docs/architecture/CORRELATION_ENGINE.md) | [Quick Reference](docs/architecture/CORRELATION_QUICK_REFERENCE.md)
- **Features:** [Security](docs/features/SECURITY_FEATURES.md) | [AI Training](docs/ai/AI_TRAINING.md) | [OSINT](docs/features/OSINT_INTEGRATION.md)
- **RAG Enhancement:** [RAG User Guide](docs/rag/RAG_USER_GUIDE.md) | [Implementation Guide](docs/rag/FIDELITY_IMPLEMENTATION_GUIDE.md)
- **Architecture:** [Performance](docs/architecture/PERFORMANCE_ARCHITECTURE.md) | [Schema Normalization](docs/architecture/SCHEMA_NORMALIZATION.md)

### External Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [VECTR](https://vectr.io/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---
<br>

## 🤝 Contributing

Feel free to open issues or submit pull requests to improve Archer.

---
<br>

## 📝 License

This project is licensed under the MIT License. See the LICENSE file for details.
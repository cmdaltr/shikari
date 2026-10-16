# Future Features

This document describes planned features and integrations for Archer that are not yet implemented or are only partially implemented.

> ⚠️ **Status**: Not Functional

These features have configuration stubs or placeholder code but are not yet functional. They are planned for future development.

---

## VECTR Integration

**Status**: CLI stub exists but not yet functional

### Overview

Integration with [VECTR](https://vectr.io/) for hunt tracking and purple team collaboration. Track detection coverage, manage purple team exercises, and collaborate across red and blue teams.

### Planned Capabilities

- 📊 **Hunt Tracking** - Track threat hunts and detection coverage in VECTR
- 🔴🔵 **Purple Team Collaboration** - Coordinate red/blue team activities
- 📈 **Coverage Mapping** - Map Archer detections to VECTR campaigns
- 🔄 **Bi-directional Sync** - Push detections to VECTR, pull results back
- 📋 **Campaign Management** - Create and manage detection validation campaigns

### Configuration Stub

```bash
# Placeholder environment variables (not yet implemented)
export VECTR_URL=https://vectr.instance.com
export VECTR_API_KEY=your-api-key
```

### Planned Usage

```bash
# Push detections to VECTR campaign (planned)
python3 archer.py vectr push "APT29" --campaign "Q4-2024-Hunt"

# Pull VECTR test results to validate detections (planned)
python3 archer.py vectr pull --campaign "Q4-2024-Hunt"

# Sync detection coverage (planned)
python3 archer.py vectr sync
```

### What Exists Now

- CLI argument parser for `vectr` subcommand
- Placeholder functions in codebase
- Configuration variable definitions

### What's Missing

- VECTR API client implementation
- Authentication handling
- Data mapping between Archer and VECTR formats
- Campaign management logic
- Coverage tracking algorithms

### Dependencies

- VECTR instance (self-hosted or cloud)
- VECTR API documentation and testing
- User feedback on desired workflow

### Timeline

- **Target**: Q1-Q2 2025
- **Blockers**: Requires VECTR instance for testing, API documentation review
- **Help Wanted**: Contributors with VECTR experience

---

## CALDERA Integration

**Status**: Configuration exists but integration not implemented

### Overview

Integration with [CALDERA](https://github.com/mitre/caldera), MITRE's automated adversary emulation platform. Automate adversary emulation at scale and use results to validate and enrich detections.

### Planned Capabilities

- 💥 **Automated Adversary Emulation** - Execute CALDERA operations automatically
- 🔄 **Operation Management** - Create and manage emulation operations
- 📊 **Evidence Collection** - Collect operation artifacts for detection enrichment
- 🎯 **Ability-Based Generation** - Generate detections based on CALDERA abilities
- 🔗 **Bi-directional Integration** - Push detections to CALDERA, pull execution results

### Configuration Stub

```bash
# Placeholder environment variables (not yet implemented)
export CALDERA_API_URL=http://caldera-server:8888
export CALDERA_API_KEY=your-api-key
```

### Planned Usage

```bash
# Generate detections from CALDERA abilities (planned)
python3 archer.py caldera generate --adversary apt29

# Execute CALDERA operation and enrich detections (planned)
python3 archer.py caldera emulate "APT29" --operation "purple-team-test" --enrich

# Sync CALDERA abilities with Archer (planned)
python3 archer.py caldera sync
```

### What Exists Now

- Environment variable definitions
- Configuration placeholders in code
- References in documentation

### What's Missing

- CALDERA API client implementation
- Ability-to-technique mapping
- Operation execution logic
- Evidence collection and parsing
- Enrichment integration

### Dependencies

- CALDERA instance (self-hosted)
- CALDERA API client library or custom implementation
- Mapping between CALDERA abilities and ATT&CK techniques
- Testing environment

### Timeline

- **Target**: Q2-Q3 2025
- **Blockers**: Requires CALDERA instance for testing, API integration complexity
- **Help Wanted**: Contributors with CALDERA deployment experience

---

## MACAT Integration

**Status**: Configuration exists but integration not implemented

### Overview

Integration with [MACAT](https://github.com/cedowens/MACAT), a macOS adversary emulation framework. Enable macOS-specific adversary emulation and detection generation.

### Planned Capabilities

- 💥 **macOS Adversary Emulation** - Execute MACAT tests on macOS systems
- 🍎 **macOS-Specific Detections** - Generate macOS detection queries (ES, osquery)
- 📊 **macOS Evidence Collection** - Collect execution artifacts from macOS
- 🔧 **Endpoint Security Integration** - Generate ES (Endpoint Security) queries
- 🔍 **osquery Integration** - Generate osquery-based detections

### Configuration Stub

```bash
# Placeholder environment variables (not yet implemented)
export MACAT_PATH=/path/to/macat
```

### Planned Usage

```bash
# Emulate macOS technique (planned)
python3 archer.py macat emulate T1059.002 --enrich

# Generate macOS-specific detections (planned)
python3 archer.py macat generate "macOS threats" --format osquery

# Execute MACAT test suite (planned)
python3 archer.py macat test-suite --category persistence
```

### What Exists Now

- Environment variable definition
- Configuration placeholder in code
- Reference in documentation

### What's Missing

- MACAT integration code
- macOS detection query generation (ES, osquery)
- Evidence collection from macOS
- Test execution logic
- macOS platform-specific handling

### Dependencies

- MACAT framework installation
- macOS testing environment
- Endpoint Security or osquery deployment
- macOS-specific ATT&CK technique coverage

### Timeline

- **Target**: Q3-Q4 2025
- **Blockers**: Requires macOS environment, MACAT testing, ES/osquery query generation
- **Help Wanted**: Contributors with macOS security experience

---

## Additional Planned Features

### Multi-SIEM Support Expansion

**Supported**: Google SecOps (YARA-L), Microsoft Defender (KQL), Splunk (SPL), Elastic Security (Query DSL). No other SIEMs are planned.

### AI/ML Enhancements

**Planned**:
- Local LLM support (llama.cpp, Ollama)
- Fine-tuned models for detection generation
- Automated detection quality scoring
- False positive prediction

### Detection Testing Suite

**Status**: Implemented

The Runtime Detection Validation feature is now available:
- Automated detection validation in containerized SIEMs
- False positive/negative testing with precision/recall metrics
- AI-assisted query refinement
- Coverage gap identification through F1 score analysis

**Documentation**: [Runtime Validation Guide](../features/RUNTIME_VALIDATION.md)

**Remaining Work**:
- Performance impact analysis
- Integration with CI/CD pipelines

### API Enhancements

**Planned**:
- GraphQL API
- Webhook support
- Real-time streaming updates
- Batch operations API

### Cloud Integrations

**Planned**:
- AWS CloudTrail query generation
- Azure Activity Log queries
- GCP Cloud Logging queries
- Multi-cloud detection coverage

---

## How to Contribute

Want to help implement these features? Here's how:

### 1. Choose a Feature

Pick a feature from this document that interests you or matches your expertise.

### 2. Review Existing Code

```bash
# Search for existing stubs and placeholders
grep -r "VECTR\|CALDERA\|MACAT" archer/
```

### 3. Open an Issue

Before starting work:
1. Open a GitHub issue: [New Feature Implementation](https://github.com/cmdaltr/archer/issues/new)
2. Tag it with `enhancement` and `help wanted`
3. Describe your implementation plan
4. Get feedback from maintainers

### 4. Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/vectr-integration`
3. Implement the feature with tests
4. Update documentation
5. Submit a pull request

### 5. Testing Requirements

All new features must include:
- Unit tests with >80% coverage
- Integration tests with mock services
- Documentation with usage examples
- Configuration guide
- Error handling

---

## Feature Requests

Have an idea for a new feature? We'd love to hear it!

**Submit a feature request**:
1. Open a [GitHub Issue](https://github.com/cmdaltr/archer/issues/new)
2. Tag it with `feature-request`
3. Describe the feature and use case
4. Explain the value it would provide
5. Include any relevant examples or references

**Good feature requests include**:
- Clear problem statement
- Proposed solution
- Use cases and examples
- Alternative approaches considered
- Willingness to help implement

---

## Roadmap

### Q1 2025
- [ ] VECTR integration (basic)
- [ ] Enhanced API documentation
- [x] Detection testing suite (v1) - **Completed Feb 2026**

### Q2 2025
- [ ] CALDERA integration (basic)
- [ ] Multi-SIEM support expansion (Elastic)
- [ ] Local LLM support

### Q3 2025
- [ ] MACAT integration
- [ ] Cloud integration (AWS)
- [ ] Advanced detection validation

### Q4 2025
- [ ] GraphQL API
- [ ] Multi-cloud support
- [ ] AI-powered quality scoring

*Roadmap subject to change based on community feedback and contributions*

---

## Open feature requests

| Issue | Feature |
|---|---|
| [#15](https://github.com/cmdaltr/archer/issues/15) | Precision checks: flag queries that parse but can't mean anything |
| [#16](https://github.com/cmdaltr/archer/issues/16) | Hit counts: run a detection read-only against the SIEM to measure false positives |
| [#17](https://github.com/cmdaltr/archer/issues/17) | IOC sweeps: known-good lists and IOC expiry (`[redacted]` wildcards and system-file exclusion done) |
| [#18](https://github.com/cmdaltr/archer/issues/18) | Threat Feed watchlists |
| [#19](https://github.com/cmdaltr/archer/issues/19) | STIX/TAXII and MISP import and export |
| [#20](https://github.com/cmdaltr/archer/issues/20) | Detections as code: export to git, push to the SIEM, diff between runs |
| [#21](https://github.com/cmdaltr/archer/issues/21) | Technology stack: only hunt what applies to the products the organisation runs |

---

## Regex tester: real engines

**Status**: Feature request [#14](https://github.com/cmdaltr/archer/issues/14)

Build → Regex matches with the browser's JavaScript engine, translating the pattern where a flavour only spells something differently. Constructs JavaScript lacks (possessive quantifiers, atomic groups, conditionals) are checked but not run, and behaviour that differs between engines shows JavaScript's result. The plan: RE2 and PCRE2 compiled to WebAssembly, vendored and loaded in the existing worker only for their flavour, with the translation kept as the fallback.

---

## Priority Features

Based on community interest and impact, current priority features are:

1. **VECTR Integration** - High demand, clear use case
2. **Detection Testing Suite** - Critical for production deployments
3. **Elastic Support** - Frequently requested SIEM platform
4. **Local LLM Support** - Reduce dependency on external AI providers

Vote on features by adding 👍 to the corresponding GitHub issue!

---

**Last Updated**: 2024-11-14

**Questions?** Open a [GitHub Discussion](https://github.com/cmdaltr/archer/discussions)

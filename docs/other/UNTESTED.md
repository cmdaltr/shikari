# Untested Features

This document describes features that have been implemented in Shikari but have not been validated with live deployments or production environments.

> ⚠️ **Status**: Code exists but not validated with live deployments

These features may work as intended but require testing and validation before being considered production-ready. Use at your own risk and please report any issues or successes to help validate these features.

---

## Lab recording (Coming soon)

**Status**: Code written and unit-tested, not yet run on a real lab

`scripts/telemetry/record-atomics.ps1` runs Atomic Red Team tests on a Windows, Linux or macOS test machine and saves each test's logs (Windows event logs; auditd and the journal; eslogger, the unified log and launch item plist changes on macOS). `python -m shikari.telemetry --mde-export` fetches each test's Defender for Endpoint rows through Microsoft Graph's Advanced Hunting. Runs copied into `data/telemetry/lab/` appear on the Emulate page as **Your lab**.

Setup, step by step: [Recording a lab](../guide/20-recording-a-lab.md).

### Known limitations

- The script parses in PowerShell 7 and its macOS plist functions were exercised; no atomic has been run with it
- `--mde-export` matches devices by the manifest's host name (`DeviceName startswith`), and takes up to 5,000 rows per table per test
- Running atomics from Shikari itself (`shikari offline emulate`, the console's `emulate`, **Run Emulation** on Results) depended on an `shikari.emulation` package that has been removed; those entry points say Coming soon

## Query Execution

**Status**: Splunk client implemented but not validated against a live Splunk; Defender XDR not implemented

Running a generated query against the SIEM and reading the results back. `shikari/query/splunk.py` (`SplunkClient`) runs SPL through Splunk's search jobs API. Defender XDR execution will be built with hit counts ([#16](https://github.com/cmdaltr/shikari/issues/16)) on Microsoft Graph's `runHuntingQuery` (application permission `ThreatHunting.Read.All`), reusing the token and query code in `shikari/telemetry/mde.py`. The older client for the retiring `api.securitycenter.microsoft.com` API was removed unused.

### Configuration

```bash
export SPLUNK_HOST=splunk.example.com
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=your-password
```

Needs a Splunk Enterprise or Cloud instance with API access and a user allowed to search. There's no page or CLI command that runs it yet.

### Known Limitations

- Not validated against a live Splunk deployment
- API rate limits not fully tested
- Large result sets may require pagination tuning
- Error handling may need environment-specific adjustments

---

## Testing & Validation

If you test any of these features, please help the community by:

1. **Opening an issue** with your results: [GitHub Issues](https://github.com/cmdaltr/shikari/issues)
2. **Sharing configurations** that worked in your environment
3. **Reporting bugs** or unexpected behavior
4. **Contributing fixes** via pull requests

### What to Test

**Lab recording**:
- [ ] `record-atomics.ps1` on Windows (events.xml), Ubuntu (audit.log, journal.log) and macOS (es.ndjson, unified.ndjson, plists.ndjson)
- [ ] `--mde-export` against a Defender for Endpoint trial tenant
- [ ] A run appearing as Your lab, and a group's detections checked against it

**Query Execution**:
- [ ] Splunk token authentication
- [ ] Splunk query execution and results
- [ ] API error handling
- [ ] Rate limiting behavior

### Validation Checklist

When testing, please document:
- ✅ Environment (OS, SIEM platform, versions)
- ✅ Configuration used
- ✅ What worked
- ✅ What didn't work
- ✅ Any errors encountered
- ✅ Suggested improvements

---

## Contributing Validation Results

Your validation helps make these features production-ready!

**To contribute**:
1. Test a feature following the documentation
2. Document your setup, results, and any issues
3. Open a GitHub issue with the tag `validation-result`
4. Include environment details and configuration
5. Share any fixes or improvements you made

**Example validation report**:
```markdown
**Feature**: Lab recording
**Environment**: Ubuntu 24.04, auditd with Neo23x0's rules, PowerShell 7.5
**Status**: ✅ Working
**Notes**: 10 techniques recorded; audit.log and journal.log in every test folder.
**Fixes Applied**: None
```

---

## Migration to Tested Features

Once a feature is validated by the community:
1. The feature will be documented as production-ready
2. This documentation will be moved to the main feature docs
3. The feature will be removed from this UNTESTED.md file
4. Known issues and workarounds will be documented

---

**Last Updated**: 2026-10-29

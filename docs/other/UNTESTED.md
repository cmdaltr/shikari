# Untested Features

This document describes features that have been implemented in Shikari but have not been validated with live deployments or production environments.

> ⚠️ **Status**: Code exists but not validated with live deployments

These features may work as intended but require testing and validation before being considered production-ready. Use at your own risk and please report any issues or successes to help validate these features.

---

## Defender for Endpoint lab export

**Status**: Code written and unit-tested, not yet run against a tenant ([#45](https://github.com/cmdaltr/shikari/issues/45))

`python -m shikari.telemetry --mde-export data/telemetry/lab/<run>` fetches each recorded test's Defender for Endpoint rows through Microsoft Graph's Advanced Hunting. `record-atomics.ps1` itself has run on Windows 11, Ubuntu 24.04 and macOS (9–10 November 2026: 70, 35 and 19 tests); setup in [Recording a lab](../guide/20-recording-a-lab.md).

### Known limitations

- `--mde-export` matches devices by the manifest's host name (`DeviceName startswith`), and takes up to 5,000 rows per table per test
- Running atomics from Shikari itself (`shikari offline emulate`, the console's `emulate`, **Run Emulation** on Results) depended on an `shikari.emulation` package that has been removed; those entry points say Coming soon

Splunk query execution was validated against a live Splunk in [#44](https://github.com/cmdaltr/shikari/issues/44): see [Query Execution](../features/QUERY_EXECUTION.md).

---

## Testing & Validation

If you test any of these features, please help the community by:

1. **Opening an issue** with your results: [GitHub Issues](https://github.com/cmdaltr/shikari/issues)
2. **Sharing configurations** that worked in your environment
3. **Reporting bugs** or unexpected behavior
4. **Contributing fixes** via pull requests

### What to Test

**Defender for Endpoint lab export**:
- [ ] `--mde-export` against a Defender for Endpoint trial tenant

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

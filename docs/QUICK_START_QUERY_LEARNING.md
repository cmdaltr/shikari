# Quick Start: Enhanced Query Generation

Get up and running with AI-enhanced detection query generation in 5 minutes.

## What You'll Get

- Higher quality detection queries
- Real-world patterns from security experts
- Queries that use YOUR field names
- Best practices automatically applied

## Prerequisites

- Git installed (`git --version`)
- ~300MB disk space for examples
- Internet connection for initial download

## Setup (5 minutes)

### 1. Download Query Examples

```bash
python scripts/manage_query_examples.py update
```

This clones:
- Splunk Security Content
- SigmaHQ Sigma Rules
- Microsoft Defender Hunting Queries

**First time**: Takes 2-3 minutes (~300MB download)

### 2. Build the Index

```bash
python scripts/manage_query_examples.py rebuild
```

This parses all examples and creates a searchable index.

**Takes**: 1-2 minutes

### 3. Enable Enhanced Generation

```bash
export ARCHER_ENHANCED_QUERIES=true
```

Or add to `.env` file:
```bash
echo "ARCHER_ENHANCED_QUERIES=true" >> .env
```

### 4. Test It

```bash
python scripts/manage_query_examples.py test
```

Expected output:
```
✓ Repository has 4,523 examples
✓ Prompt enhancer loaded successfully
✓ Generated prompt (15,234 characters)
✓ Enhanced query generation is ENABLED
```

## Usage

### Generate Detections (with enhancement)

```bash
# Enhanced queries will be used automatically
python cli.py build-correlations "Scattered Spider"
```

Look for these messages in output:
```
Using GenAI to generate KQL query for T1003 (cmd)
✓ Generated enhanced KQL query
```

### Search for Examples

```bash
# Find examples for a technique
python scripts/manage_query_examples.py search T1003

# Filter by vendor
python scripts/manage_query_examples.py search T1003 splunk
```

### View Statistics

```bash
python scripts/manage_query_examples.py stats
```

## How It Works

1. **You request** detections for "Scattered Spider" threat group
2. **System identifies** techniques used (e.g., T1003 - Credential Dumping)
3. **Finds examples** from real security teams who detect T1003
4. **Injects examples** into LLM prompt along with YOUR field schema
5. **LLM generates** query following the patterns it learned
6. **Result**: Professional-quality query using your field names

## Example: Before vs After

### Before (Template-Based)
```splunk
index=windows_events earliest=-1d
("process_command_line_arguments"="*lsass*" OR "process_command_line_arguments"="*procdump*")
| stats count BY user ComputerName
```

### After (AI-Enhanced with Examples)
```splunk
index=windows_events sourcetype=WinEventLog:Security earliest=-1d
(
  (EventCode=4688 AND (process_command_line_arguments="*lsass*" OR process_command_line_arguments="*procdump*"))
  OR
  (EventCode=4656 AND Object_Name="*lsass.exe*" AND Access_Mask IN ("0x1010", "0x1438"))
)
| eval suspicious_flags=if(match(process_command_line_arguments, "(?i)(dump|lsass)"), 1, 0)
| stats count, values(process_command_line_arguments) as commands BY _time, ComputerName, user, process_name
| where count > 0 AND suspicious_flags=1
| table _time, ComputerName, user, process_name, commands
```

Notice the improvements:
- Multiple detection angles (process + object access)
- Specific EventCodes for process creation and handle access
- Calculated fields for scoring
- Better filtering to reduce false positives
- More useful output fields for triage

## Disable/Re-enable

```bash
# Disable (use template-based generation)
unset ARCHER_ENHANCED_QUERIES

# Re-enable
export ARCHER_ENHANCED_QUERIES=true
```

The system gracefully falls back to templates if enhancement fails.

## Maintenance

Update examples monthly:

```bash
# Update repositories
python scripts/manage_query_examples.py update

# Rebuild index
python scripts/manage_query_examples.py rebuild
```

## Troubleshooting

### "No examples found"

```bash
# Check if indexed
python scripts/manage_query_examples.py stats

# If shows 0, rebuild:
python scripts/manage_query_examples.py rebuild
```

### Still seeing template queries

This is normal! Enhancement is used when:
- ✅ `ARCHER_ENHANCED_QUERIES=true`
- ✅ Examples exist for the technique
- ✅ LLM is available

For techniques without examples, templates are used as fallback.

### Git clone fails

Manual fallback:
```bash
cd archer/data/query_examples
git clone --depth 1 https://github.com/splunk/security_content.git splunk_security_content
git clone --depth 1 https://github.com/SigmaHQ/sigma.git sigma
git clone --depth 1 https://github.com/francoisfried/Defender-Advanced-Hunting-Queries.git defender_hunting
cd ../../..
python scripts/manage_query_examples.py rebuild
```

## Next Steps

- Read [QUERY_LEARNING_SYSTEM.md](QUERY_LEARNING_SYSTEM.md) for complete documentation
- Customize `archer/mappings/schemaSplunk.json` with your field names
- Add `archer/mappings/schemaMDE.json` for MDE field mappings
- Explore [Splunk Security Content](https://github.com/splunk/security_content) for available detections

## Questions?

Check the full documentation: [docs/QUERY_LEARNING_SYSTEM.md](QUERY_LEARNING_SYSTEM.md)

# Adversary Emulation Integration

This optional module integrates adversary emulation frameworks to enhance threat hunting detections with real attack execution data.

## Overview

The emulation module allows you to:
- Execute real attack techniques using Atomic Red Team (CALDERA and MACAT coming soon)
- Collect evidence from test executions (commands, processes, files, registry keys)
- Enrich existing detection queries with validated indicators
- Generate additional KQL queries from emulation evidence

## Configuration

### Enable Emulation Module

```bash
export ENABLE_EMULATION=true
```

### Atomic Red Team Setup

1. Clone Atomic Red Team repository:
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team
```

2. Set the path:
```bash
export ATOMIC_REDTEAM_PATH=/opt/atomic-red-team
```

3. Optional configuration:
```bash
# Execution mode (default: simulate)
export EMULATION_EXECUTE_MODE=simulate  # or "live" to actually run tests

# Output directories
export EMULATION_OUTPUT_DIR=data/emulation
export EMULATION_EVIDENCE_DIR=data/emulation/evidence
```

## Usage

### CLI Commands

#### 1. Single Technique Emulation

Simulate Atomic Tests for a specific technique (Safe):

```bash
# Simulate execution (doesn't actually run commands)
python3 archer.py emulate --technique-id T1059.001 --verbose
```

**Output:**
```
======================================================================
Adversary Emulation - ATOMIC
======================================================================

ℹ️  SIMULATION MODE - Tests will be simulated (set --execute to run live)

Executing Atomic Red Team tests for T1059.001...

======================================================================
EXECUTION SUMMARY
======================================================================
Technique: PowerShell (T1059.001)
Tests executed: 15
Evidence collected: 23
```

With automatic detection enrichment:

```bash
# Run emulation and enrich existing detections
python3 archer.py emulate --technique-id T1059.001 --enrich --verbose
```

This will:
1. Execute atomic tests for the technique
2. Parse evidence from execution
3. Find existing YAML detection files for the technique
4. Add `emulation_evidence` section to YAML files
5. Generate additional KQL queries

#### 2. Threat Group Emulation (NEW!)

Run Atomic Red Team tests for ALL techniques used by a threat group:

```bash
# Simulate all APT29 techniques
python3 archer.py emulate --threat-group "APT29" --enrich

# Limit to first 10 techniques (for testing)
python3 archer.py emulate --threat-group "APT29" --max-techniques 10 --enrich
```

**Output:**
```
======================================================================
Adversary Emulation - ATOMIC
======================================================================

ℹ️  SIMULATION MODE - Tests will be simulated

Fetching techniques for threat group: APT29
Found group: APT29

Found 12 techniques with Atomic Red Team tests:
  - T1003.001
  - T1027
  - T1059.001
  - T1071.001
  ...

[1/12] Testing T1003.001...
[2/12] Testing T1027...
...

======================================================================
GROUP EMULATION SUMMARY
======================================================================
Threat Group: APT29
Total Techniques: 45
Testable Techniques: 12
Total Tests Executed: 87
  Successful: 0
  Failed: 0
  Simulated: 87
  Skipped: 15

✅ Results saved to data/emulation/APT29_group_emulation_*.json

Enriching detections with group emulation evidence...
Techniques Enriched: 12
Files Updated: 24
Queries Generated: 36
```

Benefits of Group Emulation:
- Test entire threat group attack chains
- Bulk enrichment with single command
- Comprehensive evidence collection
- Realistic attack simulation

#### 3. Execute Live Tests (Use with Caution!)

⚠️ **WARNING**: Live execution will actually run attack techniques on your system. Only use in isolated test environments.

```bash
# Single technique - live execution
python3 archer.py emulate --technique-id T1059.001 --execute --enrich

# Threat group - live execution (LAB ONLY!)
python3 archer.py emulate --threat-group "APT29" --execute --enrich
```

### Programmatic Usage

```python
from archer.emulation import AtomicRedTeam, enrich_detections_with_emulation

# Initialize Atomic Red Team
atomic = AtomicRedTeam()

# List available techniques
techniques = atomic.list_techniques()
print(f"Available: {len(techniques)} techniques")

# Execute tests for a technique
results = atomic.execute_technique("T1059.001")

print(f"Tests executed: {len(results['tests_executed'])}")
print(f"Evidence collected: {len(results['evidence_collected'])}")

# Enrich detections with evidence
enrich_result = enrich_detections_with_emulation("T1059.001")

if enrich_result['status'] == 'success':
    print(f"Enriched {len(enrich_result['enriched_files'])} files")
    print(f"Generated {enrich_result['additional_queries_generated']} queries")
```

## Emulation Evidence

### Evidence Types

The parser extracts multiple indicator types from emulation executions:

1. **Commands**: Full command-line executions
2. **Processes**: Process names and executables
3. **Files**: File paths created/modified
4. **Registry Keys**: Windows registry modifications
5. **Network**: Network connections (future enhancement)

### Example Evidence Output

```json
{
  "technique_id": "T1059.001",
  "technique_name": "PowerShell",
  "timestamp": "2025-01-05T10:30:00Z",
  "tests_executed": [
    {
      "test_number": 1,
      "test_name": "Mimikatz",
      "status": "simulated",
      "command": "powershell.exe -nop -w hidden -encodedcommand ..."
    }
  ],
  "evidence_collected": [
    {
      "type": "command_line",
      "technique_id": "T1059.001",
      "value": "powershell.exe -nop -w hidden -encodedcommand ...",
      "description": "Execution command used in atomic test"
    },
    {
      "type": "execution_log",
      "technique_id": "T1059.001",
      "file_path": "data/emulation/evidence/T1059.001_1_stdout.log",
      "description": "Standard output from test execution"
    }
  ]
}
```

### Enriched YAML Example

After enrichment, detection YAML files will include:

```yaml
name: PowerShell Encoded Command Execution
description: Detects execution of encoded PowerShell commands
tags:
  - APT29 (Group)
  - PowerShell
  - Obfuscation
relevantTechniques:
  - T1059.001
  - T1027

# Added by emulation enrichment
emulation_evidence:
  source: Atomic Red Team
  technique_id: T1059.001
  processes:
    - powershell.exe
    - powershell.exe (encoded)
  sample_commands:
    - "powershell.exe -nop -w hidden -encodedcommand ..."
    - "powershell.exe -EncodedCommand ..."
  registry_keys:
    - HKEY_CURRENT_USER\Software\Microsoft\PowerShell
  file_paths:
    - C:\Windows\Temp\payload.ps1
```

## Integration with Detection Workflow

### Complete Workflow Example

```bash
# Step 1: Generate detections for a threat group
python3 archer.py generate "APT29"

# Step 2: Run emulation tests for discovered techniques
python3 archer.py emulate T1059.001 --enrich
python3 archer.py emulate T1071.001 --enrich

# Step 3: Build correlations (now with enriched evidence)
python3 archer.py correlate --verbose

# Step 4: Review enriched detections
ls data/generate/*.yaml
```

### Benefits of Emulation Enrichment

1. **Validated Indicators**: Evidence from actual execution, not just theoretical
2. **Better Coverage**: Discover indicators missed in static analysis
3. **Platform-Specific**: Real commands and artifacts for your environment
4. **Correlation Confidence**: Higher confidence in correlations based on proven artifacts

## Supported Frameworks

### Current

- ✅ **Atomic Red Team**: Local test execution with 1000+ techniques

### Planned

- 🔄 **MITRE CALDERA**: Autonomous adversary emulation
- 🔄 **MACAT**: Mapped Attack Chain Analysis Tool

## Safety and Best Practices

### ⚠️ Important Safety Notes

1. **Default to Simulation**: Always test in simulation mode first
2. **Isolated Environment**: Run live tests only in isolated lab environments
3. **Cleanup**: Atomic tests include cleanup commands - review before running
4. **Platform Check**: Tests are platform-specific (Windows/Linux/macOS)
5. **Permissions**: Some tests require administrative privileges

### Recommended Testing Workflow

```bash
# 1. Start with simulation
python3 archer.py emulate T1059.001 --verbose

# 2. Review the commands that would be executed
cat data/emulation/T1059.001_atomic_*.json | jq '.tests_executed[].command'

# 3. If safe, run in isolated environment
export EMULATION_EXECUTE_MODE=live
python3 archer.py emulate T1059.001 --execute --verbose

# 4. Verify cleanup occurred
# Check logs and system state
```

## Troubleshooting

### Atomic Red Team Not Found

```
ERROR: Atomic Red Team not found at /opt/atomic-red-team
```

**Solution:**
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team
export ATOMIC_REDTEAM_PATH=/opt/atomic-red-team
```

### Module Not Enabled

```
ERROR: Emulation module is not enabled.
```

**Solution:**
```bash
export ENABLE_EMULATION=true
```

### No Tests for Technique

```
No atomic tests available for T1234.567
```

**Reason**: Not all MITRE techniques have Atomic Red Team tests. Check available techniques:

```python
from archer.emulation import AtomicRedTeam
atomic = AtomicRedTeam()
print(atomic.list_techniques())
```

## Output Files

### Emulation Results

```
data/emulation/
├── T1059.001_atomic_20250105_103000.json
├── T1071.001_atomic_20250105_104500.json
└── evidence/
    ├── T1059.001_1_stdout.log
    ├── T1059.001_2_stdout.log
    └── .gitkeep
```

### Structure

- `T{technique_id}_atomic_{timestamp}.json`: Complete test execution results
- `evidence/`: Captured logs and artifacts from test execution

## Future Enhancements

- [ ] MITRE CALDERA integration
- [ ] MACAT integration
- [ ] Network traffic capture from emulation
- [ ] Memory dump analysis integration
- [ ] EDR telemetry correlation
- [ ] Web UI for emulation management
- [ ] Automated test scheduling
- [ ] Multi-platform test orchestration

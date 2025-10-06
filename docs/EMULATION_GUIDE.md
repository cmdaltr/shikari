# Adversary Emulation Integration

This optional module integrates adversary emulation frameworks to enhance threat hunting detections with real attack execution data.

## Overview

The emulation module allows you to:
- Execute real attack techniques using Atomic Red Team (CALDERA and MACAT coming soon)
- **Remote Execution** via SSH (Linux/macOS) or WinRM (Windows) for cross-platform testing
- Collect evidence from test executions (commands, processes, files, registry keys)
- Enrich existing detection queries with validated indicators
- Generate additional KQL queries from emulation evidence

## Configuration

### Enable Emulation Module

Emulation is automatically enabled when using the `emulate` command - no environment variable needed.

### Atomic Red Team Setup

The CLI will offer to install Atomic Red Team if not found:

```bash
# Run any emulate command - will prompt for installation
python3 archer.py emulate T1059.001

# You'll be prompted to choose installation location:
# [1] /opt/atomic-red-team (system-wide)
# [2] archer/data/emulation/atomic-red-team (local)
```

Manual installation:
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team
export ATOMIC_REDTEAM_PATH=/opt/atomic-red-team
```

### Remote Execution Setup

#### SSH (Linux/macOS)

**Password Authentication:**
```bash
# No additional setup needed
```

**SSH Key Authentication (Recommended):**
```bash
# Generate SSH key if you don't have one
ssh-keygen -t rsa -b 4096 -f ~/.ssh/archer_key

# Copy public key to remote host
ssh-copy-id -i ~/.ssh/archer_key.pub user@192.168.1.100

# Use with Archer
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.100 \
  --remote-user admin \
  --ssh-key ~/.ssh/archer_key
```

#### WinRM (Windows)

**HTTPS (Default - Recommended):**
```powershell
# On Windows target, enable WinRM HTTPS (port 5986)
winrm quickconfig -transport:https

# Create self-signed certificate
New-SelfSignedCertificate -DnsName "hostname" -CertStoreLocation Cert:\LocalMachine\My

# Configure HTTPS listener
winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname="hostname"; CertificateThumbprint="THUMBPRINT"}

# Enable firewall rule
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow
```

**HTTP (Lab Only):**
```powershell
# On Windows target, enable WinRM HTTP (port 5985) - LAB ONLY!
winrm quickconfig

# Enable firewall rule
New-NetFirewallRule -DisplayName "WinRM HTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow
```

**Use with Archer:**
```bash
# HTTPS (default)
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.101 \
  --remote-user Administrator \
  --remote-password 'P@ssw0rd' \
  --remote-platform windows

# HTTP (lab only)
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.101 \
  --remote-user Administrator \
  --remote-password 'P@ssw0rd' \
  --remote-platform windows \
  --http
```

## Usage

### CLI Commands

#### 1. Local Execution

**Single Technique (Safe Simulation):**

```bash
# Simulate execution (doesn't actually run commands)
python3 archer.py emulate T1059.001 --verbose
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

**With Automatic Detection Enrichment:**

```bash
# Run emulation and enrich existing detections
python3 archer.py emulate T1059.001 --enrich --verbose
```

This will:
1. Execute atomic tests for the technique
2. Parse evidence from execution
3. Find existing YAML detection files for the technique
4. Add `emulation_evidence` section to YAML files
5. Generate additional KQL queries

**Threat Group Emulation:**

Run Atomic Red Team tests for ALL techniques used by a threat group:

```bash
# Simulate all APT29 techniques
python3 archer.py emulate "APT29" --enrich

# Limit to first 10 techniques (for testing)
python3 archer.py emulate "APT29" --max-techniques 10 --enrich
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

**Live Execution (Use with Caution!):**

⚠️ **WARNING**: Live execution will actually run attack techniques on your system. Only use in isolated test environments.

```bash
# Single technique - live execution
python3 archer.py emulate T1059.001 --execute --enrich

# Threat group - live execution (LAB ONLY!)
python3 archer.py emulate "APT29" --execute --enrich
```

#### 2. Remote Execution

Execute emulation tests on remote systems via SSH or WinRM.

**SSH - Linux/macOS (Password Authentication):**

```bash
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.100 \
  --remote-user admin \
  --remote-password 'YourPassword' \
  --enrich
```

**SSH - Linux/macOS (SSH Key - Recommended):**

```bash
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.100 \
  --remote-user admin \
  --ssh-key ~/.ssh/archer_key \
  --enrich
```

**WinRM - Windows (HTTPS - Default):**

```bash
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.101 \
  --remote-user Administrator \
  --remote-password 'P@ssw0rd' \
  --remote-platform windows \
  --enrich
```

**WinRM - Windows (HTTP - Lab Only):**

```bash
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.101 \
  --remote-user Administrator \
  --remote-password 'P@ssw0rd' \
  --remote-platform windows \
  --http \
  --enrich
```

**Remote Threat Group Emulation:**

```bash
# Test entire threat group on remote Windows system
python3 archer.py emulate "APT29" \
  --remote-host 192.168.1.101 \
  --remote-user Administrator \
  --ssh-key ~/.ssh/windows_key \
  --remote-platform windows \
  --max-techniques 10 \
  --enrich
```

**How Remote Enrichment Works:**

1. Commands execute on remote host via SSH/WinRM
2. Output captured and returned to local system
3. Artifacts extracted from remote output (commands, files, processes)
4. Results saved locally to `data/emulation/`
5. Local YAML files enriched with remote evidence
6. Works seamlessly with existing enrichment workflow

**Benefits of Remote Execution:**

- ✅ Test Windows techniques from macOS/Linux
- ✅ Test Linux techniques from Windows
- ✅ Isolated test environments (VMs, lab systems)
- ✅ Cross-platform validation
- ✅ Evidence collection from any platform
- ✅ No local system compromise risk

#### 3. Programmatic Usage

**Local Execution:**

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

**Remote Execution:**

```python
from archer.emulation.remote import create_remote_executor
from archer.emulation.atomic import execute_atomic_remote

# SSH execution
executor = create_remote_executor(
    host="192.168.1.100",
    username="admin",
    ssh_key="~/.ssh/archer_key"
)

# WinRM execution
executor = create_remote_executor(
    host="192.168.1.101",
    username="Administrator",
    password="P@ssw0rd",
    platform="windows",
    use_http=False  # HTTPS default
)

# Execute technique remotely
result = execute_atomic_remote(
    executor=executor,
    technique_id="T1059.001",
    execute=False,  # simulation mode
    enrich=True     # collect and enrich
)

print(f"Exit code: {result['exit_code']}")
print(f"Output: {result['output']}")
if 'artifacts' in result:
    print(f"Commands: {result['artifacts']['commands']}")
    print(f"Files: {result['artifacts']['files']}")
    print(f"Processes: {result['artifacts']['processes']}")
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

**Local Emulation:**

```bash
# Step 1: Generate detections for a threat group
python3 archer.py generate "APT29"

# Step 2: Run emulation tests for discovered techniques
python3 archer.py emulate T1059.001 --enrich
python3 archer.py emulate T1071.001 --enrich

# Step 3: Build correlations (now with enriched evidence)
python3 archer.py correlate "APT29"

# Step 4: Review enriched detections
ls data/generate/*.yaml
```

**Remote Emulation:**

```bash
# Step 1: Generate detections
python3 archer.py generate "APT29"

# Step 2: Run tests on remote Windows VM
python3 archer.py emulate "APT29" \
  --remote-host 192.168.1.101 \
  --remote-user Administrator \
  --ssh-key ~/.ssh/lab_key \
  --remote-platform windows \
  --max-techniques 10 \
  --enrich

# Step 3: Build correlations with remote evidence
python3 archer.py correlate "APT29"

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
cat data/emulation/T1059.001_*.json | jq '.tests_executed[].command'

# 3. If safe, run in isolated environment (local or remote)
python3 archer.py emulate T1059.001 --execute --verbose

# 4. For production testing, use remote execution
python3 archer.py emulate T1059.001 \
  --remote-host 192.168.1.100 \
  --remote-user admin \
  --ssh-key ~/.ssh/lab_key \
  --execute --enrich

# 5. Verify cleanup occurred
# Check logs and system state
```

## Troubleshooting

### Atomic Red Team Not Found

```
ERROR: Atomic Red Team not found
```

**Solution:** The CLI will automatically prompt for installation. Choose option [1] for `/opt` or [2] for local installation.

Manual installation:
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team
export ATOMIC_REDTEAM_PATH=/opt/atomic-red-team
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

### SSH Connection Failed

```
ERROR: SSH connection failed
```

**Solutions:**
1. Verify SSH service is running on remote host: `systemctl status sshd`
2. Check SSH key permissions: `chmod 600 ~/.ssh/archer_key`
3. Test SSH connection manually: `ssh -i ~/.ssh/archer_key user@host`
4. Verify firewall allows SSH (port 22)

### WinRM Connection Failed

```
ERROR: WinRM connection failed
```

**Solutions:**
1. Verify WinRM is enabled: `winrm get winrm/config`
2. Check firewall rules for port 5986 (HTTPS) or 5985 (HTTP)
3. For HTTPS, verify certificate is configured correctly
4. Test WinRM from another Windows machine: `Test-WSMan -ComputerName hostname`
5. Ensure user has remote management permissions

### sshpass Not Found

```
ERROR: sshpass is required for SSH password authentication
```

**Solution:**
```bash
# macOS
brew install sshpass

# Ubuntu/Debian
sudo apt-get install sshpass

# Or use SSH key authentication instead (recommended)
```

### pywinrm Not Found

```
ERROR: pywinrm module is required for WinRM execution
```

**Solution:**
```bash
pip install pywinrm
```

## Output Files

### Emulation Results

```
data/emulation/
├── T1059.001_local_1234567890.json      # Local execution
├── T1059.001_remote_1234567891.json     # Remote execution
├── APT29_group_emulation_1234567892.json # Group emulation
├── evidence/
│   ├── T1059.001_1_stdout.log
│   ├── T1059.001_2_stdout.log
│   └── .gitkeep
└── atomic-red-team/                      # Local ART installation (if chosen)
```

### Structure

- `T{technique_id}_{local|remote}_{timestamp}.json`: Test execution results
- `{group}_group_emulation_{timestamp}.json`: Group emulation summary
- `evidence/`: Captured logs and artifacts from test execution
- Remote execution results include `artifacts` section with collected evidence

## Future Enhancements

- [ ] MITRE CALDERA integration
- [ ] MACAT integration
- [ ] Network traffic capture from remote emulation
- [ ] Memory dump analysis integration
- [ ] EDR telemetry correlation
- [ ] Web UI for remote execution management
- [ ] Automated test scheduling
- [ ] Multi-host orchestration (execute across multiple targets)

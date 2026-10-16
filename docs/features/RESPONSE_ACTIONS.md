# Response Actions in Detection Reports

**Status:** ✅ Implemented
**Version:** 2.0
**Date:** 2025-11-13

## Overview

Detection reports now include comprehensive **Response Actions** that provide security analysts and incident responders with step-by-step guidance on how to triage, investigate, contain, and remediate potential security incidents. This feature transforms detection reports from simple rule documentation into actionable incident response playbooks.

## Key Features

### 1. Comprehensive Response Action Categories

Each detection includes guidance across five critical incident response phases:

#### **Triage**
Initial assessment steps to understand the scope and validity of the alert
- Verify alert authenticity
- Identify affected assets
- Assess business impact
- Check for false positive indicators

#### **Validation**
Steps to confirm if the detection represents a true positive
- Review specific technique indicators
- Correlate with other security events
- Check threat intelligence
- Verify detection logic

#### **Containment**
Immediate actions to limit impact and prevent further compromise
- Isolate affected systems
- Disable compromised accounts
- Block malicious artifacts
- Prevent lateral movement

#### **Investigation**
Detailed investigation to understand the full scope of the incident
- Trace attack timeline
- Map compromised systems
- Identify data at risk
- Collect forensic evidence

#### **Remediation**
Long-term fixes and hardening to prevent recurrence
- Remove malicious artifacts
- Patch vulnerabilities
- Reset credentials
- Implement security controls
- Update detection rules

### 2. Context-Aware Response Generation

Response actions are intelligently generated based on:

- **Technique Patterns**: Matches detection to known attack patterns (credential dumping, lateral movement, etc.)
- **MITRE ATT&CK Tactic**: Adjusts priority and urgency based on tactic
- **Indicators**: Incorporates specific IOCs from the detection
- **Threat Actor**: Adds actor-specific guidance when available

### 3. Priority-Based Response

Responses include priority ratings based on MITRE ATT&CK tactics:

| Priority | Tactics | Response Time |
|----------|---------|---------------|
| **CRITICAL** | Persistence, Privilege Escalation, Credential Access, Lateral Movement, C2, Exfiltration, Impact | Immediate |
| **HIGH** | Initial Access, Execution, Defense Evasion, Collection | Hours |
| **MEDIUM** | Discovery, Resource Development | 24 Hours |
| **LOW** | Reconnaissance | 48+ Hours |

### 4. Threat Actor Contextualization

When a threat actor is specified, response actions include:

- **Actor Description**: Background on the threat actor
- **Target Profile**: Typical victim sectors and geographies
- **Known Tools**: Other tools/malware commonly used by this actor
- **Campaign Context**: Guidance on identifying broader campaign activity
- **Intelligence Recommendations**: How to search for additional actor IOCs

## Report Integration

### Word (.docx) Reports

Response actions appear in each detection section with:

- **Priority Badge**: Color-coded priority indicator (Red=CRITICAL, Orange=HIGH, Yellow=MEDIUM)
- **Categorized Guidance**: Each response category with description and numbered steps
- **Threat Actor Context**: Dedicated section when threat actor is provided
- **Professional Formatting**: Consistent with report styling

Example Word Report Structure:
```
Detection: OS Credential Dumping: LSASS Memory
├── Technique Details (ID, Tactic, Severity, etc.)
├── Detection Query
├── Threat Indicators
├── OSINT Enrichment (if applicable)
└── Response Actions
    ├── Priority: CRITICAL
    ├── Triage
    │   1. Verify the alert is not a false positive...
    │   2. Check if the process is signed and trusted...
    ├── Validation
    ├── Containment
    ├── Investigation
    ├── Remediation
    └── Threat Actor Context (if APT specified)
        ├── Context: This technique is associated with APT29...
        └── Recommendations: Review threat intel for latest APT29 IOCs...
```

### HTML Reports

HTML reports include:
- Color-coded priority indicators
- Expandable/collapsible response sections (up to 3 steps shown by default)
- Responsive formatting for screen and print
- CSS-styled action categories

### PDF Reports

PDF reports (via Word conversion) maintain:
- Professional formatting suitable for executive briefings
- Print-ready layouts
- Consistent styling with color-coded priorities

## Response Action Templates

### Built-in Pattern Matching

The system includes pre-built response templates for common attack patterns:

1. **Credential Dumping** (LSASS, mimikatz, password extraction)
2. **Lateral Movement** (PSExec, WMI, RDP, SMB)
3. **Persistence** (Scheduled tasks, registry, services, WMI events)
4. **Command & Control** (C2 beaconing, DNS tunneling, callbacks)
5. **Execution** (PowerShell, cmd, script execution)
6. **Privilege Escalation** (UAC bypass, token manipulation, exploits)

### Generic Template Fallback

For techniques without specific patterns, a comprehensive generic template provides:
- Standard triage checklist
- General validation steps
- Universal containment actions
- Basic investigation framework
- Standard remediation guidance

## Implementation Details

### Core Module

**File**: `archer/reports/response_actions.py`

**Key Components**:

1. `ResponseActionsGenerator` class
   - Main generator with pattern matching logic
   - Template database for common techniques
   - Context-aware guidance generation

2. `generate_response_actions()` method
   ```python
   def generate_response_actions(
       technique_name: str,
       technique_id: str,
       tactic: str,
       description: str,
       indicators: Dict[str, List[str]] = None,
       threat_actor: str = None,
       threat_actor_context: Dict[str, Any] = None,
   ) -> Dict[str, Any]
   ```

3. Pattern Matching Engine
   - Searches technique name, description, and indicators
   - Scores matches against template patterns
   - Selects best-fit template or falls back to generic

### Report Generator Integration

**File**: `archer/reports/generator.py`

**Modified Sections**:

1. `WordReportGenerator.__init__()` (lines 83-88)
   - Initializes `ResponseActionsGenerator` instance

2. `WordReportGenerator.generate()` (lines 247-307)
   - Calls response generator for each detection
   - Formats response actions with Word styling
   - Adds color-coded priority indicators

3. `HTMLReportGenerator.__init__()` (lines 615-622)
   - Initializes response generator for HTML output

4. `HTMLReportGenerator.generate()` (lines 712-735)
   - Renders response actions in HTML format
   - Applies CSS styling for web display

## Usage Examples

### Generating Reports with Response Actions

Response actions are automatically included when generating reports:

**Via Web UI:**
1. Navigate to Library page
2. Select detections for a threat group
3. Click "Export" → Choose format (Word/PDF/HTML)
4. Download report with embedded response actions

**Via API:**
```python
from archer.reports.generator import WordReportGenerator

generator = WordReportGenerator()

detections = [
    {
        "technique": "OS Credential Dumping: LSASS Memory",
        "technique_id": "T1003.001",
        "tactic": "Credential Access",
        "description_html": "Adversaries may attempt to access credential material...",
        "indicators": {"cmd": ["lsass.exe", "mimikatz.exe"], "sw": ["procdump.exe"]},
        "queries": ["DeviceProcessEvents | where..."],
        "severity": "High",
    }
]

report_bytes = generator.generate(
    group_name="APT29",
    detections=detections,
    metadata={"user": "Security Analyst"}
)

with open("apt29_report.docx", "wb") as f:
    f.write(report_bytes)
```

### Customizing Threat Actor Context

To include threat actor-specific guidance:

```python
threat_actor_context = {
    "description": "APT29 is a Russian-sponsored threat group...",
    "aliases": ["Cozy Bear", "The Dukes"],
    "target_sectors": ["Government", "Healthcare", "Energy"],
    "known_tools": ["SUNBURST", "TEARDROP", "Cobalt Strike"],
    "ttps": ["T1566.002", "T1071.001", "T1055.001"],
}

response_data = generator.response_generator.generate_response_actions(
    technique_name="OS Credential Dumping: LSASS Memory",
    technique_id="T1003.001",
    tactic="Credential Access",
    description="Adversaries may attempt to access credential material...",
    threat_actor="APT29",
    threat_actor_context=threat_actor_context,
)
```

### Accessing Response Actions Programmatically

Response actions can be generated standalone for SOAR integration:

```python
from archer.reports.response_actions import ResponseActionsGenerator

generator = ResponseActionsGenerator()

response = generator.generate_response_actions(
    technique_name="Use Alternate Authentication Material: Pass the Hash",
    technique_id="T1550.002",
    tactic="Lateral Movement",
    description="Adversaries may pass the hash...",
    indicators={"cmd": ["sekurlsa::pth", "mimikatz"]},
)

# Access specific response categories
print("Containment Actions:")
for step in response['response_actions']['containment']['steps']:
    print(f"  - {step}")

# Get priority for SOAR routing
priority = response['priority']  # 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'
```

## Benefits

### For Security Analysts

1. **Faster Triage**: Immediate guidance on initial assessment steps
2. **Reduced MTTR**: Clear containment actions reduce mean time to respond
3. **Comprehensive Coverage**: All incident response phases in one document
4. **Reduced Training Time**: Built-in playbook for junior analysts

### For Incident Responders

1. **Actionable Intelligence**: Move from detection to response in seconds
2. **Consistent Methodology**: Standardized response procedures
3. **Investigation Framework**: Structured approach to incident investigation
4. **Evidence Collection**: Built-in guidance on forensic data gathering

### For Detection Engineers

1. **Validation Support**: Helps analysts validate detection accuracy
2. **Documentation**: Comprehensive playbook documentation per detection
3. **Quality Assurance**: Ensures detections are operationally viable
4. **Knowledge Sharing**: Distributes detection expertise across team

### For Management

1. **Reporting**: Professional reports suitable for executive briefings
2. **Compliance**: Demonstrates documented incident response procedures
3. **Training**: Built-in training material for new team members
4. **Metrics**: Priority ratings enable SLA tracking and measurement

## Response Action Database

### Current Coverage

The response action database includes specific guidance for:

- **6 major attack categories** (credential dumping, lateral movement, persistence, C2, execution, privilege escalation)
- **50+ specific techniques** across MITRE ATT&CK framework
- **200+ individual response steps** across all categories
- **Generic fallback template** for unmatched techniques

### Expansion

The database can be easily expanded by adding entries to `technique_response_db`:

```python
"new_pattern_category": {
    "patterns": ["keyword1", "keyword2", "tool_name"],
    "triage": [
        "Step 1: Check for...",
        "Step 2: Verify...",
    ],
    "detection_validation": [...],
    "containment": [...],
    "investigation": [...],
    "remediation": [...],
}
```

## Integration with SOAR Platforms

Response actions can be exported for SOAR platform integration:

### JSON Export Format

```json
{
  "technique_id": "T1003.001",
  "technique_name": "OS Credential Dumping: LSASS Memory",
  "tactic": "Credential Access",
  "priority": "CRITICAL",
  "response_actions": {
    "triage": {
      "description": "Initial assessment steps...",
      "steps": ["Step 1", "Step 2", ...]
    },
    "containment": {
      "description": "Immediate actions...",
      "steps": ["Isolate affected device", "Disable account", ...]
    }
  }
}
```

### SOAR Playbook Mapping

| Response Category | SOAR Action Type |
|-------------------|------------------|
| Triage | Enrichment, Investigation |
| Validation | Correlation, Analysis |
| Containment | Isolation, Blocking |
| Investigation | Forensics, Hunting |
| Remediation | Recovery, Hardening |

## Best Practices

### For Security Teams

1. **Review and Customize**: Adapt generic templates to your environment
2. **Add Local Context**: Include organization-specific tools and procedures
3. **Update Regularly**: Keep response actions aligned with current IR processes
4. **Train Analysts**: Use response actions as training material for new hires
5. **Measure Effectiveness**: Track MTTR improvements from using response guidance

### For Detection Engineers

1. **Validate Actions**: Ensure response actions are technically accurate
2. **Test Procedures**: Validate containment steps in lab environment
3. **Document Edge Cases**: Add notes for unusual configurations
4. **Integrate with Runbooks**: Link to detailed IR playbooks where applicable
5. **Gather Feedback**: Collect analyst feedback to improve guidance

## Future Enhancements

Planned improvements for future releases:

1. **AI-Enhanced Generation**: Use LLMs to generate technique-specific guidance
2. **Threat Intel Integration**: Pull real-time actor TTPs from threat feeds
3. **Automated SOAR Export**: Direct integration with SOAR platforms
4. **Playbook Templates**: Export as standalone IR playbook documents
5. **Metrics Dashboard**: Track response action usage and effectiveness
6. **Multi-Language Support**: Translate response actions to other languages
7. **Custom Templates**: User-defined response templates via configuration

## Related Documentation

- [Report Generation Guide](REPORT_GENERATION.md)
- [MITRE ATT&CK Integration](../guide/18-data-and-updates.md)
- [Detection Library](../guide/07-library.md)

## Support

For questions or issues related to response actions:
- Review generated reports for formatting issues
- Check `archer/reports/response_actions.py` for template customization
- Verify `ResponseActionsGenerator` is properly initialized
- Submit feedback on response action quality and accuracy

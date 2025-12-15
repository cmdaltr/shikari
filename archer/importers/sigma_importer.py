"""
Sigma Rule Importer

Imports detection rules from the Sigma project and converts them
to Archer's knowledge base format.

Sigma Project: https://github.com/SigmaHQ/sigma
"""

import yaml
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class SigmaImporter:
    """Import and convert Sigma rules to Archer knowledge base format."""

    # Map Sigma tactics to MITRE ATT&CK tactics
    TACTIC_MAPPING = {
        'reconnaissance': 'reconnaissance',
        'resource_development': 'resource_development',
        'initial_access': 'initial_access',
        'execution': 'execution',
        'persistence': 'persistence',
        'privilege_escalation': 'privilege_escalation',
        'defense_evasion': 'defense_evasion',
        'credential_access': 'credential_access',
        'discovery': 'discovery',
        'lateral_movement': 'lateral_movement',
        'collection': 'collection',
        'exfiltration': 'exfiltration',
        'command_and_control': 'command_and_control',
        'impact': 'impact',
    }

    # Map Sigma logsources to Archer platforms
    PLATFORM_MAPPING = {
        'windows': {
            'security': 'Splunk',
            'sysmon': 'Splunk',
            'powershell': 'Splunk',
            'application': 'Splunk',
            'system': 'Splunk',
        },
        'linux': {
            'auditd': 'Splunk',
            'syslog': 'Splunk',
        },
        'macos': {
            'file_event': 'Splunk',
        },
        'azure': {
            'activitylogs': 'MicrosoftThreatProtection',
            'signinlogs': 'MicrosoftThreatProtection',
        },
        'aws': {
            'cloudtrail': 'Splunk',
        }
    }

    def __init__(self, sigma_repo_path: str, output_path: str):
        """
        Initialize Sigma importer.

        Args:
            sigma_repo_path: Path to cloned Sigma repository
            output_path: Path to Archer knowledge base
        """
        self.sigma_path = Path(sigma_repo_path)
        self.output_path = Path(output_path)
        self.stats = {
            'total_files': 0,
            'processed': 0,
            'imported': 0,
            'skipped': 0,
            'errors': 0,
            'by_tactic': {},
            'by_platform': {}
        }

    def import_all(self, min_level: str = 'medium') -> Dict:
        """
        Import all Sigma rules.

        Args:
            min_level: Minimum rule level (low, medium, high, critical)

        Returns:
            Dictionary with import statistics
        """
        print(f"Importing Sigma rules from: {self.sigma_path}")
        print(f"Output directory: {self.output_path}")
        print(f"Minimum level: {min_level}")
        print()

        # Find all Sigma rule files
        rule_files = list(self.sigma_path.glob("**/*.yml"))
        self.stats['total_files'] = len(rule_files)

        print(f"Found {len(rule_files)} Sigma rule files")
        print()

        level_priority = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        min_level_priority = level_priority.get(min_level, 1)

        for rule_file in rule_files:
            try:
                self.stats['processed'] += 1

                # Parse Sigma rule
                with open(rule_file, 'r', encoding='utf-8') as f:
                    sigma_rule = yaml.safe_load(f)

                if not sigma_rule:
                    self.stats['skipped'] += 1
                    continue

                # Check rule level
                rule_level = sigma_rule.get('level', 'medium')
                if level_priority.get(rule_level, 0) < min_level_priority:
                    self.stats['skipped'] += 1
                    continue

                # Extract MITRE ATT&CK technique
                technique_id = self._extract_technique(sigma_rule)
                if not technique_id:
                    self.stats['skipped'] += 1
                    continue

                # Convert to Archer format
                archer_detection = self._convert_to_archer_format(sigma_rule, technique_id)
                if not archer_detection:
                    self.stats['skipped'] += 1
                    continue

                # Determine output file path
                tactic = archer_detection.get('tactic', 'unknown')
                platform = archer_detection.get('platform', 'unknown')

                output_file = self._get_output_path(technique_id, tactic, platform, rule_file.stem)

                # Write to knowledge base
                self._write_detection(output_file, archer_detection)

                self.stats['imported'] += 1
                self.stats['by_tactic'][tactic] = self.stats['by_tactic'].get(tactic, 0) + 1
                self.stats['by_platform'][platform] = self.stats['by_platform'].get(platform, 0) + 1

                if self.stats['processed'] % 100 == 0:
                    print(f"  Processed: {self.stats['processed']}/{self.stats['total_files']} "
                          f"(Imported: {self.stats['imported']}, Skipped: {self.stats['skipped']})")

            except Exception as e:
                self.stats['errors'] += 1
                if self.stats['errors'] <= 10:  # Only show first 10 errors
                    print(f"  Error processing {rule_file.name}: {e}")

        print()
        print("=" * 70)
        print("Import Complete")
        print("=" * 70)
        print(f"Total files: {self.stats['total_files']}")
        print(f"Processed: {self.stats['processed']}")
        print(f"Imported: {self.stats['imported']}")
        print(f"Skipped: {self.stats['skipped']}")
        print(f"Errors: {self.stats['errors']}")
        print()
        print("By Tactic:")
        for tactic, count in sorted(self.stats['by_tactic'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {tactic}: {count}")
        print()
        print("By Platform:")
        for platform, count in sorted(self.stats['by_platform'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {platform}: {count}")

        return self.stats

    def _extract_technique(self, sigma_rule: Dict) -> Optional[str]:
        """Extract MITRE ATT&CK technique ID from Sigma rule tags."""
        tags = sigma_rule.get('tags', [])

        for tag in tags:
            # Look for attack.t#### or attack.t####.###
            if isinstance(tag, str) and tag.startswith('attack.t'):
                technique = tag.replace('attack.', '').upper()
                # Validate format
                if re.match(r'^T\d{4}(\.\d{3})?$', technique):
                    return technique

        return None

    def _extract_tactic(self, sigma_rule: Dict) -> Optional[str]:
        """Extract MITRE ATT&CK tactic from Sigma rule tags."""
        tags = sigma_rule.get('tags', [])

        for tag in tags:
            if isinstance(tag, str) and tag.startswith('attack.'):
                tactic_name = tag.replace('attack.', '').lower()
                if tactic_name in self.TACTIC_MAPPING:
                    return self.TACTIC_MAPPING[tactic_name]

        return None

    def _determine_platform(self, sigma_rule: Dict) -> str:
        """Determine platform from Sigma logsource."""
        logsource = sigma_rule.get('logsource', {})

        product = logsource.get('product', '').lower()
        service = logsource.get('service', '').lower()
        category = logsource.get('category', '').lower()

        # Try to map to platform
        if product == 'windows':
            if service in ['security', 'sysmon', 'powershell', 'application', 'system']:
                return 'Splunk'
            return 'MicrosoftThreatProtection'
        elif product == 'linux':
            return 'Splunk'
        elif product == 'azure':
            return 'MicrosoftThreatProtection'
        elif product == 'aws':
            return 'Splunk'
        elif product == 'gcp':
            return 'GoogleSecOps'

        # Default based on category
        if category in ['process_creation', 'network_connection', 'file_event']:
            return 'Splunk'

        return 'Splunk'  # Default

    def _estimate_fidelity(self, sigma_rule: Dict) -> float:
        """
        Estimate fidelity score based on Sigma rule characteristics.

        Factors:
        - Rule level (critical=0.9, high=0.85, medium=0.75, low=0.65)
        - False positive level
        - Number of detection conditions
        """
        level = sigma_rule.get('level', 'medium')
        falsepositives = sigma_rule.get('falsepositives', [])

        level_scores = {
            'critical': 0.90,
            'high': 0.85,
            'medium': 0.75,
            'low': 0.65,
            'informational': 0.50
        }

        base_score = level_scores.get(level, 0.70)

        # Adjust for false positives
        fp_count = len(falsepositives) if isinstance(falsepositives, list) else 0
        fp_penalty = min(0.15, fp_count * 0.03)

        # Detection complexity (more conditions = higher fidelity)
        detection = sigma_rule.get('detection', {})
        condition_count = len([k for k in detection.keys() if k != 'condition'])
        complexity_bonus = min(0.10, condition_count * 0.02)

        final_score = max(0.50, min(0.95, base_score - fp_penalty + complexity_bonus))

        return round(final_score, 2)

    def _convert_to_archer_format(self, sigma_rule: Dict, technique_id: str) -> Optional[Dict]:
        """
        Convert Sigma rule to Archer knowledge base format.

        Returns:
            Dictionary in Archer format, or None if conversion fails
        """
        try:
            technique_name = sigma_rule.get('title', technique_id)
            tactic = self._extract_tactic(sigma_rule) or 'unknown'
            platform = self._determine_platform(sigma_rule)
            fidelity = self._estimate_fidelity(sigma_rule)

            # Build Archer detection
            archer_detection = {
                'technique_id': technique_id,
                'technique_name': technique_name,
                'tactic': tactic,
                'platform': platform,
                'connectorId': platform,
                'fidelity_score': fidelity,
                'validated': True,
                'source': 'sigma',
                'sigma_id': sigma_rule.get('id', 'unknown'),
                'level': sigma_rule.get('level', 'medium'),
                'query': self._format_query_description(sigma_rule),
                'explanation': sigma_rule.get('description', ''),
                'false_positives': sigma_rule.get('falsepositives', []),
                'references': sigma_rule.get('references', []),
                'tags': sigma_rule.get('tags', []),
                'logsource': sigma_rule.get('logsource', {}),
                'detection': sigma_rule.get('detection', {}),
                'metadata': {
                    'created_date': sigma_rule.get('date', str(datetime.now().date())),
                    'modified_date': sigma_rule.get('modified', str(datetime.now().date())),
                    'author': sigma_rule.get('author', 'Sigma Project'),
                    'status': sigma_rule.get('status', 'stable'),
                    'imported_date': str(datetime.now().date()),
                }
            }

            return archer_detection

        except Exception as e:
            print(f"  Error converting rule: {e}")
            return None

    def _format_query_description(self, sigma_rule: Dict) -> str:
        """
        Format Sigma detection logic as a human-readable query description.

        Since Sigma rules need to be converted to specific platforms (Splunk, KQL, etc.),
        we store the detection logic as YAML that can be processed later.
        """
        detection = sigma_rule.get('detection', {})

        # Format detection as YAML for later platform-specific conversion
        query_lines = [
            "# Sigma Detection Logic",
            "# Convert to platform-specific query using Sigma tools:",
            "# https://github.com/SigmaHQ/sigma",
            "",
            yaml.dump(detection, default_flow_style=False)
        ]

        return "\n".join(query_lines)

    def _get_output_path(self, technique_id: str, tactic: str, platform: str, rule_name: str) -> Path:
        """Determine output file path for detection."""
        tactic_dir = self.output_path / "detection_examples" / tactic
        tactic_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize filename
        safe_name = re.sub(r'[^\w\-_.]', '_', rule_name)
        filename = f"{technique_id}_{platform.lower()}_sigma_{safe_name}.yaml"

        return tactic_dir / filename

    def _write_detection(self, output_file: Path, detection: Dict):
        """Write detection to YAML file."""
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(detection, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def main():
    """Main function for testing."""
    import sys

    if len(sys.argv) < 3:
        print("Usage: python sigma_importer.py <sigma_repo_path> <output_path>")
        sys.exit(1)

    importer = SigmaImporter(sys.argv[1], sys.argv[2])
    stats = importer.import_all(min_level='medium')

    print()
    print("Import statistics saved to import_stats.json")
    with open('import_stats.json', 'w') as f:
        json.dump(stats, f, indent=2)


if __name__ == "__main__":
    main()

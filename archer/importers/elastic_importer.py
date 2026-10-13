"""
Elastic Detection Rules Importer

Imports Elastic Security detection rules into Archer knowledge base.
Elastic Detection Rules: https://github.com/elastic/detection-rules
"""

import toml
from pathlib import Path
from typing import Dict, List, Optional
import yaml


# MITRE ATT&CK tactic ID to name mapping
TACTIC_ID_TO_NAME = {
    'TA0001': 'initial_access',
    'TA0002': 'execution',
    'TA0003': 'persistence',
    'TA0004': 'privilege_escalation',
    'TA0005': 'defense_evasion',
    'TA0006': 'credential_access',
    'TA0007': 'discovery',
    'TA0008': 'lateral_movement',
    'TA0009': 'collection',
    'TA0010': 'exfiltration',
    'TA0011': 'command_and_control',
    'TA0040': 'impact'
}

# Severity to risk score mapping
SEVERITY_SCORES = {
    'critical': 0.95,
    'high': 0.85,
    'medium': 0.75,
    'low': 0.65
}


class ElasticImporter:
    """Import Elastic Detection Rules."""

    def __init__(self, repo_path: str, output_path: str):
        """
        Initialize Elastic importer.

        Args:
            repo_path: Path to Elastic Detection Rules repository root
            output_path: Path to knowledge base output directory
        """
        self.repo_path = Path(repo_path)
        self.output_path = Path(output_path)
        self.rules_paths = [
            self.repo_path / 'rules',
            self.repo_path / 'rules_building_block'
        ]

    def import_all(self, min_severity: str = 'medium') -> Dict:
        """
        Import all Elastic detection rules.

        Args:
            min_severity: Minimum severity to import (low, medium, high, critical)

        Returns:
            Dictionary with import statistics
        """
        print(f"Importing Elastic Detection Rules from: {self.repo_path}")
        print(f"Output directory: {self.output_path}")
        print(f"Minimum severity: {min_severity}")
        print()

        # Collect all rule files
        detection_files = []
        for rules_path in self.rules_paths:
            if rules_path.exists():
                detection_files.extend(list(rules_path.rglob('*.toml')))

        if not detection_files:
            print(f"Error: No detection rules found in {self.repo_path}")
            return {'imported': 0, 'skipped': 0, 'errors': 0}

        print(f"Found {len(detection_files)} Elastic detection files")
        print()

        stats = {
            'total': len(detection_files),
            'imported': 0,
            'skipped': 0,
            'errors': 0
        }

        severity_levels = ['low', 'medium', 'high', 'critical']
        min_severity_index = severity_levels.index(min_severity.lower())

        for i, file_path in enumerate(detection_files, 1):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    elastic_detection = toml.load(f)

                if not elastic_detection or 'rule' not in elastic_detection:
                    stats['skipped'] += 1
                    continue

                rule = elastic_detection['rule']

                # Check severity
                severity = rule.get('severity', 'low').lower()
                if severity not in severity_levels:
                    severity = 'medium'

                if severity_levels.index(severity) < min_severity_index:
                    stats['skipped'] += 1
                    continue

                # Extract MITRE technique IDs
                technique_ids = self._extract_techniques(elastic_detection)
                if not technique_ids:
                    stats['skipped'] += 1
                    continue

                # Check maturity
                metadata = elastic_detection.get('metadata', {})
                maturity = metadata.get('maturity', '').lower()
                if maturity == 'deprecated':
                    stats['skipped'] += 1
                    continue

                # Import for each technique
                for technique_id in technique_ids:
                    archer_detection = self._convert_to_archer_format(
                        elastic_detection,
                        technique_id
                    )

                    if archer_detection:
                        self._save_detection(archer_detection, technique_id)
                        stats['imported'] += 1

                # Progress update
                if i % 100 == 0:
                    print(f"  Processed: {i}/{len(detection_files)} "
                          f"(Imported: {stats['imported']}, "
                          f"Skipped: {stats['skipped']})")

            except Exception as e:
                stats['errors'] += 1
                if stats['errors'] < 10:  # Only print first 10 errors
                    print(f"  Error processing {file_path.name}: {e}")

        print()
        print("=" * 70)
        print("Import Complete")
        print("=" * 70)
        print(f"Total files: {stats['total']}")
        print(f"Processed: {stats['total']}")
        print(f"Imported: {stats['imported']}")
        print(f"Skipped: {stats['skipped']}")
        print(f"Errors: {stats['errors']}")
        print()

        return stats

    def _extract_techniques(self, detection: Dict) -> List[str]:
        """Extract MITRE ATT&CK technique IDs from detection."""
        techniques = []

        rule = detection.get('rule', {})
        threats = rule.get('threat', [])

        for threat in threats:
            if not isinstance(threat, dict):
                continue

            # Get techniques from threat
            threat_techniques = threat.get('technique', [])
            for tech in threat_techniques:
                if isinstance(tech, dict):
                    tech_id = tech.get('id', '')
                    if tech_id and tech_id.startswith('T'):
                        techniques.append(tech_id)

                    # Get sub-techniques
                    subtechniques = tech.get('subtechnique', [])
                    for subtech in subtechniques:
                        if isinstance(subtech, dict):
                            subtech_id = subtech.get('id', '')
                            if subtech_id and subtech_id.startswith('T'):
                                techniques.append(subtech_id)

        return list(set(techniques))  # Remove duplicates

    def _get_tactic(self, detection: Dict, technique_id: str) -> str:
        """Determine MITRE tactic from detection."""
        rule = detection.get('rule', {})
        threats = rule.get('threat', [])

        # Try to get tactic from threat data
        for threat in threats:
            if not isinstance(threat, dict):
                continue

            tactic = threat.get('tactic', {})
            if isinstance(tactic, dict):
                tactic_id = tactic.get('id', '')
                if tactic_id in TACTIC_ID_TO_NAME:
                    return TACTIC_ID_TO_NAME[tactic_id]

        # Fallback: infer from technique ID range
        technique_num = int(technique_id[1:5])

        if technique_num < 1020:
            return 'initial_access'
        elif technique_num < 1100:
            return 'execution'
        elif technique_num < 1140:
            return 'persistence'
        elif technique_num < 1220:
            return 'privilege_escalation'
        elif technique_num < 1300:
            return 'defense_evasion'
        elif technique_num < 1400:
            return 'credential_access'
        elif technique_num < 1500:
            return 'discovery'
        elif technique_num < 1560:
            return 'lateral_movement'
        elif technique_num < 1610:
            return 'collection'
        elif technique_num < 1650:
            return 'exfiltration'
        else:
            return 'execution'  # Default

    def _estimate_fidelity(self, detection: Dict) -> float:
        """Estimate fidelity score based on Elastic detection characteristics."""
        rule = detection.get('rule', {})
        metadata = detection.get('metadata', {})

        # Base score from severity
        severity = rule.get('severity', 'medium').lower()
        score = SEVERITY_SCORES.get(severity, 0.75)

        # Maturity bonus
        maturity = metadata.get('maturity', '').lower()
        if maturity == 'production':
            score += 0.10
        elif maturity == 'beta':
            score += 0.05

        # Query complexity indicator (longer, more specific queries tend to be better)
        query = rule.get('query', '')
        if query:
            query_length = len(query)
            if query_length > 500:
                score += 0.05
            elif query_length > 200:
                score += 0.03

        # Has investigation guide
        if rule.get('note', ''):
            score += 0.03

        # Has references
        if rule.get('references', []):
            score += 0.02

        return min(max(score, 0.50), 0.95)

    def _convert_to_archer_format(self, elastic_detection: Dict, technique_id: str) -> Optional[Dict]:
        """Convert Elastic detection to Archer knowledge base format."""
        try:
            rule = elastic_detection.get('rule', {})
            metadata = elastic_detection.get('metadata', {})

            name = rule.get('name', 'Unknown')
            query = rule.get('query', '')

            if not query:
                return None

            tactic = self._get_tactic(elastic_detection, technique_id)
            fidelity = self._estimate_fidelity(elastic_detection)

            # Build Archer detection
            archer_detection = {
                'technique_id': technique_id,
                'technique_name': name,
                'tactic': tactic,
                'platform': 'Elastic',
                'fidelity_score': fidelity,
                'validated': metadata.get('maturity', '').lower() == 'production',
                'query': query.strip(),
                'explanation': rule.get('description', '').strip(),
                'source': 'Elastic Detection Rules',
                'source_url': f"https://github.com/elastic/detection-rules/tree/main/rules/{rule.get('rule_id', '')}.toml"
            }

            # Add query type/language
            query_type = rule.get('type', 'query')
            query_language = rule.get('language', 'kuery')
            archer_detection['query_type'] = query_type
            archer_detection['query_language'] = query_language

            # Add indicators from tags
            indicators = []
            tags = rule.get('tags', [])

            # Extract data sources
            data_sources = [tag.replace('Data Source: ', '') for tag in tags if tag.startswith('Data Source:')]
            for ds in data_sources:
                indicators.append({
                    'type': 'data_source',
                    'value': ds,
                    'confidence': 'high'
                })

            # Extract OS
            os_types = [tag.replace('OS: ', '') for tag in tags if tag.startswith('OS:')]
            for os in os_types:
                indicators.append({
                    'type': 'operating_system',
                    'value': os,
                    'confidence': 'high'
                })

            if indicators:
                archer_detection['indicators'] = indicators

            # Add false positives from investigation note
            note = rule.get('note', '')
            if 'false positive' in note.lower():
                # Extract false positive section
                fp_start = note.lower().find('false positive')
                if fp_start >= 0:
                    fp_section = note[fp_start:fp_start+500]  # Get ~500 chars
                    archer_detection['false_positives'] = [{
                        'description': fp_section.strip(),
                        'mitigation': 'Review investigation guide for details'
                    }]

            # Add references
            references = rule.get('references', [])
            if references:
                archer_detection['references'] = references

            # Add investigation guide flag
            if note:
                archer_detection['has_investigation_guide'] = True

            # Add risk score
            risk_score = rule.get('risk_score', 0)
            if risk_score:
                archer_detection['risk_score'] = risk_score

            return archer_detection

        except Exception as e:
            print(f"Error converting detection {elastic_detection.get('rule', {}).get('name', 'unknown')}: {e}")
            return None

    def _save_detection(self, detection: Dict, technique_id: str):
        """Save detection to knowledge base."""
        tactic = detection['tactic']
        tactic_dir = self.output_path / 'detection_examples' / tactic
        tactic_dir.mkdir(parents=True, exist_ok=True)

        # Create filename
        safe_name = detection['technique_name'].lower()
        safe_name = safe_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
        safe_name = ''.join(c for c in safe_name if c.isalnum() or c in ('_', '-'))

        filename = f"{technique_id}_{safe_name}_elastic.yaml"
        output_file = tactic_dir / filename

        # Save as YAML
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(detection, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

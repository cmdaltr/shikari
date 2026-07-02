"""
Splunk Security Content Importer

Imports Splunk Security Content detections into Archer knowledge base.
Splunk Security Content: https://github.com/splunk/security_content
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional


# MITRE ATT&CK tactic mapping
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
    'command_and_control': 'command_and_control',
    'exfiltration': 'exfiltration',
    'impact': 'impact'
}


class SplunkImporter:
    """Import Splunk Security Content rules."""

    def __init__(self, repo_path: str, output_path: str):
        """
        Initialize Splunk importer.

        Args:
            repo_path: Path to Splunk Security Content repository root
            output_path: Path to knowledge base output directory
        """
        self.repo_path = Path(repo_path)
        self.output_path = Path(output_path)
        self.detections_path = self.repo_path / 'detections'

    def import_all(self, min_risk_score: int = 40) -> Dict:
        """
        Import all Splunk Security Content detections.

        Args:
            min_risk_score: Minimum risk score to import (default: 40)

        Returns:
            Dictionary with import statistics
        """
        print(f"Importing Splunk Security Content from: {self.detections_path}")
        print(f"Output directory: {self.output_path}")
        print(f"Minimum risk score: {min_risk_score}")
        print()

        if not self.detections_path.exists():
            print(f"Error: Detections directory not found: {self.detections_path}")
            return {'imported': 0, 'skipped': 0, 'errors': 0}

        # Find all YAML files
        detection_files = list(self.detections_path.rglob('*.yml'))
        print(f"Found {len(detection_files)} Splunk detection files")
        print()

        stats = {
            'total': len(detection_files),
            'imported': 0,
            'skipped': 0,
            'errors': 0
        }

        for i, file_path in enumerate(detection_files, 1):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    splunk_detection = yaml.safe_load(f)

                if not splunk_detection:
                    stats['skipped'] += 1
                    continue

                # Extract MITRE technique IDs
                technique_ids = self._extract_techniques(splunk_detection)
                if not technique_ids:
                    stats['skipped'] += 1
                    continue

                # Check risk score
                risk_score = self._get_risk_score(splunk_detection)
                if risk_score < min_risk_score:
                    stats['skipped'] += 1
                    continue

                # Check if it's a production-ready detection
                status = splunk_detection.get('status', '').lower()
                if status == 'deprecated':
                    stats['skipped'] += 1
                    continue

                # Import for each technique
                for technique_id in technique_ids:
                    archer_detection = self._convert_to_archer_format(
                        splunk_detection,
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

        tags = detection.get('tags', {})
        mitre_ids = tags.get('mitre_attack_id', [])

        if isinstance(mitre_ids, list):
            techniques.extend(mitre_ids)
        elif isinstance(mitre_ids, str):
            techniques.append(mitre_ids)

        # Filter to valid technique IDs (T####.###)
        valid_techniques = []
        for tid in techniques:
            if isinstance(tid, str) and tid.startswith('T') and len(tid) >= 5:
                valid_techniques.append(tid)

        return valid_techniques

    def _get_risk_score(self, detection: Dict) -> int:
        """Get risk score from detection."""
        rba = detection.get('rba', {})
        risk_objects = rba.get('risk_objects', [])

        # Get max risk score from risk objects
        max_score = 0
        for risk_obj in risk_objects:
            score = risk_obj.get('score', 0)
            if score > max_score:
                max_score = score

        return max_score

    def _get_tactic(self, detection: Dict, technique_id: str) -> str:
        """Determine MITRE tactic from detection."""
        # Try to get from security_domain
        tags = detection.get('tags', {})
        security_domain = tags.get('security_domain', '').lower()

        # Map common security domains to tactics
        domain_to_tactic = {
            'endpoint': 'execution',
            'network': 'command_and_control',
            'access': 'initial_access',
            'threat': 'execution'
        }

        if security_domain in domain_to_tactic:
            return domain_to_tactic[security_domain]

        # Default based on technique ID range
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
        """Estimate fidelity score based on Splunk detection characteristics."""
        score = 0.70  # Base score

        # Status bonus
        status = detection.get('status', '').lower()
        if status == 'production':
            score += 0.15
        elif status == 'experimental':
            score += 0.05

        # Risk score bonus
        risk_score = self._get_risk_score(detection)
        if risk_score >= 80:
            score += 0.10
        elif risk_score >= 60:
            score += 0.05

        # Type bonus
        detection_type = detection.get('type', '').lower()
        if detection_type == 'ttp':
            score += 0.10
        elif detection_type == 'anomaly':
            score += 0.05

        # Known false positives penalty
        known_fps = detection.get('known_false_positives', '')
        if known_fps and len(known_fps) < 50:
            score -= 0.05

        return min(max(score, 0.50), 0.95)

    def _convert_to_archer_format(self, splunk_detection: Dict, technique_id: str) -> Optional[Dict]:
        """Convert Splunk detection to Archer knowledge base format."""
        try:
            name = splunk_detection.get('name', 'Unknown')
            search = splunk_detection.get('search', '')

            if not search:
                return None

            tactic = self._get_tactic(splunk_detection, technique_id)
            fidelity = self._estimate_fidelity(splunk_detection)

            # Build Archer detection
            archer_detection = {
                'technique_id': technique_id,
                'technique_name': name,
                'tactic': tactic,
                'platform': 'Splunk',
                'fidelity_score': fidelity,
                'validated': splunk_detection.get('status', '').lower() == 'production',
                'query': search.strip(),
                'explanation': splunk_detection.get('description', '').strip(),
                'source': 'Splunk Security Content',
                'source_url': f"https://research.splunk.com/detections/{splunk_detection.get('id', '')}/"
            }

            # Add indicators
            indicators = []

            # Extract data sources as indicators
            data_sources = splunk_detection.get('data_source', [])
            if isinstance(data_sources, list):
                for ds in data_sources:
                    indicators.append({
                        'type': 'data_source',
                        'value': ds,
                        'confidence': 'high'
                    })

            # Add risk objects as indicators
            rba = splunk_detection.get('rba', {})
            risk_objects = rba.get('risk_objects', [])
            for risk_obj in risk_objects:
                field = risk_obj.get('field', '')
                obj_type = risk_obj.get('type', 'unknown')
                if field:
                    indicators.append({
                        'type': f'risk_{obj_type}',
                        'value': field,
                        'confidence': 'high'
                    })

            if indicators:
                archer_detection['indicators'] = indicators

            # Add false positives
            known_fps = splunk_detection.get('known_false_positives', '')
            if known_fps:
                archer_detection['false_positives'] = [{
                    'description': known_fps.strip(),
                    'mitigation': 'Review context and user activity'
                }]

            # Add references
            references = splunk_detection.get('references', [])
            if references:
                archer_detection['references'] = references

            # Add validation data if available
            tests = splunk_detection.get('tests', [])
            if tests:
                archer_detection['validation'] = {
                    'test_available': True,
                    'test_count': len(tests),
                    'test_data_url': tests[0].get('attack_data', [{}])[0].get('data', '') if tests else ''
                }

            return archer_detection

        except Exception as e:
            print(f"Error converting detection {splunk_detection.get('name', 'unknown')}: {e}")
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

        filename = f"{technique_id}_{safe_name}_splunk.yaml"
        output_file = tactic_dir / filename

        # Save as YAML
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(detection, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

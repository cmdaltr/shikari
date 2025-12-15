"""
Test Runner

Runs validation tests on detection queries using test data samples.
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional
from .field_validator import FieldValidator
from .query_validator import QueryValidator


class TestRunner:
    """Runs validation tests on detection queries."""

    def __init__(self, knowledge_base_path: str = 'data/external/detections'):
        """
        Initialize test runner.

        Args:
            knowledge_base_path: Path to knowledge base directory
        """
        self.kb_path = Path(knowledge_base_path)
        self.test_samples_path = Path('data/validation/test_samples')
        self.results_path = Path('data/validation/validation_results')

        self.field_validator = FieldValidator(knowledge_base_path)
        self.query_validator = QueryValidator()

    def run_all_tests(self) -> Dict:
        """
        Run all validation tests.

        Returns:
            Test results summary
        """
        print("=" * 70)
        print("Running Validation Tests")
        print("=" * 70)
        print()

        results = {
            'total_detections': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'details': []
        }

        # Test all detections in knowledge base
        detection_files = list(self.kb_path.glob('detection_examples/**/*.yaml'))
        results['total_detections'] = len(detection_files)

        print(f"Found {len(detection_files)} detection files to validate")
        print()

        for i, detection_file in enumerate(detection_files, 1):
            try:
                with open(detection_file, 'r', encoding='utf-8') as f:
                    detection = yaml.safe_load(f)

                test_result = self._test_detection(detection, detection_file)
                results['details'].append(test_result)

                if test_result['passed']:
                    results['passed'] += 1
                else:
                    results['failed'] += 1

                if test_result['warnings']:
                    results['warnings'] += 1

                # Progress update
                if i % 100 == 0:
                    print(f"  Tested: {i}/{len(detection_files)} "
                          f"(Passed: {results['passed']}, "
                          f"Failed: {results['failed']})")

            except Exception as e:
                print(f"  Error testing {detection_file.name}: {e}")
                results['failed'] += 1

        print()
        print("=" * 70)
        print("Validation Results")
        print("=" * 70)
        print(f"Total Detections: {results['total_detections']}")
        print(f"Passed: {results['passed']} ({results['passed']/results['total_detections']*100:.1f}%)")
        print(f"Failed: {results['failed']} ({results['failed']/results['total_detections']*100:.1f}%)")
        print(f"With Warnings: {results['warnings']} ({results['warnings']/results['total_detections']*100:.1f}%)")
        print()

        # Save results
        self._save_results(results)

        return results

    def _test_detection(self, detection: Dict, file_path: Path) -> Dict:
        """Test a single detection."""
        result = {
            'file': str(file_path),
            'technique_id': detection.get('technique_id', 'Unknown'),
            'platform': detection.get('platform', 'Unknown'),
            'passed': True,
            'errors': [],
            'warnings': [],
            'suggestions': []
        }

        query = detection.get('query', '')
        platform = detection.get('platform', 'Unknown')

        if not query:
            result['passed'] = False
            result['errors'].append("No query found in detection")
            return result

        # Run query validator
        query_result = self.query_validator.validate(query, platform)

        if not query_result['valid']:
            result['passed'] = False

        result['errors'].extend(query_result.get('errors', []))
        result['warnings'].extend(query_result.get('warnings', []))
        result['suggestions'].extend(query_result.get('suggestions', []))

        # Run field validator
        field_result = self.field_validator.validate_query(query, platform)

        if field_result['valid'] is False:
            result['passed'] = False

        if field_result['missing_fields']:
            result['errors'].append(
                f"Missing fields: {', '.join(field_result['missing_fields'])}"
            )

            # Add suggestions for missing fields
            for field, suggestions in field_result.get('suggestions', {}).items():
                result['suggestions'].append(
                    f"For missing field '{field}', consider: {', '.join(suggestions)}"
                )

        result['warnings'].extend(field_result.get('warnings', []))

        # Run logic checker
        logic_result = self.query_validator.check_logic(query, platform)
        result['warnings'].extend(logic_result.get('warnings', []))

        return result

    def test_query(self, query: str, platform: str) -> Dict:
        """
        Test a single query.

        Args:
            query: The detection query
            platform: Platform name

        Returns:
            Test result dictionary
        """
        result = {
            'platform': platform,
            'passed': True,
            'errors': [],
            'warnings': [],
            'suggestions': []
        }

        # Run query validator
        query_result = self.query_validator.validate(query, platform)

        if not query_result['valid']:
            result['passed'] = False

        result['errors'].extend(query_result.get('errors', []))
        result['warnings'].extend(query_result.get('warnings', []))
        result['suggestions'].extend(query_result.get('suggestions', []))

        # Run field validator
        field_result = self.field_validator.validate_query(query, platform)

        if field_result['valid'] is False:
            result['passed'] = False

        if field_result['missing_fields']:
            result['errors'].append(
                f"Missing fields: {', '.join(field_result['missing_fields'])}"
            )

            for field, suggestions in field_result.get('suggestions', {}).items():
                result['suggestions'].append(
                    f"For missing field '{field}', consider: {', '.join(suggestions)}"
                )

        result['warnings'].extend(field_result.get('warnings', []))

        # Run logic checker
        logic_result = self.query_validator.check_logic(query, platform)
        result['warnings'].extend(logic_result.get('warnings', []))

        return result

    def _save_results(self, results: Dict):
        """Save validation results to file."""
        self.results_path.mkdir(parents=True, exist_ok=True)

        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = self.results_path / f'validation_results_{timestamp}.yaml'

        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(results, f, default_flow_style=False, sort_keys=False)

        print(f"Results saved to: {output_file}")

    def generate_report(self, results: Dict) -> str:
        """
        Generate a human-readable validation report.

        Args:
            results: Test results from run_all_tests()

        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 70)
        report.append("DETECTION VALIDATION REPORT")
        report.append("=" * 70)
        report.append("")
        report.append(f"Total Detections Tested: {results['total_detections']}")
        report.append(f"Passed: {results['passed']} ({results['passed']/results['total_detections']*100:.1f}%)")
        report.append(f"Failed: {results['failed']} ({results['failed']/results['total_detections']*100:.1f}%)")
        report.append(f"With Warnings: {results['warnings']} ({results['warnings']/results['total_detections']*100:.1f}%)")
        report.append("")

        # Show failures
        failures = [d for d in results['details'] if not d['passed']]
        if failures:
            report.append("=" * 70)
            report.append("FAILED DETECTIONS")
            report.append("=" * 70)
            report.append("")

            for i, failure in enumerate(failures[:10], 1):  # Show first 10
                report.append(f"{i}. {failure['technique_id']} ({failure['platform']})")
                report.append(f"   File: {Path(failure['file']).name}")

                for error in failure['errors']:
                    report.append(f"   ERROR: {error}")

                report.append("")

            if len(failures) > 10:
                report.append(f"... and {len(failures) - 10} more failures")
                report.append("")

        # Show common warnings
        all_warnings = {}
        for detail in results['details']:
            for warning in detail.get('warnings', []):
                all_warnings[warning] = all_warnings.get(warning, 0) + 1

        if all_warnings:
            report.append("=" * 70)
            report.append("COMMON WARNINGS")
            report.append("=" * 70)
            report.append("")

            sorted_warnings = sorted(all_warnings.items(), key=lambda x: x[1], reverse=True)
            for warning, count in sorted_warnings[:10]:
                report.append(f"- {warning} ({count} occurrences)")

            report.append("")

        return "\n".join(report)

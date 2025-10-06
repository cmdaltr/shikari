"""
Atomic Red Team Integration

Executes Atomic Red Team tests and collects evidence to enhance threat hunting detections.

Usage:
    atomic = AtomicRedTeam()
    results = atomic.execute_technique("T1059.001", auto_cleanup=True)
    evidence = atomic.extract_evidence(results)
"""

import os
import json
import subprocess
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime


class AtomicRedTeam:
    """Interface for executing and managing Atomic Red Team tests."""

    def __init__(self, atomic_path: Optional[str] = None):
        """
        Initialize Atomic Red Team integration.

        Args:
            atomic_path: Path to atomic-red-team directory.
                        Defaults to ATOMIC_REDTEAM_PATH env var or /opt/atomic-red-team
        """
        from archer.config import EmulationConfig

        self.atomic_path = atomic_path or EmulationConfig.atomic_path
        self.output_dir = Path(EmulationConfig.output_dir)
        self.evidence_dir = Path(EmulationConfig.evidence_dir)

        # Create output directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Validate Atomic Red Team installation
        self.atomics_dir = Path(self.atomic_path) / "atomics"
        if not self.atomics_dir.exists():
            raise FileNotFoundError(
                f"Atomic Red Team not found at {self.atomic_path}. "
                f"Clone from: https://github.com/redcanaryco/atomic-red-team"
            )

    def list_techniques(self) -> List[str]:
        """List all available Atomic Red Team technique IDs."""
        techniques = []
        for technique_dir in self.atomics_dir.glob("T*"):
            if technique_dir.is_dir():
                techniques.append(technique_dir.name)
        return sorted(techniques)

    def get_technique_atomics(self, technique_id: str) -> Dict[str, Any]:
        """
        Load atomic tests for a given technique.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1059.001")

        Returns:
            Dictionary containing atomic test definitions
        """
        technique_path = self.atomics_dir / technique_id / f"{technique_id}.yaml"

        if not technique_path.exists():
            raise FileNotFoundError(f"No atomic tests found for {technique_id}")

        with open(technique_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def execute_technique(
        self,
        technique_id: str,
        test_numbers: Optional[List[int]] = None,
        auto_cleanup: bool = True,
        executor: str = "powershell",
    ) -> Dict[str, Any]:
        """
        Execute Atomic Red Team tests for a technique.

        Args:
            technique_id: MITRE ATT&CK technique ID
            test_numbers: Specific test numbers to run (default: all)
            auto_cleanup: Run cleanup commands after tests
            executor: Executor to use (powershell, bash, cmd, sh)

        Returns:
            Dictionary containing execution results and evidence
        """
        atomic_data = self.get_technique_atomics(technique_id)
        atomic_tests = atomic_data.get("atomic_tests", [])

        if not atomic_tests:
            return {
                "technique_id": technique_id,
                "status": "no_tests",
                "message": "No atomic tests defined for this technique",
            }

        # Filter to specific test numbers if provided
        if test_numbers:
            atomic_tests = [
                test for i, test in enumerate(atomic_tests) if i + 1 in test_numbers
            ]

        results = {
            "technique_id": technique_id,
            "technique_name": atomic_data.get("display_name", ""),
            "timestamp": datetime.utcnow().isoformat(),
            "executor": executor,
            "tests_executed": [],
            "evidence_collected": [],
            "status": "success",
        }

        for i, test in enumerate(atomic_tests, start=1):
            test_result = self._execute_single_test(
                technique_id, test, i, executor, auto_cleanup
            )
            results["tests_executed"].append(test_result)

            # Collect evidence from test execution
            if test_result.get("status") == "success":
                evidence = self._collect_test_evidence(technique_id, test, test_result)
                results["evidence_collected"].extend(evidence)

        # Save results
        self._save_results(technique_id, results)

        return results

    def _execute_single_test(
        self,
        technique_id: str,
        test: Dict[str, Any],
        test_number: int,
        executor: str,
        auto_cleanup: bool,
    ) -> Dict[str, Any]:
        """Execute a single atomic test."""
        test_name = test.get("name", f"Test {test_number}")
        supported_platforms = test.get("supported_platforms", [])
        executor_info = test.get("executor", {})

        result = {
            "test_number": test_number,
            "test_name": test_name,
            "description": test.get("description", ""),
            "supported_platforms": supported_platforms,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Check if current platform is supported
        current_platform = self._get_current_platform()
        if current_platform not in supported_platforms:
            result["status"] = "skipped"
            result["message"] = (
                f"Platform {current_platform} not in {supported_platforms}"
            )
            return result

        # Get execution command
        command = executor_info.get("command", "")
        if not command:
            result["status"] = "skipped"
            result["message"] = "No command defined for this test"
            return result

        # Replace input arguments with defaults
        input_args = test.get("input_arguments", {})
        for arg_name, arg_config in input_args.items():
            default_value = arg_config.get("default", "")
            command = command.replace(f"#{{{arg_name}}}", str(default_value))

        result["command"] = command

        # Execute the command (in simulation mode by default for safety)
        # NOTE: Set EMULATION_EXECUTE_MODE=live to actually run commands
        execute_mode = os.getenv("EMULATION_EXECUTE_MODE", "simulate")

        if execute_mode == "live":
            try:
                exec_result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                )
                result["status"] = "success" if exec_result.returncode == 0 else "failed"
                result["stdout"] = exec_result.stdout
                result["stderr"] = exec_result.stderr
                result["return_code"] = exec_result.returncode
            except subprocess.TimeoutExpired:
                result["status"] = "timeout"
                result["message"] = "Test execution timed out after 5 minutes"
            except Exception as e:
                result["status"] = "error"
                result["message"] = str(e)

            # Execute cleanup if requested and available
            if auto_cleanup and executor_info.get("cleanup_command"):
                cleanup_cmd = executor_info["cleanup_command"]
                # Replace input arguments in cleanup command
                for arg_name, arg_config in input_args.items():
                    default_value = arg_config.get("default", "")
                    cleanup_cmd = cleanup_cmd.replace(
                        f"#{{{arg_name}}}", str(default_value)
                    )

                try:
                    subprocess.run(cleanup_cmd, shell=True, timeout=60)
                    result["cleanup_status"] = "success"
                except Exception as e:
                    result["cleanup_status"] = f"failed: {str(e)}"
        else:
            # Simulation mode - don't actually execute
            result["status"] = "simulated"
            result["message"] = (
                "Command simulated (set EMULATION_EXECUTE_MODE=live to execute)"
            )

        return result

    def _collect_test_evidence(
        self, technique_id: str, test: Dict[str, Any], test_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Extract evidence artifacts from test execution."""
        evidence = []

        # Extract command-line evidence
        if "command" in test_result:
            evidence.append(
                {
                    "type": "command_line",
                    "technique_id": technique_id,
                    "test_name": test.get("name"),
                    "value": test_result["command"],
                    "description": "Execution command used in atomic test",
                }
            )

        # Extract stdout/stderr logs
        if "stdout" in test_result and test_result["stdout"]:
            log_file = (
                self.evidence_dir
                / f"{technique_id}_{test_result['test_number']}_stdout.log"
            )
            log_file.write_text(test_result["stdout"])
            evidence.append(
                {
                    "type": "execution_log",
                    "technique_id": technique_id,
                    "test_name": test.get("name"),
                    "file_path": str(log_file),
                    "description": "Standard output from test execution",
                }
            )

        # Extract dependency executables
        dependencies = test.get("dependencies", [])
        for dep in dependencies:
            if "prereq_command" in dep:
                evidence.append(
                    {
                        "type": "dependency",
                        "technique_id": technique_id,
                        "test_name": test.get("name"),
                        "value": dep["prereq_command"],
                        "description": dep.get("description", "Test dependency"),
                    }
                )

        return evidence

    def _get_current_platform(self) -> str:
        """Determine the current platform for test compatibility."""
        import platform

        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        elif system == "linux":
            return "linux"
        return system

    def _save_results(self, technique_id: str, results: Dict[str, Any]) -> None:
        """Save test results to JSON file."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"{technique_id}_atomic_{timestamp}.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        print(f"✅ Atomic test results saved to {output_file}")

    def get_technique_evidence(self, technique_id: str) -> List[Dict[str, Any]]:
        """
        Get all collected evidence for a technique from previous executions.

        Args:
            technique_id: MITRE ATT&CK technique ID

        Returns:
            List of evidence dictionaries
        """
        evidence = []

        # Find all result files for this technique
        for result_file in self.output_dir.glob(f"{technique_id}_atomic_*.json"):
            with open(result_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                evidence.extend(data.get("evidence_collected", []))

        return evidence

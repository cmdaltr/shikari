"""
Remote execution backend for cross-platform emulation.

Supports:
- SSH for Linux/macOS targets
- WinRM for Windows targets
"""

import os
import subprocess
import getpass
from typing import Dict, Optional, Tuple


class RemoteExecutor:
    """Base class for remote execution"""

    def __init__(
        self,
        host: str,
        username: str = None,
        password: str = None,
        ssh_key: str = None,
        platform: str = None,
    ):
        self.host = host
        self.username = username or getpass.getuser()
        self.password = password
        self.ssh_key = ssh_key
        self.platform = platform

    def detect_platform(self) -> str:
        """Auto-detect remote platform"""
        raise NotImplementedError

    def execute_command(self, command: str) -> Tuple[int, str, str]:
        """Execute command on remote host"""
        raise NotImplementedError

    def check_atomic_installed(self) -> bool:
        """Check if Atomic Red Team is installed on remote host"""
        raise NotImplementedError

    def install_atomic(self, install_path: str) -> bool:
        """Install Atomic Red Team on remote host"""
        raise NotImplementedError


class SSHExecutor(RemoteExecutor):
    """SSH-based remote execution for Linux/macOS"""

    def detect_platform(self) -> str:
        """Detect if remote is Linux or macOS"""
        returncode, stdout, stderr = self.execute_command("uname -s")

        if returncode == 0:
            os_name = stdout.strip().lower()
            if "darwin" in os_name:
                return "macos"
            elif "linux" in os_name:
                return "linux"

        return "unknown"

    def execute_command(self, command: str) -> Tuple[int, str, str]:
        """Execute command via SSH"""
        # Build SSH command
        ssh_cmd = ["ssh"]

        # Add SSH key if provided
        if self.ssh_key:
            ssh_cmd.extend(["-i", self.ssh_key])

        # Add connection details
        ssh_cmd.extend([f"{self.username}@{self.host}", command])

        # Use sshpass if password provided (and no SSH key)
        if self.password and not self.ssh_key:
            ssh_cmd = ["sshpass", "-p", self.password] + ssh_cmd

        result = subprocess.run(ssh_cmd, capture_output=True, text=True)

        return result.returncode, result.stdout, result.stderr

    def check_atomic_installed(self) -> bool:
        """Check if Atomic Red Team is installed"""
        # Check common installation paths
        paths_to_check = [
            "/opt/atomic-red-team",
            "~/atomic-red-team",
            "/usr/local/atomic-red-team",
        ]

        for path in paths_to_check:
            returncode, _, _ = self.execute_command(f"test -d {path} && echo 'exists'")
            if returncode == 0:
                return True

        return False

    def install_atomic(self, install_path: str = "/opt/atomic-red-team") -> bool:
        """Install Atomic Red Team via SSH"""
        print(f"Installing Atomic Red Team on {self.host}:{install_path}...")

        # Clone repository
        clone_cmd = f"sudo git clone https://github.com/redcanaryco/atomic-red-team.git {install_path}"
        returncode, stdout, stderr = self.execute_command(clone_cmd)

        if returncode == 0:
            print(f"✅ Successfully installed Atomic Red Team on {self.host}")
            return True
        else:
            print(f"❌ Failed to install: {stderr}")
            return False


class WinRMExecutor(RemoteExecutor):
    """WinRM-based remote execution for Windows"""

    def __init__(self, host: str, username: str = None, password: str = None, use_http: bool = False):
        super().__init__(host, username, password, None, "windows")

        # Check if pywinrm is available
        try:
            import winrm
            self.winrm = winrm
        except ImportError:
            raise ImportError(
                "pywinrm is required for Windows remote execution. "
                "Install with: pip install pywinrm"
            )

        # Create WinRM session (HTTPS by default, HTTP if specified)
        if use_http:
            endpoint = f"http://{self.host}:5985/wsman"
            print("⚠️  Using HTTP for WinRM (insecure)")
        else:
            endpoint = f"https://{self.host}:5986/wsman"

        self.session = self.winrm.Session(
            endpoint,
            auth=(self.username, self.password),
            transport="ntlm",
            server_cert_validation="ignore",  # For self-signed certs
        )

    def detect_platform(self) -> str:
        """WinRM is Windows-only"""
        return "windows"

    def execute_command(self, command: str) -> Tuple[int, str, str]:
        """Execute PowerShell command via WinRM"""
        result = self.session.run_ps(command)

        return result.status_code, result.std_out.decode(), result.std_err.decode()

    def check_atomic_installed(self) -> bool:
        """Check if Atomic Red Team is installed on Windows"""
        paths_to_check = [
            "C:\\AtomicRedTeam",
            "C:\\Tools\\atomic-red-team",
            "$env:USERPROFILE\\atomic-red-team",
        ]

        for path in paths_to_check:
            returncode, stdout, _ = self.execute_command(f"Test-Path {path}")
            if returncode == 0 and "True" in stdout:
                return True

        return False

    def install_atomic(
        self, install_path: str = "C:\\AtomicRedTeam"
    ) -> bool:
        """Install Atomic Red Team via WinRM"""
        print(f"Installing Atomic Red Team on {self.host}:{install_path}...")

        # Use PowerShell to clone
        clone_cmd = f"""
        if (-not (Test-Path {install_path})) {{
            git clone https://github.com/redcanaryco/atomic-red-team.git {install_path}
        }}
        """

        returncode, stdout, stderr = self.execute_command(clone_cmd)

        if returncode == 0:
            print(f"✅ Successfully installed Atomic Red Team on {self.host}")
            return True
        else:
            print(f"❌ Failed to install: {stderr}")
            return False


def create_remote_executor(
    host: str,
    username: str = None,
    password: str = None,
    ssh_key: str = None,
    platform: str = None,
    use_http: bool = False,
) -> RemoteExecutor:
    """Factory function to create appropriate remote executor"""

    # Prompt for password if not provided (and no SSH key)
    if not password and not ssh_key:
        password = getpass.getpass(f"Password for {username or getpass.getuser()}@{host}: ")

    # Auto-detect platform if not specified
    if not platform:
        # Try SSH first (works for Linux/macOS)
        try:
            ssh_exec = SSHExecutor(host, username, password, ssh_key)
            detected = ssh_exec.detect_platform()
            if detected in ["linux", "macos"]:
                platform = detected
                print(f"Detected remote platform: {platform}")
        except Exception:
            pass

    # Create appropriate executor
    if platform == "windows":
        return WinRMExecutor(host, username, password, use_http=use_http)
    else:
        return SSHExecutor(host, username, password, ssh_key, platform)


def execute_atomic_remote(
    executor: RemoteExecutor,
    technique_id: str,
    execute: bool = False,
    enrich: bool = False,
) -> Dict:
    """Execute Atomic Red Team test on remote host and collect artifacts for enrichment"""

    # Check if Atomic is installed
    if not executor.check_atomic_installed():
        print(f"⚠️  Atomic Red Team not found on {executor.host}")
        print("Attempting to install...")

        if executor.platform == "windows":
            success = executor.install_atomic("C:\\AtomicRedTeam")
            atomic_path = "C:\\AtomicRedTeam"
        else:
            success = executor.install_atomic("/opt/atomic-red-team")
            atomic_path = "/opt/atomic-red-team"

        if not success:
            return {"status": "error", "message": "Failed to install Atomic Red Team"}
    else:
        # Find atomic path
        if executor.platform == "windows":
            atomic_path = "C:\\AtomicRedTeam"
        else:
            atomic_path = "/opt/atomic-red-team"

    # Build execution command based on platform
    if executor.platform == "windows":
        if execute:
            cmd = f"""
            Import-Module {atomic_path}\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1
            Invoke-AtomicTest {technique_id}
            """
        else:
            cmd = f"""
            Import-Module {atomic_path}\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1
            Invoke-AtomicTest {technique_id} -ShowDetails
            """
    else:
        if execute:
            cmd = f"""
            cd {atomic_path} && \
            powershell -Command "Import-Module ./invoke-atomicredteam/Invoke-AtomicRedTeam.psd1; Invoke-AtomicTest {technique_id}"
            """
        else:
            cmd = f"""
            cd {atomic_path} && \
            powershell -Command "Import-Module ./invoke-atomicredteam/Invoke-AtomicRedTeam.psd1; Invoke-AtomicTest {technique_id} -ShowDetails"
            """

    # Execute
    print(f"Executing {technique_id} on {executor.host} ({executor.platform})...")
    returncode, stdout, stderr = executor.execute_command(cmd)

    if returncode == 0:
        result = {
            "status": "success",
            "technique_id": technique_id,
            "host": executor.host,
            "platform": executor.platform,
            "output": stdout,
            "executed": execute,
        }

        # If enrichment requested, collect additional artifacts
        if enrich and execute:
            print("Collecting artifacts for enrichment...")
            artifacts = _collect_artifacts(executor, technique_id, stdout)
            result["artifacts"] = artifacts

        return result
    else:
        return {
            "status": "error",
            "technique_id": technique_id,
            "host": executor.host,
            "error": stderr,
        }


def _collect_artifacts(executor: RemoteExecutor, technique_id: str, output: str) -> Dict:
    """Collect forensic artifacts from remote execution for enrichment"""
    artifacts = {
        "commands_executed": [],
        "files_created": [],
        "processes_spawned": [],
        "registry_modified": [],
        "network_connections": [],
    }

    # Parse output for common artifact patterns
    import re

    # Extract commands from output
    cmd_patterns = [
        r"Command: (.+)",
        r"Executing: (.+)",
        r"\$ (.+)",
        r"PS> (.+)",
    ]
    for pattern in cmd_patterns:
        matches = re.findall(pattern, output, re.MULTILINE)
        artifacts["commands_executed"].extend(matches)

    # Extract file paths
    file_patterns = [
        r"Created file: (.+)",
        r"Writing to: (.+)",
        r"File: ([C-Z]:\\[^\\s]+)",
        r"File: (/[^\\s]+)",
    ]
    for pattern in file_patterns:
        matches = re.findall(pattern, output)
        artifacts["files_created"].extend(matches)

    # Extract process names
    proc_patterns = [
        r"Process: (.+)",
        r"Started: (.+\.exe)",
        r"Spawned: (.+)",
    ]
    for pattern in proc_patterns:
        matches = re.findall(pattern, output, re.IGNORECASE)
        artifacts["processes_spawned"].extend(matches)

    return artifacts

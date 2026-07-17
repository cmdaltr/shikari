#!/usr/bin/env python3
"""
Quick Start Script for RAG Fidelity Enhancement System

This script automates the setup of the RAG-based fidelity enhancement system.

Usage:
    python scripts/config/quickstart_rag.py
    python scripts/config/quickstart_rag.py --step 1    # Only run step 1
    python scripts/config/quickstart_rag.py --step 3-5  # Run steps 3 through 5
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path


# ANSI color codes (cross-platform via colorama fallback)
class Colors:
    """Cross-platform terminal colors."""

    def __init__(self):
        self.enabled = self._check_color_support()
        if self.enabled:
            self.RED = '\033[0;31m'
            self.GREEN = '\033[0;32m'
            self.YELLOW = '\033[1;33m'
            self.BLUE = '\033[0;34m'
            self.NC = '\033[0m'
        else:
            self.RED = self.GREEN = self.YELLOW = self.BLUE = self.NC = ''

    def _check_color_support(self):
        """Check if terminal supports colors."""
        if sys.platform == 'win32':
            # Enable ANSI colors on Windows 10+
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except Exception:
                return False
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()


colors = Colors()


def print_step(message):
    """Print a step header."""
    print(f"{colors.BLUE}{'=' * 70}{colors.NC}")
    print(f"{colors.BLUE}{message}{colors.NC}")
    print(f"{colors.BLUE}{'=' * 70}{colors.NC}")
    print()


def print_success(message):
    """Print a success message."""
    print(f"{colors.GREEN}✓ {message}{colors.NC}")


def print_warning(message):
    """Print a warning message."""
    print(f"{colors.YELLOW}⚠ {message}{colors.NC}")


def print_error(message):
    """Print an error message."""
    print(f"{colors.RED}✗ {message}{colors.NC}")


def get_project_root():
    """Get the project root directory."""
    return Path(__file__).parent.parent.parent


def run_command(cmd, cwd=None, check=True):
    """Run a command and return the result."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=check
        )
        return result
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {' '.join(cmd)}")
        if e.stderr:
            print(e.stderr)
        raise


def run_python_script(script_path, args=None, cwd=None):
    """Run a Python script with arguments."""
    cmd = [sys.executable, str(script_path)]
    if args:
        cmd.extend(args)
    return run_command(cmd, cwd=cwd)


def step1_check_dependencies():
    """Step 1: Check and install dependencies."""
    print_step("Step 1: Checking Dependencies")

    # Check Python version
    version = sys.version_info
    print_success(f"Python {version.major}.{version.minor}.{version.micro} found")

    # Check if in virtual environment
    if not (hasattr(sys, 'real_prefix') or
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)):
        print_warning("Not in a virtual environment. Consider creating one:")
        if sys.platform == 'win32':
            print("  python -m venv venv")
            print("  venv\\Scripts\\activate")
        else:
            print("  python3 -m venv venv")
            print("  source venv/bin/activate")
        print()

    # Install dependencies
    print("Installing Python dependencies...")
    try:
        run_command([
            sys.executable, "-m", "pip", "install", "-q",
            "sentence-transformers>=2.2.2",
            "faiss-cpu>=1.7.4",
            "pyyaml>=6.0.1"
        ])
        print_success("Dependencies installed")
    except subprocess.CalledProcessError:
        print_error("Failed to install dependencies")
        return False

    print()
    return True


def step2_setup_knowledge_base():
    """Step 2: Setup knowledge base structure."""
    print_step("Step 2: Setting Up Knowledge Base Structure")

    root = get_project_root()
    script = root / "scripts" / "config" / "setup_knowledge_base.py"

    try:
        run_python_script(script, cwd=root)
        print_success("Knowledge base structure created")
    except subprocess.CalledProcessError:
        print_error("Failed to setup knowledge base")
        return False

    print()
    return True


def step3_clone_repositories():
    """Step 3: Clone community detection repositories."""
    print_step("Step 3: Cloning Community Detection Repositories")

    root = get_project_root()
    repos_dir = root / "data" / "external" / "repos"
    repos_dir.mkdir(parents=True, exist_ok=True)

    repositories = [
        {
            "name": "splunk",
            "url": "https://github.com/splunk/security_content.git",
            "enabled": True
        },
        {
            "name": "elastic",
            "url": "https://github.com/elastic/detection-rules.git",
            "enabled": False  # Optional, set to True to enable
        }
    ]

    for repo in repositories:
        if not repo["enabled"]:
            continue

        repo_path = repos_dir / repo["name"]
        if repo_path.exists():
            print_warning(f"{repo['name']} repository already exists, skipping clone")
        else:
            print(f"Cloning {repo['name']} rules (this may take a few minutes)...")
            try:
                run_command([
                    "git", "clone", "--depth", "1",
                    repo["url"], str(repo_path)
                ])
                print_success(f"{repo['name']} repository cloned")
            except subprocess.CalledProcessError:
                print_error(f"Failed to clone {repo['name']}")
                return False

    print()
    return True


def step4_import_rules():
    """Step 4: Import community detection rules."""
    print_step("Step 4: Importing Community Detection Rules")

    root = get_project_root()
    script = root / "scripts" / "config" / "import_community_rules.py"

    print("Importing Splunk Security Content rules...")
    try:
        run_python_script(
            script,
            args=["--source", "splunk"],
            cwd=root
        )
        print_success("Community rules imported")
    except subprocess.CalledProcessError:
        print_error("Failed to import community rules")
        return False

    print()
    return True


def step5_build_embeddings():
    """Step 5: Build vector embeddings."""
    print_step("Step 5: Building Vector Embeddings")

    root = get_project_root()
    script = root / "scripts" / "config" / "build_embeddings.py"

    print("Generating embeddings...")
    try:
        run_python_script(script, cwd=root)
        print_success("Vector embeddings built")
    except subprocess.CalledProcessError:
        print_error("Failed to build embeddings")
        return False

    print()
    return True


def step6_test_system():
    """Step 6: Test the system."""
    print_step("Step 6: Testing the System")

    root = get_project_root()
    script = root / "scripts" / "config" / "search_similar_detections.py"

    print("Testing retrieval for T1003.001 (LSASS Memory Dump)...")
    try:
        run_python_script(
            script,
            args=["--technique", "T1003.001", "--platform", "Splunk", "--top-k", "3"],
            cwd=root
        )
        print_success("System test complete")
    except subprocess.CalledProcessError:
        print_error("System test failed")
        return False

    print()
    return True


def print_completion():
    """Print completion message with next steps."""
    print_step("Setup Complete!")

    print(f"{colors.GREEN}✓ RAG Fidelity Enhancement System is ready!{colors.NC}")
    print()
    print("Next steps:")
    print("  1. Set up LLM provider (optional):")
    if sys.platform == 'win32':
        print('     set OPENAI_API_KEY=your-key-here')
    else:
        print("     export OPENAI_API_KEY='your-key-here'")
    print()
    print("  2. Test enhancement:")
    print("     python scripts/config/search_similar_detections.py --technique T1003.001 --show-query")
    print()
    print("  3. Generate enhanced detections:")
    print("     python archer.py generate APT29")
    print()
    print("  4. Read the documentation:")
    print("     docs/rag/FIDELITY_IMPLEMENTATION_GUIDE.md")
    print("     docs/rag/FIDELITY_SYSTEM_SUMMARY.md")
    print()
    print_success("Happy hunting!")


def parse_step_range(step_arg):
    """Parse step argument like '1', '3-5', or None for all."""
    if not step_arg:
        return None

    if '-' in step_arg:
        start, end = step_arg.split('-')
        return list(range(int(start), int(end) + 1))
    else:
        return [int(step_arg)]


def main():
    parser = argparse.ArgumentParser(
        description="Quick start setup for RAG fidelity enhancement system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all steps
  python scripts/config/quickstart_rag.py

  # Run only step 1 (check dependencies)
  python scripts/config/quickstart_rag.py --step 1

  # Run steps 3 through 5
  python scripts/config/quickstart_rag.py --step 3-5

Steps:
  1. Check and install dependencies
  2. Setup knowledge base structure
  3. Clone community repositories (Splunk)
  4. Import community detection rules
  5. Build vector embeddings
  6. Test the system
        """
    )

    parser.add_argument(
        '--step',
        type=str,
        help='Run specific step(s): "1", "3", or "3-5" for range'
    )

    args = parser.parse_args()

    # Check if running from project root
    root = get_project_root()
    if not (root / "archer.py").exists():
        print_error("Please run this script from the archer project root directory")
        sys.exit(1)

    # Change to project root
    os.chdir(root)

    # Define steps
    steps = [
        (1, step1_check_dependencies),
        (2, step2_setup_knowledge_base),
        (3, step3_clone_repositories),
        (4, step4_import_rules),
        (5, step5_build_embeddings),
        (6, step6_test_system),
    ]

    # Parse which steps to run
    run_steps = parse_step_range(args.step)

    # Run steps
    for step_num, step_func in steps:
        if run_steps is None or step_num in run_steps:
            success = step_func()
            if not success:
                sys.exit(1)

            # If running single step, exit after completion
            if run_steps and len(run_steps) == 1:
                print_success(f"Step {step_num} complete!")
                sys.exit(0)

    # Print completion message if all steps ran
    if run_steps is None:
        print_completion()


if __name__ == "__main__":
    main()

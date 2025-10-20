#!/usr/bin/env python3
"""
Archer Repository Cleanup Script (Python version)
Removes temporary files, caches, and build artifacts
Cross-platform alternative to cleanup.sh

Usage:
    python scripts/cleanup.py              # Clean up repository
    python scripts/cleanup.py --dry-run    # Preview what will be deleted
    python scripts/cleanup.py --help       # Show help
"""

import os
import sys
import shutil
import argparse
from pathlib import Path
from typing import List, Tuple


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color

    @staticmethod
    def disable():
        """Disable colors for Windows or when redirecting output"""
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.BOLD = ''
        Colors.NC = ''


def find_items(root_dir: Path, pattern: str, is_dir: bool = False) -> List[Path]:
    """
    Find all files or directories matching the pattern.

    Args:
        root_dir: Root directory to search from
        pattern: Glob pattern to match (e.g., "*.pyc", "__pycache__")
        is_dir: True if looking for directories, False for files

    Returns:
        List of matching Path objects
    """
    # Directories to exclude from cleanup
    exclude_dirs = {'.venv', 'venv', 'env', 'ENV', 'node_modules', '.git'}
    # Specific paths to exclude (archer/build is application code, archer/data is handled by .gitignore)
    exclude_paths = {'archer/build', 'archer/data'}
    matches = []

    def should_exclude(path: Path) -> bool:
        """Check if path should be excluded from cleanup"""
        # Check if path contains any excluded directory
        if any(excluded in path.parts for excluded in exclude_dirs):
            return True
        # Check if path is under any excluded path
        try:
            for excluded_path in exclude_paths:
                if path.is_relative_to(root_dir / excluded_path):
                    return True
        except (ValueError, AttributeError):
            # is_relative_to not available in Python < 3.9, fallback
            for excluded_path in exclude_paths:
                try:
                    path.relative_to(root_dir / excluded_path)
                    return True
                except ValueError:
                    continue
        return False

    if is_dir:
        # For directory patterns like __pycache__
        for path in root_dir.rglob(pattern):
            if path.is_dir() and not should_exclude(path):
                matches.append(path)
    else:
        # For file patterns like *.pyc
        for path in root_dir.rglob(pattern):
            if not should_exclude(path):
                matches.append(path)

    return matches


def remove_items(root_dir: Path, pattern: str, description: str,
                 is_dir: bool = False, dry_run: bool = False) -> Tuple[int, int]:
    """
    Remove files or directories matching the pattern.

    Args:
        root_dir: Root directory to search from
        pattern: Glob pattern to match
        description: Human-readable description
        is_dir: True if removing directories
        dry_run: If True, only preview without deleting

    Returns:
        Tuple of (items_found, items_removed)
    """
    print(f"{Colors.BLUE}Searching for: {description}{Colors.NC}")

    try:
        items = find_items(root_dir, pattern, is_dir)
        count = len(items)

        if count == 0:
            print(f"{Colors.GREEN}No items found matching '{pattern}'{Colors.NC}\n")
            return 0, 0

        if dry_run:
            print(f"{Colors.YELLOW}Would remove {count} item(s) matching '{pattern}'{Colors.NC}")
            # Show first 5 items
            for item in items[:5]:
                print(f"  {item.relative_to(root_dir)}")
            if count > 5:
                print(f"  ... and {count - 5} more")
            print()
            return count, 0
        else:
            removed = 0
            for item in items:
                try:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                    removed += 1
                except (PermissionError, OSError) as e:
                    print(f"{Colors.YELLOW}  Warning: Could not remove {item}: {e}{Colors.NC}")

            print(f"{Colors.GREEN}✓ Removed {removed} item(s) matching '{pattern}'{Colors.NC}\n")
            return count, removed

    except Exception as e:
        print(f"{Colors.RED}Error processing '{pattern}': {e}{Colors.NC}\n")
        return 0, 0


def print_header(text: str):
    """Print a section header"""
    print(f"\n{Colors.BLUE}━━━ {text} ━━━{Colors.NC}\n")


def main():
    """Main cleanup function"""
    parser = argparse.ArgumentParser(
        description='Archer Repository Cleanup Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python scripts/cleanup.py              # Clean up repository
  python scripts/cleanup.py --dry-run    # Preview changes
  python scripts/cleanup.py --no-color   # Disable colored output
        '''
    )
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview what will be deleted without actually deleting')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')

    args = parser.parse_args()

    # Disable colors if requested or on Windows
    if args.no_color or sys.platform == 'win32':
        Colors.disable()

    # Get repository root (parent of scripts directory)
    root_dir = Path(__file__).parent.parent

    # Print banner
    print(f"\n{Colors.GREEN}{'='*50}")
    print(f"   Archer Repository Cleanup Script")
    print(f"{'='*50}{Colors.NC}\n")

    if args.dry_run:
        print(f"{Colors.YELLOW}Running in DRY-RUN mode (no files will be deleted){Colors.NC}\n")

    total_found = 0
    total_removed = 0

    # Python cache files
    print_header("Python Cache Files")
    patterns = [
        ("__pycache__", "Python cache directories", True),
        ("*.pyc", "Compiled Python files (.pyc)", False),
        ("*.pyo", "Optimized Python files (.pyo)", False),
        ("*.pyd", "Python DLL files (.pyd)", False),
    ]

    for pattern, desc, is_dir in patterns:
        found, removed = remove_items(root_dir, pattern, desc, is_dir, args.dry_run)
        total_found += found
        total_removed += removed

    # Python build artifacts
    print_header("Python Build Artifacts")
    patterns = [
        ("*.egg-info", "Python egg-info directories", True),
        ("*.egg", "Python egg files", False),
        ("dist", "Distribution directories", True),
        ("build", "Build directories", True),
        (".eggs", "Eggs directories", True),
    ]

    for pattern, desc, is_dir in patterns:
        found, removed = remove_items(root_dir, pattern, desc, is_dir, args.dry_run)
        total_found += found
        total_removed += removed

    # Testing artifacts
    print_header("Testing Artifacts")
    patterns = [
        (".pytest_cache", "Pytest cache directories", True),
        (".coverage", "Coverage data files", False),
        ("htmlcov", "HTML coverage reports", True),
        (".tox", "Tox directories", True),
        (".nox", "Nox directories", True),
    ]

    for pattern, desc, is_dir in patterns:
        found, removed = remove_items(root_dir, pattern, desc, is_dir, args.dry_run)
        total_found += found
        total_removed += removed

    # IDE and OS files
    print_header("IDE and OS Files")
    patterns = [
        (".DS_Store", "macOS .DS_Store files", False),
        ("Thumbs.db", "Windows thumbnail cache", False),
        ("desktop.ini", "Windows desktop.ini files", False),
    ]

    for pattern, desc, is_dir in patterns:
        found, removed = remove_items(root_dir, pattern, desc, is_dir, args.dry_run)
        total_found += found
        total_removed += removed

    # Jupyter Notebook checkpoints
    print_header("Jupyter Artifacts")
    found, removed = remove_items(root_dir, ".ipynb_checkpoints",
                                  "Jupyter notebook checkpoints", True, args.dry_run)
    total_found += found
    total_removed += removed

    # Log files
    print_header("Log Files")
    patterns = [
        ("*.log", "Log files", False),
        ("*.log.*", "Rotated log files", False),
    ]

    for pattern, desc, is_dir in patterns:
        found, removed = remove_items(root_dir, pattern, desc, is_dir, args.dry_run)
        total_found += found
        total_removed += removed

    # Temporary files
    print_header("Temporary Files")
    patterns = [
        ("*.tmp", "Temporary files (.tmp)", False),
        ("*.temp", "Temporary files (.temp)", False),
        ("*.swp", "Vim swap files", False),
        ("*.swo", "Vim swap files", False),
        ("*~", "Backup files", False),
    ]

    for pattern, desc, is_dir in patterns:
        found, removed = remove_items(root_dir, pattern, desc, is_dir, args.dry_run)
        total_found += found
        total_removed += removed

    # SQLite journal files
    print_header("Database Temporary Files")
    print(f"{Colors.YELLOW}Note: Keeping active database, only cleaning up journal files{Colors.NC}")
    found, removed = remove_items(root_dir, "*.db-journal",
                                  "SQLite journal files", False, args.dry_run)
    total_found += found
    total_removed += removed

    # Print summary
    print(f"\n{Colors.GREEN}{'='*50}")
    print(f"            Cleanup Complete!")
    print(f"{'='*50}{Colors.NC}\n")

    if args.dry_run:
        print(f"{Colors.YELLOW}This was a dry-run. Found {total_found} item(s) to clean.{Colors.NC}")
        print(f"{Colors.YELLOW}Run without --dry-run to actually delete files:{Colors.NC}")
        print(f"{Colors.YELLOW}    python scripts/cleanup.py{Colors.NC}\n")
    else:
        print(f"{Colors.GREEN}✓ Successfully removed {total_removed} item(s)!{Colors.NC}\n")

        # Show repository size
        print(f"{Colors.BLUE}Tip: Run 'du -sh .' (Unix) or check folder properties (Windows){Colors.NC}")
        print(f"{Colors.BLUE}     to see current repository size{Colors.NC}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Cleanup cancelled by user{Colors.NC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.NC}")
        sys.exit(1)

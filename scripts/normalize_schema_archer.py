#!/usr/bin/env python3
"""
Archer Schema Normalization CLI Wrapper (Cross-Platform)

This script provides a simple command-line interface to the schema normalizer.
It can be called from anywhere in the Archer workflow.

Works on Windows, macOS, and Linux.
"""

import sys
import subprocess
import argparse
from pathlib import Path


class Colors:
    """ANSI color codes."""
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    NC = '\033[0m'

    @staticmethod
    def disable():
        """Disable colors for Windows."""
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.NC = ''


def main():
    """Main function."""
    # Disable colors on Windows if needed
    if sys.platform == 'win32':
        Colors.disable()

    parser = argparse.ArgumentParser(
        description='Archer Schema Normalization CLI Wrapper',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python scripts/normalize_schema_archer.py                      # Normalize only new indexes
  python scripts/normalize_schema_archer.py --force              # Re-normalize all indexes
  python scripts/normalize_schema_archer.py --schema /tmp/test.json  # Normalize custom schema
        '''
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='Force re-normalization of all indexes'
    )
    parser.add_argument(
        '--silent',
        action='store_true',
        help='Suppress output'
    )
    parser.add_argument(
        '--schema',
        type=str,
        default='',
        help='Path to schema file (default: archer/mappings/schemaSplunk.json)'
    )

    args = parser.parse_args()

    # Get project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    # Build Python command
    normalize_script = project_root / "archer" / "mappings" / "normalize_manual.py"

    if not normalize_script.exists():
        print(f"{Colors.RED}❌ Error: normalize_manual.py not found at {normalize_script}{Colors.NC}")
        sys.exit(1)

    cmd = [sys.executable, str(normalize_script)]

    if args.force:
        cmd.append('--force')

    if args.schema:
        cmd.extend(['--schema', args.schema])

    # Run normalization
    try:
        if args.silent:
            result = subprocess.run(
                cmd,
                capture_output=True,
                cwd=project_root
            )
            if result.returncode == 0:
                print(f"{Colors.GREEN}✅ Schema normalization complete{Colors.NC}")
            else:
                print(f"{Colors.RED}❌ Schema normalization failed{Colors.NC}")
                if result.stderr:
                    print(result.stderr.decode())
                sys.exit(result.returncode)
        else:
            result = subprocess.run(cmd, cwd=project_root)
            sys.exit(result.returncode)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.NC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.NC}")
        sys.exit(1)


if __name__ == "__main__":
    main()

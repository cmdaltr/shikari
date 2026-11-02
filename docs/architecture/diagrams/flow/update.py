#!/usr/bin/env python3
"""
Flow Diagram Update Script

This script regenerates PNG and PDF files from DOT diagram sources in the
docs/flow/ directory.

Usage:
    python update.py              # Update all diagrams
    python update.py shikari       # Update only main shikari flow diagram

Requirements:
    - Graphviz must be installed (brew install graphviz, or apt-get install graphviz)
    - DOT files must exist: shikari_flow.dot

Output:
    - PNG files: shikari_flow.png
    - PDF files: shikari_flow.pdf
"""

import argparse
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


class DiagramUpdater:
    """Update flow diagrams from DOT files."""

    def __init__(self, directory: Path):
        """Initialize with the flow directory."""
        self.directory = directory
        self.diagrams = {
            'shikari': 'shikari_flow',
        }

    def check_graphviz(self) -> bool:
        """Check if Graphviz is installed."""
        try:
            result = subprocess.run(
                ['dot', '-V'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stderr.strip()
                print(f"✓ Graphviz found: {version}")
                return True
            else:
                print("✗ Graphviz not working properly")
                return False
        except FileNotFoundError:
            print("✗ Graphviz not found")
            print("\nInstall Graphviz:")
            print("  macOS:   brew install graphviz")
            print("  Ubuntu:  sudo apt-get install graphviz")
            print("  Windows: choco install graphviz")
            print("\nOr download from: https://graphviz.org/download/")
            return False
        except Exception as e:
            print(f"✗ Error checking Graphviz: {e}")
            return False

    def update_diagram(self, name: str) -> bool:
        """Update a single diagram (both PNG and PDF)."""
        dot_file = self.directory / f"{name}.dot"

        if not dot_file.exists():
            print(f"  ✗ DOT file not found: {dot_file}")
            return False

        print(f"  → Processing {dot_file.name}")

        # Generate PNG
        png_file = self.directory / f"{name}.png"
        success_png = self._generate_format(dot_file, png_file, 'png')

        # Generate PDF
        pdf_file = self.directory / f"{name}.pdf"
        success_pdf = self._generate_format(dot_file, pdf_file, 'pdf')

        if success_png and success_pdf:
            print(f"  ✓ Generated: {png_file.name}, {pdf_file.name}")
            self._print_file_sizes(png_file, pdf_file)
            return True
        else:
            return False

    def _generate_format(self, dot_file: Path, output_file: Path, format: str) -> bool:
        """Generate a specific format from a DOT file."""
        try:
            result = subprocess.run(
                ['dot', f'-T{format}', str(dot_file), '-o', str(output_file)],
                capture_output=True,
                text=True,
                timeout=60  # Flow diagrams can be large, allow more time
            )

            if result.returncode == 0:
                # Show warnings if any (but don't fail)
                if result.stderr:
                    warning_lines = [line for line in result.stderr.strip().split('\n')
                                     if line.strip() and 'Warning' in line]
                    if warning_lines:
                        print(f"    ⚠ {len(warning_lines)} warning(s) (rankset conflicts are normal)")
                return True
            else:
                print(f"  ✗ Error generating {format.upper()}: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            print(f"  ✗ Timeout generating {format.upper()} (>60s)")
            return False
        except Exception as e:
            print(f"  ✗ Error generating {format.upper()}: {e}")
            return False

    def _print_file_sizes(self, png_file: Path, pdf_file: Path):
        """Print file sizes in human-readable format."""
        def format_size(size_bytes: int) -> str:
            """Convert bytes to human-readable format."""
            for unit in ['B', 'KB', 'MB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.1f}{unit}"
                size_bytes /= 1024.0
            return f"{size_bytes:.1f}GB"

        if png_file.exists() and pdf_file.exists():
            png_size = format_size(png_file.stat().st_size)
            pdf_size = format_size(pdf_file.stat().st_size)
            print(f"    PNG: {png_size}, PDF: {pdf_size}")

    def update_all(self, specific_diagram: Optional[str] = None) -> dict:
        """Update all diagrams or a specific one."""
        stats = {"success": 0, "failed": 0, "skipped": 0}

        # Determine which diagrams to update
        if specific_diagram:
            if specific_diagram not in self.diagrams:
                print(f"✗ Unknown diagram: {specific_diagram}")
                print(f"   Available: {', '.join(self.diagrams.keys())}")
                stats["skipped"] = len(self.diagrams)
                return stats

            diagrams_to_update = {specific_diagram: self.diagrams[specific_diagram]}
        else:
            diagrams_to_update = self.diagrams

        print(f"\nUpdating {len(diagrams_to_update)} flow diagram(s)...\n")

        for key, name in diagrams_to_update.items():
            print(f"[{key.upper()}] {name}")
            if self.update_diagram(name):
                stats["success"] += 1
            else:
                stats["failed"] += 1
            print()

        return stats


def main():
    parser = argparse.ArgumentParser(
        description="Update flow diagrams from DOT files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python update.py              # Update all diagrams
  python update.py shikari       # Update only main shikari flow

Available Diagrams:
  shikari  - Main Shikari flow (shikari_flow.dot)

Requirements:
  Graphviz must be installed: https://graphviz.org/download/

Notes:
  - Warning messages about rankset conflicts are normal for complex flow diagrams
  - These warnings occur when layout hints ({rank=same}) override cluster groupings
  - The diagrams will still render correctly
        """
    )

    parser.add_argument(
        'diagram',
        nargs='?',
        choices=['shikari'],
        help='Specific diagram to update (optional, default: all)'
    )

    parser.add_argument(
        '--directory',
        type=str,
        default='.',
        help='Flow directory (default: current directory)'
    )

    args = parser.parse_args()

    # Initialize updater
    directory = Path(args.directory).resolve()
    updater = DiagramUpdater(directory)

    print("=" * 70)
    print("Flow Diagram Updater")
    print("=" * 70)
    print(f"Directory: {directory}")
    print("=" * 70)

    # Check Graphviz
    if not updater.check_graphviz():
        sys.exit(1)

    # Update diagrams
    stats = updater.update_all(args.diagram)

    # Print summary
    print("=" * 70)
    print("Update Summary")
    print("=" * 70)
    print(f"✓ Successful: {stats['success']}")
    print(f"✗ Failed: {stats['failed']}")
    if stats['skipped'] > 0:
        print(f"⊘ Skipped: {stats['skipped']}")
    print(f"Total: {stats['success'] + stats['failed']}")
    print("=" * 70)

    if stats['failed'] > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()

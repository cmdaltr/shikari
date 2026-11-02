#!/usr/bin/env python3
"""
CLI wrapper — rebuilds data/mitre_procedures.csv.

All logic lives in shikari.mitre.procedures.
Run directly or via:  python -m shikari.mitre.procedures
"""
import sys
from pathlib import Path

# Allow running from project root without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shikari.mitre.procedures import _cli

if __name__ == "__main__":
    _cli()

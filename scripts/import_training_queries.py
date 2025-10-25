#!/usr/bin/env python3
"""
Import high-quality queries as training examples for AI learning.

This script can:
1. Extract queries from YAML/JSON files (-file mode)
2. Import queries to database (-db mode)

Usage:
    # Extract from directory to JSON
    python3 import_training_queries.py -file /path/to/queries

    # Import from directory to database
    python3 import_training_queries.py -db /path/to/queries

    # Import from JSON file to database
    python3 import_training_queries.py -db queries.json

    # Dry run (show what would be imported)
    python3 import_training_queries.py -db /path/to/queries --dry-run
"""

import argparse
import json
import yaml
import sys
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import enum

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from archer.database.db import get_db, init_db
from archer.database.models import Base
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Float,
    DateTime,
    Enum as SQLEnum,
    create_engine,
)


# Define QueryPlatform enum
class QueryPlatform(enum.Enum):
    """Detection platform"""

    SPLUNK = "splunk"
    MDE = "mde"
    SENTINEL = "sentinel"
    CHRONICLE = "chronicle"


# Define QueryTrainingExample model
class QueryTrainingExample(Base):
    """Training examples for query generation."""

    __tablename__ = "query_training_examples"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String(20), nullable=False, index=True)
    platform = Column(SQLEnum(QueryPlatform), nullable=False, index=True)
    query = Column(Text, nullable=False)
    technique_description = Column(Text, nullable=False)
    attack_scenario = Column(Text, nullable=True)
    expected_detections = Column(Text, nullable=True)
    avg_rating = Column(Float, nullable=True)
    usage_count = Column(Integer, default=0)
    success_rate = Column(Float, nullable=True)
    source = Column(String(50), nullable=False)
    tags = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by = Column(Integer, nullable=True)


class QueryExtractor:
    """Extract queries from YAML/JSON files."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.extracted = []
        self.errors = []

    def log(self, message: str):
        """Print message if verbose."""
        if self.verbose:
            print(message)

    def extract_from_directory(self, directory: Path) -> List[Dict]:
        """
        Extract queries from all YAML/JSON files in directory.

        Args:
            directory: Path to directory containing query files

        Returns:
            List of extracted query dictionaries
        """
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        if not directory.is_dir():
            raise ValueError(f"Not a directory: {directory}")

        self.log(f"\n🔍 Scanning directory: {directory}")

        # Find all YAML and JSON files
        yaml_files = list(directory.glob("**/*.yaml")) + list(directory.glob("**/*.yml"))
        json_files = list(directory.glob("**/*.json"))

        total_files = len(yaml_files) + len(json_files)
        self.log(f"Found {len(yaml_files)} YAML and {len(json_files)} JSON files\n")

        # Process YAML files
        for yaml_file in yaml_files:
            self._extract_from_yaml(yaml_file)

        # Process JSON files
        for json_file in json_files:
            self._extract_from_json(json_file)

        self.log(f"\n✓ Extracted {len(self.extracted)} queries from {total_files} files")
        if self.errors:
            self.log(f"⚠️  {len(self.errors)} files had errors")

        return self.extracted

    def _extract_from_yaml(self, yaml_file: Path):
        """Extract query from YAML file."""
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                return

            # Extract query data
            query_data = self._parse_query_data(data, yaml_file)

            if query_data:
                self.extracted.append(query_data)
                self.log(
                    f"  ✓ {yaml_file.name}: {query_data['technique_id']} ({query_data['platform']})"
                )

        except Exception as e:
            self.errors.append({"file": str(yaml_file), "error": str(e)})
            self.log(f"  ✗ {yaml_file.name}: {e}")

    def _extract_from_json(self, json_file: Path):
        """Extract query from JSON file."""
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Handle array of queries
            if isinstance(data, list):
                for item in data:
                    query_data = self._parse_query_data(item, json_file)
                    if query_data:
                        self.extracted.append(query_data)
                        self.log(
                            f"  ✓ {json_file.name}: {query_data['technique_id']} ({query_data['platform']})"
                        )
            else:
                query_data = self._parse_query_data(data, json_file)
                if query_data:
                    self.extracted.append(query_data)
                    self.log(
                        f"  ✓ {json_file.name}: {query_data['technique_id']} ({query_data['platform']})"
                    )

        except Exception as e:
            self.errors.append({"file": str(json_file), "error": str(e)})
            self.log(f"  ✗ {json_file.name}: {e}")

    def _parse_query_data(self, data: Dict, source_file: Path) -> Optional[Dict]:
        """
        Parse query data from various formats.

        Supports multiple formats:
        - Sigma/Splunk format: detection.search or detection.query
        - Simple format: query field
        - Custom format with explicit fields
        """
        if not isinstance(data, dict):
            return None

        # Extract technique ID
        technique_id = (
            data.get("technique_id") or data.get("mitre_attack", {}).get("technique_id")
            if isinstance(data.get("mitre_attack"), dict)
            else (
                None or data.get("tags", {}).get("mitre_attack_id")
                if isinstance(data.get("tags"), dict)
                else None or self._extract_technique_from_filename(source_file)
            )
        )

        if not technique_id:
            return None

        # Extract query
        query = (
            data.get("query")
            or data.get("search")
            or (
                data.get("detection", {}).get("search")
                if isinstance(data.get("detection"), dict)
                else None
            )
            or (
                data.get("detection", {}).get("query")
                if isinstance(data.get("detection"), dict)
                else None
            )
            or data.get("detection_query")
            or data.get("spl")
        )

        if not query or len(query) < 10:  # Skip trivial queries
            return None

        # Extract platform
        platform = self._detect_platform(data, query, source_file)

        # Extract metadata
        technique_name = (
            data.get("technique_name")
            or data.get("title")
            or data.get("name")
            or data.get("description", "")[:100]
        )

        quality_rating = data.get("quality_rating") or data.get("rating") or 4.0
        if isinstance(quality_rating, str):
            quality_map = {"high": 5.0, "medium": 4.0, "low": 3.0}
            quality_rating = quality_map.get(quality_rating.lower(), 4.0)

        tags = data.get("tags", [])
        if isinstance(tags, dict):
            tags = [f"{k}:{v}" for k, v in tags.items()]
        elif not isinstance(tags, list):
            tags = []

        return {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "platform": platform,
            "query": query.strip(),
            "quality": "high" if quality_rating >= 4.5 else "medium",
            "rating": quality_rating,
            "notes": data.get("notes")
            or data.get("comment")
            or f"Imported from {source_file.name}",
            "tags": tags,
            "attack_scenario": data.get("attack_scenario") or data.get("scenario"),
            "expected_detections": data.get("expected_detections"),
        }

    def _extract_technique_from_filename(self, file_path: Path) -> Optional[str]:
        """Extract technique ID from filename (e.g., T1003.001_splunk.yaml)."""
        import re

        match = re.search(r"T\d{4}(?:\.\d{3})?", file_path.name)
        return match.group(0) if match else None

    def _detect_platform(self, data: Dict, query: str, file_path: Path) -> str:
        """Detect platform from data, query content, or filename."""
        # Explicit platform field
        platform = data.get("platform") or data.get("detection_platform")
        if platform:
            return platform.lower()

        # Detect from filename
        filename_lower = file_path.name.lower()
        if "splunk" in filename_lower or "spl" in filename_lower:
            return "splunk"
        if "mde" in filename_lower or "kql" in filename_lower or "defender" in filename_lower:
            return "mde"
        if "sentinel" in filename_lower:
            return "sentinel"
        if "chronicle" in filename_lower:
            return "chronicle"

        # Detect from query content
        query_lower = query.lower()
        if "index=" in query_lower or "sourcetype=" in query_lower or "| stats" in query_lower:
            return "splunk"
        if (
            "deviceprocessevents" in query_lower
            or "devicefileevents" in query_lower
            or "has_any" in query_lower
        ):
            return "mde"

        # Default
        return "splunk"

    def save_to_json(self, output_file: Path):
        """Save extracted queries to JSON file."""
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            json.dump(self.extracted, f, indent=2)

        self.log(f"\n💾 Saved to: {output_file}")
        self.log(f"   Total queries: {len(self.extracted)}")


class QueryImporter:
    """Import queries to database."""

    def __init__(self, dry_run: bool = False, verbose: bool = True):
        self.dry_run = dry_run
        self.verbose = verbose
        self.imported = 0
        self.skipped = 0
        self.errors = []

    def log(self, message: str):
        """Print message if verbose."""
        if self.verbose:
            print(message)

    def import_from_file(self, input_file: Path):
        """Import queries from JSON file."""
        with open(input_file, "r") as f:
            queries = json.load(f)

        self._import_queries(queries)

    def import_from_list(self, queries: List[Dict]):
        """Import queries from list."""
        self._import_queries(queries)

    def _import_queries(self, queries: List[Dict]):
        """Import list of queries to database."""
        if self.dry_run:
            self.log("\n🔍 DRY RUN - No changes will be made\n")
        else:
            # Initialize database and create table
            init_db()
            engine = create_engine("sqlite:///data/archer.db")
            QueryTrainingExample.__table__.create(engine, checkfirst=True)
            self.log("\n📊 Importing to database...\n")

        db = next(get_db())

        for query_data in queries:
            try:
                technique_id = query_data["technique_id"]
                platform = query_data["platform"]

                # Check if already exists
                if not self.dry_run:
                    existing = (
                        db.query(QueryTrainingExample)
                        .filter(
                            QueryTrainingExample.technique_id == technique_id,
                            QueryTrainingExample.platform == QueryPlatform[platform.upper()],
                            QueryTrainingExample.query == query_data["query"],
                        )
                        .first()
                    )

                    if existing:
                        self.log(f"  ⊘ {technique_id} ({platform}): Already exists")
                        self.skipped += 1
                        continue

                # Create training example
                if self.dry_run:
                    self.log(f"  ✓ {technique_id} ({platform}): Would import")
                else:
                    example = QueryTrainingExample(
                        technique_id=technique_id,
                        platform=QueryPlatform[platform.upper()],
                        query=query_data["query"],
                        technique_description=query_data.get("technique_name", ""),
                        attack_scenario=query_data.get("notes", ""),
                        expected_detections=query_data.get("expected_detections"),
                        avg_rating=float(query_data.get("rating", 4.0)),
                        source="manual_import",
                        tags=json.dumps(query_data.get("tags", [])),
                    )

                    db.add(example)
                    self.log(f"  ✓ {technique_id} ({platform}): Imported")

                self.imported += 1

            except Exception as e:
                self.errors.append(
                    {"query": query_data.get("technique_id", "unknown"), "error": str(e)}
                )
                self.log(f"  ✗ {query_data.get('technique_id', 'unknown')}: {e}")

        if not self.dry_run:
            db.commit()

        db.close()

        # Summary
        self.log(f"\n{'=' * 60}")
        if self.dry_run:
            self.log(f"DRY RUN Summary:")
            self.log(f"  Would import: {self.imported}")
        else:
            self.log(f"Import Summary:")
            self.log(f"  ✓ Imported: {self.imported}")
            self.log(f"  ⊘ Skipped (duplicates): {self.skipped}")

        if self.errors:
            self.log(f"  ✗ Errors: {len(self.errors)}")

        self.log(f"{'=' * 60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Import high-quality queries as training examples",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract queries from directory to JSON
  %(prog)s -file /path/to/queries

  # Extract and specify output file
  %(prog)s -file /path/to/queries -o custom_output.json

  # Import from directory to database
  %(prog)s -db /path/to/queries

  # Import from JSON file to database
  %(prog)s -db queries.json

  # Dry run (show what would be imported)
  %(prog)s -db /path/to/queries --dry-run

  # Quiet mode
  %(prog)s -db /path/to/queries --quiet

Supported file formats:
  - YAML (.yaml, .yml)
  - JSON (.json)

Expected query structure (flexible):
  {
    "technique_id": "T1003.001",
    "technique_name": "LSASS Memory",
    "platform": "splunk",
    "query": "index=windows EventCode=10 ...",
    "quality": "high",
    "rating": 5.0,
    "tags": ["persistence", "windows"],
    "notes": "Reduces false positives..."
  }
        """,
    )

    # Modes
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "-file",
        "--extract-to-file",
        metavar="DIR",
        help="Extract queries from directory to JSON file",
    )
    mode_group.add_argument(
        "-db",
        "--import-to-database",
        metavar="PATH",
        help="Import queries from directory or JSON file to database",
    )

    # Options
    parser.add_argument(
        "-o",
        "--output",
        default="data/query_examples.json",
        help="Output JSON file (default: data/query_examples.json)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be imported without making changes"
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress verbose output")

    args = parser.parse_args()

    verbose = not args.quiet

    try:
        # Mode 1: Extract to file
        if args.extract_to_file:
            input_path = Path(args.extract_to_file)
            output_path = Path(args.output)

            extractor = QueryExtractor(verbose=verbose)
            extractor.extract_from_directory(input_path)
            extractor.save_to_json(output_path)

            if verbose:
                print(f"\n✅ Extraction complete!")
                print(f"\nNext step: python3 {sys.argv[0]} -db {output_path}")

        # Mode 2: Import to database
        elif args.import_to_database:
            input_path = Path(args.import_to_database)

            importer = QueryImporter(dry_run=args.dry_run, verbose=verbose)

            # Check if input is a file or directory
            if input_path.is_file() and input_path.suffix == ".json":
                # Import from JSON file
                importer.import_from_file(input_path)
            elif input_path.is_dir():
                # Extract from directory and import
                extractor = QueryExtractor(verbose=verbose)
                queries = extractor.extract_from_directory(input_path)
                importer.import_from_list(queries)
            else:
                print(f"❌ Error: {input_path} must be a JSON file or directory")
                sys.exit(1)

            if not args.dry_run and verbose:
                print(f"✅ Import complete!")
                print(f"\nYou can now use these examples in query generation.")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

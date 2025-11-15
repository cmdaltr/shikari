#!/usr/bin/env python3
"""
Import YAML detections from data/groups/ into the library database.

This script reads all YAML detection files and imports them into the library
with proper formatting, indicators, OSINT data, and all metadata.
"""

import sys
import os
import json
import yaml
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from archer.database.db import get_db
from archer.database.models import LibraryDetection, DetectionType, VisibilityType, User


def load_yaml_file(yaml_path: str) -> dict:
    """Load and parse a YAML detection file."""
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading {yaml_path}: {e}")
        return None


def convert_yaml_to_library_format(yaml_data: dict, platform: str) -> dict:
    """
    Convert YAML detection to library database format.

    This creates a detection object that matches what the results page expects:
    - technique: technique_id
    - title: technique_name
    - queries: array of query strings
    - description_html: description
    - indicators: extracted indicators
    - tactics: array of tactics
    - osint data if available
    """
    # Extract basic fields
    technique_id = yaml_data.get('technique_id', '')
    technique_name = yaml_data.get('name', '')
    description = yaml_data.get('description', '')
    query = yaml_data.get('query', '')

    # Extract tactics
    tactics = yaml_data.get('tactics', [])

    # Extract indicators
    indicators = yaml_data.get('indicators', {})

    # Extract OSINT data
    osint_enhanced = yaml_data.get('osint_enhanced', False)
    osint_compared = yaml_data.get('osint_compared', False)
    osint_indicators = yaml_data.get('osint_indicators', {})

    # Extract MDE table names or Splunk indexes from requiredDataConnectors
    # This is for the "MDE Tables" or "Splunk Indexes" section, NOT for the platform
    mde_tables = []
    splunk_indexes = []
    connectors = yaml_data.get('requiredDataConnectors', [])
    if connectors and isinstance(connectors, list) and len(connectors) > 0:
        data_types = connectors[0].get('dataTypes', [])
        if data_types:
            # These are table names like "DeviceEvents", not platforms
            if platform == 'mde':
                mde_tables = data_types
            elif platform == 'splunk':
                splunk_indexes = data_types

    # Extract group/threat actor from tags
    tags = yaml_data.get('tags', [])
    group_name = "Unknown"
    for tag in tags:
        if tag and not tag.startswith('Group:'):
            group_name = tag
            break

    # Build the detection object in results.html format
    detection = {
        "technique": technique_id,  # This is technique_id in results format
        "title": technique_name,     # This is technique_name in results format
        "description": description,
        "description_html": description,  # Same as description but marked as HTML-safe
        "query": query,
        "queries": [query] if query else [],  # Array format for results page
        "data_source": platform,  # Use platform (mde, splunk, etc) not table name
        "mde_tables": mde_tables,  # MDE table names like DeviceEvents
        "splunk_indexes": splunk_indexes,  # Splunk index names
        "indicators": indicators,
        "tactics": tactics,
        "tactic": tactics[0] if tactics else "Unknown",  # First tactic as string
        "tags": tags,
        "group": group_name,
        "osint_enriched": osint_enhanced,
        "osint_compared": osint_compared,
        "osint_indicators": osint_indicators,
        "needs_review": False
    }

    return detection


def import_yaml_detections(yaml_dir: str = "data/groups", user_id: int = 1, delete_old: bool = True):
    """
    Import all YAML detections from the specified directory into the library.

    Args:
        yaml_dir: Directory containing YAML detection files
        user_id: User ID to associate with imported detections
        delete_old: If True, delete old stub detections before importing
    """
    db = next(get_db())

    try:
        # Get or verify user exists
        user = db.query(User).filter_by(id=user_id).first()
        if not user:
            print(f"Error: User with ID {user_id} not found")
            return

        print(f"Importing YAML detections for user: {user.email}")

        # Delete old stub detections if requested
        if delete_old:
            print("\nDeleting old stub detections...")
            old_count = 0
            for det in db.query(LibraryDetection).filter_by(user_id=user_id).all():
                try:
                    content = json.loads(det.content) if isinstance(det.content, str) else det.content
                    # Check if it's an old stub (only has technique, title, description)
                    if isinstance(content, dict) and set(content.keys()) == {'technique', 'title', 'description'}:
                        db.delete(det)
                        old_count += 1
                except:
                    pass

            db.commit()
            print(f"✓ Deleted {old_count} old stub detections")

        # Get all YAML files
        yaml_files = list(Path(yaml_dir).glob("*.yaml"))
        print(f"\nFound {len(yaml_files)} YAML files to import")

        imported = 0
        skipped = 0
        errors = 0

        for yaml_file in yaml_files:
            try:
                # Load YAML
                yaml_data = load_yaml_file(str(yaml_file))
                if not yaml_data:
                    errors += 1
                    continue

                # Determine platform from filename
                filename = yaml_file.stem
                if 'DeviceEvents' in filename or 'DeviceProcess' in filename or 'DeviceFile' in filename or 'DeviceImage' in filename or 'DeviceRegistry' in filename or 'DeviceNetwork' in filename:
                    platform = 'mde'
                elif 'splunk' in filename.lower():
                    platform = 'splunk'
                elif 'elastic' in filename.lower():
                    platform = 'elastic'
                elif 'microsoft_defender' in filename or 'microsoft_windows' in filename:
                    platform = 'mde'
                elif 'mcafee' in filename:
                    platform = 'mcafee'
                elif 'unix' in filename or 'linux' in filename:
                    platform = 'unix'
                else:
                    platform = 'unknown'

                # Convert to library format
                detection_data = convert_yaml_to_library_format(yaml_data, platform)

                # Create title for the library entry
                technique_name = detection_data.get('title', 'Unknown Technique')
                # Use platform for title (mde_tables/splunk_indexes are stored separately in content)
                title = f"{technique_name} - {platform}"

                # Check if already exists (same title and platform)
                existing = db.query(LibraryDetection).filter_by(
                    user_id=user_id,
                    title=title,
                    platform=platform
                ).first()

                if existing:
                    # Update existing
                    existing.content = json.dumps(detection_data)
                    existing.updated_at = datetime.utcnow()
                    skipped += 1
                else:
                    # Create new library detection
                    lib_det = LibraryDetection(
                        user_id=user_id,
                        title=title,
                        detection_type=DetectionType.DETECTION,
                        visibility=VisibilityType.PRIVATE,
                        content=json.dumps(detection_data),
                        platform=platform,
                        tags=json.dumps(detection_data.get('tags', []))
                    )
                    db.add(lib_det)
                    imported += 1

                if (imported + skipped) % 50 == 0:
                    print(f"Progress: {imported} imported, {skipped} updated, {errors} errors")

            except Exception as e:
                print(f"Error processing {yaml_file.name}: {e}")
                errors += 1
                continue

        # Commit all changes
        db.commit()

        print(f"\n{'='*60}")
        print(f"Import Complete!")
        print(f"{'='*60}")
        print(f"✓ Imported: {imported} new detections")
        print(f"✓ Updated: {skipped} existing detections")
        print(f"✗ Errors: {errors}")
        print(f"\nTotal in library: {db.query(LibraryDetection).filter_by(user_id=user_id).count()}")

    except Exception as e:
        db.rollback()
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Import YAML detections into library')
    parser.add_argument('--yaml-dir', default='data/groups', help='Directory containing YAML files')
    parser.add_argument('--user-id', type=int, default=1, help='User ID to import for')
    parser.add_argument('--keep-old', action='store_true', help='Keep old stub detections (default: delete them)')

    args = parser.parse_args()

    import_yaml_detections(
        yaml_dir=args.yaml_dir,
        user_id=args.user_id,
        delete_old=not args.keep_old
    )

#!/usr/bin/env python3
"""
Clean extra newlines in descriptions to make them flow better.
"""
import json
import os
import sys
import re

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from archer.database.db import SessionLocal
from archer.database.models import LibraryDetection

def clean_newlines():
    """Remove extra newlines between sentences in descriptions."""
    db = SessionLocal()
    try:
        # Get all detections
        detections = db.query(LibraryDetection).all()
        updated_count = 0

        for det in detections:
            if det.content:
                try:
                    content = json.loads(det.content)
                    description = content.get("description", "")
                    description_html = content.get("description_html", "")

                    # Clean both description fields
                    updated = False

                    # Replace patterns like ".\n " (period, newline, space) with ". " (period, space)
                    # This makes the descriptions flow as single paragraphs
                    if description and '\n' in description:
                        cleaned = re.sub(r'\.\n\s+', '. ', description)
                        cleaned = cleaned.strip()
                        if cleaned != description:
                            content["description"] = cleaned
                            updated = True

                    if description_html and '\n' in description_html:
                        cleaned = re.sub(r'\.\n\s+', '. ', description_html)
                        cleaned = cleaned.strip()
                        if cleaned != description_html:
                            content["description_html"] = cleaned
                            updated = True

                    if updated:
                        det.content = json.dumps(content)
                        updated_count += 1

                except json.JSONDecodeError:
                    print(f"Warning: Could not parse content for detection {det.id}")
                    continue

        # Commit changes
        db.commit()
        print(f"✅ Cleaned newlines in {updated_count} detection descriptions")

    except Exception as e:
        db.rollback()
        print(f"❌ Error: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    print("Cleaning extra newlines from descriptions...")
    clean_newlines()
    print("Done!")

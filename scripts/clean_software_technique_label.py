#!/usr/bin/env python3
"""
Clean 'Software technique:' label from existing descriptions in the database.
"""
import json
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from archer.database.db import SessionLocal
from archer.database.models import LibraryDetection

def clean_descriptions():
    """Remove 'Software technique:' label from all detection descriptions."""
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
                    if "Software technique:" in description:
                        # Handle both \n\nSoftware technique: and \nSoftware technique:
                        cleaned = description.replace("\n\nSoftware technique:", " ")
                        cleaned = cleaned.replace("\nSoftware technique:", " ")
                        content["description"] = cleaned
                        updated = True

                    if "Software technique:" in description_html:
                        # Handle both \n\nSoftware technique: and \nSoftware technique:
                        cleaned = description_html.replace("\n\nSoftware technique:", " ")
                        cleaned = cleaned.replace("\nSoftware technique:", " ")
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
        print(f"✅ Cleaned {updated_count} detection descriptions")

    except Exception as e:
        db.rollback()
        print(f"❌ Error: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    print("Cleaning 'Software technique:' labels from database...")
    clean_descriptions()
    print("Done!")

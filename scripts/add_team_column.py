#!/usr/bin/env python3
"""
Migration script to add 'team' column to users table.

This script adds the team field to existing user databases.
Run this script once to migrate your database.

Usage:
    python scripts/add_team_column.py
"""

import sqlite3
from pathlib import Path

def add_team_column():
    """Add team column to users table if it doesn't exist."""
    db_path = Path("data/archer.db")

    if not db_path.exists():
        print(f"❌ Database not found at {db_path}")
        print("   Database will be created on first run with team field included.")
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if column already exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]

        if 'team' in columns:
            print("✓ Team column already exists in users table")
        else:
            # Add the column
            cursor.execute("ALTER TABLE users ADD COLUMN team VARCHAR(255)")
            conn.commit()
            print("✓ Successfully added 'team' column to users table")

        conn.close()

    except Exception as e:
        print(f"❌ Error: {e}")
        raise

if __name__ == "__main__":
    add_team_column()

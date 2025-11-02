#!/usr/bin/env python3
"""
Convert Archer documentation to Notion-compatible format.

This script automates the conversion of Markdown files to Notion-compatible
format with proper emoji icons, callouts, code blocks, and formatting.

Usage:
    python3 scripts/convert_docs_to_notion.py
"""

import re
import os
from pathlib import Path
from typing import Dict, List, Tuple

# Emoji mapping for different file types
EMOJI_MAP = {
    "SECURITY_FEATURES": "🔒",
    "API_REFERENCE": "📚",
    "AI_TRAINING": "🤖",
    "IMPORT_TRAINING_QUERIES": "📥",
    "MAPPINGS_INTEGRATION_GUIDE": "🔧",
    "SCHEMA_NORMALIZATION": "📊",
    "SCRIPTS": "⚙️",
    "DOCKER": "🐳",
    "DETECTION_VALIDATION": "✅",
    "OSINT_INTEGRATION": "🔍",
    "MAPPINGS_README": "📖",
    "PARENT_SUBTECHNIQUE_EXPANSION": "🌳",
    "MITRE_PROCEDURES": "🎯",
    "INDICATOR_EXTRACTION_FIX": "🔧",
    "CORRELATION_GUIDE": "🔗",
    "EMULATION_GUIDE": "🎭",
    "QUERY_API_GUIDE": "🔌",
    "TESTING_GUIDE": "🧪",
    "CVE_HUNTING_GUIDE": "🎯",
}

def get_emoji_for_file(filename: str) -> str:
    """Get emoji icon for a given filename."""
    base = filename.replace(".md", "").upper()
    for key, emoji in EMOJI_MAP.items():
        if key in base:
            return emoji
    return "📄"  # Default emoji


def convert_blockquotes_to_callouts(content: str) -> str:
    """Convert blockquotes to Notion-style callouts."""

    # Pattern 1: > **Type**: Content
    pattern1 = r'^> \*\*(\w+)\*\*:(.+)$'

    # Pattern 2: Simple > Content
    pattern2 = r'^> (.+)$'

    lines = content.split('\n')
    converted_lines = []

    for line in lines:
        # Check for type-based callout
        match1 = re.match(pattern1, line)
        if match1:
            callout_type = match1.group(1)
            callout_content = match1.group(2).strip()

            # Map types to emoji
            emoji_map = {
                "Note": "📝",
                "Tip": "💡",
                "Warning": "⚠️",
                "Caution": "⚠️",
                "Important": "❗",
                "Success": "✅",
                "Error": "❌",
                "Info": "ℹ️",
            }

            emoji = emoji_map.get(callout_type, "📝")
            converted_lines.append(f"> **{emoji} {callout_type}**:{callout_content}")
            continue

        # Check for simple blockquote
        match2 = re.match(pattern2, line)
        if match2:
            content_text = match2.group(1).strip()
            # Add note emoji if not already prefixed
            if not any(emoji in content_text for emoji in ["📝", "💡", "⚠️", "❗", "✅", "❌", "ℹ️"]):
                converted_lines.append(f"> **📝 Note**: {content_text}")
            else:
                converted_lines.append(line)
            continue

        converted_lines.append(line)

    return '\n'.join(converted_lines)


def add_emoji_to_headers(content: str, file_emoji: str) -> str:
    """Add emoji icons to headers."""
    lines = content.split('\n')
    converted_lines = []

    # Header emoji mapping by content
    header_emojis = {
        "overview": "📋",
        "features": "✨",
        "installation": "⚙️",
        "setup": "🔧",
        "configuration": "⚙️",
        "usage": "💻",
        "examples": "📝",
        "troubleshooting": "🔧",
        "faq": "❓",
        "api": "🔌",
        "reference": "📚",
        "security": "🔒",
        "authentication": "🔐",
        "authorization": "🛡️",
        "deployment": "🚀",
        "docker": "🐳",
        "testing": "🧪",
        "development": "👨‍💻",
        "architecture": "🏗️",
        "database": "🗄️",
        "performance": "⚡",
        "monitoring": "📊",
        "logging": "📋",
        "best practices": "⭐",
        "advanced": "🎓",
        "integration": "🔗",
        "migration": "🔄",
        "backup": "💾",
        "recovery": "🔄",
        "support": "🆘",
        "prerequisites": "📋",
        "requirements": "📋",
        "quick start": "⚡",
        "getting started": "🚀",
    }

    in_code_block = False

    for line in lines:
        # Track code blocks to avoid modifying them
        if line.strip().startswith("```"):
            in_code_block = not in_code_block
            converted_lines.append(line)
            continue

        if in_code_block:
            converted_lines.append(line)
            continue

        # Check if it's a header
        if line.startswith("#"):
            # Extract heading level and text
            match = re.match(r'^(#+)\s+(.+)$', line)
            if match:
                level, text = match.groups()

                # Skip if already has emoji
                if re.match(r'^[^\w\s]', text.strip()):
                    converted_lines.append(line)
                    continue

                # Find appropriate emoji
                text_lower = text.lower().strip()
                emoji = None

                for keyword, keyword_emoji in header_emojis.items():
                    if keyword in text_lower:
                        emoji = keyword_emoji
                        break

                # Use file emoji for main title
                if not emoji:
                    emoji = file_emoji if level == "#" else "📌"

                converted_lines.append(f"{level} {emoji} {text}")
            else:
                converted_lines.append(line)
        else:
            converted_lines.append(line)

    return '\n'.join(converted_lines)


def ensure_code_block_languages(content: str) -> str:
    """Ensure all code blocks have language specifications."""
    lines = content.split('\n')
    converted_lines = []

    i = 0
    while i < len(lines):
        line = lines[i]

        # Check for code block without language
        if line.strip() == "```":
            # Look ahead to determine language
            next_line = lines[i + 1] if i + 1 < len(lines) else ""

            # Heuristics to detect language
            lang = "bash"  # Default

            if "def " in next_line or "import " in next_line or "class " in next_line:
                lang = "python"
            elif "function" in next_line or "const " in next_line or "let " in next_line:
                lang = "javascript"
            elif "{" in next_line or "SELECT" in next_line.upper():
                lang = "sql"
            elif "version:" in next_line or "services:" in next_line:
                lang = "yaml"
            elif '"' in next_line and ":" in next_line:
                lang = "json"
            elif "index=" in next_line or "| stats" in next_line:
                lang = "splunk"
            elif "DeviceProcessEvents" in next_line or "| where" in next_line:
                lang = "kql"
            elif "$" in next_line or "sudo" in next_line or "apt" in next_line:
                lang = "bash"

            converted_lines.append(f"```{lang}")
        else:
            converted_lines.append(line)

        i += 1

    return '\n'.join(converted_lines)


def add_visual_separators(content: str) -> str:
    """Add horizontal rules between major sections."""
    lines = content.split('\n')
    converted_lines = []

    prev_was_h2 = False

    for i, line in enumerate(lines):
        # Add separator before ## headers (but not the first one)
        if line.startswith("## ") and i > 0 and not prev_was_h2:
            # Check if previous line is not already a separator
            if converted_lines and converted_lines[-1].strip() != "---":
                converted_lines.append("")
                converted_lines.append("---")
                converted_lines.append("")

        converted_lines.append(line)
        prev_was_h2 = line.startswith("## ")

    return '\n'.join(converted_lines)


def format_tables(content: str) -> str:
    """Ensure tables are properly formatted for Notion."""
    # Tables should already be in proper format, but we can verify
    lines = content.split('\n')
    converted_lines = []

    in_table = False

    for line in lines:
        # Detect table rows
        if '|' in line and not line.strip().startswith('```'):
            in_table = True
            # Ensure consistent spacing
            parts = line.split('|')
            formatted_parts = [part.strip() for part in parts]
            converted_lines.append('| ' + ' | '.join(formatted_parts[1:-1]) + ' |')
        else:
            if in_table and line.strip() == '':
                in_table = False
            converted_lines.append(line)

    return '\n'.join(converted_lines)


def convert_file_to_notion(input_path: Path, output_path: Path) -> None:
    """Convert a single Markdown file to Notion format."""
    print(f"Converting: {input_path.name}")

    # Read original content
    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Get emoji for this file
    file_emoji = get_emoji_for_file(input_path.name)

    # Apply conversions
    content = convert_blockquotes_to_callouts(content)
    content = add_emoji_to_headers(content, file_emoji)
    content = ensure_code_block_languages(content)
    content = add_visual_separators(content)
    content = format_tables(content)

    # Write converted content
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"  ✅ Created: {output_path.name}")


def main():
    """Main conversion function."""
    print("=" * 70)
    print("Archer Documentation → Notion Conversion")
    print("=" * 70)
    print()

    # Define base paths
    docs_dir = Path(__file__).parent.parent / "docs"
    guides_dir = docs_dir / "guides"

    # Files to convert (excluding MAPPING_FILES_GUIDE as requested)
    files_to_convert = [
        ("SECURITY_FEATURES.md", docs_dir),
        ("API_REFERENCE.md", docs_dir),
        ("AI_TRAINING.md", docs_dir),
        ("IMPORT_TRAINING_QUERIES.md", docs_dir),
        ("MAPPINGS_INTEGRATION_GUIDE.md", docs_dir),
        ("SCHEMA_NORMALIZATION.md", docs_dir),
        ("SCRIPTS.md", docs_dir),
        ("DOCKER.md", docs_dir),
        ("DETECTION_VALIDATION.md", docs_dir),
        ("OSINT_INTEGRATION.md", docs_dir),
        ("MAPPINGS_README.md", docs_dir),
        ("PARENT_SUBTECHNIQUE_EXPANSION.md", docs_dir),
        ("MITRE_PROCEDURES.md", docs_dir),
        ("INDICATOR_EXTRACTION_FIX.md", docs_dir),
        ("CORRELATION_GUIDE.md", guides_dir),
        ("EMULATION_GUIDE.md", guides_dir),
        ("QUERY_API_GUIDE.md", guides_dir),
        ("TESTING_GUIDE.md", guides_dir),
        ("CVE_HUNTING_GUIDE.md", guides_dir),
    ]

    converted_count = 0
    skipped_count = 0

    for filename, directory in files_to_convert:
        input_path = directory / filename
        output_filename = filename.replace(".md", "_NOTION.md")
        output_path = directory / output_filename

        # Check if file exists
        if not input_path.exists():
            print(f"⚠️  Skipping {filename} - file not found")
            skipped_count += 1
            continue

        try:
            convert_file_to_notion(input_path, output_path)
            converted_count += 1
        except Exception as e:
            print(f"❌ Error converting {filename}: {e}")
            skipped_count += 1

    print()
    print("=" * 70)
    print("Conversion Complete!")
    print("=" * 70)
    print(f"✅ Converted: {converted_count} files")
    if skipped_count > 0:
        print(f"⚠️  Skipped: {skipped_count} files")
    print()
    print("Next steps:")
    print("1. Review converted files in docs/*_NOTION.md")
    print("2. Follow NOTION_DOCS_IMPORT_GUIDE.md for import instructions")
    print("3. Import to Notion using bulk import feature")
    print()


if __name__ == "__main__":
    main()

#!/bin/bash

# Archer Repository Cleanup Script
# Removes temporary files, caches, and build artifacts
# Usage: ./scripts/cleanup.sh [--dry-run]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if dry-run mode
DRY_RUN=false
if [ "$1" == "--dry-run" ]; then
    DRY_RUN=true
    echo -e "${YELLOW}Running in DRY-RUN mode (no files will be deleted)${NC}\n"
fi

# Function to remove files/directories
remove_items() {
    local pattern=$1
    local description=$2
    local count=0

    echo -e "${BLUE}Searching for: ${description}${NC}"

    if [ "$DRY_RUN" = true ]; then
        count=$(find . -name "$pattern" -not -path "./.venv/*" -not -path "./venv/*" -not -path "./env/*" -not -path "./ENV/*" -not -path "./node_modules/*" -not -path "./.git/*" -not -path "./archer/build" -not -path "./archer/data/*" 2>/dev/null | wc -l | xargs)
        if [ "$count" -gt 0 ]; then
            echo -e "${YELLOW}Would remove ${count} items matching '${pattern}'${NC}"
            find . -name "$pattern" -not -path "./.venv/*" -not -path "./venv/*" -not -path "./env/*" -not -path "./ENV/*" -not -path "./node_modules/*" -not -path "./.git/*" -not -path "./archer/build" -not -path "./archer/data/*" 2>/dev/null | head -5
            if [ "$count" -gt 5 ]; then
                echo "  ... and $((count - 5)) more"
            fi
        else
            echo -e "${GREEN}No items found matching '${pattern}'${NC}"
        fi
    else
        # Count before deletion
        count=$(find . -name "$pattern" -not -path "./.venv/*" -not -path "./venv/*" -not -path "./env/*" -not -path "./ENV/*" -not -path "./node_modules/*" -not -path "./.git/*" -not -path "./archer/build" -not -path "./archer/data/*" 2>/dev/null | wc -l | xargs)
        if [ "$count" -gt 0 ]; then
            find . -name "$pattern" -type f -not -path "./.venv/*" -not -path "./venv/*" -not -path "./env/*" -not -path "./ENV/*" -not -path "./node_modules/*" -not -path "./.git/*" -not -path "./archer/build" -not -path "./archer/data/*" -delete 2>/dev/null || true
            find . -name "$pattern" -type d -not -path "./.venv/*" -not -path "./venv/*" -not -path "./env/*" -not -path "./ENV/*" -not -path "./node_modules/*" -not -path "./.git/*" -not -path "./archer/build" -not -path "./archer/data/*" -exec rm -rf {} + 2>/dev/null || true
            echo -e "${GREEN}✓ Removed ${count} items matching '${pattern}'${NC}"
        else
            echo -e "${GREEN}No items found matching '${pattern}'${NC}"
        fi
    fi
    echo ""
}

echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Archer Repository Cleanup Script        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

# Python cache files
echo -e "${BLUE}━━━ Python Cache Files ━━━${NC}\n"
remove_items "__pycache__" "Python cache directories"
remove_items "*.pyc" "Compiled Python files (.pyc)"
remove_items "*.pyo" "Optimized Python files (.pyo)"
remove_items "*.pyd" "Python DLL files (.pyd)"

# Python build artifacts
echo -e "${BLUE}━━━ Python Build Artifacts ━━━${NC}\n"
remove_items "*.egg-info" "Python egg-info directories"
remove_items "*.egg" "Python egg files"
remove_items "dist" "Distribution directories"
remove_items "build" "Build directories"
remove_items ".eggs" "Eggs directories"

# Testing artifacts
echo -e "${BLUE}━━━ Testing Artifacts ━━━${NC}\n"
remove_items ".pytest_cache" "Pytest cache directories"
remove_items ".coverage" "Coverage data files"
remove_items "htmlcov" "HTML coverage reports"
remove_items ".tox" "Tox directories"
remove_items ".nox" "Nox directories"

# IDE and OS files
echo -e "${BLUE}━━━ IDE and OS Files ━━━${NC}\n"
remove_items ".DS_Store" "macOS .DS_Store files"
remove_items "Thumbs.db" "Windows thumbnail cache"
remove_items ".vscode" "VS Code settings (if not tracked)"
remove_items ".idea" "PyCharm/IntelliJ settings (if not tracked)"

# Jupyter Notebook checkpoints
echo -e "${BLUE}━━━ Jupyter Artifacts ━━━${NC}\n"
remove_items ".ipynb_checkpoints" "Jupyter notebook checkpoints"

# Log files
echo -e "${BLUE}━━━ Log Files ━━━${NC}\n"
remove_items "*.log" "Log files"
remove_items "*.log.*" "Rotated log files"

# Temporary files
echo -e "${BLUE}━━━ Temporary Files ━━━${NC}\n"
remove_items "*.tmp" "Temporary files (.tmp)"
remove_items "*.temp" "Temporary files (.temp)"
remove_items "*.swp" "Vim swap files"
remove_items "*.swo" "Vim swap files"
remove_items "*~" "Backup files"

# Node modules (if any)
echo -e "${BLUE}━━━ Node.js Artifacts ━━━${NC}\n"
remove_items "node_modules" "Node.js modules"
remove_items "package-lock.json" "NPM lock files"

# Database files (be careful with this!)
if [ "$DRY_RUN" = false ]; then
    echo -e "${BLUE}━━━ Database Backups ━━━${NC}\n"
    echo -e "${YELLOW}Note: Keeping active database, only cleaning up .db-journal files${NC}"
    remove_items "*.db-journal" "SQLite journal files"
    echo ""
fi

# Summary
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            Cleanup Complete!               ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}This was a dry-run. Run without --dry-run to actually delete files.${NC}"
    echo -e "${YELLOW}Command: ./scripts/cleanup.sh${NC}\n"
else
    echo -e "${GREEN}✓ Repository cleaned successfully!${NC}\n"
fi

# Show disk space saved (approximate)
if [ "$DRY_RUN" = false ]; then
    echo -e "${BLUE}Tip: Run 'du -sh .' to check current repository size${NC}"
fi

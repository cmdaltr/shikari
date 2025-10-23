#!/bin/bash
#
# Archer Schema Normalization CLI Wrapper
#
# This script provides a simple command-line interface to the schema normalizer.
# It can be called from anywhere in the Archer workflow.
#

set -e  # Exit on error

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default values
FORCE=false
SILENT=false
SCHEMA_PATH=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE=true
            shift
            ;;
        --silent)
            SILENT=true
            shift
            ;;
        --schema)
            SCHEMA_PATH="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --force         Force re-normalization of all indexes"
            echo "  --silent        Suppress output"
            echo "  --schema PATH   Path to schema file (default: archer/mappings/schemaSplunk.json)"
            echo "  --help, -h      Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                      # Normalize only new indexes"
            echo "  $0 --force              # Re-normalize all indexes"
            echo "  $0 --schema /tmp/test.json  # Normalize custom schema"
            echo ""
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Build Python command
PYTHON_CMD="python3 $PROJECT_ROOT/archer/mappings/normalize_manual.py"

if [ "$FORCE" = true ]; then
    PYTHON_CMD="$PYTHON_CMD --force"
fi

if [ -n "$SCHEMA_PATH" ]; then
    PYTHON_CMD="$PYTHON_CMD --schema $SCHEMA_PATH"
fi

# Run normalization
if [ "$SILENT" = true ]; then
    $PYTHON_CMD > /dev/null 2>&1
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}✅ Schema normalization complete${NC}"
    else
        echo -e "${RED}❌ Schema normalization failed${NC}"
        exit $EXIT_CODE
    fi
else
    $PYTHON_CMD
    EXIT_CODE=$?
fi

exit $EXIT_CODE

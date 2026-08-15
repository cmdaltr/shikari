#!/usr/bin/env bash
REQUIRED_VERSION="3.11"
CURRENT_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [ "$CURRENT_VERSION" != "$REQUIRED_VERSION" ]; then
    echo "✕ Wrong Python version: $CURRENT_VERSION (need $REQUIRED_VERSION)"
    echo "  Run: pyenv local $REQUIRED_VERSION && rm -rf .venv && python3 -m venv .venv"
    exit 1
fi
echo "✓ Python version OK: $CURRENT_VERSION"

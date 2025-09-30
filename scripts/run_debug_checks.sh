#!/usr/bin/env bash
set -euo pipefail
PYENV="${VIRTUAL_ENV:-.venv}"
echo "Using venv: ${PYENV}"
echo "Running template checks..."
python3 scripts/debug_templates.py || { echo "Template checks failed"; exit 1; }
echo
echo "Running endpoint smoke checks (uses TestClient) ..."
python3 scripts/debug_endpoints.py || { echo "Endpoint checks failed"; exit 2; }
echo
echo "All debug checks completed successfully."
#!/usr/bin/env bash
# doctor.sh — environment health check for Archer development
set -uo pipefail
PASS=0
FAIL=0

check() {
    if eval "$2" > /dev/null 2>&1; then
        echo "✓ $1"
        PASS=$((PASS+1))
    else
        echo "✕ $1"
        FAIL=$((FAIL+1))
    fi
}

echo "=== Python environment ==="
check "Python version is 3.11.x" "python3 --version | grep -q '3\.11'"
check "Virtual env is active" "[ -n \"\${VIRTUAL_ENV:-}\" ]"
check ".python-version file exists" "[ -f .python-version ]"

echo ""
echo "=== Key dependencies importable ==="
check "fastapi importable" "python3 -c 'import fastapi'"
check "yaml importable" "python3 -c 'import yaml'"
check "bs4 importable" "python3 -c 'import bs4'"
check "playwright importable" "python3 -c 'import playwright'"

echo ""
echo "=== Playwright browsers ==="
check "playwright CLI resolves to venv" "which playwright | grep -q '.venv'"
PW_VERSION=$(python3 -c "import playwright._impl._driver as d; print(d.compute_driver_executable())" 2>/dev/null | grep -oE '[0-9]+' | head -1)
check "Chromium browser binary present" "ls \$HOME/Library/Caches/ms-playwright/ 2>/dev/null | grep -q chromium"

echo ""
echo "=== MITRE cache freshness ==="
CACHE_FILE="archer/data/cache/enterprise-attack.json"
if [ -f "$CACHE_FILE" ]; then
    AGE_DAYS=$(( ( $(date +%s) - $(stat -f %m "$CACHE_FILE" 2>/dev/null || stat -c %Y "$CACHE_FILE") ) / 86400 ))
    if [ "$AGE_DAYS" -gt 90 ]; then
        echo "⚠ MITRE cache is $AGE_DAYS days old — consider: bash scripts/refresh-mitre-cache.sh"
    else
        echo "✓ MITRE cache is $AGE_DAYS days old (fresh enough)"
        PASS=$((PASS+1))
    fi
else
    echo "✕ MITRE cache file not found"
    FAIL=$((FAIL+1))
fi

echo ""
echo "=== Local server ==="
check "Archer server responding on :8000" "curl -sf -o /dev/null http://127.0.0.1:8000/health"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "Environment looks healthy." || echo "Fix the ✕ items above before running the full test suite."

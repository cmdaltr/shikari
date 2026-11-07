#!/bin/bash
# =============================================================================
# Shikari Comprehensive Test Runner
# =============================================================================
#
# Runs all test categories and generates documented output.
#
# Usage:
#   ./tests/run_all_tests.sh                    # Run all tests
#   ./tests/run_all_tests.sh --api-only         # API tests only
#   ./tests/run_all_tests.sh --ui-only          # UI tests only
#   ./tests/run_all_tests.sh --unit-only        # Unit tests only
#   ./tests/run_all_tests.sh --headed           # UI tests with visible browser
#   ./tests/run_all_tests.sh --report           # Generate HTML report
#
# Prerequisites:
#   - Shikari must be running: uvicorn shikari.app:app --host 0.0.0.0 --port 32453
#   - pip install pytest requests pytest-playwright pytest-html
#   - playwright install chromium
#
# Environment variables:
#   SHIKARI_BASE_URL    Base URL (default: http://127.0.0.1:32453)
#   SHIKARI_TEST_EMAIL  Login email
#   SHIKARI_TEST_PASSWORD  Login password
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="$SCRIPT_DIR/reports"
LOG_DIR="$SCRIPT_DIR/logs"
SCREENSHOT_DIR="$SCRIPT_DIR/screenshots"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Parse arguments
API_ONLY=false
UI_ONLY=false
UNIT_ONLY=false
HEADED=""
REPORT=false
FEATURE_TESTS=""

for arg in "$@"; do
    case $arg in
        --api-only)     API_ONLY=true ;;
        --ui-only)      UI_ONLY=true ;;
        --unit-only)    UNIT_ONLY=true ;;
        --headed)       HEADED="--headed" ;;
        --report)       REPORT=true ;;
        --features)     FEATURE_TESTS="--run-feature-tests" ;;
    esac
done

# Create output dirs
mkdir -p "$REPORT_DIR" "$LOG_DIR" "$SCREENSHOT_DIR"

# Colours
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  Shikari Comprehensive Test Suite${NC}"
echo -e "${BLUE}  $(date)${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""

# Check Shikari is running
SHIKARI_URL="${SHIKARI_BASE_URL:-http://127.0.0.1:32453}"
echo -n "Checking Shikari at $SHIKARI_URL... "
if curl -s -o /dev/null -w "%{http_code}" "$SHIKARI_URL/health" | grep -q "200"; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "Shikari is not running. Start with: uvicorn shikari.app:app --host 0.0.0.0 --port 32453"
    exit 1
fi
echo ""

# Report flag
REPORT_FLAG=""
if $REPORT; then
    REPORT_FLAG="--html=$REPORT_DIR/test_report_${TIMESTAMP}.html --self-contained-html"
fi

OVERALL_EXIT=0

# =========================================================================
# 1. Unit Tests
# =========================================================================
if ! $API_ONLY && ! $UI_ONLY; then
    echo -e "${YELLOW}━━━ Unit Tests ━━━${NC}"
    pytest "$SCRIPT_DIR/unit/" -v --tb=short $REPORT_FLAG 2>&1 | tee "$LOG_DIR/unit_${TIMESTAMP}.log" || OVERALL_EXIT=1
    echo ""
fi

# =========================================================================
# 2. Integration Tests (TestClient, no running server needed)
# =========================================================================
if ! $API_ONLY && ! $UI_ONLY && ! $UNIT_ONLY; then
    echo -e "${YELLOW}━━━ Integration Tests ━━━${NC}"
    pytest "$SCRIPT_DIR/integration/" -v --tb=short 2>&1 | tee "$LOG_DIR/integration_${TIMESTAMP}.log" || OVERALL_EXIT=1
    echo ""
fi

# =========================================================================
# 3. API Tests (requires running Shikari)
# =========================================================================
if ! $UI_ONLY && ! $UNIT_ONLY; then
    echo -e "${YELLOW}━━━ API Tests ━━━${NC}"
    pytest "$SCRIPT_DIR/api/" -v --tb=short --shikari-url="$SHIKARI_URL" 2>&1 | tee "$LOG_DIR/api_${TIMESTAMP}.log" || OVERALL_EXIT=1
    echo ""
fi

# =========================================================================
# 4. Input Method Tests (requires running Shikari)
# =========================================================================
if ! $UI_ONLY && ! $UNIT_ONLY; then
    echo -e "${YELLOW}━━━ Input Method Tests ━━━${NC}"
    pytest "$SCRIPT_DIR/inputs/" -v --tb=short --shikari-url="$SHIKARI_URL" 2>&1 | tee "$LOG_DIR/inputs_${TIMESTAMP}.log" || OVERALL_EXIT=1
    echo ""
fi

# =========================================================================
# 5. Security Tests
# =========================================================================
if ! $API_ONLY && ! $UI_ONLY && ! $UNIT_ONLY; then
    echo -e "${YELLOW}━━━ Security Tests ━━━${NC}"
    pytest "$SCRIPT_DIR/security/" -v --tb=short --shikari-url="$SHIKARI_URL" 2>&1 | tee "$LOG_DIR/security_${TIMESTAMP}.log" || OVERALL_EXIT=1
    echo ""
fi

# =========================================================================
# 6. UI Tests (Playwright, requires running Shikari)
# =========================================================================
if ! $API_ONLY && ! $UNIT_ONLY; then
    echo -e "${YELLOW}━━━ UI Tests (Playwright) ━━━${NC}"
    pytest "$SCRIPT_DIR/ui/" -v --tb=short $HEADED 2>&1 | tee "$LOG_DIR/ui_${TIMESTAMP}.log" || OVERALL_EXIT=1
    echo ""
fi

# =========================================================================
# 7. Feature Tests (end-to-end generation, slow)
# =========================================================================
if [ -n "$FEATURE_TESTS" ]; then
    echo -e "${YELLOW}━━━ Feature Tests (End-to-End Generation) ━━━${NC}"
    pytest "$SCRIPT_DIR/features/" -v --tb=short --run-feature-tests --shikari-url="$SHIKARI_URL" 2>&1 | tee "$LOG_DIR/features_${TIMESTAMP}.log" || OVERALL_EXIT=1
    echo ""
fi

# =========================================================================
# 8. Standalone Runner
# =========================================================================
if ! $UI_ONLY && ! $UNIT_ONLY && ! $API_ONLY; then
    echo -e "${YELLOW}━━━ Standalone Test Runner ━━━${NC}"
    python "$SCRIPT_DIR/run_test.py" --json 2>&1 | tee "$LOG_DIR/standalone_${TIMESTAMP}.log" || OVERALL_EXIT=1
    echo ""
fi

# =========================================================================
# Summary
# =========================================================================
echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  Test Run Complete${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""
echo "Logs:        $LOG_DIR/"
echo "Screenshots: $SCREENSHOT_DIR/"
if $REPORT; then
    echo "HTML Report: $REPORT_DIR/test_report_${TIMESTAMP}.html"
fi
echo ""

if [ $OVERALL_EXIT -eq 0 ]; then
    echo -e "${GREEN}All test suites passed.${NC}"
else
    echo -e "${RED}Some tests failed. Check logs above.${NC}"
fi

exit $OVERALL_EXIT

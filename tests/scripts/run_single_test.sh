#!/bin/bash
# Run a single Shikari feature test
#
# Usage:
#   ./run_single_test.sh <test_name>
#   ./run_single_test.sh apt29_basic
#   ./run_single_test.sh cve_log4shell --no-wait
#
# Use --list to see available tests:
#   ./run_single_test.sh --list

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 is required${NC}"
    exit 1
fi

# Handle special flags
if [ "$1" == "--list" ] || [ "$1" == "-l" ]; then
    python3 "${SCRIPT_DIR}/run_test.py" --list "${@:2}"
    exit $?
fi

if [ "$1" == "--status" ] || [ "$1" == "-s" ]; then
    python3 "${SCRIPT_DIR}/run_test.py" --status
    exit $?
fi

if [ "$1" == "--help" ] || [ "$1" == "-h" ] || [ -z "$1" ]; then
    echo "Usage: $0 <test_name> [options]"
    echo ""
    echo "Options:"
    echo "  --list, -l      List all available tests"
    echo "  --status, -s    Show status of running jobs"
    echo "  --no-wait       Don't wait for completion"
    echo "  --help, -h      Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 apt29_basic"
    echo "  $0 cve_log4shell --no-wait"
    echo "  $0 --list --tag threat_group"
    echo ""
    exit 0
fi

TEST_NAME="$1"
shift

# Check if --no-wait flag is set
WAIT_FLAG="--wait"
for arg in "$@"; do
    if [ "$arg" == "--no-wait" ]; then
        WAIT_FLAG=""
    fi
done

# Check Shikari is running
SHIKARI_URL="${SHIKARI_API_URL:-http://127.0.0.1:8000}"
echo -n "Checking Shikari at ${SHIKARI_URL}... "
if curl -s "${SHIKARI_URL}/health" > /dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo -e "${YELLOW}Please start Shikari before running tests${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}Running test: ${TEST_NAME}${NC}"
echo ""

# Run the test
python3 "${SCRIPT_DIR}/run_test.py" --run "$TEST_NAME" $WAIT_FLAG

exit $?

#!/bin/bash
# Common functions for Shikari test batch scripts

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$TESTS_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log directory
LOG_DIR="${TESTS_DIR}/logs"
mkdir -p "$LOG_DIR"

print_header() {
    local batch_id="$1"
    local batch_name="$2"
    local est_time="$3"

    echo ""
    echo -e "${BLUE}======================================================================${NC}"
    echo -e "${BLUE}  BATCH ${batch_id}: ${batch_name}${NC}"
    echo -e "${BLUE}  Estimated Time: ${est_time}${NC}"
    echo -e "${BLUE}  Started: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${BLUE}======================================================================${NC}"
    echo ""
}

print_footer() {
    local batch_id="$1"
    local passed="$2"
    local failed="$3"

    echo ""
    echo -e "${BLUE}======================================================================${NC}"
    echo -e "${BLUE}  BATCH ${batch_id} COMPLETE${NC}"
    echo -e "${GREEN}  Passed: ${passed}${NC}"
    if [ "$failed" -gt 0 ]; then
        echo -e "${RED}  Failed: ${failed}${NC}"
    else
        echo -e "${GREEN}  Failed: ${failed}${NC}"
    fi
    echo -e "${BLUE}  Finished: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${BLUE}======================================================================${NC}"
    echo ""
}

check_shikari_running() {
    local url="${SHIKARI_API_URL:-http://127.0.0.1:32453}"

    echo -n "Checking if Shikari is running at ${url}... "
    if curl -s "${url}/health" > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        echo "Please start Shikari before running tests"
        return 1
    fi
}

run_test() {
    local test_name="$1"
    local wait_flag="${2:---wait}"

    echo -e "${YELLOW}Running test: ${test_name}${NC}"

    python3 "${TESTS_DIR}/run_test.py" --run "$test_name" $wait_flag
    return $?
}

run_batch() {
    local batch_id="$1"
    local batch_name="$2"
    local est_time="$3"
    shift 3
    local tests=("$@")

    local log_file="${LOG_DIR}/${batch_id}-$(date '+%Y%m%d-%H%M%S').log"
    local passed=0
    local failed=0

    print_header "$batch_id" "$batch_name" "$est_time"

    # Check Shikari is running
    if ! check_shikari_running; then
        exit 1
    fi

    echo ""
    echo "Tests in this batch: ${tests[*]}"
    echo "Logging to: ${log_file}"
    echo ""

    for test_name in "${tests[@]}"; do
        echo ""
        echo "----------------------------------------"

        if run_test "$test_name" --wait 2>&1 | tee -a "$log_file"; then
            ((passed++))
        else
            ((failed++))
        fi
    done

    print_footer "$batch_id" "$passed" "$failed"

    # Return non-zero if any tests failed
    [ "$failed" -eq 0 ]
}

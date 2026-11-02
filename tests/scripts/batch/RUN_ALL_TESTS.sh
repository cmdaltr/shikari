#!/bin/bash
# Run All Shikari Feature Tests
#
# This script runs all test batches sequentially.
# Estimated total time: ~2-3 hours
#
# Usage:
#   ./RUN_ALL_TESTS.sh              # Run all batches
#   ./RUN_ALL_TESTS.sh --quick      # Run only quick tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/batch_common.sh"

# Parse arguments
QUICK_MODE=false
for arg in "$@"; do
    if [ "$arg" == "--quick" ]; then
        QUICK_MODE=true
    fi
done

echo ""
echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}  SHIKARI COMPLETE TEST SUITE${NC}"
echo -e "${BLUE}  Started: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
if [ "$QUICK_MODE" = true ]; then
    echo -e "${YELLOW}  Mode: QUICK (skipping slow tests)${NC}"
fi
echo -e "${BLUE}======================================================================${NC}"
echo ""

# Check Shikari is running
if ! check_shikari_running; then
    exit 1
fi

TOTAL_PASSED=0
TOTAL_FAILED=0
FAILED_BATCHES=()

# Run batches
run_batch_and_track() {
    local batch_script="$1"
    local batch_name="$(basename "$batch_script" .sh)"

    echo ""
    echo -e "${YELLOW}Starting batch: ${batch_name}${NC}"

    if bash "$batch_script"; then
        echo -e "${GREEN}Batch ${batch_name} completed successfully${NC}"
    else
        echo -e "${RED}Batch ${batch_name} had failures${NC}"
        FAILED_BATCHES+=("$batch_name")
    fi
}

# Quick tests
run_batch_and_track "${SCRIPT_DIR}/1a_threat_groups_quick.sh"
run_batch_and_track "${SCRIPT_DIR}/2a_cve_tests.sh"
run_batch_and_track "${SCRIPT_DIR}/4a_techniques.sh"
run_batch_and_track "${SCRIPT_DIR}/5a_profiles.sh"
run_batch_and_track "${SCRIPT_DIR}/6a_export_documents.sh"
run_batch_and_track "${SCRIPT_DIR}/6b_export_data.sh"
run_batch_and_track "${SCRIPT_DIR}/6c_export_yara.sh"

# Full tests (skip in quick mode)
if [ "$QUICK_MODE" = false ]; then
    run_batch_and_track "${SCRIPT_DIR}/1b_threat_groups_full.sh"
    run_batch_and_track "${SCRIPT_DIR}/3a_blog_analysis.sh"
    run_batch_and_track "${SCRIPT_DIR}/3b_blog_crowdstrike.sh"
    run_batch_and_track "${SCRIPT_DIR}/3c_blog_ncsc.sh"
    run_batch_and_track "${SCRIPT_DIR}/3d_blog_cybereason.sh"
fi

# Final summary
echo ""
echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}  COMPLETE TEST SUITE FINISHED${NC}"
echo -e "${BLUE}  Finished: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""

if [ ${#FAILED_BATCHES[@]} -eq 0 ]; then
    echo -e "${GREEN}All batches passed!${NC}"
    exit 0
else
    echo -e "${RED}Failed batches:${NC}"
    for batch in "${FAILED_BATCHES[@]}"; do
        echo -e "${RED}  - ${batch}${NC}"
    done
    exit 1
fi

#!/bin/bash
# Batch 1b: Full Threat Group Tests
#
# Tests all threat group detection generation including correlation.
# These are longer-running tests.

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "1b" "Threat Groups (Full)" "~45 minutes" \
    "apt29_with_correlation" \
    "lazarus_group" \
    "salt_typhoon" \
    "wizard_spider" \
    "fin7_with_correlation"

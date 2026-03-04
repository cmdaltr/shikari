#!/bin/bash
# Batch 1a: Quick Threat Group Tests
#
# Tests basic threat group detection generation for common APT groups.
# These are fast tests without correlation.

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "1a" "Threat Groups (Quick)" "~20 minutes" \
    "apt29_basic" \
    "apt28_basic" \
    "scattered_spider"

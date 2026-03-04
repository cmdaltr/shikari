#!/bin/bash
# Batch 3a: Blog Analysis Tests - DFIR Report
#
# Tests threat intelligence blog analysis from The DFIR Report.
# These are live URL tests that fetch and analyze real blog posts.

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "3a" "Blog Analysis - DFIR Report" "~25 minutes" \
    "blog_dfir_lynx" \
    "blog_dfir_lunar_spider" \
    "blog_dfir_bumblebee_akira" \
    "blog_dfir_blacksuit" \
    "blog_dfir_trigona"

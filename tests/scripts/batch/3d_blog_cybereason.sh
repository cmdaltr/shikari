#!/bin/bash
# Batch 3d: Blog Analysis Tests - Cybereason
#
# Tests threat intelligence blog analysis from Cybereason.
# These are live URL tests that fetch and analyze real blog posts.

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "3d" "Blog Analysis - Cybereason" "~20 minutes" \
    "blog_cybereason_cuckoobees" \
    "blog_cybereason_deadringer" \
    "blog_cybereason_prometei" \
    "blog_cybereason_soft_cell"

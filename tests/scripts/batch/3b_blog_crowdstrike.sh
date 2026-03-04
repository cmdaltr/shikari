#!/bin/bash
# Batch 3b: Blog Analysis Tests - CrowdStrike
#
# Tests threat intelligence blog analysis from CrowdStrike.
# These are live URL tests that fetch and analyze real blog posts.

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "3b" "Blog Analysis - CrowdStrike" "~20 minutes" \
    "blog_crowdstrike_scattered_spider_byovd" \
    "blog_crowdstrike_telecom_bpo" \
    "blog_crowdstrike_owassrf" \
    "blog_crowdstrike_overwatch_2024"

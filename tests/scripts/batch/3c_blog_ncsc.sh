#!/bin/bash
# Batch 3c: Blog Analysis Tests - NCSC UK
#
# Tests threat intelligence blog analysis from UK NCSC.
# These are live URL tests that fetch and analyze real blog posts.

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "3c" "Blog Analysis - NCSC UK" "~15 minutes" \
    "blog_ncsc_russian_state" \
    "blog_ncsc_sandworm" \
    "blog_ncsc_apt29_covid"

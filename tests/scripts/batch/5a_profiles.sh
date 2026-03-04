#!/bin/bash
# Batch 5a: Company Profile Tests
#
# Tests company threat profile generation.

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "5a" "Company Profiles" "~10 minutes" \
    "profile_sans" \
    "profile_splunk" \
    "profile_crowdstrike"

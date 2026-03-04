#!/bin/bash
# Batch 4a: Technique Hunting Tests
#
# Tests individual MITRE ATT&CK technique detection generation.

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "4a" "Technique Hunting" "~15 minutes" \
    "technique_powershell" \
    "technique_spearphishing" \
    "technique_valid_accounts" \
    "technique_lsass" \
    "technique_process_injection"

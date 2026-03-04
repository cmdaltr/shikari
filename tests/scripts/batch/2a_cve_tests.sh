#!/bin/bash
# Batch 2a: CVE Detection Tests
#
# Tests CVE-based detection generation for well-known vulnerabilities.

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "2a" "CVE Detections" "~20 minutes" \
    "cve_http2_rapid_reset" \
    "cve_panos_injection" \
    "cve_citrix_bleed" \
    "cve_log4shell" \
    "cve_confluence_rce"

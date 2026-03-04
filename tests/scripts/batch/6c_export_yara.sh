#!/bin/bash
# Batch 6c: Export Tests - YARA Rules
#
# Tests exporting detections as YARA rules.

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "6c" "Export - YARA Rules" "~10 minutes" \
    "export_apt29_yara" \
    "export_lazarus_yara" \
    "export_fin7_yara"

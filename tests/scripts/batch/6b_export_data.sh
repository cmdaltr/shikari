#!/bin/bash
# Batch 6b: Export Tests - Data Formats
#
# Tests exporting detections to data formats (JSON, CSV, XLSX).

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "6b" "Export - Data Formats" "~10 minutes" \
    "export_apt29_json" \
    "export_apt29_csv" \
    "export_apt29_xlsx"

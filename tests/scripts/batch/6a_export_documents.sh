#!/bin/bash
# Batch 6a: Export Tests - Document Formats
#
# Tests exporting detections to document formats (PDF, DOCX, MD, TXT).

source "$(dirname "${BASH_SOURCE[0]}")/batch_common.sh"

run_batch "6a" "Export - Documents" "~15 minutes" \
    "export_apt29_pdf" \
    "export_apt29_docx" \
    "export_apt29_md" \
    "export_apt29_txt"

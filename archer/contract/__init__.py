"""Archer output contract: schema, validator, legacy lint, LLM pipeline hook and prompt material.

Dependency-light (stdlib, PyYAML, jsonschema). See archer/contract/docs/ for the rubric, schema,
checklist and rationale, and archer/contract/exemplars/ for the few-shot anchors.
"""
from .validator import (CONTRACT_VERSION, Report, validate_text, validate_file, lint_query,
                        detect_siem, is_contract_document)
from .legacy import gate_query, lint_legacy_file, strict_mode
from .pipeline import handle_contract_response
from .prompt import contract_prompt_block, contract_mode

__all__ = ["CONTRACT_VERSION", "Report", "validate_text", "validate_file", "lint_query", "detect_siem",
           "is_contract_document", "gate_query", "lint_legacy_file", "strict_mode",
           "handle_contract_response", "contract_prompt_block", "contract_mode"]

# archer.contract — output contract v1.0

The strict output contract for generated detections, with its validator, a query-level lint for
the legacy YAML corpus, the LLM pipeline hook and the prompt material (checklist, schema, exemplars).

| Path | Purpose |
|---|---|
| `schema.json` | JSON Schema (draft 2020-12) for `archer_output` documents |
| `validator.py` | `validate_text` / `validate_file` (full contract), `lint_query` (query-level only) |
| `legacy.py` | `gate_query` used by `build/yaml.py` and `build/detections.py` on every write |
| `pipeline.py` | `handle_contract_response`: validates and persists LLM contract documents |
| `prompt.py` | `contract_prompt_block`: checklist + schema + exemplars for the LLM prompt |
| `exemplars/` | Nine validated few-shot anchors (five YARA-L rules, two KQL rules, two rejections) |
| `docs/` | Diagnosis, rubric, schema, checklist and rationale |

## Environment switches

| Variable | Default | Effect |
|---|---|---|
| `ARCHER_CONTRACT_STRICT` | `0` | `1`: a legacy write whose query has lint findings is refused instead of warned |
| `ARCHER_CONTRACT_MODE` | `0` | `1`: `build_llm_prompt` appends the contract block; the model is expected to emit `archer_output` |
| `ARCHER_CONTRACT_SIEM` | `yara_l` | Syntax requested in the contract block (`yara_l` or `kql`) |
| `ARCHER_CONTRACT_TYPE` | `scheduled_detection` | Detection type requested in the contract block |

Contract documents from the LLM are written under `data/groups/contract/` (`rejections/` and `failed/`
subfolders for the other two outcomes). A failed or rejected document produces no legacy YAML.

## CLI

```bash
python -m archer.contract validate archer/contract/exemplars/*.yaml
python -m archer.contract lint data/groups            # exit 1 on findings
python -m archer.contract report data/generate        # per-gate summary of the legacy corpus
python -m archer.contract prompt --siem kql --type hunt
```

## Tests

```bash
pytest tests/unit/test_contract_validator.py -q
```

The tests load the package by path and need only PyYAML and jsonschema. They cover the nine
exemplars, 22 mutations taken from the fidelity workbook's Low rows, the legacy lint against the
Q037/Q042/Q044/Q048 patterns, the strict-mode gate, the pipeline round trip and the prompt block.

# Adding a New SIEM to Archer

This checklist covers every layer a SIEM integration touches, based on the
existing MDE/Splunk/Elastic implementations. Not every SIEM needs every
layer (e.g. Docker-based live testing may not be feasible for all vendors),
but each should be a deliberate decision, not an oversight.

## 1. Query Generator (required)
Create `archer/build/<vendor>.py` with a `<Vendor>QueryGenerator` class.
Reference: `archer/build/elastic.py`, `archer/build/chronicle.py`.
Must implement: `generate_query()`, `validate_query()`, `format_query_for_display()`.

## 2. Schema mapping (required)
Add `bespoke/mappings/schemas/schema<Vendor>.json` — field mappings the
generator uses to translate MITRE technique data into vendor-specific syntax.

## 3. Register in the generation pipeline (required)
- `archer/build/detections.py`: add to `ALL_SIEMS` frozenset, add display
  name, add to `merge_detections()` signature and query counting.
- `archer/build/yaml.py`: add the generation call block (import, instantiate,
  generate, validate, format — follow the existing Elastic block as a template).

## 4. CLI support (required)
- `archer/cli/modules/generate.py`: add to the `--siem` help text.
- `archer/cli/preview.py`: add to `VALID_SIEMS`.

## 5. Web UI/API (required)
In `archer/app.py`, search for every existing `"elastic"` reference as a
guide (or `"splunk"`/`"mde"` if Elastic has been removed by the time you
read this) — covers: exclude-vendor form field, vendor icon, vendor display
name, vendor ordering for results/correlations, filename vendor detection.

## 6. Database
`archer/database/models.py` — update the `platform` column comments (no
code change needed, these are documentation-only).

## 7. OSINT enrichment (optional but recommended)
If the vendor has a public detection-rules GitHub repo:
- `archer/build/osint_repos.py`: add repo URL/path to `REPOS` dict.
- `archer/build/osint_index.py`: add an `_index_<vendor>()` function,
  register in the index dispatch dict.
- `archer/build/osint_comparison.py`: add `search_<vendor>_rules()` and
  wire into the comparison aggregation.

## 8. Importer (optional)
If existing vendor-native rules should be importable into Archer's format:
`archer/importers/<vendor>_importer.py` — implement a `<Vendor>Importer`
class, register in `archer/importers/__init__.py`.

## 9. AI-assisted generation (optional but recommended)
- `archer/ai/genai/engine.py`: add vendor detection logic (filename/keyword
  matching to infer vendor from context).
- `archer/ai/genai/query_examples.py`: add an empty/seed entry for the vendor.
- `archer/ai/genai/query_prompt_enhancer.py`: map vendor to its schema filename.

## 10. Validation & live testing (optional, higher effort)
Only pursue if you want Archer to actually execute generated queries
against a real instance for validation:
- `archer/validation/query_syntax_validator.py`: add syntax-checking rules.
- `archer/validation/query_validator.py`: add a `_validate_<vendor>()` method.
- `archer/validation/field_validator.py`: add field-name validation.
- `archer/validation/detection_refiner.py`: add vendor-specific refinement rules.
- `archer/validation/docker_manager.py`: add a Docker container definition
  (image, credentials, ingest/query methods) if live testing via a
  containerized instance is wanted.
- `archer/validation/event_generator.py`: add synthetic event generation
  in the vendor's native log format, for feeding the Docker test instance.
- `archer/validation/orchestrator.py`: add to `supported_vendors`.

## 11. Dependencies
Check `requirements.txt` for any vendor-specific client libraries needed
(e.g. an official Python SDK for the SIEM's API).

## 12. Tests (required)
`tests/test_<vendor>_generator.py` — mirror the structure of
`tests/test_chronicle_generator.py` or `tests/test_splunk_client.py`.

## 13. Documentation
Update any docs referencing the list of supported SIEMs (search
`docs/ -ri "splunk\|elastic\|chronicle\|mde"` to find them).

---

## Finding what to update for a specific vendor
This exact checklist was derived by running:
```bash
grep -rln -i "<vendor>" --include="*.py" . | grep -v __pycache__ | grep -v .venv
```
Run the same command with an existing vendor's name (e.g. `splunk`) to get
a live, accurate reference list — this doc may drift from the codebase
over time, the grep command won't.

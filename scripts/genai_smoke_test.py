"""
Smoke test for local GenAI integration.

Usage:
  # heuristic fallback
  python3 scripts/genai_smoke_test.py

  # local-llm mode (requires LLAMA_MODEL_PATH and llama-cpp-python)
  export GENAI_MODE=local_llm
  export LLAMA_MODEL_PATH=/Users/you/models/ggml-7b-q4_0.bin
  python3 scripts/genai_smoke_test.py

The script reads YAMLs from data/samples, runs gorgon.genai.generate_correlations
and writes data/correlations/smoke_test.json. If LLAMA_MODEL_PATH isn't set or
llama-cpp-python isn't installed, the heuristic generator will be used.
"""

import os
import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = ROOT / "data" / "samples"
OUT_DIR = ROOT / "data" / "correlations"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Make project importable when running the script directly (no package install required)
sys.path.insert(0, str(ROOT))

try:
    from gorgon.genai import generate_correlations
except Exception as e:
    # Print the raw error and helpful diagnostics so users can see which interpreter
    # is running and whether bs4 is available in that interpreter.
    print("Failed to import gorgon.genai:", e)
    print("Python executable:", sys.executable)
    # Common cause: 'python3' is aliased to a global interpreter even when venv prompt
    # shows activated. Show an exact pip install command for this interpreter.
    try:
        import bs4  # type: ignore

        print("bs4 imports successfully in this interpreter.")
        print(
            "If gorgon.genai still fails to import, try running:\n  {0} -c \"import importlib; importlib.import_module('gorgon.genai')\"".format(
                sys.executable
            )
        )
    except Exception:
        print(
            "bs4 does not import in this interpreter. Install it into this venv with:\n  {0} -m pip install beautifulsoup4".format(
                sys.executable
            )
        )
    print(
        "If your shell aliases 'python3' to a global interpreter, run the script with the venv python directly, e.g.:\n  {0} scripts/genai_smoke_test.py\nOr activate the venv so its python is first on PATH.".format(
            sys.executable
        )
    )
    sys.exit(1)


def main():
    group = "smoke_test"
    yaml_dir = str(SAMPLE_DIR)
    model_path = os.environ.get("LLAMA_MODEL_PATH")
    mode = os.environ.get("GENAI_MODE", "heuristic")
    print(f"GENAI_MODE={mode}, LLAMA_MODEL_PATH={model_path}")

    # Call generate_correlations; the function will detect local-llm if enabled
    try:
        results = generate_correlations(group, yaml_dir)
        out_path = OUT_DIR / f"{group}.json"
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print("Wrote", out_path)
        print(
            "Results summary: vendor_correlations=",
            len(results.get("vendor_correlations", [])),
            "cross=",
            len(results.get("cross_vendor_correlations", [])),
        )
    except Exception as e:
        print("Error running generate_correlations:", e)
        sys.exit(2)


if __name__ == "__main__":
    main()

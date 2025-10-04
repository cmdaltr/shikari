Local Llama/llama.cpp setup (Mac M2)

This document explains how to run a local, quantized ggml model with llama.cpp
and the python binding `llama-cpp-python` on macOS (Apple Silicon / M1/M2).

Overview
- Recommended model: quantized GGML 7B (q4_0 or q4_1) for Mac M2 (16GB).
- The repo contains a smoke test script `scripts/genai_smoke_test.py` that will
  call the local model when `LLAMA_MODEL_PATH` is set. The script is safe: if
  the env var is not set, it will fall back to the repo's heuristic generator.

Prerequisites
- Homebrew installed
- Command-line tools (Xcode command line tools)

Install system deps
```bash
brew install cmake libomp
```

Install Python deps
```bash
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install llama-cpp-python
# optional: install transformers if you plan to try transformers-based local models
# python3 -m pip install transformers
```

Obtain a GGML quantized model
- Download a ggml quantized 7B model (for example: ggml-7b-q4_0.bin) from a
  trusted source (Hugging Face community repo or TheBloke conversions). Respect
  model licensing (Llama 2 models require agreeing to the model license).
- Place the model binary somewhere on disk, e.g. `~/models/ggml-7b-q4_0.bin`.

Set environment variables and run the smoke test
```bash
export GENAI_MODE=local_llm
export LLAMA_MODEL_PATH=/Users/you/models/ggml-7b-q4_0.bin
python3 scripts/genai_smoke_test.py
```

What the smoke test does
- If `LLAMA_MODEL_PATH` is set and `llama-cpp-python` is available, the script
  will load the model, run a small prompt across `data/samples/` and
  produce `data/correlations/smoke_test.json`.
- If the model or binding are not available, the script will run the heuristic
  fallback (no external deps) and write the same `data/correlations/smoke_test.json`.

Troubleshooting
- If you hit memory errors, try a smaller quantized model or close other apps.
- If `llama-cpp-python` installation fails, ensure you have cmake and libomp
  installed and try again. On macOS, you may need to set architecture flags.

Notes
- This approach keeps everything local and offline. If you later want to
  experiment with external APIs, the repo genai module supports adding an
  OpenAI/Anthropic adapter.

If you'd like, I can also add a small shell script to download a recommended
community-converted ggml 7B model and place it in `~/models` (I won't add the
large model binary to the repo). Please confirm if you'd like that.

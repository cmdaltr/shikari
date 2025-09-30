"""
Lightweight GenAI stub for generating correlation suggestions.

This module intentionally avoids external AI providers and instead provides
heuristic-based synthesis from generated YAMLs. It is pluggable and can be
replaced with a true GenAI integration later (e.g., OpenAI, local LLM, n8n).
"""

import os
import json
from typing import List, Dict
from .build.progress import write_progress

# Optional local-LLM support. We attempt to import known local backends but
# degrade gracefully to the heuristic generator if none are available.
_HAS_LLAMA = False
_HAS_TRANSFORMERS = False
try:
    import llama_cpp  # type: ignore

    _HAS_LLAMA = True
except Exception:
    _HAS_LLAMA = False

try:
    import transformers  # type: ignore

    _HAS_TRANSFORMERS = True
except Exception:
    _HAS_TRANSFORMERS = False


def _list_yaml_files(group_name: str, yaml_dir: str) -> List[str]:
    if not os.path.isdir(yaml_dir):
        return []
    return [
        os.path.join(yaml_dir, f)
        for f in os.listdir(yaml_dir)
        if f.endswith(".yaml") or f.endswith(".yml")
    ]


def _parse_yaml_for_vendor(path: str) -> Dict:
    # Very small heuristic: look for a top-level 'vendor' field or 'platform'
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except Exception:
        return {}
    vendor = None
    for line in text.splitlines():
        if line.lower().startswith("vendor:"):
            vendor = line.split(":", 1)[1].strip()
            break
        if line.lower().startswith("platform:"):
            vendor = line.split(":", 1)[1].strip()
            break
    # fallback: try filename hints
    if not vendor:
        name = os.path.basename(path).lower()
        if "splunk" in name:
            vendor = "splunk"
        elif "mde" in name or "microsoft" in name:
            vendor = "mde"
        elif "ecs" in name or "prisma" in name:
            vendor = "prisma"
    return {"path": path, "vendor": vendor}


def generate_correlations(
    group_name: str, yaml_dir: str, progress_prefix: str = "genai"
) -> Dict:
    """
    Scan YAMLs and produce two result sets:
    - vendor_correlations: list of dicts where multiple queries from same vendor are paired
    - cross_vendor_correlations: list of dicts correlating results across vendors

    Progress updates are written using `write_progress` with keys under the
    provided `group_name` progress JSON.
    """
    files = _list_yaml_files(group_name, yaml_dir)
    write_progress(
        group_name,
        {"status": "genai_started", "total_files": len(files), "processed": 0},
    )

    # If configured to use a local model, attempt it and gracefully fallback
    mode = os.environ.get("GENAI_MODE", "heuristic").lower()
    if mode == "local_llm" and (_HAS_LLAMA or _HAS_TRANSFORMERS):
        try:
            results = _generate_with_local_llm(group_name, files)
            write_progress(
                group_name,
                {
                    "status": "genai_complete",
                    "vendor_count": len(results.get("vendor_correlations", [])),
                    "cross_count": len(results.get("cross_vendor_correlations", [])),
                },
            )
            return results
        except Exception:
            # fall through to heuristic
            pass

    parsed = [_parse_yaml_for_vendor(p) for p in files]
    by_vendor = {}
    for p in parsed:
        v = p.get("vendor") or "unknown"
        by_vendor.setdefault(v, []).append(p["path"])

    vendor_corr = []
    # vendor correlations: pair files within same vendor
    for v, paths in by_vendor.items():
        if len(paths) < 2:
            continue
        # simple pairwise combinations
        for i in range(len(paths)):
            for j in range(i + 1, len(paths)):
                vendor_corr.append({"vendor": v, "a": paths[i], "b": paths[j]})

    # cross-vendor correlations: take top N from each vendor and cross correlate
    cross_corr = []
    vendors = [k for k in by_vendor.keys() if k != "unknown"]
    if len(vendors) >= 2:
        # pair first vendor with each of the others for a simple cross correlation
        base = vendors[0]
        for other in vendors[1:]:
            a = by_vendor[base][0]
            b = by_vendor[other][0]
            cross_corr.append({"a_vendor": base, "b_vendor": other, "a": a, "b": b})

    # write results to data/correlations/<group_name>.json
    out_dir = os.path.join("data", "correlations")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{group_name}.json")
    results = {
        "vendor_correlations": vendor_corr,
        "cross_vendor_correlations": cross_corr,
    }
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
    except Exception:
        pass

    # final progress update
    write_progress(
        group_name,
        {
            "status": "genai_complete",
            "vendor_count": len(vendor_corr),
            "cross_count": len(cross_corr),
        },
    )
    return results


def _generate_with_local_llm(group_name: str, files: List[str]) -> Dict:
    """
    Very small local-LLM driver. Uses llama_cpp or transformers if available.
    The prompt is a simple instruction to summarize YAMLs and suggest correlations.
    This is a best-effort fallback and should be tuned for your local model.
    """
    texts = []
    for p in files:
        try:
            with open(p, "r", encoding="utf-8") as fh:
                texts.append((p, fh.read()[:4096]))
        except Exception:
            texts.append((p, ""))

    prompt = """
You are a tool that examines detection YAMLs and suggests correlation pairs.
For each file, identify a vendor/platform if present, then produce two lists:
- vendor_correlations: pairs of files from the same vendor that should be correlated
- cross_vendor_correlations: pairs across vendors to check for combined activity
Represent results as JSON with keys vendor_correlations and cross_vendor_correlations.
"""

    # Basic single-shot prompt construction (concatenate filenames + snippets)
    body = prompt + "\nFiles:\n"
    for p, t in texts:
        body += f"--- {p}\n{t}\n"

    # llama_cpp path
    if _HAS_LLAMA:
        try:
            # Keep import local to avoid top-level import issues
            from llama_cpp import Llama  # type: ignore

            model_path = os.environ.get("LLAMA_MODEL_PATH")
            if not model_path:
                raise RuntimeError("LLAMA_MODEL_PATH not set")
            llm = Llama(model_path=model_path)
            resp = llm.create_completion(prompt=body, max_tokens=512)
            text = resp.get("choices", [{}])[0].get("text", "")
            return _parse_llm_json_output(text, files)
        except Exception:
            pass

    if _HAS_TRANSFORMERS:
        try:
            # Use a text-generation pipeline if available
            from transformers import pipeline  # type: ignore

            gen = pipeline(
                "text-generation", model=os.environ.get("TRANSFORMERS_MODEL", "gpt2")
            )
            out = gen(body, max_length=1024, do_sample=False)
            text = out[0].get("generated_text", "")
            return _parse_llm_json_output(text, files)
        except Exception:
            pass

    # If we get here, fallback to heuristic
    return _heuristic_fallback(files)


def _parse_llm_json_output(text: str, files: List[str]) -> Dict:
    # Try to extract JSON from LLM output
    import re

    m = re.search(r"(\{.*\})", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    # fallback
    return _heuristic_fallback(files)


def _heuristic_fallback(files: List[str]) -> Dict:
    parsed = [_parse_yaml_for_vendor(p) for p in files]
    by_vendor = {}
    for p in parsed:
        v = p.get("vendor") or "unknown"
        by_vendor.setdefault(v, []).append(p["path"])

    vendor_corr = []
    for v, paths in by_vendor.items():
        if len(paths) < 2:
            continue
        for i in range(len(paths)):
            for j in range(i + 1, len(paths)):
                vendor_corr.append({"vendor": v, "a": paths[i], "b": paths[j]})

    cross_corr = []
    vendors = [k for k in by_vendor.keys() if k != "unknown"]
    if len(vendors) >= 2:
        base = vendors[0]
        for other in vendors[1:]:
            a = by_vendor[base][0]
            b = by_vendor[other][0]
            cross_corr.append({"a_vendor": base, "b_vendor": other, "a": a, "b": b})

    results = {
        "vendor_correlations": vendor_corr,
        "cross_vendor_correlations": cross_corr,
    }
    out_dir = os.path.join("data", "correlations")
    os.makedirs(out_dir, exist_ok=True)
    # derive a filename from the first YAML or fallback to 'group'
    base = "group"
    if files:
        base = os.path.splitext(os.path.basename(files[0]))[0]
    out_path = os.path.join(out_dir, f"{base}.json")
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
    except Exception:
        pass
    return results

import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "data" / "correlate" / "smoke_test.json"
SCHEMA = ROOT / "docs" / "genai_schema.json"


def summarize(path: Path, sample=3):
    data = json.loads(path.read_text(encoding="utf-8"))
    vc = data.get("vendor_correlations", [])
    cc = data.get("cross_vendor_correlations", [])
    print(f"File: {path}")
    print(f"Vendor correlations: {len(vc)}")
    print(f"Cross-vendor correlations: {len(cc)}")
    if vc:
        print("\nExample vendor correlations:")
        for item in vc[:sample]:
            if "members" in item and isinstance(item["members"], list):
                members = " | ".join(item["members"])
                reason = item.get("reason", "")[:200]
                print(f" - MEMBERS: [{members}]  | {reason}")
            else:
                a = (
                    item.get("a")
                    or item.get("path_a")
                    or item.get("left")
                    or "<unknown a>"
                )
                b = (
                    item.get("b")
                    or item.get("path_b")
                    or item.get("right")
                    or "<unknown b>"
                )
                reason = item.get("reason", "")[:200]
                print(f" - {a}  <->  {b}  | {reason}")
    if cc:
        print("\nExample cross-vendor correlations:")
        for item in cc[:sample]:
            if "members" in item and isinstance(item["members"], list):
                members = " | ".join(item["members"])
                reason = item.get("reason", "")[:200]
                print(f" - MEMBERS: [{members}]  | {reason}")
            else:
                a = item.get("a") or item.get("left") or "<unknown a>"
                b = item.get("b") or item.get("right") or "<unknown b>"
                reason = item.get("reason", "")[:200]
                print(f" - {a}  <->  {b}  | {reason}")


def validate(path: Path):
    if not SCHEMA.exists():
        print("No schema available at", SCHEMA, "- skipping strict validation.")
        return True
    try:
        import jsonschema  # type: ignore
    except Exception:
        print(
            "jsonschema not installed; to enable strict validation run: pip install jsonschema"
        )
        return True
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(
            instance=json.loads(path.read_text(encoding="utf-8")), schema=schema
        )
        print("Validation: OK (jsonschema)")
        return True
    except Exception as e:
        print("Validation failed:", e)
        return False


if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    if not p.exists():
        print("Summary file not found:", p)
        sys.exit(2)
    ok = validate(p)
    summarize(p)
    if not ok:
        sys.exit(3)

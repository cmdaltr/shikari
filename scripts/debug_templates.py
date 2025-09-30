#!/usr/bin/env python3
import sys
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, TemplateSyntaxError

TEMPLATES_DIR = Path("templates")
env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))


def check_all():
    files = sorted([p.name for p in TEMPLATES_DIR.glob("*.html")])
    any_fail = False
    for name in files:
        try:
            env.get_template(name)
            print(f"[OK]  {name}")
        except TemplateSyntaxError as e:
            any_fail = True
            print(
                f"[ERROR] {name} - TemplateSyntaxError at line {e.lineno}: {e.message}"
            )
            with open(TEMPLATES_DIR / name) as f:
                lines = f.readlines()
            start = max(0, e.lineno - 6)
            end = min(len(lines), e.lineno + 6)
            for i in range(start, end):
                print(f"{i+1:4d}: {lines[i].rstrip()}")
            print("-" * 60)
    if any_fail:
        sys.exit(2)
    print("All templates compiled successfully.")


if __name__ == "__main__":
    if not TEMPLATES_DIR.exists():
        print("Templates directory not found:", TEMPLATES_DIR)
        sys.exit(1)
    check_all()

#!/usr/bin/env python3
"""
Fix the missing `{% for %}` in templates/manual.html by replacing the
div + stray `{% endfor %}` with a proper for-loop over tactics[0:left_slice_end].
A backup of the original file is written as .bak.
"""
from pathlib import Path
import re

p = Path("templates/manual.html")
if not p.exists():
    print("templates/manual.html not found")
    raise SystemExit(1)

text = p.read_text()

# pattern: a tactics-item div followed by whitespace and an `{% endfor %}`
pat = re.compile(
    r'(?P<div><div class="tactics-item"[^>]*>.*?{{\s*tactic\s*}}.*?</div>\s*)\n\s*{%\s*endfor\s*%}',
    re.S,
)

if not pat.search(text):
    print("Pattern not found; file may already be fixed or different. Exiting.")
    raise SystemExit(2)

replacement = (
    "{% for tactic in tactics[0:left_slice_end] %}\n"
    '                                      <div class="tactics-item" style="display:block; width:100%;"><label style="display:inline-block;"> '
    '<input type="checkbox" name="tactics" value="{{ tactic }}" style="margin-right:0.5rem; vertical-align:middle;"> {{ tactic }}</label></div>\n'
    "                                  {% endfor %}"
)

bak = p.with_suffix(".html.bak")
bak.write_text(text)
new_text = pat.sub(replacement, text, count=1)
p.write_text(new_text)
print(f"Patched {p} (backup at {bak})")

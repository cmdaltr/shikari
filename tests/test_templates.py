from pathlib import Path
import pytest
from jinja2 import Environment, FileSystemLoader, TemplateSyntaxError

TEMPLATES_DIR = Path("templates")
env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))


def test_all_templates_compile():
    files = sorted([p.name for p in TEMPLATES_DIR.glob("*.html")])
    assert files, "No templates found in templates/ directory"
    for name in files:
        try:
            env.get_template(name)
        except TemplateSyntaxError as e:
            pytest.fail(
                f"TemplateSyntaxError in {name} at line {e.lineno}: {e.message}"
            )

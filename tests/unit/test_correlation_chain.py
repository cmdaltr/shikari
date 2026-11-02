"""A correlation's technique chain names each technique once, however it was spelled or split."""
import html
import re

import shikari.app as app_module


def _chain(correlation):
    macro = app_module.templates.env.get_template("shared_macros.html").module.render_correlation_techniques
    text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", str(macro(correlation)))))
    return [re.sub(r"^\W+", "", name).strip() for name in re.split(r" [→/] ", text.strip())]


def test_a_technique_named_twice_shows_once():
    techniques = [{"name": "Multi-Factor Authentication", "tactic": "Defense Impairment"},
                  {"name": "Multi-FactorAuthentication", "tactic": "Defense Impairment"},
                  {"name": "Pass the Hash", "tactic": "Lateral Movement"},
                  {"name": "Pass the Hash", "tactic": "Lateral Movement"}]
    for merged in (True, False):
        assert _chain({"is_merged": merged, "techniques": techniques}) == ["Multi-Factor Authentication",
                                                                           "Pass the Hash"]

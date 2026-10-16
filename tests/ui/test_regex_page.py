"""
Playwright UI tests for the Regex page (Build → Regex): the flavour checks, matching, the
time limit on runaway patterns, and the per-SIEM snippets. Needs a running Archer.
"""
import pytest

pytestmark = pytest.mark.ui


def levels(page, pattern, flags="", flavour="kql"):
    return page.evaluate("([p, f, fl]) => archerRegex.checks(p, f, fl).map(x => [x.level, x.text])", [pattern, flags, flavour])


@pytest.fixture
def regex_page(page, base_url):
    page.goto(f"{base_url}/regex")
    page.wait_for_function("window.archerRegex")
    return page


class TestRegexChecks:
    def test_rejects_what_re2_cannot_do(self, regex_page):
        for pattern in (r"(?<=foo)bar", r"(\w+)\1", r"a{1,2000}"):
            assert any(l == "error" for l, _ in levels(regex_page, pattern, flavour="kql")), pattern
            assert any(l == "error" for l, _ in levels(regex_page, pattern, flavour="yaral")), pattern

    def test_pcre_accepts_them(self, regex_page):
        for pattern in (r"(?<=foo)bar", r"(\w+)\1", r"a{1,2000}"):
            assert not any(l == "error" for l, _ in levels(regex_page, pattern, flavour="spl")), pattern

    def test_windows_path_with_single_backslashes(self, regex_page):
        found = levels(regex_page, r"C:\Windows\System32\cmd.exe")
        assert any(l == "error" and "\\W" in t for l, t in found)
        assert any("unescaped ." in t for _, t in found)
        assert not any("reads as the regex escape" in t for _, t in levels(regex_page, r"C:\\Windows\\cmd\.exe", "i"))

    def test_matches_everything(self, regex_page):
        assert any(l == "error" and "empty string" in t for l, t in levels(regex_page, "foo|"))

    def test_elastic_is_whole_value(self, regex_page):
        found = levels(regex_page, r"^cmd\.exe$", flavour="elastic")
        assert any(l == "error" and "anchors" in t for l, t in found)
        assert any("whole value" in t for _, t in found)

    def test_nested_quantifier_only_warns_for_backtracking_engines(self, regex_page):
        assert any(l == "warn" and "exponential" in t for l, t in levels(regex_page, "(a+)+$", flavour="spl"))
        assert not any(l == "warn" for l, _ in levels(regex_page, "(a+)+$", flavour="kql"))


class TestRegexMatching:
    def test_matches_and_groups(self, regex_page):
        page = regex_page
        page.click('[data-flavour="kql"]')
        page.check('[data-flag="i"]')
        page.fill("#rx-pattern", r"\\(?:psexec|paexec)(?:64)?\.exe\s+\\\\(?P<host>[^\\\s]+)")
        page.fill("#rx-text", "C:\\Tools\\PsExec64.exe \\\\FS01 -s cmd.exe\nC:\\ProgramData\\paexec.exe \\\\DC02 -s")
        page.wait_for_function("document.getElementById('rx-count').textContent.startsWith('2 match')")
        assert "FS01" in page.inner_text("#rx-matches") and "host" in page.inner_text("#rx-matches")

    def test_runaway_pattern_is_stopped(self, regex_page):
        page = regex_page
        page.click('[data-flavour="spl"]')
        page.fill("#rx-pattern", "(a+)+$")
        page.fill("#rx-text", "a" * 40 + "!")
        page.wait_for_function("document.getElementById('rx-status').textContent.startsWith('Stopped')", timeout=5000)


class TestRegexSnippets:
    def test_escaping_per_siem(self, regex_page):
        s = dict(regex_page.evaluate(r"""archerRegex.snippets('\\\\psexec\\.exe "x"', 'i')"""))
        assert s["Defender XDR (KQL)"].endswith('@"(?i)\\\\psexec\\.exe ""x"""')
        assert s["Google SecOps (YARA-L)"].endswith("`) nocase")
        assert '\\\\\\\\psexec' in s["Splunk (SPL)"] and '\\"x\\"' in s["Splunk (SPL)"]
        assert ' regex~ "' in s["Elastic (EQL)"]  # ends in a quote, so not a triple-quoted string

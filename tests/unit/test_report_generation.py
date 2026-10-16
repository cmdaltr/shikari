"""
Upload/blog generation: a report's techniques become detections, its IOCs one sweep.

Upload had never produced a detection. It handed process_group a dict where a
list of {tactic, techniques} was expected, and a report attributed to an ATT&CK
alias (UNC3944) sent process_group down the group path, where the exact-name
lookup found 0 procedures. The report's 43 techniques were ignored.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from archer.build import orchestrator
from archer.build.ioc_sweep import clean_report_iocs, mde_sweep, secops_sweep, write_ioc_sweeps
from archer.mitre.retrieve import retrieve_group
from archer.parsers.blog_analyzer import _drop_citation_links

SPIDER = {"type": "intrusion-set", "id": "intrusion-set--spider", "name": "Scattered Spider",
          "aliases": ["Scattered Spider", "Roasted 0ktapus", "UNC3944"]}


def test_retrieve_group_matches_exact_aliases_only():
    bundle = SimpleNamespace(objects=[SPIDER])
    assert retrieve_group(bundle, "unc3944") == "intrusion-set--spider"
    assert retrieve_group(bundle, "Scattered Spider") == "intrusion-set--spider"
    assert retrieve_group(bundle, "UNC394") is None  # substring of an alias is not a match


def test_supplied_techniques_win_over_a_known_group_name():
    manual = [{"tactic": "Discovery", "techniques": [
        {"technique": "T1018", "name": "Remote System Discovery", "activity_desc": "Spider ran net view",
         "op_guidance": {"cmd": ["net view"]}, "red_tool": {}, "detect_guidance": ""}]}]
    seen = []
    with patch.object(orchestrator, "get_stix_data", return_value=MagicMock(objects=[])), \
         patch.object(orchestrator, "obtain_technique_descriptions", return_value=[]), \
         patch.object(orchestrator, "check_group_in_mitre", return_value="Y"), \
         patch.object(orchestrator, "load_indicator_mappings"), \
         patch.object(orchestrator, "retrieve_procedures") as group_path, \
         patch.object(orchestrator, "compile_query", side_effect=lambda d, **k: seen.append(dict(d))), \
         patch.object(orchestrator, "safe_progress_update"):
        orchestrator.process_group("UNC3944", manual_data=manual)

    group_path.assert_not_called()
    assert [(d["technique_id"], d["technique"], d["activity_desc"]) for d in seen] == [
        ("T1018", "Remote System Discovery", "Spider ran net view")]


def test_report_iocs_are_refanged_validated_and_patterned():
    clean = clean_report_iocs({
        "domain": ["fleetdeck[.]io", "targetsname-sso[.]com", "oktalogin-targetcompany[.]com", "not a domain"],
        "ip": ["10.0.0.5", "45.153.240[.]1"],
        "hash": ["44d88612fea8a8f36de82e1278abb02f", "d41d8cd98f00b204e9800998ecf8427e", "xyz"],
        "file": ["//www.trellix.com/page.html", "C:\\Users\\Public\\rclone.exe"],
    })
    assert clean["domain"] == ["fleetdeck.io"]
    assert clean["domain_pattern"] == [r"[a-z0-9-]+-sso\.com", r"oktalogin-[a-z0-9-]+\.com"]
    assert clean["ip"] == ["45.153.240.1"]  # private 10.0.0.5 dropped
    assert clean["md5"] == ["44d88612fea8a8f36de82e1278abb02f"]  # the empty file's hash is known good
    assert clean["file"] == ["C:\\Users\\Public\\rclone.exe"]

    kql = mde_sweep(clean)
    assert 'RemoteUrl has_any (ioc_domain)' in kql and 'RemoteIP in (ioc_ip)' in kql
    assert r'matches regex @"(?i)(^|[./])[a-z0-9-]+-sso\.com($|[/:])"' in kql
    assert "MD5 in (ioc_md5)" in kql and kql.startswith("let ioc_domain")
    rule = secops_sweep(clean, "UNC3944")
    assert rule.startswith("rule archer_ioc_sweep_unc3944 {")
    assert r"re.regex($e.network.dns.questions.name, `(^|\.)fleetdeck\.io$`) nocase" in rule
    assert '$e.target.ip = "45.153.240.1"' in rule
    events = rule.split("events:")[1].split("outcome:")[0].split("condition:")[0]
    assert len([l for l in events.splitlines() if l.strip()]) == 1  # alternatives on one line


def test_citation_links_are_not_iocs():
    text = ("The actors used fleetdeck[.]io for remote access. "
            "References: https://www.trellix.com/en-us/research/spider.html "
            "and https://www.malwarebytes.com/blog. Contact level.io support.")
    iocs = {"domain": ["fleetdeck[.]io", "www[.]trellix[.]com", "www[.]malwarebytes[.]com", "level[.]io"],
            "file": ["//www.trellix.com/en-us/research/spider.html"],
            "cmd": ["to discover targets for lateral movement across the whole estate", "net view"]}
    out = _drop_citation_links(iocs, text)
    # Defanged in the text, or mentioned outside a URL: kept. Only ever a link host: dropped.
    assert out["domain"] == ["fleetdeck[.]io", "level[.]io"]
    assert out["file"] == []
    assert out["cmd"] == ["net view"]


def test_sweep_yaml_parses(tmp_path):
    import yaml
    paths = write_ioc_sweeps("APT: Spider", {"domain": ["fleetdeck[.]io"]}, "report.pdf", str(tmp_path))
    assert len(paths) == 2
    for p in paths:
        doc = yaml.safe_load(open(p))
        assert doc["name"] == "IOC Sweep - APT - Spider"

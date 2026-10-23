"""Anatomy workflow: actor, tools, CVEs and services down to objectives, each link marked detected or not."""

import csv
import json
import re

from archer.visualization import anatomy

HEADER = ["group_sw_id", "group_sw_name", "technique_id", "technique_name", "tactic", "platforms", "framework",
          "procedure_example", "evidence", "detectable_via"]


def _csv(tmp_path, rows):
    path = tmp_path / "procedures.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(HEADER)
        for tid, name, tactic, text in rows:
            w.writerow(["G9999", "Test Spider", tid, name, tactic, "Windows", "Enterprise", text, "{}", ""])
    return str(path)


ROWS = [
    ("T1102.002", "Bidirectional Communication", "Command and Control",
     "[Software: Empire] [Empire](https://attack.mitre.org/software/S0363) can use Dropbox for C2."),
    ("T1567.002", "Exfiltration to Cloud Storage", "Exfiltration", "Test Spider has exfiltrated data to MEGA and Dropbox."),
    ("T1190", "Exploit Public-Facing Application", "Initial Access", "Test Spider exploited CVE-2021-44228 in VMware Horizon."),
    ("T1003.001", "LSASS Memory", "Credential Access", "[Software: Mimikatz] Mimikatz dumps LSASS."),
    ("T1003.006", "DCSync", "Credential Access", "[Software: Mimikatz] Mimikatz performs DCSync."),
    ("T1566.004", "Spearphishing Voice", "Initial Access", "[Campaign: C0027] During C0027 the group called the help desk."),
]


def _cards(view):
    return {c["id"]: c for c in view["nodes"]}


def _items(card):
    return {sec["title"]: sec["items"] for sec in card["sections"]}


def test_a_groups_anatomy_branches_in_and_out_of_its_toolkit(tmp_path):
    view = anatomy.build_group("test spider", {"T1567", "T1003.001"}, _csv(tmp_path, ROWS))
    cards = _cards(view)
    assert list(cards) == ["actor", "way:Exploit", "way:Phishing", "runs", "does", "service:Code and storage"]
    assert cards["way:Exploit"]["sections"][0]["items"] == ["CVE-2021-44228"]
    assert cards["way:Phishing"]["sub"] == "Lures"  # phished, nothing named
    assert _items(cards["runs"]) == {"Offensive frameworks": ["Empire"], "Credential stealers": ["Mimikatz"]}
    assert _items(cards["does"]) == {"Steals logins": ["Mimikatz"], "Takes data out": ["by hand"]}
    assert " · ".join(l["text"] for l in cards["does"]["lines"][1:]) == "Steals logins · Takes data out"
    assert cards["service:Code and storage"]["sections"][0]["items"] == ["Dropbox", "MEGA"]
    assert _items(cards["actor"]) == {"Campaigns": ["C0027"]}
    assert [(e["source"], e["target"]) for e in view["edges"]] == [
        ("actor", "way:Exploit"), ("actor", "way:Phishing"), ("way:Exploit", "runs"), ("way:Phishing", "runs"),
        ("runs", "does"), ("does", "service:Code and storage")]
    # The fan into the toolkit is labelled once; no technique IDs anywhere a viewer reads
    assert [e["label"] for e in view["edges"] if e["target"] == "runs"].count("Runs") == 1
    shown = json.dumps([[c["title"], c["sub"], c["sections"], c["lines"]] for c in view["nodes"]] +
                       [e["label"] for e in view["edges"]])
    assert not re.search(r"T\d{4}", shown)


def test_a_step_is_detected_when_most_of_it_is(tmp_path):
    view = anatomy.build_group("test spider", {"T1567", "T1003.001"}, _csv(tmp_path, ROWS))
    steps = {e["target"]: e for e in view["edges"]}
    assert steps["service:Code and storage"]["state"] == "gap"  # C2 over Dropbox undetected, exfiltration detected
    assert (steps["runs"]["detected"], steps["runs"]["total"]) == (1, 3)
    assert (steps["does"]["detected"], steps["does"]["total"]) == (2, 3)  # LSASS and exfiltration, not DCSync
    assert view["stats"]["links"] == 5  # the fan into the toolkit counts once
    view = anatomy.build_group("test spider", {"T1567", "T1102", "T1003", "T1190", "T1566"}, _csv(tmp_path, ROWS))
    assert all(e["state"] == "detected" for e in view["edges"])


def test_a_service_they_get_in_through_is_not_repeated_where_they_go(tmp_path):
    rows = ROWS + [("T1078.004", "Cloud Accounts", "Initial Access", "Test Spider signed in to AWS."),
                   ("T1530", "Data from Cloud Storage", "Collection", "Test Spider stole data from AWS S3 buckets.")]
    cards = _cards(anatomy.build_group("test spider", set(), _csv(tmp_path, rows)))
    assert cards["way:Credentials"]["sections"][0]["items"] == ["AWS"]
    assert "service:Cloud" not in cards


def test_tools_are_grouped_by_what_they_are():
    assert anatomy.tool_group("Cobalt Strike", ["T1003.001"]) == "Offensive frameworks"
    assert anatomy.tool_group("Vidar", ["T1105"]) == "Credential stealers"
    assert anatomy.tool_group("China Chopper", []) == "Web shells"
    assert anatomy.tool_group("BlackCat", ["T1486"]) == "Ransomware"
    assert anatomy.tool_group("certutil", ["T1105"]) == "Built-in tools"
    assert anatomy.tool_group("PlugX", ["T1071.001", "T1055"]) == "Backdoors and RATs"


def _chain(n):
    chain = anatomy._Chain()
    for i in range(n):
        chain.card(f"c{i}", "software", f"Node {i}")
        if i:
            chain.link(f"c{i - 1}", f"c{i}", "Then")
    return anatomy._finish(chain, "cve")["nodes"]


def test_a_chain_runs_along_one_line_and_snakes_back_when_long():
    six = _chain(6)
    assert max(n["y"] for n in six) - min(n["y"] for n in six) < 40
    assert [n["x"] for n in six] == sorted(n["x"] for n in six)
    eight = _chain(8)
    assert eight[5]["y"] > eight[4]["y"] + 60 and eight[5]["x"] > eight[7]["x"]  # the second line comes back
    for a in eight:
        for b in eight:
            if a is not b:
                assert abs(a["x"] - b["x"]) >= 150 or abs(a["y"] - b["y"]) >= 80


def test_under_a_node_one_short_line_per_group():
    card = {"title": "Runs", "sub": "", "sections": [
        {"title": "Credential stealers", "items": ["LaZagne", "Raccoon Stealer", "Vidar", "Mimikatz"], "brief": True},
        {"title": "Ransomware", "items": ["BlackCat"], "brief": True}]}
    lines = [l["text"] for l in anatomy._lines(card, 30)]
    assert lines[0] == "Runs" and lines[2] == "Ransomware: BlackCat"
    assert lines[1].startswith("Stealers: LaZagne") and re.search(r" \+\d$", lines[1]) and len(lines[1]) <= 33


def test_no_procedures_no_anatomy(tmp_path):
    assert anatomy.build_group("Nobody", set(), _csv(tmp_path, ROWS)) is None


def test_a_cves_anatomy_from_its_research(tmp_path, monkeypatch):
    research = {
        "cve_id": "CVE-2026-109618", "exploit_name": "PHP2Shell", "techniques": ["T1190"],
        "nvd_data": {"description": "PHP ... remote code execution (RCE).", "product": "php", "vendor": "php",
                     "cpes": ["cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"], "cvss_v3": {"score": 9.8}},
        "pocs": [{"type": "github", "source": "ikow/php2shell-poc", "stars": 10}],
        "exploit": {"indicators": {}}, "reference_iocs": {"iocs": {"ip": ["203.0.113[.]5", "203.0.113.5"]}},
    }
    (tmp_path / "CVE-2026-109618.json").write_text(json.dumps(research))
    monkeypatch.setattr(anatomy, "_groups_exploiting", lambda cve, *a: [])
    files = ["CVE-2026-109618_PHP2Shell_RuntimeShell_KQL.yaml", "CVE-2026-109618_PHP2Shell_IOCSweep_KQL.yaml"]
    view = anatomy.build_cve("CVE-2026-109618", files, set(), cache_dir=str(tmp_path))
    cards = _cards(view)
    c = "CVE-2026-109618:"
    assert [k.split(":")[1] for k in cards] == ["actor", "exploit", "cve", "worker", "shell", "infra"]
    assert cards[c + "cve"]["sub"] == "PHP · CVSS 9.8" and cards[c + "exploit"]["title"] == "PHP2Shell"
    assert _items(cards[c + "infra"]) == {"IPs": ["203.0.113.5"]}
    steps = {e["target"]: e for e in view["edges"]}
    assert steps[c + "cve"]["state"] == "gap"  # no exploit-request detection
    assert steps[c + "worker"]["covered_by"] == ["Runtime shell detection"]
    assert steps[c + "infra"]["state"] == "detected"  # the IOC sweep
    assert anatomy.build_cve("CVE-2026-1", [], set(), cache_dir=str(tmp_path)) is None

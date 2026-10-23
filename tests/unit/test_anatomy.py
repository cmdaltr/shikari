"""Anatomy workflow: actor, tools, CVEs and services down to objectives, each link marked detected or not."""

import csv
import json

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


def test_a_groups_anatomy_links_tools_services_cves_and_objectives(tmp_path):
    view = anatomy.build_group("test spider", {"T1567", "T1003.001"}, _csv(tmp_path, ROWS))
    nodes = {n["id"]: n for n in view["nodes"]}
    assert {"actor", "software:Empire", "software:Mimikatz", "service:Dropbox", "service:MEGA", "cve:CVE-2021-44228",
            "campaign:C0027", "objective:Credential Access"} <= set(nodes)
    edges = {(e["source"], e["target"]): e for e in view["edges"]}
    # Empire's C2 over Dropbox: no detection for T1102; the group's exfiltration to Dropbox is (T1567 parent)
    assert edges[("software:Empire", "service:Dropbox")]["roles"] == ["C2"]
    assert edges[("software:Empire", "service:Dropbox")]["state"] == "gap"
    assert edges[("actor", "service:Dropbox")]["state"] == "detected"
    assert edges[("actor", "cve:CVE-2021-44228")]["roles"] == ["Exploit"]
    # Credentials hangs off the actor and names the tool that does it; one of its two techniques is detected
    cred = nodes["objective:Credential Access"]
    assert cred["sub"] == "2 techniques · Mimikatz"
    assert edges[("actor", "objective:Credential Access")]["state"] == "detected"
    assert view["stats"]["links"] == view["stats"]["detected"] + view["stats"]["gaps"]


def test_layout_keeps_the_actor_alone_in_the_middle_and_nodes_apart(tmp_path):
    view = anatomy.build_group("test spider", set(), _csv(tmp_path, ROWS))
    nodes = {n["id"]: n for n in view["nodes"]}
    middle = [n for n in view["nodes"] if n["x"] == nodes["actor"]["x"]]
    assert {n["kind"] for n in middle} == {"actor", "campaign"}
    assert max(n["y"] for n in middle if n["kind"] == "campaign") < nodes["actor"]["y"]
    spots = [(n["x"], n["y"]) for n in view["nodes"]]
    assert len(spots) == len(set(spots))
    assert all(n["y"] > nodes["actor"]["y"] for n in view["nodes"] if n["col"] == "band")


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
    nodes = {n["id"]: n for n in view["nodes"]}
    assert nodes["cve:CVE-2026-109618"]["sub"] == "PHP2Shell · PHP · CVSS 9.8"
    assert nodes["exploit:CVE-2026-109618"]["label"] == "PHP2Shell"
    assert [n["label"] for n in view["nodes"] if n["kind"] == "ioc"] == ["203.0.113.5"]
    edges = {(e["source"], e["target"]): e for e in view["edges"]}
    assert edges[("exploit:CVE-2026-109618", "cve:CVE-2026-109618")]["state"] == "gap"  # no exploit-request detection
    worker = next(n["id"] for n in view["nodes"] if n["kind"] == "process")
    assert edges[("cve:CVE-2026-109618", worker)]["state"] == "detected"  # the runtime shell detection
    assert edges[("shell:CVE-2026-109618", "ioc:203.0.113.5")]["state"] == "detected"  # the IOC sweep
    assert anatomy.build_cve("CVE-2026-1", [], set(), cache_dir=str(tmp_path)) is None

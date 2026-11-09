"""Technology stack (#21): group hunts leave out what can't happen in the organisation's estate."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from shikari.build import orchestrator, run_files
from shikari.intelligence import feed
from shikari.intelligence import tech_stack as stack

ATTACK_PLATFORMS = {"Windows", "macOS", "Linux", "ESXi", "IaaS", "Network Devices", "PRE", "Office Suite",
                    "SaaS", "Identity Provider", "Containers"}


def test_catalogue_uses_attack_platform_names():
    products = stack.catalogue()["products"]
    assert len(products) > 50
    for pid, p in products.items():
        assert p["platforms"] and set(p["platforms"]) <= ATTACK_PLATFORMS, pid
        assert p["category"] in stack.catalogue()["categories"], pid


def test_products_named():
    assert stack.products_named("APT29 trojanised the SolarWinds Orion update") == ["solarwinds"]
    assert "fortinet" in stack.products_named("exploited CVE-2018-13379 in FortiOS SSL VPN")
    # Capitalised aliases are names: "orion" in prose isn't SolarWinds
    assert stack.products_named("the orion constellation") == []
    assert stack.products_named("ran kubectl get secrets") == ["kubernetes"]


def test_platforms():
    assert not stack.platform_applies(["ESXi"], ["windows", "m365"])
    assert stack.platform_applies(["Office Suite", "Windows"], ["m365"])
    assert stack.platform_applies(["PRE"], ["windows"])  # Reconnaissance applies to everyone
    assert stack.platform_applies(["ESXi"], [])  # no stack: everything applies


def test_procedures_naming_products():
    windows_m365 = ["windows", "m365", "active_directory"]
    assert not stack.text_applies("compromised the SolarWinds Orion build", windows_m365)
    assert stack.text_applies("used net view to list hosts", windows_m365)
    # Any product the stack has keeps it
    assert stack.text_applies("exploited Citrix, Pulse Secure and FortiOS", ["windows", "fortinet"])
    assert stack.text_applies("searched Exchange Online mailboxes", windows_m365)
    # The attacker's own infrastructure says nothing about the victim's stack
    assert stack.text_applies("established GitHub accounts to host malware", windows_m365)
    assert stack.text_applies("exfiltrated data to Google Drive", windows_m365)
    assert stack.text_applies("installed AnyDesk for remote access", windows_m365)
    assert stack.off_stack("harvested vCenter service accounts", windows_m365) == ["VMware vCenter"]


def test_cpes():
    assert stack.cpe_products(["cpe:2.3:a:solarwinds:orion_platform:2020.2:*:*:*:*:*:*:*"]) == ["solarwinds"]
    assert stack.cpe_products(["cpe:2.3:o:fortinet:fortios:7.0.0:*:*:*:*:*:*:*"]) == ["fortinet"]
    assert stack.cpe_products(["cpe:2.3:a:example:unknown_thing:1:*:*:*:*:*:*:*"]) == []


def test_company_profile_takes_only_what_it_observed():
    profile = {"threat_profile": {
        "tech_stack": {"web_server": "nginx", "technologies": ["AWS", "Google Cloud", "WordPress"]},
        "supply_chain": {"email_providers": ["Microsoft 365"]}}}
    assert stack.from_profile(profile) == ["m365", "nginx", "wordpress"]
    profile["threat_profile"]["tech_stack"].update(web_server="Tesco Web Server", web_server_custom_banner=True)
    assert "nginx" not in stack.from_profile(profile)


def _proc(tid, desc, platforms):
    return (tid, tid, ["Execution"], desc, {"cmd": ["x"]}, {}, [[""]], platforms, {}, "", platforms)


def test_group_hunt_leaves_out_what_the_stack_cannot_have():
    procedures = [_proc("T1059", "ran cmd.exe", ["Windows"]),
                  _proc("T1675", "ran esxcli", ["ESXi"]),
                  _proc("T1195.002", "trojanised the SolarWinds Orion update", ["Windows"])]
    compiled, outcomes, keep = [], [], {}

    def retrieve(bundle, techniques, keep_desc=None):
        keep["fn"] = keep_desc
        return procedures

    with patch.object(orchestrator, "get_stix_data", return_value=MagicMock(objects=[])), \
         patch.object(orchestrator, "obtain_technique_descriptions", return_value=[]), \
         patch.object(orchestrator, "check_group_in_mitre", return_value="Y"), \
         patch.object(orchestrator, "load_indicator_mappings"), \
         patch("shikari.build.queries.platform_mappings"), \
         patch.object(orchestrator, "retrieve_group"), patch.object(orchestrator, "retrieve_techniques"), \
         patch.object(orchestrator, "retrieve_procedures", side_effect=retrieve), \
         patch.object(orchestrator, "compile_query", side_effect=lambda d, **k: compiled.append(d["technique_id"])), \
         patch.object(orchestrator.run_files, "outcome", side_effect=lambda *a: outcomes.append((a[1], a[4]))), \
         patch.object(orchestrator, "safe_progress_update"):
        orchestrator.process_group("APT29", tech_stack=["windows", "m365"])

    assert compiled == ["T1059"]
    assert ("T1675", "stack_platform") in outcomes and ("T1195.002", "stack_product") in outcomes
    # Other groups' procedures are filtered the same way before they become evidence
    assert keep["fn"]("used SolarWinds Serv-U") is False and keep["fn"]("used whoami") is True


def test_explicit_hunt_warns_and_generates(tmp_path):
    manual = [{"tactic": "Lateral Movement", "techniques": [
        {"technique": "T1021.007", "name": "Cloud Services", "activity_desc": "used Okta to reach vCenter"}]}]
    seen = []
    bundle = SimpleNamespace(objects=[{"type": "attack-pattern", "external_references": [{"external_id": "T1021.007"}],
                                       "x_mitre_platforms": ["IaaS", "SaaS"]}])
    with patch.object(run_files, "RUNS_DIR", str(tmp_path)), \
         patch.object(orchestrator, "get_stix_data", return_value=bundle), \
         patch.object(orchestrator, "obtain_technique_descriptions", return_value=[]), \
         patch.object(orchestrator, "check_group_in_mitre", return_value="N"), \
         patch.object(orchestrator, "load_indicator_mappings"), \
         patch("shikari.build.queries.platform_mappings"), \
         patch.object(orchestrator, "compile_query", side_effect=lambda d, **k: seen.append(d["technique_id"])), \
         patch.object(orchestrator, "safe_progress_update"):
        run_files.begin("Report_x")
        orchestrator.process_group("Report_x", manual_data=manual, tech_stack=["windows"])
        run_files.finish("Report_x")
        warnings = json.load(open(tmp_path / "Report_x.json"))["stack_warnings"]
    assert seen == ["T1021.007"]
    assert any("IaaS, SaaS" in w for w in warnings)
    assert any("Okta" in w and "VMware vCenter" in w for w in warnings)


def test_feed_relevance_follows_the_stack():
    now = datetime.now(timezone.utc).isoformat()
    base = {"published": now, "version": feed.ANALYSIS_VERSION, "techniques": ["T1190"], "industries": {},
            "opportunistic": ["reported exploitation"], "financial": [], "groups": [], "actors": []}
    posts = {"a": {**base, "url": "a", "title": "MOVEit Transfer exploited", "products": ["moveit"]},
             "b": {**base, "url": "b", "title": "FortiGate zero-day", "products": ["fortinet"]},
             "c": {**base, "url": "c", "title": "Infostealer on GitHub", "products": ["github"]}}
    with patch.object(feed, "_load", return_value={"posts": posts}):
        out = {p["url"]: p for p in feed.view([], stack=["windows", "fortinet"])["posts"]}
        everything = {p["url"]: p for p in feed.view([])["posts"]}
    assert out["a"]["relevant"] is False and out["a"]["off_stack"] == ["Progress MOVEit"]
    assert out["b"]["relevant"] is True and out["b"]["stack"] == ["Fortinet"]
    assert out["c"]["relevant"] is True  # GitHub as the attacker's host
    assert all(p["relevant"] for p in everything.values())


def test_citations_and_links_are_not_targets():
    text = ("[Scattered Spider](https://attack.mitre.org/groups/G1015) has deployed [BlackCat](https://attack.mitre.org/"
            "software/S1068).(Citation: Check Point Scattered Spider JUL 2025)(Citation: Mandiant VMware vSphere JUL 2025)")
    assert stack.products_named(text) == []


def test_a_campaign_name_is_not_its_target():
    during = ("During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack."
              "mitre.org/groups/G0016) cleared event logs with `wevtutil`.")
    assert stack.text_applies(during, ["windows"])
    # SUNBURST runs inside Orion: its behaviour is SolarWinds-specific
    assert not stack.text_applies("[SUNBURST](https://attack.mitre.org/software/S0559) removed proxy values", ["windows"])

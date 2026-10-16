"""
SecOps rule quality: event types, indicator hygiene, regex escaping, valid YAML.

Found in the Scattered Spider run: port/protocol/service conditions ANDed onto a
PROCESS_LAUNCH event (can never match), ATT&CK prose captured as command
indicators, registry paths used as unescaped regexes (\\S = non-whitespace), and a
detection file that wasn't valid YAML because its description wrapped mid-path.
"""
import re

import pytest
import yaml

from archer.build.indicator_hygiene import clean_indicator
from archer.build.secops import SecOpsGenerator

PROSE = [
    ").(Citation: SSH Authorized Keys) Users may edit the system's SSH config file to modify the directive",
    "to ensure public key and RSA authentication are enabled, as well as modify the directive",
    "files to identify regex patterns to dump cleartext passwords from the browser's process memory.",
    ". The proc filesystem is a pseudo-filesystem used as an interface to kernel data structures",
    "file shows how memory is mapped within the process's virtual address space. And",
]
REAL = [
    ".vmdk",
    "dscl . list /Users | grep -v '_'",
    'netsh wlan show profile "Wi-Fi name" key=clear',
    "sudo -u gdm gsettings set org.gnome.login-screen disable-user-list true",
    "wmic process call create",
    "Add-MailboxPermission",
]


@pytest.mark.parametrize("value", PROSE)
def test_prose_is_rejected(value):
    assert clean_indicator(value) is None


@pytest.mark.parametrize("value", REAL)
def test_real_indicators_survive(value):
    assert clean_indicator(value) == value


def test_entities_and_placeholders():
    assert clean_indicator("&lt;user-home&gt;/.ssh/authorized_keys") == "/.ssh/authorized_keys"
    assert clean_indicator("`whoami /all`") == "whoami /all"


def _rule(indicators, name="Test Technique", tid="T1000", tactics=None):
    return SecOpsGenerator().generate_yaral_rule(tid, name, "x", "d", indicators, tactics=tactics)


def _events(code):
    return code.split("events:")[1].split("outcome:")[0].split("condition:")[0]


def _outcome(code):
    return code.split("outcome:")[1].split("condition:")[0]


def test_network_context_never_lands_on_a_process_event():
    r = _rule({"cmd": ["mstsc.exe /v:"], "protocol": ["RDP"], "port": ["3389"], "service": ["termsrv"]})
    events = _events(r["yaral_code"])
    assert r["event_types"] == ["PROCESS_LAUNCH"]
    assert "application_protocol" not in events and "target.port" not in events and "target.application" not in events
    assert 'context_protocols = "RDP"' in r["yaral_code"] and 'context_ports = "3389"' in r["yaral_code"]


def test_network_only_indicators_build_a_network_rule():
    r = _rule({"protocol": ["SSH", "kerberos", "GOPHERISH"], "port": ["22"]})
    events = _events(r["yaral_code"])
    assert r["event_types"] == ["NETWORK_CONNECTION"]
    assert '$e.network.application_protocol = "SSH"' in events and '"KRB5"' in events
    assert "GOPHERISH" not in events  # not a UDM protocol enum value
    assert "$e.target.port = 22" in events


def test_registry_paths_are_escaped_and_matched_on_registry_events():
    key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages"
    r = _rule({"cmd": [key]})
    events = _events(r["yaral_code"])
    assert set(r["event_types"]) == {"PROCESS_LAUNCH", "REGISTRY_CREATION", "REGISTRY_MODIFICATION"}
    assert r"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security\s+Packages" in events
    assert "$e.target.registry.registry_key" in events
    # One line of alternatives: separate lines in events would be ANDed
    assert len([l for l in events.splitlines() if l.strip()]) == 1


def test_every_pattern_is_a_literal():
    r = _rule({"cmd": ["rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full"]})
    pattern = re.search(r"`([^`]*)`", r["yaral_code"]).group(1)
    assert pattern == r"rundll32\.exe\s+C:\\Windows\\System32\\comsvcs\.dll,\s+MiniDump\s+624\s+C:\\temp\\l\.dmp\s+full"
    assert re.search(pattern, "rundll32.exe  C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full")


def test_a_placeholder_matches_what_stood_there():
    # "(PID)" is documentation: the event has the number
    r = _rule({"cmd": ["rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (PID) out.dmp full"]})
    pattern = re.search(r"`([^`]*)`", r["yaral_code"]).group(1)
    assert "PID" not in pattern and ".*?" in pattern
    assert re.search(pattern, "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 out.dmp full")


def test_meta_severity_matches_returned_severity():
    r = _rule({"cmd": ["mimikatz"]}, name="OS Credential Dumping", tactics=["Credential Access"])
    assert r["severity"] == "HIGH" and 'severity = "HIGH"' in r["yaral_code"]


def test_severity_comes_from_the_tactic_not_the_name():
    # "Credential" in the name used to make it HIGH whatever the stage
    assert _rule({"cmd": ["dir"]}, name="Credential Discovery", tactics=["Discovery"])["severity"] == "LOW"
    assert _rule({"cmd": ["vssadmin delete shadows"]}, tactics=["Impact"])["severity"] == "CRITICAL"
    # Several tactics: the most severe
    assert _rule({"cmd": ["x.exe"]}, tactics=["Execution", "Lateral Movement"])["severity"] == "HIGH"


def test_outcome_carries_risk_and_entities_without_aggregation():
    r = _rule({"cmd": ["procdump -ma lsass.exe"]}, tactics=["Credential Access"])
    out = _outcome(r["yaral_code"])
    assert "$risk_score = 75" in out
    assert "$hostname = $e.principal.hostname" in out and "$command_line = $e.target.process.command_line" in out
    # Single event, no aggregation: no match section (contract R06.2)
    assert "match:" not in r["yaral_code"] and not re.search(r"\b(array_distinct|count|max|min|sum)\(", out)
    # Repeated UDM fields can't be assigned without match
    assert "target.ip" not in out and "dns.questions" not in out


def test_network_rule_outcome_names_the_target():
    out = _outcome(_rule({"protocol": ["SSH"], "port": ["22"]})["yaral_code"])
    assert "$target_host = $e.target.hostname" in out and "$target_port = $e.target.port" in out
    assert "command_line" not in out


def test_wrapped_description_still_writes_valid_yaml(tmp_path, monkeypatch):
    from archer.build import yaml as yaml_writer

    monkeypatch.chdir(yaml_writer.os.path.dirname(yaml_writer.__file__) + "/../..")
    out = tmp_path / "SystemdService_GoogleSecOps.yaml"
    desc = ("[Scattered Spider](https://attack.mitre.org/groups/G1015) has run `SYSTEMD_UNIT_PATH=\"/lib/systemd/\n"
            "system/teleport.service` to establish persistence.")
    yaml_writer.write_yaml(str(out), "Systemd Service", "T1543.002", desc, "GoogleSecOps",
                           ["Persistence"], "Scattered Spider", _rule({"cmd": ["systemctl enable"]})["yaral_code"],
                           datatype="PROCESS_LAUNCH")

    data = yaml.safe_load(out.read_text())
    assert data["technique_id"] == "T1543.002"
    assert "system/teleport.service" in data["description"]


def test_rule_names_are_lowercase_snake_case():
    from archer.build.secops import build_correlation_rule
    from archer.validation.static_check import check_query

    r = _rule({"cmd": ["procdump -ma lsass.exe"]}, tid="T1003.001", tactics=["Credential Access"])
    assert r["yaral_code"].startswith("rule archer_t1003_001 {") and r["rule_name"] == "archer_t1003_001"
    assert "YL-1" not in [f.get("check") for f in check_query(r["yaral_code"], "secops")["findings"]]
    other = _rule({"cmd": ["psexec.exe"]}, tid="T1570", tactics=["Lateral Movement"])
    corr = build_correlation_rule(r["yaral_code"], other["yaral_code"])
    assert re.match(r"rule [a-z][a-z0-9_]* \{", corr)

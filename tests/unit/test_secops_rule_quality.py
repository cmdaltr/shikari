"""
SecOps query quality (UDM searches): event types, indicator hygiene, regex escaping, valid YAML.

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
    return SecOpsGenerator().generate_query(tid, name, "x", "d", indicators, tactics=tactics)


def _expr(query):
    """The search expression, without its header comment."""
    return "\n".join(l for l in query.splitlines() if not l.startswith("//"))


def _pattern(query):
    """The first /regex/ literal, unescaped back to RE2."""
    return re.search(r"= /((?:\\.|[^/\\])*)/", query).group(1).replace(r"\/", "/")


def test_network_context_never_lands_on_a_process_event():
    r = _rule({"cmd": ["mstsc.exe /v:"], "protocol": ["RDP"], "port": ["3389"], "service": ["termsrv"]})
    expr = _expr(r["query"])
    assert r["event_types"] == ["PROCESS_LAUNCH"]
    assert "application_protocol" not in expr and "target.port" not in expr and "target.application" not in expr


def test_network_only_indicators_build_a_network_search():
    r = _rule({"protocol": ["SSH", "kerberos", "GOPHERISH"], "port": ["22"]})
    expr = _expr(r["query"])
    assert r["event_types"] == ["NETWORK_CONNECTION"]
    assert 'network.application_protocol = "SSH"' in expr and '"KRB5"' in expr
    assert "GOPHERISH" not in expr  # not a UDM protocol enum value
    assert "target.port = 22" in expr


def test_registry_paths_are_escaped_and_matched_on_registry_events():
    key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages"
    r = _rule({"cmd": [key]})
    expr = _expr(r["query"])
    assert set(r["event_types"]) == {"PROCESS_LAUNCH", "REGISTRY_CREATION", "REGISTRY_MODIFICATION"}
    assert r"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security\s+Packages" in expr
    assert "target.registry.registry_key" in expr
    assert len([l for l in expr.splitlines() if l.strip()]) == 1


def test_every_pattern_is_a_literal():
    r = _rule({"cmd": ["rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full"]})
    pattern = _pattern(r["query"])
    assert pattern == r"rundll32\.exe\s+C:\\Windows\\System32\\comsvcs\.dll,\s+MiniDump\s+624\s+C:\\temp\\l\.dmp\s+full"
    assert re.search(pattern, "rundll32.exe  C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full")


def test_a_slash_in_an_indicator_doesnt_end_the_regex():
    r = _rule({"cmd": ["net user bob /add"]})
    assert r"\/add" in r["query"] and re.search(_pattern(r["query"]), "net user bob /add")


def test_a_placeholder_matches_what_stood_there():
    # "(PID)" is documentation: the event has the number
    r = _rule({"cmd": ["rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (PID) out.dmp full"]})
    pattern = _pattern(r["query"])
    assert "PID" not in pattern and ".*?" in pattern
    assert re.search(pattern, "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 out.dmp full")


def test_header_severity_matches_returned_severity():
    r = _rule({"cmd": ["mimikatz"]}, name="OS Credential Dumping", tactics=["Credential Access"])
    assert r["severity"] == "HIGH" and "severity HIGH" in r["query"].splitlines()[0]


def test_severity_comes_from_the_tactic_not_the_name():
    # "Credential" in the name used to make it HIGH whatever the stage
    assert _rule({"cmd": ["dir"]}, name="Credential Discovery", tactics=["Discovery"])["severity"] == "LOW"
    assert _rule({"cmd": ["vssadmin delete shadows"]}, tactics=["Impact"])["severity"] == "CRITICAL"
    # Several tactics: the most severe
    assert _rule({"cmd": ["x.exe"]}, tactics=["Execution", "Lateral Movement"])["severity"] == "HIGH"


def test_a_single_event_search_is_plain_udm():
    q = _rule({"cmd": ["procdump -ma lsass.exe"]}, tactics=["Credential Access"])["query"]
    # Bare UDM fields: no rule, event variable or rule-only sections
    assert not q.startswith("rule ") and "$e" not in q and "re.regex" not in q
    assert not re.search(r"^\s*(meta|events|match|outcome|condition):", q, re.M)
    assert 'metadata.event_type = "PROCESS_LAUNCH"' in q


def test_wrapped_description_still_writes_valid_yaml(tmp_path, monkeypatch):
    from archer.build import yaml as yaml_writer

    monkeypatch.chdir(yaml_writer.os.path.dirname(yaml_writer.__file__) + "/../..")
    out = tmp_path / "SystemdService_UDM.yaml"
    desc = ("[Scattered Spider](https://attack.mitre.org/groups/G1015) has run `SYSTEMD_UNIT_PATH=\"/lib/systemd/\n"
            "system/teleport.service` to establish persistence.")
    yaml_writer.write_yaml(str(out), "Systemd Service", "T1543.002", desc, "GoogleSecOps",
                           ["Persistence"], "Scattered Spider", _rule({"cmd": ["systemctl enable"]})["query"],
                           datatype="PROCESS_LAUNCH")

    data = yaml.safe_load(out.read_text())
    assert data["technique_id"] == "T1543.002"
    assert "system/teleport.service" in data["description"]
    assert data["query"].startswith("// archer_t1000:")


def test_search_names_are_lowercase_snake_case():
    from archer.build.udm import build_join

    r = _rule({"cmd": ["procdump -ma lsass.exe"]}, tid="T1003.001", tactics=["Credential Access"])
    assert r["query"].startswith("// archer_t1003_001:") and r["rule_name"] == "archer_t1003_001"
    other = _rule({"cmd": ["psexec.exe"]}, tid="T1570", tactics=["Lateral Movement"])
    corr = build_join(r["query"], other["query"])
    assert re.match(r"// archer_corr_t1003_001_then_t1570:", corr)

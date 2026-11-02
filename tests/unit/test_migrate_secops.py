"""SecOps YARA-L on disk becomes UDM search; a generated file stays generated, an edited one stays edited."""
import hashlib

from shikari.build import attack_mapping
from shikari.build.migrate_secops import migrate_file
from shikari.build.yaml import _STAMP, _query_block, file_state

RULE = """rule shikari_t1136 {
meta:
author = "Shikari Detection Engineering"
description = "Detects Create Account (T1136)"
mitre_attack_technique = "T1136"
severity = "MEDIUM"

events:
$e.metadata.event_type = "PROCESS_LAUNCH"
(re.regex($e.target.process.command_line, `net\\s+user\\s+\\S+\\s+/add`) nocase)

condition:
$e
}"""


def _file(tmp_path, query, edited=False):
    body = ("name: Create Account\ntechnique_id: T1136\nrequiredDataConnectors:\n  - connectorId: GoogleSecOps\n"
            "query: |\n" + "\n".join("  " + l if l else l for l in query.split("\n")) + "\nversion: 1.0.0\n")
    digest = hashlib.sha256((_query_block(body) + (" edited" if edited else "")).encode()).hexdigest()
    path = tmp_path / "CreateAccount_GoogleSecOps.yaml"
    path.write_text(f"# shikari-generator: 3 query-sha256: {digest}\n{body}")
    return path


def test_generated_rule_becomes_a_search_and_stays_generated(tmp_path):
    path = _file(tmp_path, RULE)
    assert migrate_file(str(path)) == "migrated"
    text = path.read_text()
    assert "  // shikari_t1136: Create Account · ATT&CK T1136 · severity MEDIUM" in text
    assert r"target.process.command_line = /net\s+user\s+\S+\s+\/add/ nocase" in text
    assert "rule " not in text and not file_state(str(path))["edited"]
    assert migrate_file(str(path)) == "unchanged"


def test_edited_rule_is_converted_but_still_edited(tmp_path):
    path = _file(tmp_path, RULE, edited=True)
    first = path.read_text().splitlines()[0]
    assert migrate_file(str(path)) == "migrated-edited"
    assert path.read_text().splitlines()[0] == first and file_state(str(path))["edited"]


def test_remapping_rewrites_the_search_header():
    q = "// shikari_t1136: Create Account · ATT&CK T1136 · severity MEDIUM\nmetadata.event_type = \"PROCESS_LAUNCH\""
    out = attack_mapping._retarget(q, {"technique_id": "T1136", "name": "Create Account"},
                                   {"technique_id": "T1136.001", "name": "Local Account", "rule_name": "shikari_t1136_001"}, "High")
    assert out.splitlines()[0] == "// shikari_t1136_001: Local Account · ATT&CK T1136.001 · severity HIGH"
    assert attack_mapping.rule_name(out) == "shikari_t1136_001"

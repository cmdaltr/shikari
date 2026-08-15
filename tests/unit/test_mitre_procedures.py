"""
Unit tests for archer.mitre.procedures

Covers:
- All three attribution paths (direct, via_software, via_campaign)
- Group resolution by ID, name, and alias
- CSV writing and column schema
- Cross-reference validation
- Edge cases (empty bundle, missing fields, deduplication)
"""

import csv
import json
import tempfile
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from archer.mitre.procedures import (
    FIELDNAMES,
    _attack_id,
    _clean,
    _tactics,
    _build_indexes,
    _resolve_group,
    get_group_techniques,
    get_all_procedures,
    build_procedures_csv,
    cross_reference,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_bundle(objects: list) -> dict:
    return {"type": "bundle", "id": "bundle--test", "objects": objects}


def _group(stix_id: str, attack_id: str, name: str, aliases: list = None, desc: str = "") -> dict:
    return {
        "type": "intrusion-set",
        "id": stix_id,
        "name": name,
        "aliases": aliases or [],
        "description": desc,
        "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}],
    }


def _technique(stix_id: str, attack_id: str, name: str, tactics: list = None) -> dict:
    kc = [
        {"kill_chain_name": "mitre-attack", "phase_name": t.lower().replace(" ", "-")}
        for t in (tactics or ["execution"])
    ]
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "description": f"Description for {name}",
        "kill_chain_phases": kc,
        "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}],
    }


def _tool(stix_id: str, name: str) -> dict:
    return {"type": "tool", "id": stix_id, "name": name}


def _malware(stix_id: str, name: str) -> dict:
    return {"type": "malware", "id": stix_id, "name": name}


def _campaign(stix_id: str, name: str) -> dict:
    return {"type": "campaign", "id": stix_id, "name": name}


def _rel(stix_id: str, rel_type: str, src: str, tgt: str, desc: str = "") -> dict:
    return {
        "type": "relationship",
        "id": stix_id,
        "relationship_type": rel_type,
        "source_ref": src,
        "target_ref": tgt,
        "description": desc,
    }


@pytest.fixture
def minimal_bundle():
    """Bundle with one group, one technique, one direct relationship."""
    return _make_bundle([
        _group("intrusion-set--g1", "G0001", "TestGroup", aliases=["TG", "TestAlias"]),
        _technique("attack-pattern--t1", "T1059.001", "PowerShell", ["Execution"]),
        _rel("rel--r1", "uses", "intrusion-set--g1", "attack-pattern--t1", "Used PowerShell."),
    ])


@pytest.fixture
def software_bundle():
    """Bundle demonstrating Path 2: group → tool → technique."""
    return _make_bundle([
        _group("intrusion-set--g1", "G0001", "TestGroup"),
        _tool("tool--mimikatz", "Mimikatz"),
        _technique("attack-pattern--t1", "T1003.001", "LSASS Memory", ["Credential Access"]),
        # group uses tool
        _rel("rel--r1", "uses", "intrusion-set--g1", "tool--mimikatz", "Used Mimikatz."),
        # tool uses technique
        _rel("rel--r2", "uses", "tool--mimikatz", "attack-pattern--t1", "Dumps LSASS."),
    ])


@pytest.fixture
def campaign_bundle():
    """Bundle demonstrating Path 3: campaign → group + campaign → technique."""
    return _make_bundle([
        _group("intrusion-set--g1", "G0001", "TestGroup"),
        _campaign("campaign--c1", "Operation Test"),
        _technique("attack-pattern--t1", "T1566.001", "Spearphishing Attachment", ["Initial Access"]),
        # campaign attributed to group
        _rel("rel--r1", "attributed-to", "campaign--c1", "intrusion-set--g1"),
        # campaign uses technique
        _rel("rel--r2", "uses", "campaign--c1", "attack-pattern--t1", "Sent spearphishing."),
    ])


@pytest.fixture
def all_paths_bundle():
    """Bundle with all three paths for the same group."""
    return _make_bundle([
        _group("intrusion-set--g1", "G0001", "TestGroup"),
        _technique("attack-pattern--t1", "T1059.001", "PowerShell", ["Execution"]),
        _technique("attack-pattern--t2", "T1003.001", "LSASS Memory", ["Credential Access"]),
        _technique("attack-pattern--t3", "T1566.001", "Spearphishing", ["Initial Access"]),
        _tool("tool--mimikatz", "Mimikatz"),
        _campaign("campaign--c1", "Campaign Alpha"),
        # Path 1: direct
        _rel("rel--r1", "uses", "intrusion-set--g1", "attack-pattern--t1", "Used PS."),
        # Path 2: via tool
        _rel("rel--r2", "uses", "intrusion-set--g1", "tool--mimikatz"),
        _rel("rel--r3", "uses", "tool--mimikatz", "attack-pattern--t2", "Dumps LSASS."),
        # Path 3: via campaign
        _rel("rel--r4", "attributed-to", "campaign--c1", "intrusion-set--g1"),
        _rel("rel--r5", "uses", "campaign--c1", "attack-pattern--t3", "Phishing."),
    ])


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_attack_id_extracts_id(self):
        obj = {"external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}]}
        assert _attack_id(obj) == "T1059.001"

    def test_attack_id_missing_returns_empty(self):
        assert _attack_id({}) == ""
        assert _attack_id({"external_references": []}) == ""

    def test_clean_strips_newlines(self):
        assert _clean("line1\nline2\r") == "line1 line2"

    def test_clean_none_returns_empty(self):
        assert _clean(None) == ""

    def test_tactics_extracts_phase_names(self):
        obj = {
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
                {"kill_chain_name": "other", "phase_name": "should-be-ignored"},
            ]
        }
        result = _tactics(obj)
        assert result == ["Initial Access"]
        assert "Should Be Ignored" not in result

    def test_tactics_empty_if_no_phases(self):
        assert _tactics({}) == []


# ---------------------------------------------------------------------------
# Index building
# ---------------------------------------------------------------------------

class TestBuildIndexes:
    def test_indexes_group(self, minimal_bundle):
        groups, techniques, software, campaigns = _build_indexes(minimal_bundle["objects"])
        assert "intrusion-set--g1" in groups

    def test_indexes_technique(self, minimal_bundle):
        groups, techniques, software, campaigns = _build_indexes(minimal_bundle["objects"])
        assert "attack-pattern--t1" in techniques

    def test_indexes_tool(self, software_bundle):
        groups, techniques, software, campaigns = _build_indexes(software_bundle["objects"])
        assert "tool--mimikatz" in software

    def test_indexes_malware(self):
        bundle = _make_bundle([_malware("malware--m1", "Cobalt Strike")])
        groups, techniques, software, campaigns = _build_indexes(bundle["objects"])
        assert "malware--m1" in software

    def test_indexes_campaign(self, campaign_bundle):
        groups, techniques, software, campaigns = _build_indexes(campaign_bundle["objects"])
        assert "campaign--c1" in campaigns

    def test_group_without_G_id_excluded(self):
        """Groups with non-G attack IDs (e.g. software) should not be in groups index."""
        obj = _group("intrusion-set--x", "S0001", "NotAGroup")
        groups, _, _, _ = _build_indexes([obj])
        assert "intrusion-set--x" not in groups


# ---------------------------------------------------------------------------
# Group resolution
# ---------------------------------------------------------------------------

class TestResolveGroup:
    def test_resolve_by_attack_id(self, minimal_bundle):
        groups, _, _, _ = _build_indexes(minimal_bundle["objects"])
        assert _resolve_group(groups, "G0001") == "intrusion-set--g1"

    def test_resolve_by_name(self, minimal_bundle):
        groups, _, _, _ = _build_indexes(minimal_bundle["objects"])
        assert _resolve_group(groups, "TestGroup") == "intrusion-set--g1"

    def test_resolve_by_alias(self, minimal_bundle):
        groups, _, _, _ = _build_indexes(minimal_bundle["objects"])
        assert _resolve_group(groups, "TestAlias") == "intrusion-set--g1"

    def test_resolve_case_insensitive(self, minimal_bundle):
        groups, _, _, _ = _build_indexes(minimal_bundle["objects"])
        assert _resolve_group(groups, "testgroup") == "intrusion-set--g1"
        assert _resolve_group(groups, "g0001") == "intrusion-set--g1"

    def test_resolve_not_found_returns_none(self, minimal_bundle):
        groups, _, _, _ = _build_indexes(minimal_bundle["objects"])
        assert _resolve_group(groups, "NoSuchGroup") is None


# ---------------------------------------------------------------------------
# Path 1 — Direct attribution
# ---------------------------------------------------------------------------

class TestPath1Direct:
    def test_direct_technique_captured(self, minimal_bundle):
        rows = get_group_techniques(minimal_bundle, "G0001")
        tech_ids = {r["technique_id"] for r in rows}
        assert "T1059.001" in tech_ids

    def test_attribution_type_is_direct(self, minimal_bundle):
        rows = get_group_techniques(minimal_bundle, "G0001")
        direct = [r for r in rows if r["attribution_type"] == "direct"]
        assert len(direct) > 0

    def test_procedure_example_preserved(self, minimal_bundle):
        rows = get_group_techniques(minimal_bundle, "G0001")
        direct = [r for r in rows if r["attribution_type"] == "direct"]
        assert any("Used PowerShell" in r["procedure_example"] for r in direct)

    def test_technique_without_description_still_captured(self):
        """Path 1 must not require a description."""
        bundle = _make_bundle([
            _group("intrusion-set--g1", "G0001", "TestGroup"),
            _technique("attack-pattern--t1", "T1059.001", "PowerShell"),
            # No description on the relationship
            _rel("rel--r1", "uses", "intrusion-set--g1", "attack-pattern--t1"),
        ])
        rows = get_group_techniques(bundle, "G0001")
        assert any(r["technique_id"] == "T1059.001" for r in rows)


# ---------------------------------------------------------------------------
# Path 2 — Via software
# ---------------------------------------------------------------------------

class TestPath2Software:
    def test_software_technique_captured(self, software_bundle):
        rows = get_group_techniques(software_bundle, "G0001")
        tech_ids = {r["technique_id"] for r in rows}
        assert "T1003.001" in tech_ids

    def test_attribution_type_contains_software_name(self, software_bundle):
        rows = get_group_techniques(software_bundle, "G0001")
        sw_rows = [r for r in rows if r["attribution_type"].startswith("via_software:")]
        assert len(sw_rows) > 0
        assert any("Mimikatz" in r["attribution_type"] for r in sw_rows)

    def test_malware_techniques_also_captured(self):
        bundle = _make_bundle([
            _group("intrusion-set--g1", "G0001", "TestGroup"),
            _malware("malware--m1", "Cobalt Strike"),
            _technique("attack-pattern--t1", "T1055", "Process Injection", ["Defense Evasion"]),
            _rel("rel--r1", "uses", "intrusion-set--g1", "malware--m1"),
            _rel("rel--r2", "uses", "malware--m1", "attack-pattern--t1", "Injects."),
        ])
        rows = get_group_techniques(bundle, "G0001")
        assert any(r["technique_id"] == "T1055" for r in rows)
        assert any("Cobalt Strike" in r["attribution_type"] for r in rows)


# ---------------------------------------------------------------------------
# Path 3 — Via campaign
# ---------------------------------------------------------------------------

class TestPath3Campaign:
    def test_campaign_technique_captured(self, campaign_bundle):
        rows = get_group_techniques(campaign_bundle, "G0001")
        tech_ids = {r["technique_id"] for r in rows}
        assert "T1566.001" in tech_ids

    def test_attribution_type_contains_campaign_name(self, campaign_bundle):
        rows = get_group_techniques(campaign_bundle, "G0001")
        camp_rows = [r for r in rows if r["attribution_type"].startswith("via_campaign:")]
        assert len(camp_rows) > 0
        assert any("Operation Test" in r["attribution_type"] for r in camp_rows)

    def test_technique_not_attributed_to_unrelated_group(self):
        """Techniques from a campaign should not appear on an unrelated group."""
        bundle = _make_bundle([
            _group("intrusion-set--g1", "G0001", "GroupA"),
            _group("intrusion-set--g2", "G0002", "GroupB"),
            _campaign("campaign--c1", "Ops"),
            _technique("attack-pattern--t1", "T1566.001", "Spearphishing"),
            # Campaign attributed to GroupA only
            _rel("rel--r1", "attributed-to", "campaign--c1", "intrusion-set--g1"),
            _rel("rel--r2", "uses", "campaign--c1", "attack-pattern--t1"),
        ])
        rows_b = get_group_techniques(bundle, "G0002")
        assert not any(r["technique_id"] == "T1566.001" for r in rows_b)


# ---------------------------------------------------------------------------
# All three paths together
# ---------------------------------------------------------------------------

class TestAllPaths:
    def test_all_three_techniques_present(self, all_paths_bundle):
        rows = get_group_techniques(all_paths_bundle, "G0001")
        tech_ids = {r["technique_id"] for r in rows}
        assert "T1059.001" in tech_ids   # Path 1
        assert "T1003.001" in tech_ids   # Path 2
        assert "T1566.001" in tech_ids   # Path 3

    def test_all_three_attribution_types_present(self, all_paths_bundle):
        rows = get_group_techniques(all_paths_bundle, "G0001")
        types = {r["attribution_type"].split(":")[0] for r in rows}
        assert "direct" in types
        assert "via_software" in types
        assert "via_campaign" in types

    def test_no_duplicates(self, all_paths_bundle):
        rows = get_group_techniques(all_paths_bundle, "G0001")
        keys = [(r["technique_id"], r["tactic"], r["attribution_type"]) for r in rows]
        assert len(keys) == len(set(keys))

    def test_group_not_found_raises(self, all_paths_bundle):
        with pytest.raises(ValueError, match="Group not found"):
            get_group_techniques(all_paths_bundle, "G9999")


# ---------------------------------------------------------------------------
# Row schema
# ---------------------------------------------------------------------------

class TestRowSchema:
    def test_all_fieldnames_present(self, minimal_bundle):
        rows = get_group_techniques(minimal_bundle, "G0001")
        for row in rows:
            for field in FIELDNAMES:
                assert field in row, f"Missing field: {field}"

    def test_tactic_title_case(self, minimal_bundle):
        rows = get_group_techniques(minimal_bundle, "G0001")
        for row in rows:
            if row["tactic"]:
                assert row["tactic"] == row["tactic"].title() or " " in row["tactic"]

    def test_multi_tactic_technique_emits_multiple_rows(self):
        bundle = _make_bundle([
            _group("intrusion-set--g1", "G0001", "TestGroup"),
            _technique("attack-pattern--t1", "T1078", "Valid Accounts",
                       ["Defense Evasion", "Persistence", "Privilege Escalation"]),
            _rel("rel--r1", "uses", "intrusion-set--g1", "attack-pattern--t1"),
        ])
        rows = get_group_techniques(bundle, "G0001")
        t1078_rows = [r for r in rows if r["technique_id"] == "T1078"]
        assert len(t1078_rows) == 3
        tactics = {r["tactic"] for r in t1078_rows}
        assert "Defense Evasion" in tactics
        assert "Persistence" in tactics


# ---------------------------------------------------------------------------
# get_all_procedures
# ---------------------------------------------------------------------------

class TestGetAllProcedures:
    def test_returns_rows_for_all_groups(self, all_paths_bundle):
        rows = get_all_procedures(all_paths_bundle)
        group_ids = {r["group_sw_id"] for r in rows}
        assert "G0001" in group_ids

    def test_empty_bundle_returns_empty(self):
        rows = get_all_procedures(_make_bundle([]))
        assert rows == []


# ---------------------------------------------------------------------------
# CSV writing
# ---------------------------------------------------------------------------

class TestBuildProceduresCSV:
    """Tests for build_procedures_csv which now delegates to run_mitresaw."""

    @staticmethod
    def _write_sample_csv(path: Path):
        """Write a sample MITRESaw-format CSV for testing."""
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerow({
                "group_sw_id": "G0001",
                "group_sw_name": "TestGroup",
                "group_sw_description": "A test group",
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "technique_description": "Adversaries may use PowerShell",
                "tactic": "Execution",
                "platforms": "Windows",
                "framework": "Enterprise",
                "procedure_example": "TestGroup has used PowerShell",
                "evidence": '{"cmd": ["powershell.exe"]}',
                "detectable_via": "Sysmon: 1",
            })

    def test_csv_written_with_correct_headers(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
            out_path = Path(f.name)

        def mock_run(output_csv=None, output_xlsx=None):
            self._write_sample_csv(output_csv or out_path)
            return (output_csv or out_path, None)

        with patch("archer.mitre.procedures.run_mitresaw", side_effect=mock_run):
            result = build_procedures_csv(output_path=out_path)

        with open(result, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            assert list(reader.fieldnames) == FIELDNAMES

        out_path.unlink(missing_ok=True)

    def test_csv_contains_correct_data(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
            out_path = Path(f.name)

        def mock_run(output_csv=None, output_xlsx=None):
            self._write_sample_csv(output_csv or out_path)
            return (output_csv or out_path, None)

        with patch("archer.mitre.procedures.run_mitresaw", side_effect=mock_run):
            result = build_procedures_csv(output_path=out_path)

        with open(result, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        assert len(rows) >= 1
        assert any(r["technique_id"] == "T1059.001" for r in rows)
        assert any(r["group_sw_id"] == "G0001" for r in rows)

        out_path.unlink(missing_ok=True)

    def test_returns_path_object(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
            out_path = Path(f.name)

        def mock_run(output_csv=None, output_xlsx=None):
            self._write_sample_csv(output_csv or out_path)
            return (output_csv or out_path, None)

        with patch("archer.mitre.procedures.run_mitresaw", side_effect=mock_run):
            result = build_procedures_csv(output_path=out_path)

        assert isinstance(result, Path)
        assert result.exists()
        out_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Cross-reference
# ---------------------------------------------------------------------------

class TestCrossReference:
    def test_no_gaps_when_all_present(self, minimal_bundle):
        rows = get_group_techniques(minimal_bundle, "G0001")
        xlsx_pairs = {("G0001", "T1059.001")}
        gaps = cross_reference(rows, xlsx_pairs)
        assert gaps == []

    def test_gap_detected_when_missing(self, minimal_bundle):
        rows = get_group_techniques(minimal_bundle, "G0001")
        # XLSX has a technique not in our rows
        xlsx_pairs = {("G0001", "T1059.001"), ("G0001", "T9999")}
        gaps = cross_reference(rows, xlsx_pairs)
        assert ("G0001", "T9999") in gaps

    def test_none_xlsx_returns_empty(self, minimal_bundle):
        rows = get_group_techniques(minimal_bundle, "G0001")
        assert cross_reference(rows, None) == []

    def test_non_group_pairs_ignored(self, minimal_bundle):
        """Software IDs (S-prefix) in XLSX should not appear in gap report."""
        rows = get_group_techniques(minimal_bundle, "G0001")
        xlsx_pairs = {("S0001", "T1059.001")}  # software, not group
        gaps = cross_reference(rows, xlsx_pairs)
        assert gaps == []


# ---------------------------------------------------------------------------
# Integration: real cached bundle (no network)
# ---------------------------------------------------------------------------

class TestWithCachedBundle:
    """Smoke tests against the locally cached enterprise-attack.json."""

    @pytest.fixture(autouse=True)
    def load_bundle(self):
        cache_path = Path(__file__).parent.parent.parent / "archer" / "data" / "cache" / "enterprise-attack.json"
        if not cache_path.exists():
            pytest.skip("Cached enterprise-attack.json not found")
        with open(cache_path) as f:
            self.bundle = json.load(f)

    def test_scattered_spider_150_techniques(self):
        rows = get_group_techniques(self.bundle, "G1015")
        unique = {r["technique_id"] for r in rows}
        assert len(unique) == 150

    def test_scattered_spider_has_all_three_paths(self):
        rows = get_group_techniques(self.bundle, "G1015")
        types = {r["attribution_type"].split(":")[0] for r in rows}
        assert "direct" in types
        assert "via_software" in types
        assert "via_campaign" in types

    def test_lookup_by_name(self):
        rows = get_group_techniques(self.bundle, "Scattered Spider")
        assert len({r["technique_id"] for r in rows}) == 150

    def test_signature_ttps_present(self):
        """Techniques that must be present for Scattered Spider."""
        rows = get_group_techniques(self.bundle, "G1015")
        tech_ids = {r["technique_id"] for r in rows}
        # T1562.001 removed: no direct or indirect (software/campaign) relationship
        # to G1015 exists in MITRE'''s official STIX data as of the current
        # enterprise-attack.json cache, despite third-party attribution
        # (e.g. CISA/Prelude Security prose reporting on BYOVD activity).
        # This test asserts against MITRE'''s formal structured relationships only.
        required = {"T1621", "T1078.004", "T1539", "T1059.001"}
        missing = required - tech_ids
        assert not missing, f"Expected techniques missing: {missing}"

    def test_no_duplicate_rows(self):
        rows = get_group_techniques(self.bundle, "G1015")
        keys = [(r["technique_id"], r["tactic"], r["attribution_type"]) for r in rows]
        assert len(keys) == len(set(keys))

    def test_all_rows_have_required_fields(self):
        rows = get_group_techniques(self.bundle, "G1015")
        for row in rows:
            assert row["technique_id"].startswith("T"), f"Bad technique_id: {row['technique_id']}"
            assert row["group_id"] == "G1015"
            assert row["group_name"] == "Scattered Spider"
            assert row["attribution_type"] in (
                "direct",
                *[t for t in [row["attribution_type"]] if t.startswith(("via_software:", "via_campaign:"))],
            )

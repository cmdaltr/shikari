"""A dotted quad is shaped like a four-part version; the IP IOC guard drops the false positives."""

from shikari.parsers.file_intelligence import FileIntelligenceParser


def _ips(text: str):
    return FileIntelligenceParser(use_openai=False, use_local_llm=False)._extract_iocs(text)["ip"]


def test_version_shaped_network_quads_dropped():
    # Every one ends in .0 and isn't a CIDR: version strings, not host indicators
    assert _ips("Indicators: 8.28.2.0 8.38.3.0 8.48.4.0 8.58.5.0") == []


def test_version_keyword_prefix_dropped():
    assert _ips("Running version 8.28.2.1 of the agent") == []
    assert _ips("build 10.2.3.4 shipped") == []
    assert _ips("firmware 1.2.3.4 update") == []


def test_longer_dotted_run_dropped():
    assert _ips("build 8.28.2.0.1 shipped") == []
    assert _ips("sequence 1.8.28.2.9 here") == []


def test_network_and_broadcast_dropped_unless_cidr():
    assert _ips("noise at 198.51.100.255 ignored") == []
    assert _ips("host 185.220.101.0 alone") == []
    # A CIDR network address is a legitimate indicator and is kept
    assert _ips("scanned from 8.28.2.0/24 range") == ["8[.]28[.]2[.]0"]


def test_real_host_indicators_kept():
    assert _ips("C2 beacon to 185.220.101.45 observed") == ["185[.]220[.]101[.]45"]
    assert _ips("resolver 8.8.8.8 used") == ["8[.]8[.]8[.]8"]
    assert _ips("callback 203[.]0[.]113[.]50 seen") == ["203[.]0[.]113[.]50"]


def test_private_ranges_still_excluded():
    assert _ips("internal 10.0.0.5 and 192.168.1.9 and 127.0.0.1") == []

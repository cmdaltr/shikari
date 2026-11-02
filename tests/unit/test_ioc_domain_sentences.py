"""Text extraction runs sentences together; the join is not a domain."""

from shikari.parsers.file_intelligence import FileIntelligenceParser


def test_sentence_join_is_not_a_domain():
    text = "used for persistence.In addition, on the firewall.Cloud NGFW; C2 at evil.com and bad[.]org"
    domains = FileIntelligenceParser(use_openai=False, use_local_llm=False)._extract_iocs(text)["domain"]
    assert sorted(domains) == ["bad[.]org", "evil[.]com"]

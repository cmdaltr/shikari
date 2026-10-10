"""
CVE research must tolerate null fields from upstream APIs.

GitHub returns "description": null for repos without one, and NVD records
with no CPE configuration yield vendor/product of None. Both used to raise
TypeError (NoneType + str) and fail the whole CVE hunt.
"""
from unittest.mock import MagicMock, patch

from archer.intelligence.cve_hunter import CVEHunter


def _hunter(tmp_path):
    with patch("archer.config.CVE_CACHE_DIR", str(tmp_path)):
        return CVEHunter()


def test_extract_iocs_with_null_poc_description_and_no_cpe(tmp_path):
    research = {
        "cve_id": "CVE-2024-3400",
        "nvd_data": {
            "description": "Command injection in GlobalProtect via ${jndi:ldap://x} payloads",
            "vendor": None,
            "product": None,
        },
        "pocs": [
            {"type": "github", "source": "someone/CVE-2024-3400", "url": "https://github.com/someone/CVE-2024-3400", "description": None},
            {"type": "github", "source": None, "url": None, "description": "PoC for GlobalProtect"},
        ],
    }

    iocs = _hunter(tmp_path)._extract_iocs(research)

    assert isinstance(iocs, dict)
    assert any("jndi" in c for c in iocs["cmd"])


def test_github_poc_null_description_normalised(tmp_path):
    hunter = _hunter(tmp_path)
    response = MagicMock()
    response.json.return_value = {"items": [{
        "full_name": "someone/CVE-2024-3400",
        "html_url": "https://github.com/someone/CVE-2024-3400",
        "description": None,
        "stargazers_count": 3,
        "language": "Python",
    }]}
    response.raise_for_status = MagicMock()

    with patch("archer.intelligence.cve_hunter.requests.get", return_value=response):
        pocs = hunter._search_github_pocs("CVE-2024-3400")

    assert pocs[0]["description"] == ""

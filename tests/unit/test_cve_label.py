"""A CVE's exploit name, from what researchers call it, and the label its run's files start with."""

from archer.intelligence.cve_label import exploit_name, label

PHP = {"description": "PHP uses longjmp() for out-of-memory errors ... remote code execution.", "vendor": "php",
       "product": "php", "cpes": ["cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"],
       "references": ["https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
                      "http://www.openwall.com/lists/oss-security/2026/10/21/6",
                      "https://www.wiz.io/blog/php2shell-php-rce"]}


def _gh(*sources):
    return [{"type": "github", "source": s, "description": ""} for s in sources]


def test_a_name_in_the_pocs_and_a_write_up():
    pocs = _gh("ikow/php2shell-poc", "assetnote/php2shell-scanner", "junaire/CVE-2026-109618-exploit")
    assert exploit_name(PHP, pocs) == "PHP2Shell"
    assert label({"CVE-2026-109618": "PHP2Shell"}) == "CVE-2026-109618_PHP2Shell"


def test_spelled_as_someone_capitalised_it():
    nvd = {"description": "RouterOS SSH rekey", "vendor": "mikrotik", "cpes": ["cpe:2.3:o:mikrotik:routeros:*"],
           "references": ["https://bishopfox.com/blog/mikrotrick-inside-the-routeros-takeover-chain"]}
    pocs = [{"type": "github", "source": "GoldAden/mikrotrick-verifier", "description": "Checks for MikroTrick"}]
    assert exploit_name(nvd, pocs) == "MikroTrick"


def test_products_advisory_ids_and_one_researcher_are_not_names():
    magento = {"description": "Adobe Commerce incorrect authorization", "vendor": "adobe", "product": "commerce",
               "references": ["https://helpx.adobe.com/security/products/magento/apsb26-92.html"]}
    assert exploit_name(magento, _gh("dinosn/cve-2026-71362-magento-lab", "mahumadad/cve-2026-71362-magento-ato")) is None
    citrix = {"description": "NetScaler ADC memory overread", "vendor": "citrix"}
    assert exploit_name(citrix, _gh("ThomasPoppelgaard/netscaler-ctx697096-checker", "a/ctx697096", "b/ctx697096")) is None
    assert exploit_name(PHP, _gh("ynsmroztas/AtlasSniper")) is None
    assert label({"CVE-2026-0257": None}) == "CVE-2026-0257"


def test_several_cves_list_their_ids_then_each_name_once():
    assert label({"CVE-2026-96652": "Plex2Shell", "CVE-2026-96654": "Plex2Shell"}) == \
        "CVE-2026-96652_CVE-2026-96654_Plex2Shell"
    assert label({f"CVE-2026-{n}": None for n in range(1000, 1005)}) == "CVE-2026-1000_plus_4"



def test_redacted_segment_becomes_a_wildcard():
    from shikari.build.ioc_sweep import clean_report_iocs, mde_sweep, secops_sweep
    clean = clean_report_iocs({"file": [r"c:\users\[redacted]\downloads\kk\undef.exe", r"C:\Users\<user>\AppData\x.dll"]})
    assert "file" not in clean
    assert clean["file_pattern"][0] == r"^c:[\\/]users[\\/][^\\/]+[\\/]downloads[\\/]kk[\\/]undef\.exe$"
    assert r'FolderPath matches regex @"(?i)^c:[\\/]users[\\/][^\\/]+' in mde_sweep(clean)
    assert r"target.process.file.full_path = /^c:[\\\/]users" in secops_sweep(clean, "r")


def test_system_files_are_swept_for_being_written():
    from shikari.build.ioc_sweep import clean_report_iocs, mde_sweep, secops_sweep
    clean = clean_report_iocs({"file": [r"c:\windows\system32\tieringengineservice.exe", "/usr/bin/.sshd",
                                        "comsvcs.dll", "undef.exe"]})
    assert clean == {"system_file": [r"c:\windows\system32\tieringengineservice.exe", "/usr/bin/.sshd"],
                     "file": ["undef.exe"]}  # comsvcs.dll alone matches every host that loads it
    kql = mde_sweep(clean)
    assert 'ActionType in ("FileCreated", "FileModified", "FileRenamed") and FolderPath in~ (ioc_system_file)' in kql
    assert "FileName in~ (ioc_file)" in kql and "tieringengineservice" not in kql.split("ioc_file =")[1].split(";")[0]
    assert 'metadata.event_type = "FILE_CREATION"' in secops_sweep(clean, "r")


def test_known_good_values_are_left_out():
    from shikari.build.ioc_sweep import clean_report_iocs
    clean = clean_report_iocs({
        "domain": ["login.microsoftonline[.]com", "evil.s3.amazonaws[.]com", "s3.amazonaws[.]com",
                   "staybud.dpdns[.]org", "raw.githubusercontent[.]com"],
        "ip": ["8.8.8.8", "172.233.228.93"],
        "hash": ["d41d8cd98f00b204e9800998ecf8427e", "a2b6c7a9c4490df70de3cdbfa5fc801a3e1cf6a872749259487e354de2876b7c"],
    })
    assert clean["domain"] == ["evil.s3.amazonaws.com", "staybud.dpdns.org"]
    assert clean["ip"] == ["172.233.228.93"]  # cloud-hosted C2 stays
    assert "md5" not in clean and clean["sha256"]


def test_known_good_extends_from_bespoke(tmp_path, monkeypatch):
    import json
    from shikari.build import ioc_sweep
    extra = tmp_path / "known_good.json"
    extra.write_text(json.dumps({"first_party_domains": {"values": ["corp-intranet.example"]}}))
    monkeypatch.setattr(ioc_sweep, "KNOWN_GOOD_FILES", ioc_sweep.KNOWN_GOOD_FILES[:1] + (str(extra),))
    ioc_sweep.known_good.cache_clear()
    try:
        assert "domain" not in ioc_sweep.clean_report_iocs({"domain": ["wiki.corp-intranet[.]example"]})
    finally:
        ioc_sweep.known_good.cache_clear()


def test_ips_and_domains_expire_on_regenerate():
    from datetime import date
    from shikari.build.ioc_sweep import apply_expiry
    first = {"ip": ["1.2.3.4"], "domain": ["evil.example"], "sha256": ["ab" * 32]}
    assert apply_expiry("G", first, regenerate=False, today=date(2026, 1, 1)) == date(2026, 4, 1)
    later = {"ip": ["1.2.3.4", "5.6.7.8"], "domain": ["evil.example"], "sha256": ["ab" * 32]}
    # A plain rewrite keeps everything; Regenerate drops what's past 90 days, never hashes
    assert apply_expiry("G", dict(later), regenerate=False, today=date(2026, 6, 1))
    apply_expiry("G", later, regenerate=True, today=date(2026, 6, 1))
    assert later == {"ip": ["5.6.7.8"], "sha256": ["ab" * 32]}

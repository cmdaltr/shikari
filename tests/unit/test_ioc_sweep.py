

def test_redacted_segment_becomes_a_wildcard():
    from archer.build.ioc_sweep import clean_report_iocs, mde_sweep, secops_sweep
    clean = clean_report_iocs({"file": [r"c:\users\[redacted]\downloads\kk\undef.exe", r"C:\Users\<user>\AppData\x.dll"]})
    assert "file" not in clean
    assert clean["file_pattern"][0] == r"^c:[\\/]users[\\/][^\\/]+[\\/]downloads[\\/]kk[\\/]undef\.exe$"
    assert r'FolderPath matches regex @"(?i)^c:[\\/]users[\\/][^\\/]+' in mde_sweep(clean)
    assert r"re.regex($e.target.process.file.full_path, `^c:[\\/]users" in secops_sweep(clean, "r")


def test_system_files_are_not_swept():
    from archer.build.ioc_sweep import clean_report_iocs
    clean = clean_report_iocs({"file": [r"c:\windows\system32\tieringengineservice.exe",
                                        r"%SystemRoot%\SysWOW64\x.dll", "undef.exe"]})
    assert clean == {"file": ["undef.exe"]}

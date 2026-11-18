"""
CVE exposure: which devices run the vulnerable software at all.

For a library or runtime CVE (Java4Shell, CVE-2026-114938: the JDK itself) the exploit request
can look like any other and the first sign may be the shell after it, so knowing where the
vulnerable version runs comes first. Defender Vulnerability Management already matches installed
software to CVE IDs (DeviceTvmSoftwareVulnerabilities); the other SIEMs keep no software inventory,
so this is Defender's only.

The table holds the current state, with no Timestamp, so it runs as a hunting query rather than a
custom detection rule.
"""

import os
import re
from typing import List, Optional


def mde_exposure_query(cve_ids: List[str]) -> str:
    cves = ", ".join(f'"{c}"' for c in cve_ids)
    return f"""let cves = dynamic([{cves}]);
DeviceTvmSoftwareVulnerabilities
| where CveId in (cves)
| summarize Software = make_set(strcat(SoftwareVendor, " ", SoftwareName, " ", SoftwareVersion)),
    Updates = make_set(RecommendedSecurityUpdate) by DeviceId, DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel
| order by CveId asc, DeviceName asc"""


def write_exposure_detections(group_name: str, cve_ids: List[str], generate_dir: str, excluded_vendors=None,
                              run_label: Optional[str] = None) -> List[str]:
    """The Defender exposure query for the CVEs; returns the paths written (none when Defender is excluded)."""
    from shikari.build.yaml import LANGUAGE_SUFFIX, write_yaml

    if not cve_ids or "mde" in {v.lower() for v in excluded_vendors or []}:
        return []
    label = ", ".join(cve_ids)
    connector = "MicrosoftThreatProtection"
    safe = re.sub(r"[^A-Za-z0-9]+", "", group_name)
    stem = f"{run_label}_Exposure" if run_label else f"Exposure{safe}"
    path = os.path.join(generate_dir, f"{stem}_{LANGUAGE_SUFFIX[connector]}.yaml")
    title = "Exploit Public-Facing Application - devices running the vulnerable software"
    title = f"{run_label} - {title}" if run_label else f"{title} - {label}"
    desc = (f"Devices Defender Vulnerability Management finds exposed to {label}, with the software and "
            "version it matched and the update that fixes it. Run it as a hunting query: the table is the "
            "current state, with no timestamp, so it can't be a custom detection rule. Patch these first, "
            "and point the exploit and runtime detections at them.")
    write_yaml(path, title, "T1190", desc, connector, ["Initial Access"], group_name, mde_exposure_query(cve_ids),
               datatype="DeviceTvmSoftwareVulnerabilities", indicators={"cves": list(cve_ids)}, severity="High")
    return [path]

"""
CVE runtime detection: the affected web runtime's worker starting a shell or recon tools.

A code-execution CVE in a server-side runtime (PHP, a Java application server, IIS, Node.js)
lands in that runtime's worker process, and what the attacker runs next starts as its
child: php-fpm -> sh -c "id; uname -a". This holds whatever the exploit request looks like,
including one whose payload travels in the body, which HTTP logs don't keep (php2shell,
CVE-2026-109618: a multipart PHP_SESSION_UPLOAD_PROGRESS field).

A web worker running a shell isn't rare on its own: PHP's exec() and system() start
/bin/sh -c for every call, for sendmail or ImageMagick. So a shell counts only when its
command line runs recon or a download; recon tools started directly always count.
"""

import os
import re
from typing import Dict, List, Optional

from shikari.build.severity import RISK_SCORE
from shikari.build.udm import from_yaral

# name: (CPE vendor:product prefixes, description pattern, worker processes; a trailing * is a prefix)
RUNTIMES = {
    "PHP": (("php:php",), re.compile(r"\bPHP\b|\b(?:WordPress|Drupal|Joomla|Laravel|Magento)\b"),
            ("php-fpm*", "php-cgi", "php-cgi.exe", "php.exe", "lsphp", "frankenphp", "httpd", "apache2")),
    "Java application server": (("apache:tomcat", "oracle:weblogic", "atlassian:confluence", "atlassian:jira",
                                 "jenkins:jenkins", "redhat:jboss", "ibm:websphere"),
                                re.compile(r"\b(?:Tomcat|WebLogic|JBoss|WildFly|WebSphere|Confluence|Jenkins)\b"),
                                ("java", "java.exe", "javaw.exe", "tomcat*")),
    "IIS": (("microsoft:internet_information_services", "microsoft:exchange_server", "microsoft:sharepoint"),
            re.compile(r"\b(?:IIS|Exchange Server|SharePoint|ASP\.NET)\b"),
            ("w3wp.exe",)),
    "Node.js": (("nodejs:node.js",), re.compile(r"\bNode\.js\b"), ("node", "node.exe")),
}
# The CVE runs code: its wording, or its weakness
_EXECUTES = re.compile(r"remote code execution|\bRCE\b|arbitrary (?:code|commands?)|command injection|code injection|"
                       r"execute (?:arbitrary )?(?:code|commands?)|deseriali[sz]|object injection|web ?shell", re.I)
_EXECUTING_CWES = {"CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-502", "CWE-434"}
RECON = ("whoami", "whoami.exe", "id", "uname", "hostname", "curl", "wget", "nc", "ncat", "socat",
         "certutil.exe", "bitsadmin.exe", "mshta.exe")
SHELLS = ("sh", "bash", "dash", "zsh", "ksh", "cmd.exe", "powershell.exe", "pwsh.exe", "pwsh")
SHELL_TERMS = ("whoami", "uname", "/etc/passwd", "curl", "wget", "/dev/tcp", "base64", "nc", "ncat",
               "chmod", "python", "perl", "certutil", "Invoke-WebRequest", "DownloadString")


def runtimes(nvd: Dict) -> List[str]:
    """The runtimes a code-execution CVE lands in, from its CPEs or, failing those, its description."""
    text = nvd.get("description") or ""
    if not (_EXECUTES.search(text) or _EXECUTING_CWES & set(nvd.get("cwe") or [])):
        return []
    cpes = [c.split(":")[3] + ":" + c.split(":")[4] for c in nvd.get("cpes") or [] if c.count(":") >= 4]
    found = [name for name, (vendors, _, _) in RUNTIMES.items()
             if any(c.startswith(v) for c in cpes for v in vendors)]
    if found or cpes:
        return found
    return [name for name, (_, pattern, _) in RUNTIMES.items() if pattern.search(text)]


def _workers(names: List[str]) -> List[str]:
    return list(dict.fromkeys(w for n in names for w in RUNTIMES[n][2]))


def _kql_list(values) -> str:
    return "dynamic([" + ", ".join(f'"{v}"' for v in values) + "])"


def mde_runtime_query(names: List[str]) -> str:
    workers = _workers(names)
    exact = [w for w in workers if not w.endswith("*")]
    prefixes = [w[:-1] for w in workers if w.endswith("*")]
    parent = "InitiatingProcessFileName in~ (workers)" + "".join(
        f' or InitiatingProcessFileName startswith "{p}"' for p in prefixes)
    return "\n".join([
        f"let workers = {_kql_list(exact)};",
        f"let recon = {_kql_list(RECON)};",
        f"let shells = {_kql_list(SHELLS)};",
        f"let shell_terms = {_kql_list(SHELL_TERMS)};",
        "DeviceProcessEvents",
        f"| where {parent}",
        "| where FileName in~ (recon) or (FileName in~ (shells) and ProcessCommandLine has_any (shell_terms))",
        "| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, "
        "ProcessCommandLine, AccountName",
    ])


def _alternation(values) -> str:
    return "|".join(re.escape(v[:-1]) + r"[\w.-]*" if v.endswith("*") else re.escape(v) for v in values)


def secops_runtime_rule(names: List[str], label: str) -> str:
    workers = _alternation(_workers(names))
    recon = _alternation(RECON)
    shells = _alternation(SHELLS)
    # Whole words, as KQL's has_any matches them: a bare nc would match sync or include
    words = [t for t in SHELL_TERMS if re.fullmatch(r"[\w-]+", t)]
    terms = r"\b(" + "|".join(re.escape(t) for t in words) + r")\b|" + "|".join(
        re.escape(t) for t in SHELL_TERMS if t not in words)
    name = "shikari_runtime_" + re.sub(r"\W+", "_", label).strip("_").lower()
    return from_yaral(f"""rule {name} {{
  meta:
    author = "Shikari Detection Engineering"
    description = "{' and '.join(names)} worker starting a shell or recon tools after {label}"
    mitre_attack_technique = "T1190"
    severity = "HIGH"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.principal.process.file.full_path, `(^|[/\\\\])({workers})$`) nocase
    (re.regex($e.target.process.file.full_path, `(^|[/\\\\])({recon})$`) nocase or (re.regex($e.target.process.file.full_path, `(^|[/\\\\])({shells})$`) nocase and re.regex($e.target.process.command_line, `{terms}`) nocase))

  outcome:
    $risk_score = {RISK_SCORE["High"]}
    $hostname = $e.principal.hostname
    $parent = $e.principal.process.file.full_path
    $command_line = $e.target.process.command_line

  condition:
    $e
}}""")


def write_runtime_detections(group_name: str, cve_ids: List[str], nvd_records: List[Dict], generate_dir: str,
                             siems=("secops", "mde"), excluded_vendors=None, run_label: Optional[str] = None) -> List[str]:
    """
    One T1190 detection per SIEM when the CVEs run code in a known runtime; returns the paths written.
    run_label (shikari.intelligence.cve_label: CVE-2026-109618_PHP2Shell) starts the file name and title.
    """
    from shikari.build.yaml import LANGUAGE_SUFFIX, write_yaml

    names = list(dict.fromkeys(n for nvd in nvd_records for n in runtimes(nvd or {})))
    if not names:
        return []
    label = ", ".join(cve_ids)
    desc = (f"{label} runs code in the {' and '.join(names)} worker ({', '.join(w.rstrip('*') for w in _workers(names))}). "
            "What the attacker runs next starts as its child: this matches the worker starting recon tools, or a "
            "shell whose command line runs recon or a download. A shell alone isn't enough, since PHP's exec() "
            "starts one for every call; expect the odd admin script or deployment hook.")
    excluded = {v.lower() for v in excluded_vendors or []}
    safe = re.sub(r"[^A-Za-z0-9]+", "", group_name)
    builders = {
        "secops": ("GoogleSecOps", "PROCESS_LAUNCH", "googlesecops", lambda: secops_runtime_rule(names, label)),
        "mde": ("MicrosoftThreatProtection", "DeviceProcessEvents", "mde", lambda: mde_runtime_query(names)),
    }
    written = []
    for siem in siems:
        connector, datatype, vendor_key, build = builders[siem]
        if vendor_key in excluded:
            continue
        stem = f"{run_label}_RuntimeShell" if run_label else f"RuntimeShell{safe}"
        path = os.path.join(generate_dir, f"{stem}_{LANGUAGE_SUFFIX[connector]}.yaml")
        title = f"Exploit Public-Facing Application - {' and '.join(names)} worker spawns a shell"
        title = f"{run_label} - {title}" if run_label else f"{title} - {label}"
        write_yaml(path, title, "T1190", desc, connector, ["Initial Access"], group_name, build(),
                   datatype=datatype, indicators={"runtimes": names, "workers": _workers(names)}, severity="High")
        written.append(path)
    return written

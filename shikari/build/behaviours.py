"""
Behaviour detections: what a technique does, not the names in its procedures.

The indicator queries match the values ATT&CK's procedures quote, and for many techniques those
are only a binary's or a privilege's name: Accessibility Features came out as "a launch of
osk.exe", Access Token Manipulation as "a command line containing runas". Those match the
ordinary use of the tool, and miss the attack. A behaviour describes the attack the way a
detection engineer would: the parent that shouldn't start that child (winlogon.exe -> cmd.exe),
the arguments that make a tool hostile (bitsadmin /SetNotifyCmdLine), the registry value or file
write that sets it up (an IFEO Debugger for sethc.exe).

Each behaviour is written once, in neutral terms, and rendered for Defender XDR (KQL), Google
SecOps (UDM search) and Elastic (ES|QL over ECS). Splunk is left out: its fields come from the
estate's own mapping (bespoke/mappings/schemas), which a fixed query can't know.

    pattern  {"kind": process | registry | file, "all": [condition, ...], "why": "..."}
    condition (role, op, values)
      roles    process: name, cmd, path, parent, parent_cmd
               registry: key, value, data, name (the process that wrote it)
               file: path, file, name (the process that wrote it)
      ops      in (the whole value, any of), contains (any of), all (contains every one),
               ends (any of), not_in (none of the whole values), regex (one pattern)

A technique's patterns are alternatives (or); a pattern's conditions all have to hold (and).
"""

import os
import re
from typing import Dict, List, Optional, Tuple

SHELLS = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe"]
OFFICE = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe"]
# Processes that serve other people's requests, or open their documents: discovery tools started by
# one of these are someone working through it
SERVING = ["w3wp.exe", "sqlservr.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "java.exe", "php-cgi.exe",
           "wmiprvse.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe"] + OFFICE
USER_WRITABLE = ["\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\", "\\programdata\\"]
ACCESSIBILITY = ["sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe",
                 "atbroker.exe"]


def _discovery(tools: List[str], args: List[str], why: str) -> Dict:
    """A discovery tool, with the arguments that make it this technique, started by a process that
    serves requests or opens documents."""
    conds = [("name", "in", tools), ("parent", "in", SERVING)]
    if args:
        conds.insert(1, ("cmd", "contains", args))
    return {"kind": "process", "all": conds, "why": why}


BEHAVIOURS: Dict[str, Dict] = {
    "T1546.008": {"title": "Accessibility binary hijack", "patterns": [
        {"kind": "process", "all": [("parent", "in", ACCESSIBILITY), ("name", "in", SHELLS + ["explorer.exe"])],
         "why": "an accessibility tool starting a shell: the binary has been replaced or debugged"},
        {"kind": "process", "all": [("parent", "in", ["winlogon.exe"]), ("name", "in", SHELLS)],
         "why": "a shell from winlogon.exe: something on the logon screen ran it"},
        {"kind": "registry", "all": [("key", "contains", ["\\image file execution options\\" + b for b in ACCESSIBILITY]),
                                     ("value", "in", ["Debugger"])],
         "why": "an IFEO Debugger on an accessibility tool runs instead of it"},
        {"kind": "file", "all": [("path", "ends", ["\\system32\\" + b for b in ACCESSIBILITY]),
                                 ("name", "not_in", ["trustedinstaller.exe", "tiworker.exe", "msiexec.exe"])],
         "why": "an accessibility binary in System32 overwritten by something other than Windows servicing"},
    ]},
    "T1134": {"title": "Token theft and privileged re-launch", "patterns": [
        {"kind": "process", "all": [("name", "in", ["runas.exe"]), ("cmd", "contains", ["/savecred"])],
         "why": "runas with saved credentials: a stored admin password re-used without a prompt"},
        {"kind": "process", "all": [("cmd", "contains", ["Invoke-TokenManipulation", "token::elevate", "Get-System",
                                                         "make_token", "steal_token", "Invoke-RunAs"])],
         "why": "token theft tooling named on the command line"},
    ]},
    "T1218.005": {"title": "Mshta running remote or inline script", "patterns": [
        {"kind": "process", "all": [("name", "in", ["mshta.exe"]),
                                    ("cmd", "contains", ["http:", "https:", "javascript:", "vbscript:", "about:"])],
         "why": "mshta given a URL or inline script rather than a local .hta"},
        {"kind": "process", "all": [("parent", "in", ["mshta.exe"]), ("name", "in", SHELLS + ["bitsadmin.exe", "certutil.exe"])],
         "why": "mshta starting a shell or downloader"},
        {"kind": "process", "all": [("name", "in", ["mshta.exe"]), ("parent", "in", OFFICE + ["wmiprvse.exe"])],
         "why": "mshta started by an Office application or WMI"},
    ]},
    "T1569.002": {"title": "Service running a shell", "patterns": [
        {"kind": "process", "all": [("parent", "in", ["services.exe"]), ("name", "in", SHELLS)],
         "why": "a service whose binary is a shell or script host: services don't run cmd.exe themselves"},
        {"kind": "process", "all": [("name", "in", ["sc.exe"]), ("cmd", "all", ["create", "binpath"]),
                                    ("cmd", "contains", ["cmd", "powershell", "\\temp\\", "\\users\\public\\", "\\appdata\\"])],
         "why": "a service created to run a shell or a binary from a user-writable folder"},
    ]},
    "T1197": {"title": "BITS job running a command or downloading", "patterns": [
        {"kind": "process", "all": [("name", "in", ["bitsadmin.exe"]), ("cmd", "contains", ["/setnotifycmdline"])],
         "why": "a BITS job set to run a command when it completes: persistence that survives reboots"},
        {"kind": "process", "all": [("name", "in", ["bitsadmin.exe"]), ("cmd", "contains", ["/transfer", "/addfile"]),
                                    ("cmd", "contains", ["http"])],
         "why": "bitsadmin downloading from the web"},
        {"kind": "process", "all": [("parent_cmd", "contains", ["-s bits"]), ("name", "in", SHELLS)],
         "why": "the BITS service starting a shell: a job's notify command firing"},
    ]},
    "T1006": {"title": "Raw disk or shadow copy read", "patterns": [
        {"kind": "process", "all": [("cmd", "contains", ["\\\\.\\physicaldrive", "\\\\.\\c:", "harddiskvolumeshadowcopy"])],
         "why": "a raw device path on the command line: reading the disk under the file system's locks"},
    ]},
    "T1685": {"title": "Defender switched off or excluded", "aliases": ["T1562.001"], "patterns": [
        {"kind": "process", "all": [("cmd", "contains", ["Set-MpPreference", "Add-MpPreference"]),
                                    ("cmd", "contains", ["-Disable", "-Exclusion"])],
         "why": "Defender's real-time protection turned off, or a path, process or extension excluded"},
        {"kind": "process", "all": [("cmd", "contains", ["windefend", "sense"]), ("cmd", "contains", ["stop", "config", "delete"]),
                                    ("name", "in", ["sc.exe", "net.exe", "net1.exe", "powershell.exe", "cmd.exe"])],
         "why": "the Defender services stopped, reconfigured or deleted"},
        {"kind": "registry", "all": [("key", "contains", ["\\windows defender"]),
                                     ("value", "in", ["DisableAntiSpyware", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
                                                      "DisableIOAVProtection", "DisableScriptScanning"])],
         "why": "a Defender policy value that turns protection off"},
    ]},
    "T1686": {"title": "Host firewall turned off or opened", "aliases": ["T1562.004"], "patterns": [
        {"kind": "process", "all": [("name", "in", ["netsh.exe"]), ("cmd", "contains", ["advfirewall"]),
                                    ("cmd", "contains", ["state off"])],
         "why": "the Windows firewall switched off for a profile"},
        {"kind": "process", "all": [("name", "in", ["netsh.exe"]), ("cmd", "contains", ["allowedprogram", "add rule"]),
                                    ("cmd", "contains", ["\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\"])],
         "why": "a firewall rule letting a program in a user-writable folder through"},
        {"kind": "process", "all": [("cmd", "contains", ["Set-NetFirewallProfile"]), ("cmd", "contains", ["-Enabled False", "-Enabled 0"])],
         "why": "the firewall switched off through PowerShell"},
        {"kind": "registry", "all": [("key", "contains", ["\\firewallpolicy\\"]), ("value", "in", ["EnableFirewall"]),
                                     ("data", "in", ["0", "0x00000000"])],
         "why": "the firewall's policy value set to off"},
    ]},
    "T1048.003": {"title": "Upload over FTP or HTTP from the command line", "patterns": [
        {"kind": "process", "all": [("name", "in", ["curl.exe", "curl"]), ("cmd", "contains", [" -t ", " --upload-file", " -f ", "--data-binary @"])],
         "why": "curl sending a file out"},
        {"kind": "process", "all": [("name", "in", ["ftp.exe"]), ("cmd", "contains", ["-s:"])],
         "why": "ftp running a script of commands: unattended transfer"},
    ]},
    "T1090": {"title": "Port forwarding and SOCKS tunnels", "patterns": [
        {"kind": "process", "all": [("cmd", "contains", ["portproxy"]), ("cmd", "contains", ["add"])],
         "why": "netsh forwarding a local port to another host"},
        {"kind": "process", "all": [("name", "in", ["ssh.exe", "plink.exe", "ssh"]), ("cmd", "contains", [" -r ", " -d "])],
         "why": "an SSH reverse forward or SOCKS proxy"},
    ]},
    "T1036.003": {"title": "Renamed system utility", "raw": {
        "kql": ('DeviceProcessEvents\n| where Timestamp > ago(1d)\n'
                '| where ProcessVersionInfoOriginalFileName in~ ("cmd.exe", "powershell.exe", "pwsh.dll", "rundll32.exe", '
                '"regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "psexec.c", "procdump", "7z.exe", "rar.exe")\n'
                '| where FileName !~ ProcessVersionInfoOriginalFileName\n'
                '| project Timestamp, DeviceName, AccountName, FileName, ProcessVersionInfoOriginalFileName, FolderPath, '
                'ProcessCommandLine, InitiatingProcessFileName'),
        "elastic": ('FROM logs-endpoint.events.process-*\n| WHERE @timestamp >= NOW() - 1 day\n'
                    '| WHERE process.pe.original_file_name IS NOT NULL AND TO_LOWER(process.pe.original_file_name) IN '
                    '("cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", '
                    '"wmic.exe", "7z.exe", "rar.exe") AND TO_LOWER(process.name) != TO_LOWER(process.pe.original_file_name)\n'
                    '| KEEP @timestamp, host.name, user.name, process.name, process.pe.original_file_name, process.executable, '
                    'process.command_line, process.parent.name')},
        "why": "a binary whose own version information names another: a system tool copied under a new name"},
    "T1047": {"title": "WMI starting a shell, or running a process remotely", "patterns": [
        {"kind": "process", "all": [("parent", "in", ["wmiprvse.exe"]), ("name", "in", SHELLS)],
         "why": "the WMI provider host starting a shell: a remote or scripted Win32_Process.Create"},
        {"kind": "process", "all": [("name", "in", ["wmic.exe"]), ("cmd", "all", ["process", "call", "create"])],
         "why": "wmic creating a process"},
    ]},
    "T1059.005": {"title": "Script host running a script from a user folder or an Office parent", "patterns": [
        {"kind": "process", "all": [("name", "in", ["wscript.exe", "cscript.exe"]), ("cmd", "contains", USER_WRITABLE)],
         "why": "a .vbs/.js run from Downloads, Temp or AppData: how phishing attachments start"},
        {"kind": "process", "all": [("name", "in", ["wscript.exe", "cscript.exe"]), ("parent", "in", OFFICE)],
         "why": "an Office document starting a script host"},
        {"kind": "process", "all": [("parent", "in", ["wscript.exe", "cscript.exe"]), ("name", "in", SHELLS + ["bitsadmin.exe", "certutil.exe"])],
         "why": "a script starting a shell or downloader"},
    ]},
    "T1059.010": {"title": "AutoIt or AutoHotkey from a user folder", "patterns": [
        {"kind": "process", "all": [("name", "in", ["autoit3.exe", "autohotkey.exe", "autohotkeyu64.exe", "autohotkeyu32.exe"]),
                                    ("path", "contains", USER_WRITABLE)],
         "why": "an AutoIt or AutoHotkey interpreter run from a user-writable folder, as loaders ship them"},
        {"kind": "process", "all": [("parent", "in", ["autoit3.exe", "autohotkey.exe", "autohotkeyu64.exe"]),
                                    ("name", "in", SHELLS)],
         "why": "an AutoIt or AutoHotkey script starting a shell"},
    ]},
    "T1098.007": {"title": "Account added to a privileged group", "patterns": [
        {"kind": "process", "all": [("cmd", "all", ["localgroup", "/add"]), ("cmd", "contains", ["administrators", "remote desktop users"])],
         "why": "a local account made an administrator or RDP user"},
        {"kind": "process", "all": [("cmd", "all", ["group", "/add", "/domain"])],
         "why": "an account added to a domain group from the command line"},
        {"kind": "process", "all": [("cmd", "contains", ["Add-LocalGroupMember", "Add-ADGroupMember"]),
                                    ("cmd", "contains", ["admin", "remote desktop"])],
         "why": "an account added to an admin group through PowerShell"},
    ]},
    "T1560.001": {"title": "Password-protected archive", "patterns": [
        {"kind": "process", "all": [("name", "in", ["rar.exe", "winrar.exe", "7z.exe", "7za.exe", "7zr.exe"]),
                                    ("cmd", "regex", [r"\s-h?p\S"])],
         "why": "an archive with a password: data staged so content inspection can't read it"},
    ]},
    "T1685.005": {"title": "Event log cleared", "aliases": ["T1070.001"], "patterns": [
        {"kind": "process", "all": [("name", "in", ["wevtutil.exe"]), ("cmd", "contains", [" cl ", " clear-log "])],
         "why": "wevtutil clearing a log"},
        {"kind": "process", "all": [("cmd", "contains", ["Clear-EventLog", "Remove-EventLog", "Limit-EventLog"])],
         "why": "an event log cleared or shrunk through PowerShell"},
    ]},
    "T1685.001": {"title": "Event logging switched off", "aliases": ["T1562.002"], "patterns": [
        {"kind": "process", "all": [("name", "in", ["auditpol.exe"]), ("cmd", "contains", ["/clear", "/remove", "disable"])],
         "why": "audit policy cleared or turned off"},
        {"kind": "process", "all": [("name", "in", ["wevtutil.exe"]), ("cmd", "contains", [" sl "]), ("cmd", "contains", ["/e:false"])],
         "why": "a log channel disabled"},
        {"kind": "process", "all": [("cmd", "contains", ["eventlog"]), ("cmd", "contains", ["stop", "disabled"]),
                                    ("name", "in", ["sc.exe", "net.exe", "net1.exe", "powershell.exe"])],
         "why": "the Event Log service stopped or disabled"},
    ]},
    "T1140": {"title": "Certutil or PowerShell decoding a payload", "patterns": [
        {"kind": "process", "all": [("name", "in", ["certutil.exe"]), ("cmd", "contains", ["-decode", "/decode", "-decodehex"])],
         "why": "certutil decoding a base64 or hex file"},
        {"kind": "process", "all": [("cmd", "contains", ["FromBase64String"]), ("cmd", "contains", ["IEX", "Invoke-Expression", "Reflection.Assembly"])],
         "why": "PowerShell decoding base64 and running the result"},
    ]},
    "T1105": {"title": "Built-in tool downloading a file", "patterns": [
        {"kind": "process", "all": [("name", "in", ["certutil.exe"]), ("cmd", "contains", ["urlcache"]), ("cmd", "contains", ["http"])],
         "why": "certutil fetching from the web"},
        {"kind": "process", "all": [("cmd", "contains", ["DownloadFile", "DownloadString", "Invoke-WebRequest", "Start-BitsTransfer", "iwr "]),
                                    ("cmd", "contains", ["http"]), ("parent", "in", SERVING + ["explorer.exe"])],
         "why": "PowerShell downloading, started from a document, script or server process"},
    ]},
    "T1553.004": {"title": "Root certificate installed", "patterns": [
        {"kind": "process", "all": [("name", "in", ["certutil.exe"]), ("cmd", "contains", ["-addstore", "/addstore"]),
                                    ("cmd", "contains", ["root"])],
         "why": "certutil adding a certificate to the trusted roots"},
        {"kind": "process", "all": [("cmd", "contains", ["Import-Certificate"]), ("cmd", "contains", ["\\root"])],
         "why": "PowerShell importing into a root store"},
    ]},
    "T1570": {"title": "Tool copied to an admin share", "patterns": [
        {"kind": "process", "all": [("cmd", "contains", ["\\admin$\\", "\\c$\\"]),
                                    ("cmd", "contains", ["copy", "xcopy", "robocopy", "move", "Copy-Item"])],
         "why": "a file copied onto another host's administrative share"},
    ]},
    "T1070.005": {"title": "Share connections removed", "patterns": [
        {"kind": "process", "all": [("name", "in", ["net.exe", "net1.exe"]), ("cmd", "contains", [" use ", " share "]),
                                    ("cmd", "contains", ["/delete", "/del"])],
         "why": "mapped drives or shares deleted to remove the trail of lateral movement"},
    ]},
    "T1218.007": {"title": "Msiexec installing from the web or quietly from a user folder", "patterns": [
        {"kind": "process", "all": [("name", "in", ["msiexec.exe"]), ("cmd", "contains", ["http:", "https:"])],
         "why": "msiexec installing a package straight from a URL"},
        {"kind": "process", "all": [("name", "in", ["msiexec.exe"]), ("parent", "in", OFFICE + ["wscript.exe", "cscript.exe", "mshta.exe"])],
         "why": "msiexec started by a document or script"},
        {"kind": "process", "all": [("name", "in", ["msiexec.exe"]), ("cmd", "contains", ["/y", "/z"]), ("cmd", "contains", [".dll"])],
         "why": "msiexec registering a DLL (/y, /z) rather than installing"},
    ]},
    "T1546.007": {"title": "Netsh helper DLL registered", "patterns": [
        {"kind": "process", "all": [("name", "in", ["netsh.exe"]), ("cmd", "contains", ["add helper"])],
         "why": "a DLL registered for netsh to load"},
        {"kind": "registry", "all": [("key", "contains", ["\\microsoft\\netsh"])],
         "why": "a helper DLL written under the NetSh key"},
    ]},
    "T1218.010": {"title": "Regsvr32 loading a remote or script component", "patterns": [
        {"kind": "process", "all": [("name", "in", ["regsvr32.exe"]), ("cmd", "contains", ["/i:http", "-i:http", "scrobj.dll"])],
         "why": "regsvr32 running a remote scriptlet (Squiblydoo)"},
        {"kind": "process", "all": [("name", "in", ["regsvr32.exe"]), ("parent", "in", OFFICE + ["wscript.exe", "cscript.exe", "mshta.exe"])],
         "why": "regsvr32 started by a document or script"},
        {"kind": "process", "all": [("name", "in", ["regsvr32.exe"]), ("cmd", "contains", USER_WRITABLE)],
         "why": "regsvr32 loading a DLL from a user-writable folder"},
    ]},
    "T1218.011": {"title": "Rundll32 running script or a DLL from a user folder", "patterns": [
        {"kind": "process", "all": [("name", "in", ["rundll32.exe"]),
                                    ("cmd", "contains", ["javascript:", "mshtml,runhtmlapplication", "url.dll,openurl",
                                                         "url.dll,fileprotocolhandler", "ieframe.dll,openurl"])],
         "why": "rundll32 running script or opening a URL through a system DLL"},
        {"kind": "process", "all": [("name", "in", ["rundll32.exe"]), ("cmd", "contains", USER_WRITABLE)],
         "why": "rundll32 loading a DLL from a user-writable folder"},
        {"kind": "process", "all": [("name", "in", ["rundll32.exe"]), ("parent", "in", OFFICE + ["wscript.exe", "cscript.exe", "mshta.exe"])],
         "why": "rundll32 started by a document or script"},
    ]},
    "T1021.002": {"title": "Admin share mounted with explicit credentials", "patterns": [
        {"kind": "process", "all": [("name", "in", ["net.exe", "net1.exe"]), ("cmd", "contains", [" use "]),
                                    ("cmd", "contains", ["\\admin$", "\\c$", "\\ipc$"]), ("cmd", "contains", ["/user:"])],
         "why": "an administrative share mounted with someone's credentials typed in"},
    ]},
    "T1202": {"title": "Command run through a proxy binary", "patterns": [
        {"kind": "process", "all": [("name", "in", ["pcalua.exe"]), ("cmd", "contains", ["-a"])],
         "why": "the Program Compatibility Assistant launching a program for someone"},
        {"kind": "process", "all": [("name", "in", ["forfiles.exe"]), ("cmd", "contains", ["/c"])],
         "why": "forfiles running a command for each file it finds"},
        {"kind": "process", "all": [("parent", "in", ["pcalua.exe", "forfiles.exe"]), ("name", "in", SHELLS)],
         "why": "a shell started through pcalua or forfiles"},
    ]},
    # Discovery: the tools are everyday admin tools, so the tell is who started them
    "T1007": {"title": "Service discovery from a serving or document process", "patterns": [
        _discovery(["sc.exe", "net.exe", "net1.exe", "tasklist.exe"], ["query", "start", "/svc"],
                   "services listed by a web server, database, document or script")]},
    "T1033": {"title": "Whoami from a serving or document process", "patterns": [
        _discovery(["whoami.exe", "quser.exe", "query.exe"], [], "who-am-I run by a web server, database, document or script")]},
    "T1057": {"title": "Process listing from a serving or document process", "patterns": [
        _discovery(["tasklist.exe"], [], "processes listed by a web server, database, document or script"),
        {"kind": "process", "all": [("cmd", "contains", ["Get-Process", "Win32_Process"]), ("parent", "in", SERVING)],
         "why": "processes listed through PowerShell or WMI by a serving or document process"}]},
    "T1018": {"title": "Remote system discovery from a serving or document process", "patterns": [
        _discovery(["net.exe", "net1.exe", "nltest.exe", "ping.exe", "arp.exe"], ["view", "/dclist", "-a", "-n "],
                   "hosts enumerated by a web server, database, document or script")]},
    "T1087.001": {"title": "Local account listing from a serving or document process", "patterns": [
        _discovery(["net.exe", "net1.exe"], [" user"], "local accounts listed by a web server, database, document or script")]},
    "T1087.002": {"title": "Domain account enumeration", "patterns": [
        {"kind": "process", "all": [("cmd", "contains", ["user /domain", "users /domain"]), ("parent", "in", SERVING)],
         "why": "domain users listed by a web server, database, document or script"},
        {"kind": "process", "all": [("cmd", "contains", ["adfind", "dsquery"]), ("cmd", "contains", ["user", "objectcategory=person"])],
         "why": "AD queried for every user with AdFind or dsquery"},
        {"kind": "process", "all": [("cmd", "contains", ["Get-ADUser"]), ("cmd", "contains", ["-Filter *", "-Filter \"*\""])],
         "why": "every AD user pulled through PowerShell"},
    ]},
    "T1069.001": {"title": "Local group listing from a serving or document process", "patterns": [
        _discovery(["net.exe", "net1.exe"], ["localgroup"], "local groups listed by a web server, database, document or script")]},
    "T1069.002": {"title": "Domain group enumeration", "patterns": [
        {"kind": "process", "all": [("cmd", "contains", ["group /domain", "groups /domain"]), ("parent", "in", SERVING)],
         "why": "domain groups listed by a web server, database, document or script"},
        {"kind": "process", "all": [("cmd", "contains", ["domain admins", "enterprise admins"]),
                                    ("cmd", "contains", ["net ", "net1 ", "Get-ADGroupMember", "dsquery", "adfind"])],
         "why": "the domain's admin groups enumerated"},
    ]},
    "T1482": {"title": "Domain trust discovery", "patterns": [
        {"kind": "process", "all": [("cmd", "contains", ["/domain_trusts", "/all_trusts", "/trusted_domains"])],
         "why": "nltest listing the domain's trusts"},
        {"kind": "process", "all": [("cmd", "contains", ["trustdmp", "trustedDomain", "Get-ADTrust", "Get-DomainTrust"])],
         "why": "trusts pulled through AdFind, dsquery or PowerShell"},
    ]},
    "T1135": {"title": "Share enumeration", "patterns": [
        _discovery(["net.exe", "net1.exe"], [" view", " share"], "shares listed by a web server, database, document or script"),
        {"kind": "process", "all": [("cmd", "contains", ["Invoke-ShareFinder", "Find-DomainShare", "Get-NetShare"])],
         "why": "share-finding tooling named on the command line"}]},
    "T1201": {"title": "Password policy discovery", "patterns": [
        _discovery(["net.exe", "net1.exe"], ["accounts"], "password policy read by a web server, database, document or script"),
        {"kind": "process", "all": [("cmd", "contains", ["Get-ADDefaultDomainPasswordPolicy", "Get-DomainPolicy"])],
         "why": "the domain password policy pulled through PowerShell"}]},
    "T1012": {"title": "Registry queried for credentials or security software", "patterns": [
        {"kind": "process", "all": [("name", "in", ["reg.exe"]), ("cmd", "contains", [" query "]),
                                    ("cmd", "contains", ["/f password", "winlogon", "putty\\sessions", "realvnc", "\\vnc\\"])],
         "why": "the registry searched for stored passwords"},
        _discovery(["reg.exe"], [" query "], "the registry queried by a web server, database, document or script")]},
    "T1083": {"title": "File discovery from a serving or document process", "patterns": [
        _discovery(["cmd.exe"], ["dir /s", "dir /a", "tree /f"], "files listed recursively by a web server, database, document or script")]},
    "T1518": {"title": "Installed software discovery", "patterns": [
        {"kind": "process", "all": [("cmd", "contains", ["\\currentversion\\uninstall"]), ("cmd", "contains", ["query", "Get-ItemProperty"]),
                                    ("parent", "in", SERVING)],
         "why": "installed software listed by a web server, database, document or script"},
        {"kind": "process", "all": [("cmd", "all", ["product", "get"]), ("name", "in", ["wmic.exe"]), ("parent", "in", SERVING)],
         "why": "wmic listing installed products for a serving or document process"}]},
}

# ATT&CK v18 IDs, for bundles and Libraries from before v19's renumbering
_ALIASES = {alias: tid for tid, b in BEHAVIOURS.items() for alias in b.get("aliases", [])}


def behaviour(technique_id: str) -> Optional[Dict]:
    tid = (technique_id or "").strip().upper()
    return BEHAVIOURS.get(tid) or BEHAVIOURS.get(_ALIASES.get(tid, ""))


# ── Rendering ────────────────────────────────────────────────────────────────

_KQL = {
    "process": ("DeviceProcessEvents", {"name": "FileName", "cmd": "ProcessCommandLine", "path": "FolderPath",
                                        "parent": "InitiatingProcessFileName", "parent_cmd": "InitiatingProcessCommandLine"},
                "Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine"),
    "registry": ("DeviceRegistryEvents", {"key": "RegistryKey", "value": "RegistryValueName", "data": "RegistryValueData",
                                          "name": "InitiatingProcessFileName"},
                 "Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine"),
    "file": ("DeviceFileEvents", {"path": "FolderPath", "file": "FileName", "name": "InitiatingProcessFileName"},
             "Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine"),
}


def _kql_str(v: str) -> str:
    return '@"' + v.replace('"', '""') + '"'


def _kql_cond(field: str, op: str, values: List[str]) -> str:
    vals = ", ".join(_kql_str(v) for v in values)
    if op == "in":
        return f"{field} in~ ({vals})"
    if op == "not_in":
        return f"{field} !in~ ({vals})"
    if op == "regex":
        return f"{field} matches regex {_kql_str('(?i)' + values[0])}"
    if op in ("contains", "all"):
        # has matches whole terms, which the padding around " -t " only stood in for
        terms = ", ".join(_kql_str(v.strip()) for v in values)
        return f"{field} {'has_any' if op == 'contains' else 'has_all'} ({terms})"
    return "(" + " or ".join(f"{field} endswith {_kql_str(v)}" for v in values) + ")"


def render_kql(b: Dict) -> str:
    if (b.get("raw") or {}).get("kql"):
        return b["raw"]["kql"]
    parts = []
    for kind in ("process", "registry", "file"):
        patterns = [p for p in b["patterns"] if p["kind"] == kind]
        if not patterns:
            continue
        table, fields, columns = _KQL[kind]
        expr = "\n    or ".join("(" + " and ".join(_kql_cond(fields[r], op, v) for r, op, v in p["all"]) + ")" for p in patterns)
        parts.append(f"{table}\n| where Timestamp > ago(1d)\n| where {expr}\n| project {columns}")
    if len(parts) == 1:
        return parts[0]
    return "union\n" + ",\n".join("(" + p + ")" for p in parts)


_UDM = {
    "process": ('metadata.event_type = "PROCESS_LAUNCH"',
                {"name": "target.process.file.full_path", "cmd": "target.process.command_line", "path": "target.process.file.full_path",
                 "parent": "principal.process.file.full_path", "parent_cmd": "principal.process.command_line"}),
    "registry": ('(metadata.event_type = "REGISTRY_MODIFICATION" or metadata.event_type = "REGISTRY_CREATION")',
                 {"key": "target.registry.registry_key", "value": "target.registry.registry_value_name",
                  "data": "target.registry.registry_value_data", "name": "principal.process.file.full_path"}),
    "file": ('(metadata.event_type = "FILE_CREATION" or metadata.event_type = "FILE_MODIFICATION")',
             {"path": "target.file.full_path", "file": "target.file.full_path", "name": "principal.process.file.full_path"}),
}
# Fields that hold a full path, where "in" means the file name at its end
_UDM_PATHS = {"target.process.file.full_path", "principal.process.file.full_path", "target.file.full_path"}


def _udm_re(v: str) -> str:
    return re.escape(v).replace("/", "\\/").replace("\\ ", " ")


def _udm_cond(field: str, op: str, values: List[str]) -> Optional[str]:
    alts = "|".join(_udm_re(v) for v in values)
    if op == "in":
        rx = f"(^|\\\\)({alts})$" if field in _UDM_PATHS else f"^({alts})$"
        return f"{field} = /{rx}/ nocase"
    if op == "contains":
        return f"{field} = /{alts}/ nocase"
    if op == "all":
        return " and ".join(f"{field} = /{_udm_re(v)}/ nocase" for v in values)
    if op == "ends":
        return f"{field} = /({alts})$/ nocase"
    if op == "regex":
        return f"{field} = /{values[0].replace('/', chr(92) + '/')}/ nocase"
    return None   # not_in: left to the KQL and ES|QL forms


def render_udm(b: Dict, technique_id: str) -> Optional[str]:
    if b.get("raw") and not b.get("patterns"):
        return None
    branches = []
    for p in b["patterns"]:
        event, fields = _UDM[p["kind"]]
        conds = [_udm_cond(fields[r], op, v) for r, op, v in p["all"]]
        if None in conds:
            continue
        branches.append(f"({event} and " + " and ".join(conds) + ")")
    if not branches:
        return None
    tag = "shikari_" + technique_id.lower().replace(".", "_")
    return f"// {tag}: {b['title']} · ATT&CK {technique_id} · behaviour\n" + "\n or ".join(branches)


_ESQL = {
    "process": ("logs-endpoint.events.process-*", "process",
                {"name": "process.name", "cmd": "process.command_line", "path": "process.executable",
                 "parent": "process.parent.name", "parent_cmd": "process.parent.command_line"}),
    "registry": ("logs-endpoint.events.registry-*", "registry",
                 {"key": "registry.path", "value": "registry.value", "data": "registry.data.strings", "name": "process.name"}),
    "file": ("logs-endpoint.events.file-*", "file", {"path": "file.path", "file": "file.name", "name": "process.name"}),
}


def _esql_like(v: str) -> str:
    # A backslash escapes in LIKE: "?" (any one character) stands in for each, which is precise enough here
    return v.lower().replace("\\", "?").replace('"', '\\"')


def _esql_cond(field: str, op: str, values: List[str]) -> str:
    f = f"TO_LOWER({field})"
    if op in ("in", "not_in"):
        vals = ", ".join('"' + v.lower().replace('"', '\\"') + '"' for v in values)
        return f"{f} {'NOT IN' if op == 'not_in' else 'IN'} ({vals})"
    if op == "all":
        return "(" + " AND ".join(f'{f} LIKE "*{_esql_like(v)}*"' for v in values) + ")"
    if op == "regex":
        return f'{f} RLIKE ".*{values[0].replace(chr(92), chr(92) * 2)}.*"'  # not lowered: \\S isn't \\s
    pattern = (lambda v: f"*{_esql_like(v)}*") if op == "contains" else (lambda v: f"*{_esql_like(v)}")
    return "(" + " OR ".join(f'{f} LIKE "{pattern(v)}"' for v in values) + ")"


def render_esql(b: Dict) -> str:
    if (b.get("raw") or {}).get("elastic"):
        return b["raw"]["elastic"]
    kinds = [k for k in ("process", "registry", "file") if any(p["kind"] == k for p in b["patterns"])]
    sources = ", ".join(_ESQL[k][0] for k in kinds)
    branches = []
    for p in b["patterns"]:
        _, category, fields = _ESQL[p["kind"]]
        conds = [_esql_cond(fields[r], op, v) for r, op, v in p["all"]]
        if len(kinds) > 1:
            conds.insert(0, f'event.category == "{category}"')
        branches.append("(" + " AND ".join(conds) + ")")
    return (f"FROM {sources}\n| WHERE @timestamp >= NOW() - 1 day\n| WHERE " + "\n  OR ".join(branches) +
            "\n| KEEP @timestamp, host.name, user.name, event.category, process.name, process.command_line, "
            "process.parent.name" + (", registry.path, registry.value, registry.data.strings" if "registry" in kinds else "") +
            (", file.path" if "file" in kinds else ""))


# ── Writing ──────────────────────────────────────────────────────────────────

def _indicators(b: Dict) -> Dict:
    """The YAML's indicators: each pattern in words (sentences, which the results page keeps off its
    indicator chips) and, for the chips, the first value of each condition."""
    firsts = list(dict.fromkeys(vs[0].strip() for p in b.get("patterns", []) for _, op, vs in p["all"] if op != "not_in"))
    whys = [p["why"] for p in b.get("patterns", [])] or [b.get("why", "")]
    return {"behaviour": [w[0].upper() + w[1:] + "." for w in whys if w], "values": firsts[:8]}


def write_behaviour_detections(technique_id: str, technique_name: str, tactics: List[str], tag: str, generate_dir: str,
                               excluded_vendors=None) -> List[str]:
    """The technique's behaviour detection for each SIEM it renders for; [] when there's none for it."""
    from shikari.build.yaml import LANGUAGE_SUFFIX, detection_action, write_yaml

    b = behaviour(technique_id)
    if not b:
        return []
    excluded = {v.lower() for v in excluded_vendors or []}
    # Named like the technique's other files (construct_yaml): AccessibilityFeatures_Behaviour_KQL.yaml
    stem = technique_name.replace(" ", "").replace("/", "") or technique_id.replace(".", "_")
    whys = [p["why"] for p in b.get("patterns", [])] or [b.get("why", "")]
    desc = (f"{b['title']}. What the technique does, rather than the names in its procedures: " + "; ".join(whys) + ".")
    builds: List[Tuple[str, str, str, str]] = []   # (vendor key, connector, datatype, query)
    if "mde" not in excluded:
        builds.append(("mde", "MicrosoftThreatProtection", "DeviceProcessEvents", render_kql(b)))
    if "googlesecops" not in excluded:
        udm = render_udm(b, technique_id)
        if udm:
            builds.append(("googlesecops", "GoogleSecOps", "PROCESS_LAUNCH", udm))
    if "elastic" not in excluded:
        builds.append(("elastic", "Elastic", "logs-endpoint.events.*", render_esql(b)))
    written = []
    for _, connector, datatype, query in builds:
        path = os.path.join(generate_dir, f"{stem}_Behaviour_{LANGUAGE_SUFFIX[connector]}.yaml")
        rewrite = detection_action(path, tag)
        if rewrite is None:
            continue
        write_yaml(path, f"{technique_name} - behaviour - {b['title']}", technique_id, desc, connector, list(tactics), tag,
                   query, datatype=datatype, indicators=_indicators(b), severity="High", **rewrite)
        written.append(path)
    return written

"""
Anatomy workflow: how an attack runs, as a short chain of cards anyone can follow.

In the style of the DFIR Report's workflow diagrams: a group's chain is the actor -> its way in (the CVEs it exploits, the services it phishes through or signs in to) -> what it
runs (its tools, grouped: offensive frameworks, credential stealers, web shells, ransomware,
built-in tools) -> what it reaches (the legitimate services it abuses, grouped: cloud storage,
messaging, tunnels). A CVE's chain is the attacker -> the exploit -> the CVE -> the worker the
code runs in -> the shell -> the infrastructure. Each step says whether this run detects most
of what's behind it. No ATT&CK technique IDs or tactics are shown: the chain is the operation,
the detection pages carry the mapping.

From ATT&CK's procedures (MITRESaw's CSV) for a group, from the cached research for a CVE. No AI.
"""

import json
import os
import re
import zlib
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set

from shikari.build.ioc_flow import refang
from shikari.visualization.flow_view import _PROCEDURES_CSV, _attributed_rows

# Legitimate services named in procedures, by group: (group, [(name, pattern)])
SERVICE_GROUPS = [
    ("Cloud storage", [("Dropbox", r"Dropbox"), ("OneDrive", r"OneDrive"), ("Google Drive", r"Google Drive|Google Docs"),
                       ("MEGA", r"\bMEGA(?:\.nz)?\b|Mega\.nz"), ("Box", r"\bBox\.com"), ("Yandex Disk", r"Yandex")]),
    ("Cloud tenants", [("AWS", r"\bAWS\b|Amazon S3|Amazon Web Services|S3 bucket"), ("Azure", r"Azure|Entra ID"),
                       ("Microsoft 365", r"Microsoft Graph|SharePoint|Microsoft 365|Office 365"), ("Okta", r"Okta"),
                       ("Firebase", r"Firebase")]),
    ("Messaging", [("Telegram", r"Telegram"), ("Discord", r"Discord"), ("Slack", r"Slack"),
                   ("Teams", r"Microsoft Teams|\bTeams\b"), ("Gmail", r"Gmail"), ("Twitter", r"Twitter")]),
    ("Code and paste sites", [("GitHub", r"GitHub"), ("GitLab", r"GitLab"), ("Pastebin", r"Pastebin"),
                              ("Bitbucket", r"Bitbucket"), ("Notion", r"\bNotion\b"), ("Trello", r"Trello")]),
    ("Tunnels and anonymisers", [("ngrok", r"ngrok"), ("Tor", r"\bTor\b"), ("Cloudflare", r"Cloudflare")]),
    ("Remote access", [("AnyDesk", r"AnyDesk"), ("TeamViewer", r"TeamViewer"),
                       ("ScreenConnect", r"ScreenConnect|ConnectWise Control"), ("Atera", r"Atera"),
                       ("Splashtop", r"Splashtop"), ("RustDesk", r"RustDesk"), ("VPN", r"\bVPNs?\b")]),
    ("Hosting", [("DigitalOcean", r"DigitalOcean"), ("Vultr", r"Vultr"), ("Linode", r"Linode")]),
]
_SERVICES = [(group, name, re.compile(rx, 0 if name in ("Tor", "MEGA") else re.I))
             for group, members in SERVICE_GROUPS for name, rx in members]

# What the actor does with a service, in plain words: the first technique prefix that matches
VERBS = [
    ("Exploits", ("T1190", "T1203", "T1068", "T1210", "T1211", "T1212", "T1189", "T1195")),
    ("Uploads to", ("T1567", "T1041", "T1048", "T1030", "T1537", "T1020")),
    ("Beacons to", ("T1071", "T1102", "T1090", "T1572", "T1573", "T1568", "T1095", "T1104", "T1001", "T1008")),
    ("Signs in to", ("T1078", "T1021.007")),
    ("Remote access", ("T1133", "T1219", "T1021")),
    ("Phishes via", ("T1566", "T1598", "T1534")),
    ("Downloads from", ("T1105", "T1608", "T1204")),
    ("Collects from", ("T1213", "T1530", "T1538", "T1114", "T1005", "T1039", "T1119")),
    ("Hosts on", ("T1583", "T1584", "T1585", "T1586")),
    ("Steals logins", ("T1555", "T1003", "T1552", "T1110", "T1556", "T1558", "T1539", "T1528")),
    ("Accesses", ("T1098", "T1580", "T1069", "T1087", "T1526", "T1619")),
]

# Tool groups, decided in this order (a framework that also dumps credentials is a framework)
BUILT_IN = {"net", "certutil", "cmd", "powershell", "psexec", "reg", "wmic", "schtasks", "at", "ipconfig", "systeminfo",
            "tasklist", "netstat", "bitsadmin", "rundll32", "regsvr32", "mshta", "ntdsutil", "vssadmin", "wevtutil",
            "nltest", "dsquery", "ping", "whoami", "arp", "route", "netsh", "sc", "taskkill", "esentutl", "msiexec",
            "cscript", "wscript", "forfiles", "expand", "findstr", "query", "qwinsta", "nbtstat", "ftp", "tar",
            "curl", "wget", "ssh", "procdump", "adexplorer", "dsget", "sdelete", "attrib", "icacls", "xcopy", "robocopy"}
FRAMEWORKS = {"cobalt strike", "empire", "powersploit", "impacket", "metasploit", "sliver", "brute ratel c4", "mythic",
              "havoc", "koadic", "pupy", "poshc2", "covenant", "nishang", "powerview", "bloodhound", "sharphound",
              "rubeus", "responder", "adfind", "crackmapexec", "netexec", "merlin", "silenttrinity"}
CREDENTIAL_TOOLS = {"mimikatz", "lazagne", "pwdump", "gsecdump", "wce", "secretsdump", "nanodump", "dumpert",
                    "safetykatz", "kekeo", "redline stealer", "lumma stealer", "vidar", "agent tesla", "formbook",
                    "azorult", "lokibot", "raccoon stealer", "stealc", "atomic stealer", "pony"}
WEB_SHELLS = {"china chopper", "aspxspy", "godzilla", "behinder", "antsword", "regeorg", "neo-regeorg", "p.a.s. webshell",
              "sharppanda", "tunna", "weevely", "b374k"}
EXFIL_TOOLS = {"rclone", "megasync", "restic", "winscp", "filezilla", "exmatter", "stealbit"}
REMOTE_TOOLS = {"anydesk", "teamviewer", "screenconnect", "connectwise", "atera", "splashtop", "rustdesk", "ngrok",
                "plink", "chisel", "frp", "ligolo", "tor", "gost", "fast reverse proxy"}
_ENCRYPT = ("T1486", "T1490", "T1485", "T1561")
_CREDS = ("T1003", "T1555", "T1552", "T1539", "T1056", "T1558", "T1110", "T1212")
TOOL_GROUPS = ["Offensive frameworks", "Credential stealers", "Web shells", "Backdoors and RATs", "Ransomware",
               "Remote access and tunnels", "Exfiltration tools", "Built-in tools"]

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_LABEL = re.compile(r"^\[(Software|Campaign): ([^\]]+)\]\s*")
_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")


def _has(tids: Iterable[str], prefixes) -> bool:
    return any(t == p or t.startswith(p + ".") for t in tids for p in prefixes)


def verb(tid: str) -> str:
    return next((v for v, prefixes in VERBS if _has([tid], prefixes)), "Uses")


def tool_group(name: str, tids: Iterable[str]) -> str:
    n, tids = name.lower(), list(tids)
    if n in BUILT_IN:
        return "Built-in tools"
    if n in FRAMEWORKS:
        return "Offensive frameworks"
    if n in WEB_SHELLS or "web shell" in n or "webshell" in n:
        return "Web shells"
    if n in CREDENTIAL_TOOLS or "stealer" in n:
        return "Credential stealers"
    if _has(tids, _ENCRYPT):
        return "Ransomware"
    if n in EXFIL_TOOLS:
        return "Exfiltration tools"
    if n in REMOTE_TOOLS:
        return "Remote access and tunnels"
    if tids and sum(_has([t], _CREDS) for t in tids) / len(tids) >= 0.4:
        return "Credential stealers"
    return "Backdoors and RATs"


def covered(tid: str, detected: Set[str]) -> bool:
    """A detection for the technique, its parent or one of its sub-techniques."""
    parent = tid.split(".")[0]
    return tid in detected or parent in detected or any(d.split(".")[0] == tid for d in detected)


def _text(procedure: str) -> str:
    """Procedure text without MITRESaw's label and with ATT&CK's links as their names."""
    return _LINK.sub(r"\1", _LABEL.sub("", procedure or "")).strip()


class _Chain:
    """
    The anatomy as a sequence of cards: each card a stage (the actor, how it gets in, what it
    runs, what it reaches), each link the step to the next. A link counts the behaviours behind
    it (techniques, never shown) towards "mostly detected"; by names the detection covering it.
    """

    def __init__(self):
        self.cards: List[Dict] = []
        self.links: Dict[tuple, Dict] = {}

    def card(self, cid: str, kind: str, title: str, sub: str = "", sections=None, evidence=None, row: int = 0,
             col: Optional[int] = None) -> Dict:
        """col places it in a column beside others (a group's ways in, its services); None, along the chain."""
        card = {"id": cid, "kind": kind, "title": title, "sub": sub, "row": row, "col": col,
                "sections": [s for s in sections or [] if s["items"]], "evidence": [e for e in evidence or [] if e][:6]}
        self.cards.append(card)
        return card

    def link(self, src: str, dst: str, label: str, behaviour: Optional[str] = None, detected: bool = False,
             text: str = "", by: str = "") -> Dict:
        e = self.links.setdefault((src, dst), {"source": src, "target": dst, "label": label, "behaviours": {},
                                               "evidence": [], "covered_by": []})
        if behaviour:
            e["behaviours"][behaviour] = e["behaviours"].get(behaviour, False) or detected
        if text and len(e["evidence"]) < 5 and text not in [x["text"] for x in e["evidence"]]:
            e["evidence"].append({"text": text, "detected": detected})
        if by and by not in e["covered_by"]:
            e["covered_by"].append(by)
        return e


def _sections(grouped: Dict[str, List[str]], order: List[str]) -> List[Dict]:
    """A stage's members by group, each listed under its node ("brief")."""
    return [{"title": t, "items": grouped[t], "brief": True}
            for t in sorted(grouped, key=lambda t: (order.index(t) if t in order else 99, t))]


# Ways in, side by side: (node, icon, the step into it, technique prefixes never shown, when nothing is named)
WAYS_IN = [
    ("Exploit", "cve", "Exploits", ("T1190", "T1203", "T1189", "T1195", "T1211"), "Public-facing apps"),
    ("Phishing", "phish", "Phishes", ("T1566", "T1598", "T1534"), "Lures"),
    ("Credentials", "key", "Signs in", ("T1078", "T1133", "T1199", "T1021.007"), "Valid accounts"),
]
# Services, side by side: (node, service groups in it)
SERVICE_BRANCHES = [
    ("Cloud", ("Cloud tenants", "Hosting", "Tunnels and anonymisers")),
    ("Messaging", ("Messaging",)),
    ("Code and storage", ("Code and paste sites", "Cloud storage")),
]
# A remote-access product (AnyDesk, Atera) the group runs is part of its toolkit, not a service it reaches
_TOOLKIT_SERVICES = {"Remote access"}

# What they do once in, in plain words: (action, technique prefixes, never shown). Listed by how
# much of it the reporting describes, not in an order: an intrusion isn't a sequence of stages
ACTIONS = [
    ("Steals logins", ("T1003", "T1555", "T1552", "T1110", "T1558", "T1539", "T1056", "T1528", "T1606",
                       "T1111", "T1621", "T1556", "T1212")),
    ("Moves across the network", ("T1021", "T1570", "T1550", "T1563", "T1210", "T1080", "T1072")),
    ("Gains admin rights", ("T1068", "T1548", "T1134", "T1484")),
    ("Keeps access", ("T1053", "T1547", "T1543", "T1136", "T1098", "T1505", "T1546", "T1574", "T1037", "T1197",
                      "T1112", "T1137", "T1542")),
    ("Hides its tracks", ("T1070", "T1562", "T1027", "T1036", "T1218", "T1564", "T1140", "T1055", "T1620", "T1497",
                          "T1480", "T1014", "T1006", "T1222", "T1553", "T1685")),
    ("Looks around", ("T1082", "T1083", "T1087", "T1018", "T1016", "T1069", "T1057", "T1046", "T1135", "T1482",
                      "T1012", "T1033", "T1049", "T1007", "T1518", "T1580", "T1538", "T1526", "T1613", "T1201",
                      "T1124", "T1120", "T1614", "T1615", "T1652", "T1654", "T1619")),
    ("Gathers data", ("T1005", "T1039", "T1213", "T1114", "T1530", "T1560", "T1074", "T1119", "T1115", "T1113",
                      "T1025", "T1123", "T1125", "T1185", "T1602")),
    ("Takes data out", ("T1567", "T1041", "T1048", "T1030", "T1537", "T1020", "T1029", "T1052")),
    ("Encrypts or destroys", ("T1486", "T1490", "T1485", "T1561", "T1489", "T1529", "T1491", "T1565", "T1499")),
    ("Extorts", ("T1657",)),
]


def action(tid: str) -> Optional[str]:
    return next((a for a, prefixes in ACTIONS if _has([tid], prefixes)), None)


def build_group(group_name: str, detected: Set[str], csv_path: str = _PROCEDURES_CSV) -> Optional[Dict]:
    """
    A group's anatomy from ATT&CK's procedures: actor -> way in -> toolkit -> actions -> services.
    None without procedures.
    """
    try:
        rows = _attributed_rows(os.path.abspath(csv_path), os.path.getmtime(csv_path)).get(group_name.lower(), [])
    except OSError:
        return None
    if not rows:
        return None
    software = defaultdict(set)
    campaigns = []
    for row in rows:
        m = _LABEL.match(row.get("procedure_example") or "")
        if not m:
            continue
        if m.group(1) == "Software":
            software[m.group(2).partition(" via ")[0]].add((row.get("technique_id") or "").upper())
        if m.group(1) == "Campaign" or " via " in m.group(2):
            campaign = m.group(2).split(" via ")[-1]
            if campaign not in campaigns:
                campaigns.append(campaign)
    groups = {name: tool_group(name, tids) for name, tids in software.items()}

    ways = {w[0]: [] for w in WAYS_IN}  # node -> CVEs or services named
    tools, actions, branches = defaultdict(list), defaultdict(list), {b[0]: [] for b in SERVICE_BRANCHES}
    weight, verbs = defaultdict(int), defaultdict(lambda: defaultdict(int))
    branch_of = {group: b for b, groups in SERVICE_BRANCHES for group in groups}
    steps = []  # (node, behaviour, detected, text)
    for row in rows:
        tid = (row.get("technique_id") or "").upper()
        text = _text(row.get("procedure_example") or "")
        hit = covered(tid, detected)
        m = _LABEL.match(row.get("procedure_example") or "")
        tool = m.group(2).partition(" via ")[0] if m and m.group(1) == "Software" else None
        way = next((w for w, _, _, prefixes, _ in WAYS_IN if _has([tid], prefixes)), None)
        if way:
            steps.append((way, tid, hit, text))
        if tool:
            if tool not in tools[groups[tool]]:
                tools[groups[tool]].append(tool)
            steps.append(("runs", tid, hit, text))
        done = action(tid)
        if done:  # what they do, and with what: the tool, or the group's own hands
            who = tool or "by hand"
            if who not in actions[done]:
                actions[done].append(who)
            weight[done] += 1
            steps.append(("does", tid, hit, text))
        for cve in dict.fromkeys(c.upper() for c in _CVE.findall(text)):
            if cve not in ways["Exploit"]:
                ways["Exploit"].append(cve)
            if way != "Exploit":
                steps.append(("Exploit", tid, hit, text))
        for group, name, rx in _SERVICES:
            if not rx.search(text) or name == tool or name in software:
                continue
            if way in ("Phishing", "Credentials"):
                if name not in ways[way]:
                    ways[way].append(name)
            elif group in _TOOLKIT_SERVICES:
                bucket = tools["Remote access and tunnels"]
                if name not in bucket:
                    bucket.append(name)
                steps.append(("runs", tid, hit, text))
            elif not any(name in named for named in ways.values()):  # shown once, where they get in
                branch = branch_of[group]
                if name not in branches[branch]:
                    branches[branch].append(name)
                verbs[branch][verb(tid)] += 1
                steps.append((branch, tid, hit, text))

    chain = _Chain()
    sub = " · ".join(x for x in (rows[0].get("group_sw_id"),
                                 f"{len(campaigns)} campaign{'s' if len(campaigns) != 1 else ''}" if campaigns else "") if x)
    chain.card("actor", "actor", rows[0].get("group_sw_name") or group_name, sub,
               [{"title": "Campaigns", "items": campaigns}], col=0)  # in the panel: the ID and count say enough

    def evidence(key):
        return [t for k, *_, t in steps if k == key]

    def link(src, dst, label, key):
        for k, tid, hit, text in steps:
            if k == key:
                chain.link(src, dst, label, tid, hit, text)

    ways_in = []
    for way, icon, step, _, fallback in WAYS_IN:
        if ways[way] or any(k == way for k, *_ in steps):
            cid = "way:" + way
            chain.card(cid, icon, way, "" if ways[way] else fallback,
                       [{"title": way, "items": ways[way], "brief": True, "flat": True}], evidence(way), col=1)
            link("actor", cid, step, way)
            ways_in.append(cid)
    previous = ways_in or ["actor"]
    if tools:
        chain.card("runs", "software", "Toolkit", sections=_sections(tools, TOOL_GROUPS), evidence=evidence("runs"), col=2)
        for src in previous:
            link(src, "runs", "Runs", "runs")
        previous = ["runs"]
    if actions:
        ordered = [dict(sec, brief=False) for sec in _sections(actions, sorted(actions, key=lambda a: -weight[a]))]
        chain.card("does", "action", "Actions", sections=ordered, evidence=evidence("does"), col=3)
        for src in previous:
            link(src, "does", "To", "does")
        previous = ["does"]
    for branch, groups_in in SERVICE_BRANCHES:
        if branches[branch]:
            cid = "service:" + branch
            chain.card(cid, "service", branch, sections=[{"title": branch, "items": branches[branch], "brief": True,
                                                          "flat": True}], evidence=evidence(branch), col=4)
            top = max(verbs[branch], key=verbs[branch].get)
            for src in previous:
                link(src, cid, top, branch)
    return _finish(chain, kind="group")


def _cve_ids(group_name: str, detection_paths: Iterable[str]) -> List[str]:
    ids = [c.upper() for c in _CVE.findall(group_name)]
    for path in detection_paths:
        ids += [c.upper() for c in _CVE.findall(os.path.basename(path))]
    return list(dict.fromkeys(ids))


def _groups_exploiting(cve: str, csv_path: str = _PROCEDURES_CSV) -> List[str]:
    """ATT&CK groups whose procedures name the CVE."""
    try:
        by_group = _attributed_rows(os.path.abspath(csv_path), os.path.getmtime(csv_path))
    except OSError:
        return []
    return sorted({rows[0].get("group_sw_name") for rows in by_group.values()
                   if any(cve in (r.get("procedure_example") or "").upper() for r in rows)} - {None, ""})


def build_cve(group_name: str, detection_paths: Iterable[str], detected: Set[str],
              cache_dir: Optional[str] = None) -> Optional[Dict]:
    """
    A CVE run's anatomy from its cached research, one chain per CVE: attacker -> exploit -> CVE ->
    the product's worker -> the shell it starts -> the infrastructure the advisories name.
    """
    from shikari.build.runtime_detection import _workers, runtimes
    from shikari.intelligence.cve_hunter import CVEHunter
    from shikari.intelligence.cve_label import exploit_name

    paths = list(detection_paths)
    names = [os.path.basename(p) for p in paths]
    has = {kind: any(f"_{kind}_" in n or n.startswith(kind) for n in names)
           for kind in ("Exploit", "RuntimeShell", "IOCSweep")}
    by = {"Exploit": "Exploit request detection", "RuntimeShell": "Runtime shell detection", "IOCSweep": "IOC sweep"}
    cache_dir = cache_dir or CVEHunter.cache_location()
    chain = _Chain()
    row = 0
    for cve in _cve_ids(group_name, paths):
        try:
            with open(os.path.join(cache_dir, f"{cve}.json"), encoding="utf-8") as fh:
                research = json.load(fh)
        except (OSError, ValueError):
            continue
        nvd = research.get("nvd_data") or {}
        name = research.get("exploit_name") or exploit_name(nvd, research.get("pocs") or [])
        cvss = (nvd.get("cvss_v3") or {}).get("score")
        product = (nvd.get("product") or "").replace("_", " ")
        product = product.upper() if len(product) <= 6 else product.title() if product.islower() else product
        prev = None

        def step(cid, kind, title, sub="", sections=None, evidence=None, label="", check=None, text=""):
            nonlocal prev
            cid = f"{cve}:{cid}"
            chain.card(cid, kind, title, sub, sections, evidence, row=row)
            if prev:
                if check:
                    chain.link(prev, cid, label, check, has[check], text, by[check] if has[check] else "")
                else:
                    chain.link(prev, cid, label)
            prev = cid

        known = _groups_exploiting(cve)
        step("actor", "actor", known[0] if known else "Attacker", "Known to exploit it" if known else "Unattributed",
             [{"title": "Also", "items": known[1:]}])
        pocs = sorted((p for p in research.get("pocs") or [] if p.get("type") == "github"),
                      key=lambda p: -(p.get("stars") or 0))
        ind = (research.get("exploit") or {}).get("indicators") or {}
        if pocs or name:
            step("exploit", "exploit", name or "Public exploit",
                 f"{len(pocs)} public PoC{'s' if len(pocs) != 1 else ''}" if pocs else "",
                 [{"title": "Most starred", "items": [p.get("source") for p in pocs[:2]]}],
                 [p.get("source") + (f" ({p.get('stars')}★)" if p.get("stars") else "") for p in pocs[:5]], "Uses")
        request = ", ".join(ind.get("paths") or [])
        step("cve", "cve", cve, " · ".join(x for x in (product, f"CVSS {cvss}" if cvss else "") if x),
             [{"title": "Request", "items": ind.get("paths") or []}], [(nvd.get("description") or "")[:400]],
             "Exploits", "Exploit", f"Requests to {request}" if request else "")
        workers = _workers(runtimes(nvd))
        if workers:
            step("worker", "process", workers[0].rstrip("*"), "Runs the attacker's code",
                 [{"title": "Or", "items": [w.rstrip("*") for w in workers[1:]]}], label="Runs code in",
                 check="RuntimeShell")
        cmds = ind.get("cmd") or []
        if workers or cmds:
            step("shell", "shell", "Shell", cmds[0] if cmds else "Recon and downloads",
                 [{"title": "Runs", "items": cmds[:2]}], cmds[:4], "Starts", "RuntimeShell", cmds[0] if cmds else "")
        refs = (research.get("reference_iocs") or {}).get("iocs") or {}
        values = list(dict.fromkeys(refang(v) for kind in ("ip", "domain") for v in refs.get(kind) or []))
        if values:
            ips = [v for v in values if re.fullmatch(r"[\d.]+", v)]
            step("infra", "ioc", "Infrastructure", "", [{"title": "IPs", "items": ips, "brief": True},
                                                        {"title": "Domains", "items": [v for v in values if v not in ips],
                                                         "brief": True}],
                 label="Connects to", check="IOCSweep")
        row += 1
    if not row:
        return None
    return _finish(chain, kind="cve")

# Layout: each chain runs along a line, a node to a stage, with what it holds in a few short lines
# under it; a longer chain snakes back along the next line. Nodes sit a little off the line and
# links are gently bowed, drawn with a sketch filter in the template: hand-drawn, not ruled
WIDTH = 1100
MAX_PER_LINE = 6
BRIEF_LINES = 4
LINE = 16
SHORT = {"Offensive frameworks": "Frameworks", "Credential stealers": "Stealers", "Backdoors and RATs": "RATs",
         "Remote access and tunnels": "Remote", "Exfiltration tools": "Exfil", "Built-in tools": "Built-in",
         "Cloud storage": "Storage", "Cloud tenants": "Cloud", "Code and paste sites": "Code sites",
         "Tunnels and anonymisers": "Tunnels", "Remote access": "Remote", "Phishes via": "Phishing",
         "Signs in to": "Sign-in", "Web shells": "Web shells", "Moves across the network": "Moves around",
         "Encrypts or destroys": "Encrypts"}


def _jitter(key: str, spread: int) -> int:
    return zlib.crc32(key.encode()) % (2 * spread + 1) - spread


def _line(head: str, items: List[str], chars: int) -> str:
    """One short line: "Stealers: LaZagne, Vidar +2", whole items only."""
    text, shown = (f"{head}: " if head else ""), 0
    for item in items:
        more = len(items) - shown - 1
        piece = (", " if shown else "") + item
        if len(text + piece) + (len(f" +{more}") if more else 0) > chars and shown:
            break
        text, shown = text + piece, shown + 1
    if len(text) > chars:
        text = text[:chars - 1] + "…"
    return text + (f" +{len(items) - shown}" if len(items) > shown else "")


def _flow(words: List[str], chars: int, sep: str = " · ", most: int = BRIEF_LINES) -> List[str]:
    """Phrases joined with sep into at most `most` lines, then "+N more"."""
    lines, current, used = [], "", 0
    for w in words:
        w = w if len(w) <= chars else w[:chars - 1] + "…"
        candidate = f"{current}{sep}{w}" if current else w
        if len(candidate) <= chars or not current:
            current, used = candidate, used + 1
            continue
        if len(lines) + 1 == most:
            break
        lines.append(current)
        current, used = w, used + 1
    lines.append(current)
    if used < len(words):
        lines.append(f"+{len(words) - used} more")
    return lines


def _lines(card: Dict, chars: int) -> List[Dict]:
    """What goes under the node: title, sub, then a line per group it holds."""
    out = [{"cls": "title", "text": card["title"] if len(card["title"]) <= chars else card["title"][:chars - 1] + "…"}]
    if card["sub"]:
        sub = card["sub"]
        out.append({"cls": "sub", "text": sub if len(sub) <= chars + 4 else sub[:chars + 3] + "…"})
    if card.get("kind") == "action":  # the actions themselves, a few to a line; who does each is in the panel
        for text in _flow([sec["title"] for sec in card["sections"]], chars):
            out.append({"cls": "item", "text": text})
        return out
    flat = [sec for sec in card["sections"] if sec.get("flat")]
    if flat:  # one list of names: a way in, a service branch
        out += [{"cls": "item", "text": t} for t in _flow(flat[0]["items"], chars, ", ", most=2)]
        return out
    brief = [sec for sec in card["sections"] if sec.get("brief")]
    single = len(brief) == 1 and not card["sub"]
    for sec in brief[:BRIEF_LINES]:
        out.append({"cls": "item", "text": _line("" if single else SHORT.get(sec["title"], sec["title"]), sec["items"], chars)})
    if len(brief) > BRIEF_LINES:
        extra = len(brief) - BRIEF_LINES
        out.append({"cls": "sub", "text": f"+{extra} more group{'s' if extra != 1 else ''}"})
    return out


def _columns(nodes: List[Dict]) -> int:
    """Side-by-side nodes in columns (a group's ways in, its services), centred on the tallest; returns the height."""
    cols = sorted({n["col"] for n in nodes})
    slot = WIDTH / len(cols)
    chars = int(min(34, (slot - 16) / 7))
    for n in nodes:
        n["lines"] = _lines(n, chars)
    block = {id(n): 34 + 46 + len(n["lines"]) * LINE + 26 for n in nodes}
    heights = {c: sum(block[id(n)] for n in nodes if n["col"] == c) for c in cols}
    tallest = max(heights.values())
    for i, c in enumerate(cols):
        y = 10 + (tallest - heights[c]) / 2
        for n in (n for n in nodes if n["col"] == c):
            n["x"] = int(slot * (i + 0.5)) + _jitter(n["id"] + "x", 8)
            n["y"] = int(y + 34) + _jitter(n["id"] + "y", 6)
            y += block[id(n)]
    return int(tallest + 20)


def _finish(chain: _Chain, kind: str) -> Dict:
    nodes = chain.cards
    if all(n.get("col") is not None for n in nodes):
        return _links(chain, kind, _columns(nodes))
    rows = defaultdict(list)
    for n in nodes:
        rows[n["row"]].append(n)
    longest = max(len(r) for r in rows.values())
    per_line = longest if longest <= MAX_PER_LINE else MAX_PER_LINE - 1
    slot = WIDTH / per_line
    chars = int(min(34, (slot - 16) / 6.6))
    y = 20
    for row in sorted(rows):
        members = rows[row]
        for start in range(0, len(members), per_line):
            line = members[start:start + per_line]
            back = (start // per_line) % 2 == 1
            for i, n in enumerate(line):
                n["lines"] = _lines(n, chars)
                pos = per_line - 1 - i if back else i
                n["x"] = int(slot * (pos + 0.5)) + _jitter(n["id"] + "x", 8)
                n["y"] = int(y + 34) + _jitter(n["id"] + "y", 9)
            y += 34 + 46 + max(len(n["lines"]) for n in line) * LINE + 40
    return _links(chain, kind, int(y - 20))


def _label_spot(p0, c1, c2, p3, label: str, boxes) -> tuple:
    """Where along the curve its label sits clear of every node: the middle if it can, else the nearest clear spot."""
    half = len(label) * 3.5 + 4

    def at(t):
        k = [(1 - t) ** 3, 3 * (1 - t) ** 2 * t, 3 * (1 - t) * t ** 2, t ** 3]
        return (k[0] * p0[0] + k[1] * c1[0] + k[2] * c2[0] + k[3] * p3[0],
                k[0] * p0[1] + k[1] * c1[1] + k[2] * c2[1] + k[3] * p3[1])

    def overlap(x, y):
        return sum(max(0, min(x + half, b[2]) - max(x - half, b[0])) * max(0, min(y + 8, b[3]) - max(y - 8, b[1]))
                   for b in boxes)

    # On the line if it can, else just above or below it; failing that, wherever it covers least
    spots = [(x, y + dy) for dy in (0, -14, 14) for x, y in map(at, (0.5, 0.42, 0.58, 0.34, 0.66, 0.26, 0.74, 0.18, 0.82))]
    return min(spots, key=lambda xy: (overlap(*xy) > 0, overlap(*xy)))


def _links(chain: _Chain, kind: str, height: int) -> Dict:
    """The links between placed nodes: bowed a little, round the end of a line, labelled once per fan."""
    nodes = chain.cards
    by_id = {n["id"]: n for n in nodes}
    # What a label mustn't sit on: each node's disc and the text under it
    boxes = [(n["x"] - max(34, max(len(l["text"]) for l in n["lines"]) * 3.6), n["y"] - 34,
              n["x"] + max(34, max(len(l["text"]) for l in n["lines"]) * 3.6), n["y"] + 40 + len(n["lines"]) * LINE)
             for n in nodes]

    links = []
    for i, e in enumerate(chain.links.values()):
        s, t = by_id[e["source"]], by_id[e["target"]]
        if abs(t["y"] - s["y"]) < 40 or t.get("col") is not None:  # across, bowed a little up or down
            sign = 1 if t["x"] > s["x"] else -1
            sx, sy, tx, ty = s["x"] + 34 * sign, s["y"], t["x"] - 38 * sign, t["y"]
            bow = (12 + abs(_jitter(e["source"] + e["target"], 8))) * (1 if i % 2 else -1)
            dx = tx - sx
            c1, c2 = (sx + dx * 0.3, sy + bow), (tx - dx * 0.3, ty + bow)
        else:  # round the end of the line to the next one, clear of the text under the node
            side = 1 if s["x"] > WIDTH / 2 else -1
            sx, sy, tx, ty = s["x"] + 34 * side, s["y"], t["x"] + 38 * side, t["y"]
            reach = 70 + _jitter(e["source"], 10)
            c1, c2 = (sx + reach * side, sy + 10), (tx + reach * side, ty - 10)
        mx, my = _label_spot((sx, sy), c1, c2, (tx, ty), e["label"], boxes)
        behaviours = e["behaviours"]
        hits = sum(behaviours.values())
        state = "none" if not behaviours else ("detected" if hits * 2 > len(behaviours) else "gap")
        links.append({
            "source": e["source"], "target": e["target"], "label": e["label"], "state": state,
            "detected": hits, "total": len(behaviours), "evidence": e["evidence"], "covered_by": e["covered_by"],
            "path": f"M{sx:.0f},{sy:.0f} C{c1[0]:.0f},{c1[1]:.0f} {c2[0]:.0f},{c2[1]:.0f} {tx:.0f},{ty:.0f}",
            "lx": int(mx), "ly": int(my),
        })
    # A fan with one label, in (three ways in, each "Runs" into the toolkit) or out, says it once, mid-fan
    for end in ("target", "source"):
        fans = defaultdict(list)
        for e in links:
            if e["label"]:
                fans[(e[end], e["label"])].append(e)
        for fan in fans.values():
            fan.sort(key=lambda e: e["ly"])
            for i, e in enumerate(fan):
                if i != len(fan) // 2:
                    e["label"] = ""
    # A fan into one node carries the same behaviours on each link: count the step once
    counted = list({e["target"]: e for e in links if e["state"] != "none"}.values())
    return {
        "kind": kind, "width": WIDTH, "height": height, "nodes": nodes, "edges": links,
        "stats": {"links": len(counted), "detected": sum(e["state"] == "detected" for e in counted),
                  "gaps": sum(e["state"] == "gap" for e in counted)},
    }


def build(group_name: str, detection_paths: Iterable[str], detected: Set[str]) -> Optional[Dict]:
    """The results page's anatomy: a CVE run's from its research, a group's from ATT&CK."""
    paths = list(detection_paths)
    if _CVE.match(group_name):
        return build_cve(group_name, paths, detected)
    return build_group(group_name, detected)


def has_anatomy(group_name: str, csv_path: str = _PROCEDURES_CSV) -> bool:
    """Whether a group or CVE has the material for one: ATT&CK procedures, or cached CVE research."""
    if _CVE.match(group_name):
        from shikari.intelligence.cve_hunter import CVEHunter

        return any(os.path.isfile(os.path.join(CVEHunter.cache_location(), f"{c}.json"))
                   for c in _cve_ids(group_name, []))
    try:
        rows = _attributed_rows(os.path.abspath(csv_path), os.path.getmtime(csv_path))
    except OSError:
        return False
    return bool(rows.get(group_name.lower()) or rows.get(group_name.replace("_", " ").lower()))


def for_group(group_name: str, generate_dir: str) -> Optional[Dict]:
    """The anatomy of a group or CVE against all of its detections (the Anatomy page; results use the run's)."""
    from shikari.build.group_files import group_yaml_files
    from shikari.visualization.flow_view import read_detection

    paths = group_yaml_files(group_name, generate_dir)
    detected = {d["id"] for d in map(read_detection, paths) if d}
    name = group_name if _CVE.match(group_name) else group_name.replace("_", " ")
    return build(name, paths, detected)

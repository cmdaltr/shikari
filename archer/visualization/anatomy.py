"""
Anatomy workflow: who did it, with what, against what, through which services, to get what.

A network for the results page, in the style of the DFIR Report's workflow diagrams: the
actor, its campaigns and tools, the CVEs it exploits and the legitimate services it abuses
(Telegram, Dropbox, ngrok), down to what it's after (credentials, data, impact). Each link
is labelled with what it's for (Exploit, C2, Exfiltration) and carries the techniques and
procedures behind it, so it can say whether this run has a detection for it.

A group's anatomy comes from ATT&CK's procedures (MITRESaw's CSV): the software or campaign
a procedure is attributed to, the CVEs and services its text names. A CVE's comes from its
research: the PoCs, the affected product, the worker the code runs in and what the exploit
runs next. No AI.

Laid out here, not in the browser: columns left to right and the objectives along the
bottom, so the template only draws it.
"""

import json
import os
import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set

from archer.build.ioc_flow import refang
from archer.visualization.flow_view import _PROCEDURES_CSV, _attributed_rows, canonical_tactic

MAX = {"software": 8, "campaign": 3, "cve": 5, "service": 7, "ioc": 6}

# Legitimate services named in procedures: (canonical name, pattern)
SERVICES = [
    ("Telegram", r"Telegram"), ("Discord", r"Discord"), ("Slack", r"Slack"), ("Dropbox", r"Dropbox"),
    ("OneDrive", r"OneDrive"), ("Google Drive", r"Google Drive|Google Docs"), ("GitHub", r"GitHub"),
    ("GitLab", r"GitLab"), ("Pastebin", r"Pastebin"), ("ngrok", r"ngrok"), ("Cloudflare", r"Cloudflare"),
    ("AWS", r"AWS|Amazon S3|Amazon Web Services|S3 bucket"), ("Azure", r"Azure|Entra ID"), ("MEGA", r"MEGA(?:\.nz)?\b|Mega\.nz"),
    ("Tor", r"Tor\b(?! ?Browser Bundle)"), ("Microsoft Graph", r"Microsoft Graph"), ("SharePoint", r"SharePoint"),
    ("Teams", r"Microsoft Teams|\bTeams\b"), ("Gmail", r"Gmail"), ("AnyDesk", r"AnyDesk"), ("TeamViewer", r"TeamViewer"),
    ("ScreenConnect", r"ScreenConnect|ConnectWise Control"), ("Atera", r"Atera"), ("Splashtop", r"Splashtop"),
    ("RustDesk", r"RustDesk"), ("Rclone", r"Rclone"), ("Twitter", r"Twitter"), ("Firebase", r"Firebase"),
    ("Yandex", r"Yandex"), ("Box", r"\bBox\.com|\bBox\b cloud"), ("Notion", r"Notion\b"), ("Trello", r"Trello"),
    ("Bitbucket", r"Bitbucket"), ("DigitalOcean", r"DigitalOcean"), ("Vultr", r"Vultr"), ("Okta", r"Okta"),
    ("VPN", r"\bVPNs?\b"),
]
_SERVICES = [(name, re.compile(rf"\b(?:{rx})", re.I if name not in ("Tor", "Box", "MEGA") else 0))
             for name, rx in SERVICES]

# What a link is for, from its technique: the first prefix that matches
ROLES = [
    ("Exploit", ("T1190", "T1203", "T1068", "T1210", "T1211", "T1212", "T1189", "T1195")),
    ("Remote access", ("T1133", "T1219", "T1021", "T1078")),
    ("Exfiltration", ("T1567", "T1041", "T1048", "T1030", "T1537", "T1020")),
    ("C2", ("T1071", "T1102", "T1090", "T1572", "T1573", "T1568", "T1095", "T1104", "T1001", "T1008")),
    ("Phishing", ("T1566", "T1598", "T1534")),
    ("Delivery", ("T1105", "T1608", "T1204")),
    ("Collection", ("T1213", "T1530", "T1538", "T1114", "T1005", "T1039", "T1119", "T1560")),
    ("Infrastructure", ("T1583", "T1584", "T1585", "T1586", "T1587", "T1588")),
    ("Credentials", ("T1555", "T1003", "T1552", "T1110", "T1556", "T1558", "T1539", "T1528")),
    ("Cloud access", ("T1098", "T1580", "T1069", "T1087", "T1526", "T1619")),
]
# Objectives along the bottom: (tactic, label)
OBJECTIVES = [("Credential Access", "Credentials"), ("Lateral Movement", "Lateral movement"),
              ("Collection", "Data collected"), ("Exfiltration", "Data exfiltrated"), ("Impact", "Impact")]

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_LABEL = re.compile(r"^\[(Software|Campaign): ([^\]]+)\]\s*")
_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")


def role(tid: str, tactics: Iterable[str] = ()) -> str:
    for name, prefixes in ROLES:
        if any(tid == p or tid.startswith(p + ".") for p in prefixes):
            return name
    by_tactic = {"Command and Control": "C2", "Exfiltration": "Exfiltration", "Collection": "Collection",
                 "Initial Access": "Access", "Credential Access": "Credentials", "Lateral Movement": "Lateral movement"}
    return next((by_tactic[t] for t in tactics if t in by_tactic), "Uses")


def covered(tid: str, detected: Set[str]) -> bool:
    """A detection for the technique, its parent or one of its sub-techniques."""
    parent = tid.split(".")[0]
    return tid in detected or parent in detected or any(d.split(".")[0] == tid for d in detected)


def _text(procedure: str) -> str:
    """Procedure text without MITRESaw's label and with ATT&CK's links as their names."""
    return _LINK.sub(r"\1", _LABEL.sub("", procedure or "")).strip()


class _Graph:
    def __init__(self):
        self.nodes: Dict[str, Dict] = {}
        self.edges: Dict[tuple, Dict] = {}

    def node(self, nid: str, kind: str, label: str, col: str, **extra) -> Dict:
        n = self.nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label, "col": col, "weight": 0,
                                        "techniques": [], "evidence": [], **extra})
        n["weight"] += 1
        return n

    def edge(self, src: str, dst: str, label: str, tid: Optional[str] = None, name: str = "", evidence: str = "",
             detected: Optional[bool] = None) -> Dict:
        """One link per pair, whatever it's for: AWS reached for cloud access and exfiltration is one arrow."""
        e = self.edges.setdefault((src, dst), {"source": src, "target": dst, "roles": [], "techniques": [],
                                               "evidence": [], "detected": False, "checked": False})
        if label and label not in e["roles"]:
            e["roles"].append(label)
        # A detection decides it even without a technique (an IOC sweep)
        e["checked"] = e["checked"] or detected is not None
        if tid and tid not in [t["id"] for t in e["techniques"]]:
            e["techniques"].append({"id": tid, "name": name, "detected": bool(detected)})
        if evidence and len(e["evidence"]) < 4 and evidence not in e["evidence"]:
            e["evidence"].append(evidence)
        e["detected"] = e["detected"] or bool(detected)
        return e


def build_group(group_name: str, detected: Set[str], csv_path: str = _PROCEDURES_CSV) -> Optional[Dict]:
    """A group's anatomy from ATT&CK's procedures; None when ATT&CK has none for it."""
    try:
        rows = _attributed_rows(os.path.abspath(csv_path), os.path.getmtime(csv_path)).get(group_name.lower(), [])
    except OSError:
        return None
    if not rows:
        return None
    software, campaigns = defaultdict(int), defaultdict(int)
    for row in rows:
        m = _LABEL.match(row.get("procedure_example") or "")
        if m and m.group(1) == "Software":
            name, _, via = m.group(2).partition(" via ")
            software[name] += 1
            if via:
                campaigns[via] += 1
        elif m:
            campaigns[m.group(2)] += 1
    top_sw = sorted(software, key=lambda s: (-software[s], s))[:MAX["software"]]
    top_camp = sorted(campaigns, key=lambda c: (-campaigns[c], c))[:MAX["campaign"]]

    g = _Graph()
    actor = "actor"
    # Tools on the left, the actor alone in the middle under its campaigns, what it reaches on the
    # right: no link has to cross a column, and the objectives hang straight down from the actor
    g.node(actor, "actor", rows[0].get("group_sw_name") or group_name, "b",
           sub=rows[0].get("group_sw_id") or "")
    for c in top_camp:
        g.node("campaign:" + c, "campaign", c, "b", sub="Campaign")
        g.edge(actor, "campaign:" + c, "")
    cve_count, service_count = defaultdict(int), defaultdict(int)
    objective_by = defaultdict(lambda: defaultdict(list))  # tactic -> source -> rows

    for row in rows:
        tid = (row.get("technique_id") or "").upper()
        tname = row.get("technique_name") or tid
        tactics = [t for t in (canonical_tactic(x) for x in (row.get("tactic") or "").split(",")) if t]
        text = _text(row.get("procedure_example") or "")
        m = _LABEL.match(row.get("procedure_example") or "")
        source = actor
        if m and m.group(1) == "Software":
            name, _, via = m.group(2).partition(" via ")
            if name in top_sw:
                source = "software:" + name
                g.node(source, "software", name, "a", sub="Tool")
                parent = "campaign:" + via if via in top_camp else actor
                g.edge(parent, source, "")
        elif m and m.group(2) in top_camp:
            source = "campaign:" + m.group(2)
        hit = covered(tid, detected)
        for cve in dict.fromkeys(c.upper() for c in _CVE.findall(text)):
            cve_count[cve] += 1
            if len(cve_count) <= MAX["cve"] or cve in g.nodes:
                g.node("cve:" + cve, "cve", cve, "c", sub="Exploited")
                g.edge(source, "cve:" + cve, "Exploit", tid, tname, text, hit)
        for name, rx in _SERVICES:
            if rx.search(text) and "software:" + name != source:
                service_count[name] += 1
                nid = "software:" + name if "software:" + name in g.nodes else "service:" + name
                if nid in g.nodes or len([n for n in g.nodes if n.startswith("service:")]) < MAX["service"]:
                    if nid not in g.nodes:
                        g.node(nid, "service", name, "c", sub="Service")
                    g.edge(source, nid, role(tid, tactics), tid, tname, text, hit)
        for tactic in tactics:
            objective_by[tactic][source].append((tid, tname, text, hit))

    # Each objective hangs off the actor, naming the tool that does most of it (Mimikatz -> Credentials)
    for tactic, label in OBJECTIVES:
        by_source = objective_by.get(tactic)
        if not by_source:
            continue
        lead = max(by_source, key=lambda s: (len({t for t, *_ in by_source[s]}), s != actor))
        oid = "objective:" + tactic
        all_rows = [r for rs in by_source.values() for r in rs]
        techniques = {t: (n, h) for t, n, _, h in all_rows}
        sub = f"{len(techniques)} technique{'s' if len(techniques) != 1 else ''}"
        if lead != actor:
            sub += " · " + g.nodes[lead]["label"]
        g.node(oid, "objective", label, "band", sub=sub)
        g.nodes[oid]["techniques"] = [{"id": t, "name": n, "detected": h} for t, (n, h) in sorted(techniques.items())]
        for tid, tname, text, hit in all_rows:
            g.edge(actor, oid, label, tid, tname, text, hit)

    view = _finish(g, kind="group")
    view["stats"].update(software_more=max(0, len(software) - len(top_sw)),
                         cve_more=max(0, len(cve_count) - MAX["cve"]))
    return view


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
    A CVE run's anatomy from its cached research: attacker -> exploit -> CVE -> the product's
    worker -> what it runs -> the infrastructure it reaches, and what the CVE gives the attacker.
    """
    from archer.build.runtime_detection import _workers, runtimes
    from archer.intelligence.cve_hunter import CVEHunter
    from archer.intelligence.cve_label import exploit_name

    paths = list(detection_paths)
    names = [os.path.basename(p) for p in paths]
    has = {kind: any(f"_{kind}_" in n or n.startswith(kind) for n in names)
           for kind in ("Exploit", "RuntimeShell", "IOCSweep")}
    cache_dir = cache_dir or CVEHunter.cache_location()
    g = _Graph()
    g.node("actor", "actor", "Attacker", "a", sub="Unattributed")
    found = False
    for cve in _cve_ids(group_name, paths):
        try:
            with open(os.path.join(cache_dir, f"{cve}.json"), encoding="utf-8") as fh:
                research = json.load(fh)
        except (OSError, ValueError):
            continue
        found = True
        nvd = research.get("nvd_data") or {}
        name = research.get("exploit_name") or exploit_name(nvd, research.get("pocs") or [])
        cvss = (nvd.get("cvss_v3") or {}).get("score")
        product = (nvd.get("product") or "").replace("_", " ")
        product = product.upper() if len(product) <= 6 else product.title() if product.islower() else product
        cid = "cve:" + cve
        # The product rides on the CVE: as its own node it stacked on the worker in one column
        g.node(cid, "cve", cve, "c", sub=" · ".join(x for x in (name, product, f"CVSS {cvss}" if cvss else "") if x),
               evidence=[(nvd.get("description") or "")[:400]] if nvd.get("description") else [])
        for group in _groups_exploiting(cve):  # beside the PoC, so its link doesn't cross it
            g.node("group:" + group, "actor", group, "b", sub="ATT&CK group")
            g.edge("group:" + group, cid, "Exploit", "T1190", "Exploit Public-Facing Application", "", has["Exploit"])
        pocs = [p for p in research.get("pocs") or [] if p.get("type") == "github"]
        exp = research.get("exploit") or {}
        ind = exp.get("indicators") or {}
        request = ", ".join(ind.get("paths") or [])
        if pocs or name:
            pid = "exploit:" + cve
            g.node(pid, "exploit", name or "Public PoC", "b",
                   sub=f"{len(pocs)} public PoC{'s' if len(pocs) != 1 else ''}" if pocs else "Exploit",
                   evidence=[f"{p.get('source')}" + (f" ({p.get('stars')}★)" if p.get("stars") else "")
                             for p in sorted(pocs, key=lambda p: -(p.get("stars") or 0))[:5]])
            g.edge("actor", pid, "")
            src = pid
        else:
            src = "actor"
        g.edge(src, cid, "Exploit", "T1190", "Exploit Public-Facing Application",
               f"Requests to {request}" if request else "", has["Exploit"])
        last = cid
        workers = _workers(runtimes(nvd))
        if workers:
            wid = "process:" + ",".join(workers)
            g.node(wid, "process", " / ".join(w.rstrip("*") for w in workers[:3]), "d", sub="Worker process")
            g.edge(last, wid, "Code execution", "T1190", "Exploit Public-Facing Application", "", has["RuntimeShell"])
            last = wid
        cmds = ind.get("cmd") or []
        if workers or cmds:
            sid = "shell:" + cve
            g.node(sid, "shell", "Shell", "e", sub=(cmds[0] if cmds else "recon / download"),
                   evidence=cmds[:4])
            g.edge(last, sid, "Spawns" if workers else "Code execution", "T1059", "Command and Scripting Interpreter", cmds[0] if cmds else "",
                   has["RuntimeShell"] or covered("T1059", detected))
            last = sid
        refs = (research.get("reference_iocs") or {}).get("iocs") or {}
        seen = set()
        for kind in ("ip", "domain"):
            for value in refs.get(kind) or []:
                value = refang(value)
                if value in seen or len(seen) >= MAX["ioc"]:
                    continue
                seen.add(value)
                g.node("ioc:" + value, "ioc", value, "f", sub=kind.upper() if kind == "ip" else "Domain")
                g.edge(last, "ioc:" + value, "C2 / staging", None, "", "", has["IOCSweep"])
    if not found:
        return None
    # What the run's own technique detections reach, beyond the exploit itself
    for tactic, label in OBJECTIVES:
        hits = sorted(t for t in detected if _tactic_of(t, paths) == tactic)
        if hits:
            oid = "objective:" + tactic
            g.node(oid, "objective", label, "band", sub=f"{len(hits)} detected")
            g.nodes[oid]["techniques"] = [{"id": t, "name": t, "detected": True} for t in hits]
            src = next((n for n in g.nodes if n.startswith("shell:")), "actor")
            for t in hits:
                g.edge(src, oid, label, t, t, "", True)
    return _finish(g, kind="cve")


def _tactic_of(tid: str, paths: List[str]) -> Optional[str]:
    from archer.visualization.flow_view import read_detection

    for p in paths:
        d = read_detection(p)
        if d and d["id"] == tid and d["tactics"]:
            return d["tactics"][0]
    return None


# Layout: columns left to right, objectives along the bottom
COLUMNS = ["a", "b", "c", "d", "e", "f"]
# Top to bottom within a column: a group's campaigns above it, CVEs above services, product above worker
KIND_ORDER = ["campaign", "actor", "exploit", "software", "cve", "service", "product", "process", "shell", "ioc"]
NODE_GAP = 92
TOP = 70
WIDTH = 1100
BAND_GAP = 110


def _into_band(g: _Graph, e: Dict) -> bool:
    return g.nodes[e["target"]]["col"] == "band"


def _finish(g: _Graph, kind: str) -> Dict:
    nodes = list(g.nodes.values())
    cols = [c for c in COLUMNS if any(n["col"] == c for n in nodes)]
    xs = {c: int(110 + i * (WIDTH - 220) / max(1, len(cols) - 1)) if len(cols) > 1 else WIDTH // 2
          for i, c in enumerate(cols)}
    tallest = 0
    by_col = defaultdict(list)
    for n in nodes:
        by_col[n["col"]].append(n)
    for members in by_col.values():
        members.sort(key=lambda n: KIND_ORDER.index(n["kind"]) if n["kind"] in KIND_ORDER else len(KIND_ORDER))
    for c, members in by_col.items():
        if c == "band":
            continue
        tallest = max(tallest, len(members))
    height_main = TOP + max(1, tallest) * NODE_GAP
    for c, members in by_col.items():
        if c == "band":
            continue
        # Centred on the tallest column
        offset = (tallest - len(members)) * NODE_GAP / 2
        for i, n in enumerate(members):
            n["x"], n["y"] = xs[c], int(TOP + offset + i * NODE_GAP)
    band = by_col.get("band", [])
    band_y = height_main + BAND_GAP - NODE_GAP // 2
    for i, n in enumerate(band):
        n["x"] = int(WIDTH * (i + 1) / (len(band) + 1))
        n["y"] = band_y
    height = band_y + 90 if band else height_main + 10

    edges = []
    for e in g.edges.values():
        s, t = g.nodes[e["source"]], g.nodes[e["target"]]
        down = t["col"] == "band" or abs(s["x"] - t["x"]) < 40
        if down and t["y"] < s["y"]:  # a group's campaigns sit above it
            sx, sy, tx, ty = s["x"], s["y"] - 30, t["x"], t["y"] + 66
            c1, c2 = (sx, sy - 10), (tx, ty + 10)
        elif down:
            sx, sy, tx, ty = s["x"], s["y"] + 30, t["x"], t["y"] - 34
            c1, c2 = (sx, sy + (ty - sy) * 0.55), (tx, ty - (ty - sy) * 0.45)
        else:
            sign = 1 if t["x"] > s["x"] else -1
            sx, sy, tx, ty = s["x"] + 34 * sign, s["y"], t["x"] - 38 * sign, t["y"]
            dx = (tx - sx) * 0.5
            c1, c2 = (sx + dx, sy), (tx - dx, ty)
        # Label on the curve towards its target (a cubic Bézier at t = 0.7), clear of the crowd at the source
        t = 0.7
        k = [(1 - t) ** 3, 3 * (1 - t) ** 2 * t, 3 * (1 - t) * t ** 2, t ** 3]
        mx = k[0] * sx + k[1] * c1[0] + k[2] * c2[0] + k[3] * tx
        my = k[0] * sy + k[1] * c1[1] + k[2] * c2[1] + k[3] * ty
        roles = [] if _into_band(g, e) else e["roles"]  # an objective is its own label
        e = dict(e, label=" · ".join(roles[:2]) + (f" +{len(roles) - 2}" if len(roles) > 2 else ""), path=f"M{sx:.0f},{sy:.0f} C{c1[0]:.0f},{c1[1]:.0f} {c2[0]:.0f},{c2[1]:.0f} {tx:.0f},{ty:.0f}",
                 lx=int(mx), ly=int(my),
                 state="detected" if e["detected"] else ("gap" if e["checked"] else "none"))
        edges.append(e)
    # A fan of links with the same label from one source (six IPs, all C2 / staging), or into one
    # target, says it once, mid-fan
    fans = defaultdict(list)
    for e in edges:
        if e["label"]:
            fans[("from", e["source"], e["label"])].append(e)
            fans[("to", e["target"], e["label"])].append(e)
    for fan in sorted(fans.values(), key=len, reverse=True):
        fan = [e for e in fan if e["label"]]
        if len(fan) < 2:
            continue
        fan.sort(key=lambda e: e["ly"])
        for i, e in enumerate(fan):
            if i != len(fan) // 2:
                e["label"] = ""
    links = [e for e in edges if e["checked"]]
    return {
        "kind": kind,
        "width": WIDTH,
        "height": int(height),
        "band_y": band_y - 50 if band else None,
        "nodes": nodes,
        "edges": edges,
        "stats": {"nodes": len(nodes), "links": len(links),
                  "detected": sum(1 for e in links if e["detected"]),
                  "gaps": sum(1 for e in links if not e["detected"])},
    }


def build(group_name: str, detection_paths: Iterable[str], detected: Set[str]) -> Optional[Dict]:
    """The results page's anatomy: a CVE run's from its research, a group's from ATT&CK."""
    paths = list(detection_paths)
    if _CVE.match(group_name):
        return build_cve(group_name, paths, detected)
    return build_group(group_name, detected)

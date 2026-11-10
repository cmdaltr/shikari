"""
The campaign intelligence report: a researched campaign (shikari.intelligence.campaign)
in Word or PDF, in the branded shell, under a TLP label.

Everything is from the campaign's sources and the detection library, except the analyst profile,
which an AI model wrote when one was chosen: its sections are marked † and the disclaimer at the end
says what that means.
"""

from datetime import date
from typing import Dict, List, Optional
from urllib.parse import urlparse

from shikari.intelligence import campaign as campaign_mod
from shikari.reports import assessment_charts as charts
from shikari.reports import assessment_data as data
from shikari.reports import branded, tlp as tlp_mod
from shikari.reports.branded import Table

REPORT_KIND = "Campaign Intelligence Report"
MAX_INDICATORS = 200
TRIAGE = [
    (campaign_mod.ACTIVE, "Active", charts.RED),
    (campaign_mod.UNKNOWN, "Age unknown", charts.GOLD),
    (campaign_mod.BURNED, "Likely burned", charts.WING),
    (campaign_mod.PATTERN, "Infrastructure pattern", charts.INK),
]
TRIAGE_COLOUR = {k: c for k, _, c in TRIAGE}
COVERAGE = [("covered", "Detection in the library", charts.CHESTNUT), ("gap", "No detection yet", charts.WING)]
_KIND = {"ip": "IP address or range", "domain": "Domain", "hash": "File hash"}
_OTHER = {"cmd": "Commands", "reg": "Registry keys", "evt": "Event IDs", "sw": "Software and processes",
          "file": "Files and paths"}


def context(campaign: Dict, generate_dir: str, tlp: str = "", today: Optional[date] = None) -> Dict:
    """The campaign with what the report adds: the library's detections per technique and the label."""
    library = data.library_index(generate_dir)
    techniques = []
    for t in campaign.get("techniques") or []:
        found = library.get(t["id"]) or []
        techniques.append({**t, "detections": len(found), "detections_ai": any(d["ai"] for d in found)})
    return {**campaign, "techniques": techniques, "tlp": tlp_mod.normalise(tlp),
            "report_date": (today or date.today()).isoformat(),
            "covered": sum(1 for t in techniques if t["detections"]),
            "library_ai": any(t["detections_ai"] for t in techniques)}


def _publisher(url: str) -> str:
    host = urlparse(url).hostname or url
    return host[4:] if host.startswith("www.") else host


def _mark(flag: bool) -> str:
    return f" {data.AI_MARK}" if flag else ""


def executive_paragraphs(c: Dict) -> List[str]:
    n = c["sources_read"]
    span = ""
    if c["timeline"]:
        first, last = c["timeline"][0]["date"], c["timeline"][-1]["date"]
        span = f", published {first}" if first == last else f", published between {first} and {last}"
    counts = c["triage_counts"]
    out = [f"This report profiles the campaign {c['name']} from {data.plural(n, 'source')}{span}. "
           f"Together they describe {data.plural(len(c['techniques']), 'ATT&CK technique')} and "
           f"{data.plural(len(c['indicators']), 'network or file indicator')}."]
    if c["indicators"]:
        out.append(f"{data.plural(counts.get(campaign_mod.ACTIVE, 0), 'indicator')} "
                   f"{'is' if counts.get(campaign_mod.ACTIVE, 0) == 1 else 'are'} recent enough to hunt for now; "
                   f"{counts.get(campaign_mod.BURNED, 0)} are probably burned, "
                   f"{counts.get(campaign_mod.PATTERN, 0)} describe infrastructure rather than a single host, and "
                   f"{counts.get(campaign_mod.UNKNOWN, 0)} come from sources without a publication date.")
    if c["techniques"]:
        gap = len(c["techniques"]) - c["covered"]
        out.append(f"The Shikari detection library already has detections for {c['covered']} of the "
                   f"{len(c['techniques'])} techniques{'' if not gap else f'; {gap} have none yet'}.")
    if c["groups"]:
        named = ", ".join(f"{g['name']} ({data.plural(g['sources'], 'source')})" for g in c["groups"])
        out.append(f"The sources name {named}.")
    else:
        out.append("None of the sources names an ATT&CK group.")
    return out


def sources_table(c: Dict) -> Table:
    rows = [[str(i + 1), s["title"], _publisher(s["url"]), s["published"] or "Not given", str(s["techniques"]),
             str(s["iocs"])] for i, s in enumerate(x for x in c["sources"] if x["success"])]
    return ["#", "Source", "Publisher", "Published", "Techniques", "Indicators"], rows, [0.8, 7.4, 3.4, 2.2, 1.7, 1.7], {}


def groups_table(c: Dict) -> Table:
    return ["Group named", "Sources"], [[g["name"], str(g["sources"])] for g in c["groups"]], [12.0, 5.0], {}


def timeline_table(c: Dict) -> Table:
    return ["Date", "Reported by", "Report"], [[e["date"], _publisher(e["url"]), e["title"]] for e in c["timeline"]], \
        [2.6, 4.0, 10.6], {}


def techniques_table(c: Dict) -> Table:
    rows, fills = [], {}
    for i, t in enumerate(c["techniques"]):
        rows.append([t["id"], t["name"] or "Not in ATT&CK", ", ".join(t["tactics"]) or "Unmapped", str(t["sources"]),
                     (str(t["detections"]) + _mark(t["detections_ai"])) if t["detections"] else "None"])
        fills[(i, 4)] = charts.CHESTNUT if t["detections"] else charts.WING
    return ["ID", "Technique", "Tactics", "Sources", "Detections"], rows, [2.0, 6.2, 4.6, 1.6, 2.6], fills


def indicators_table(c: Dict) -> Table:
    order = {k: i for i, (k, _, _) in enumerate(TRIAGE)}
    shown = sorted(c["indicators"], key=lambda i: (order.get(i["triage"], 9), i["kind"], i["value"]))[:MAX_INDICATORS]
    rows, fills = [], {}
    for r, i in enumerate(shown):
        rows.append([i["value"], _KIND.get(i["kind"], i["kind"]), i["triage"], i["last_seen"] or "Not given",
                     str(i["sources"])])
        fills[(r, 2)] = TRIAGE_COLOUR.get(i["triage"], charts.WING)
    return ["Indicator", "Type", "Triage", "Newest source", "Sources"], rows, [6.6, 3.2, 3.4, 2.4, 1.6], fills


def triage_method() -> Table:
    rows = [
        ["Active", f"An IP, domain or URL from a source no more than {campaign_mod.NETWORK_DAYS} days old, or a hash "
                   f"from one no more than {campaign_mod.HASH_DAYS} days old. Hunt for it now."],
        ["Likely burned", "Older than that. Attackers rotate infrastructure quickly; search historical logs, but "
                          "don't expect it in new activity."],
        ["Infrastructure pattern", "A CIDR range, a wildcard domain or an ASN. It describes the infrastructure "
                                   "rather than one host: use it to pivot and to scope blocks."],
        ["Age unknown", "No source citing it gives a publication date. Treat it as active until checked."],
    ]
    fills = {(i, 0): TRIAGE_COLOUR[k] for i, (k, _, _) in enumerate(
        [TRIAGE[0], TRIAGE[2], TRIAGE[3], TRIAGE[1]])}
    return ["Triage", "Meaning"], rows, [4.0, 13.0], fills


def unread_table(c: Dict) -> Table:
    rows = [[s["url"], s["error"]] for s in c["sources"] if not s["success"]]
    return ["Source", "Why it wasn't read"], rows, [9.0, 8.0], {}


def _figures(c: Dict) -> Dict[str, bytes]:
    figs = {}
    if c["indicators"]:
        figs["triage"] = charts.donut(c["triage_counts"], scheme=TRIAGE, centre_label="indicators")
    if c["techniques"]:
        columns: Dict[str, list] = {}
        for t in c["techniques"]:
            columns.setdefault((t["tactics"] or ["Unmapped"])[0], []).append(
                (t["id"], "covered" if t["detections"] else "gap"))
        figs["matrix"] = charts.coverage_matrix(columns, scheme=COVERAGE)
    return figs


def cover(c: Dict) -> branded.Cover:
    lines = [f"First reported: {c['first_reported']}"] if c.get("first_reported") else []
    return branded.Cover(kind=REPORT_KIND, title=c["name"], date=c["report_date"], tlp=c["tlp"], lines=lines)


def blocks(c: Dict, figs: Dict[str, bytes]) -> List[tuple]:
    p = c.get("profile") or {}
    ai = bool(c.get("ai") and p)
    out: List[tuple] = [("section", "Executive Summary")]
    out += [("para", t) for t in executive_paragraphs(c)]
    if ai and p.get("summary"):
        out += [("sub", f"Analyst profile {data.AI_MARK}"), ("para", p["summary"])]

    out += [("section", "Sources"),
            ("para", "The reports this profile is built from. Each was read by the same analyser as Upload blog URL: "
                     "ATT&CK technique IDs and the commands that imply them, the indicators, and the groups named.")]
    if c["sources_read"]:
        out.append(("table", sources_table(c), "Sources read", False))
    else:
        out.append(("para", "No source could be read."))

    out.append(("section", "Attribution" + _mark(ai and bool(p.get("actor") or p.get("motivation")))))
    if c["groups"]:
        out.append(("table", groups_table(c), "ATT&CK groups the sources name", True))
    else:
        out.append(("para", "None of the sources names an ATT&CK group, so the campaign isn't attributed here."))
    if ai and p.get("actor"):
        out += [("sub", f"The actor {data.AI_MARK}"), ("para", p["actor"])]
    if ai and p.get("motivation"):
        out += [("sub", f"Motivation {data.AI_MARK}"), ("para", p["motivation"])]
    victims = p.get("victims") or {}
    if ai and (victims.get("sectors") or victims.get("regions") or victims.get("notes")):
        out.append(("sub", f"Victims {data.AI_MARK}"))
        rows = [[k, ", ".join(victims.get(k.lower()) or []) or "Not stated"] for k in ("Sectors", "Regions")]
        out.append(("table", (["Victims", "Detail"], rows, [4.0, 13.0], {}), "Victimology", True))
        if victims.get("notes"):
            out.append(("para", victims["notes"]))

    out.append(("section", "Timeline" + _mark(ai and bool(p.get("timeline")))))
    if c["timeline"]:
        out.append(("table", timeline_table(c), "When the sources were published", False))
    else:
        out.append(("para", "None of the sources gives a publication date."))
    if ai and p.get("timeline"):
        out += [("sub", f"Events the sources describe {data.AI_MARK}"),
                ("table", (["When", "Event"], [[e.get("date") or "", e["event"]] for e in p["timeline"]],
                           [3.0, 14.0], {}), "Campaign events", True)]

    out.append(("section", "Techniques"))
    if c["techniques"]:
        out.append(("para", "Techniques by the number of sources that describe them. Each is coloured by whether "
                            "the detection library has a detection for it, from any group."))
        if "matrix" in figs:
            out.append(("figure", figs["matrix"], "The campaign's techniques by tactic, coloured by library coverage", 17.0))
        out.append(("table", techniques_table(c), "Techniques", True))
    else:
        out.append(("para", "The sources don't describe any ATT&CK techniques."))
    if ai and p.get("tooling"):
        out += [("sub", f"Tooling {data.AI_MARK}"),
                ("table", (["Tool", "Purpose"], [[t["name"], t.get("purpose") or ""] for t in p["tooling"]],
                           [5.0, 12.0], {}), "Tools the sources describe", True)]

    out.append(("section", "Indicators"))
    if c["indicators"]:
        out.append(("para", "Network and file indicators, triaged by the age of the newest source that cites them "
                            "(Appendix A). Active indicators come first."))
        if "triage" in figs:
            out.append(("figure", figs["triage"], "Indicators by triage", 14.0))
        out.append(("table", indicators_table(c), "Indicators", False))
        if len(c["indicators"]) > MAX_INDICATORS:
            out.append(("para", f"The first {MAX_INDICATORS} of {len(c['indicators'])} are shown; the full list is "
                                "in the campaign's export from Shikari."))
    else:
        out.append(("para", "The sources don't give any network or file indicators."))
    other = c.get("other_iocs") or {}
    for kind, label in _OTHER.items():
        if other.get(kind):
            out += [("sub", label), ("bullets", other[kind][:40])]

    out += [("section", "Detections"),
            ("para", f"The library has detections for {c['covered']} of the campaign's "
                     f"{len(c['techniques'])} techniques. Generating detections for the campaign builds them for "
                     f"every technique and active indicator here, in each SIEM you use, saved under "
                     f"{c['group'].replace('_', ' ')}."),
            ("para", "For Defender XDR, the master hunt query combines them into one advanced hunting query that "
                     "ranks devices by how many of the campaign's techniques they show.")]

    out += [("section", "Appendices"), ("sub", "Appendix A: Indicator triage"),
            ("table", triage_method(), "How indicators are triaged", True)]
    if any(not s["success"] for s in c["sources"]):
        out += [("sub", "Appendix B: Sources not read"), ("table", unread_table(c), "Sources not read", False)]
    out.append(("note", disclaimer(c)))
    return out


def disclaimer(c: Dict) -> List[str]:
    m = data.AI_MARK
    ai = bool(c.get("ai") and c.get("profile"))
    out = [f"{m} AI-assisted content. Items marked {m} were generated or influenced by an AI model (a large "
           f"language model){' that read the sources' if ai else ''}, or cite detections written with AI when the "
           "Shikari detection library was built. AI output can be incomplete or wrong. These items have not been "
           "independently verified for this report and are provided without warranty of any kind: check them "
           "against the sources before relying on them."]
    out.append("Everything else is extracted directly from the sources and the detection library, without AI."
               + ("" if ai or c.get("library_ai") else f" Nothing in this report is marked {m}."))
    return out


def to_docx(c: Dict, figs: Optional[Dict[str, bytes]] = None) -> bytes:
    return branded.to_docx(cover(c), blocks(c, figs if figs is not None else _figures(c)))


def to_pdf(c: Dict, figs: Optional[Dict[str, bytes]] = None) -> bytes:
    return branded.to_pdf(cover(c), blocks(c, figs if figs is not None else _figures(c)))


def render(c: Dict, fmt: str) -> bytes:
    """The report as 'docx' or 'pdf'."""
    return branded.render(cover(c), blocks(c, _figures(c)), fmt)

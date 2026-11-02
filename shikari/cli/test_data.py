"""
Sample data for a guided tour of Shikari (`shikari-cli test populate`).

Seeds one cohesive, clearly-labelled scenario — a fictional group **SampleSpider** and a fictional
company **sample-corp.example** — across every surface that displays data, so you can see where and
how each kind of data appears and is accessed. Everything it creates is recorded in a manifest
(``data/.sample_data_manifest.json``) and removed exactly by ``shikari-cli test depopulate``, so it
never gets confused with real work and never lingers in the Library.

Subcommands: populate [--force] [--user EMAIL] · depopulate · status.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta

import yaml

from shikari.config import DATA_DIR, GENERATE_DIR, CORRELATE_DIR

PROFILES_DIR = os.path.join(DATA_DIR, "profiles")
RUNS_DIR = os.path.join(DATA_DIR, "runs")
MANIFEST = os.path.join(DATA_DIR, ".sample_data_manifest.json")

GROUP = "SampleSpider"
DOMAIN = "sample-corp.example"
TAG = f"{GROUP} (Group)"
LABEL = "[SAMPLE]"

# (technique_id, name, tactic, mde_table, udm_event_type, mde_predicate, udm_predicate, indicators)
TECHNIQUES = [
    ("T1566.001", "Spearphishing Attachment", "Initial Access", "DeviceFileEvents", "FILE_CREATION",
     'FileName endswith ".iso" or FileName endswith ".lnk"',
     'target.file.full_path = /\\.(iso|lnk)$/ nocase',
     {"file": ["invoice_q4.iso", "statement.lnk"]}),
    ("T1059.001", "PowerShell", "Execution", "DeviceProcessEvents", "PROCESS_LAUNCH",
     'FileName =~ "powershell.exe" and ProcessCommandLine has_any("-enc", "IEX", "DownloadString")',
     'target.process.file.full_path = /powershell\\.exe/ nocase and target.process.command_line = /-enc|IEX|DownloadString/ nocase',
     {"cmd": ["powershell -enc", "IEX (New-Object Net.WebClient).DownloadString"]}),
    ("T1003.001", "LSASS Memory", "Credential Access", "DeviceProcessEvents", "PROCESS_LAUNCH",
     'ProcessCommandLine has_any("procdump", "comsvcs.dll") and ProcessCommandLine has "lsass"',
     'target.process.command_line = /procdump|comsvcs\\.dll/ nocase and target.process.command_line = /lsass/ nocase',
     {"cmd": ["procdump -ma lsass.exe", "rundll32 comsvcs.dll MiniDump"], "sw": ["lsass.exe"]}),
]


def _detection_doc(tid, name, tactic, vendor, table_or_et, query, indicators):
    connector = "MicrosoftThreatProtection" if vendor == "mde" else "GoogleSecOps"
    return {
        "name": name,
        "technique_id": tid,
        "description": f"{LABEL} Sample detection — {GROUP} using {name}. Remove with `shikari-cli test depopulate`.",
        "severity": "High",
        "requiredDataConnectors": [{"connectorId": connector, "dataTypes": [table_or_et]}],
        "queryFrequency": "1d", "queryPeriod": "1d", "triggerOperator": "gt", "triggerThreshold": 0,
        "tactics": [tactic],
        "tags": [TAG],
        "query": query,
        "indicators": indicators,
    }


def _write_yaml(path, doc):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# {LABEL} sample data — shikari-cli test populate\n")
        yaml.dump(doc, f, sort_keys=False, allow_unicode=True, width=10000)


def _mde_query(table, predicate):
    return (f"{table}\n| where Timestamp > ago(1d)\n| where {predicate}\n"
            f"| summarize Events = count(), FirstSeen = min(Timestamp) by DeviceName, AccountName, "
            f"InitiatingProcessCommandLine")


def _resolve_user(db, email):
    from shikari.database.models import User, UserRole
    user = None
    if email:
        user = db.query(User).filter(User.email == email).first()
    if not user:
        user = db.query(User).filter(User.role == UserRole.ADMIN).order_by(User.id).first()
    if not user:
        user = db.query(User).order_by(User.id).first()
    return user


# --------------------------------------------------------------------------- populate

def populate(force=False, email=""):
    if os.path.exists(MANIFEST):
        if not force:
            print(f"Sample data already present ({MANIFEST}).\n"
                  f"Run `shikari-cli test depopulate` first, or `shikari-cli test populate --force`.")
            return 1
        depopulate()

    for d in (GENERATE_DIR, CORRELATE_DIR, PROFILES_DIR, RUNS_DIR):
        os.makedirs(d, exist_ok=True)

    manifest = {"created_at": time.time(), "group": GROUP, "domain": DOMAIN,
                "files": [], "db": {}, "db_user_id": None}

    # 1) Detections (one MDE + one SecOps per technique)
    det_files = []
    for tid, name, tactic, table, udm, mde_pred, udm_pred, iocs in TECHNIQUES:
        compact = tid.replace(".", "_")
        mde = _detection_doc(tid, name, tactic, "mde", table, _mde_query(table, mde_pred), iocs)
        mde_path = os.path.join(GENERATE_DIR, f"{GROUP}_{compact}_KQL.yaml")
        _write_yaml(mde_path, mde)
        det_files.append(mde_path)

        udm_doc = _detection_doc(tid, name, tactic, "secops", udm,
                                 f'metadata.event_type = "{udm}" and {udm_pred}', iocs)
        udm_path = os.path.join(GENERATE_DIR, f"{GROUP}_{compact}_UDM.yaml")
        _write_yaml(udm_path, udm_doc)
        det_files.append(udm_path)
    manifest["files"].extend(det_files)
    print(f"  detections   {len(det_files)} YAMLs in {GENERATE_DIR}  →  Detections → Results (hunt '{GROUP}'), Coverage, Library")

    # 2) Run record (so the group lists in Results / export dropdowns)
    run_path = os.path.join(RUNS_DIR, f"{GROUP}.json")
    with open(run_path, "w", encoding="utf-8") as f:
        json.dump({"group": GROUP, "started_at": time.time(), "completed_at": time.time(),
                   "files": [os.path.basename(p) for p in det_files], "no_detection": [],
                   "kept_edited": [], "sample": True}, f, indent=2)
    manifest["files"].append(run_path)
    print(f"  run          {run_path}  →  /results?group_name={GROUP}")

    # 3) Correlations — a same-vendor chain plus a cross-vendor playbook, in the shape the engine
    #    emits, so the Results correlation sections render (the sample set is small, so this is
    #    crafted rather than engine-derived).
    corr_path = os.path.join(CORRELATE_DIR, f"{GROUP}.json")
    with open(corr_path, "w", encoding="utf-8") as f:
        json.dump(_sample_correlations(), f, indent=2)
    manifest["files"].append(corr_path)
    print(f"  correlations {corr_path}  →  Results (correlations + cross-vendor playbooks)")

    # 4) Company profile (Catalogue, Exposure map, Review)
    prof_path = os.path.join(PROFILES_DIR, f"{DOMAIN.replace('.', '_')}_profile.json")
    with open(prof_path, "w", encoding="utf-8") as f:
        json.dump(_sample_profile(), f, indent=2)
    manifest["files"].append(prof_path)
    print(f"  company      {prof_path}  →  Intel → Catalogue, /exposure?domain={DOMAIN}, /review")

    # 5) Database: threat library + an assessment (per user)
    _seed_db(manifest, email)

    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nManifest: {MANIFEST}")
    print(f"Remove everything with: shikari-cli test depopulate")
    return 0


def _udm_path(tid):
    return f"data/groups/{GROUP}_{tid.replace('.', '_')}_UDM.yaml"


def _kql_path(tid):
    return f"data/groups/{GROUP}_{tid.replace('.', '_')}_KQL.yaml"


def _sample_correlations():
    names = {t[0]: t[1] for t in TECHNIQUES}
    tactics = {t[0]: t[2] for t in TECHNIQUES}
    order = [t[0] for t in TECHNIQUES]  # T1566.001, T1059.001, T1003.001

    # A same-vendor (SecOps) chain across all three techniques.
    vendor_corr = [{
        "vendor": "googlesecops",
        "a": _udm_path(order[0]),
        "b": [_udm_path(order[1]), _udm_path(order[2])],
        "chain": True,
        "techniques_involved": [names[t] for t in order],
        "tactics": [tactics[t] for t in order],
        "relevance_score": 0.9,
        "query_a": "", "query_b": "",
        "combined_query": ("// SampleSpider chain: Spearphishing Attachment -> PowerShell -> LSASS Memory, "
                           "same host within 1h\n$e1.metadata.event_type = \"FILE_CREATION\"\n"
                           "$e2.metadata.event_type = \"PROCESS_LAUNCH\"\nmatch: $host over 1h"),
        "file": f"{GROUP}/{GROUP}_chain_UDM.yaml",
    }]

    # Per-vendor query objects for a cross-vendor playbook stage.
    def stage(tid):
        return {
            "technique_id": tid, "technique_name": names[tid], "tactic": tactics[tid],
            "vendors": {
                "googlesecops": {"query": f'metadata.event_type = "PROCESS_LAUNCH" // {names[tid]}',
                                 "file": _udm_path(tid), "label": "Google SecOps"},
                "mde": {"query": f'DeviceProcessEvents | where Timestamp > ago(1d) // {names[tid]}',
                        "file": _kql_path(tid), "label": "Microsoft Defender XDR"},
            },
        }

    cross_vendor = [{
        "correlation_id": "xv_sample01",
        "type": "cross_vendor",
        "techniques_involved": [names[t] for t in order],
        "tactics": [tactics[t] for t in order],
        "vendors": ["googlesecops", "mde"],
        "vendor_labels": ["Google SecOps", "Microsoft Defender XDR"],
        "attack_chain_length": len(order),
        "relevance_score": 0.9,
        "time_window": "1h",
        "join_keys": [{"entity": "host",
                       "fields": {"googlesecops": "principal.hostname", "mde": "DeviceName",
                                  "splunk": "host", "elastic": "host.name"}},
                      {"entity": "user",
                       "fields": {"googlesecops": "principal.user.userid", "mde": "AccountName",
                                  "splunk": "user", "elastic": "user.name"}}],
        "stages": [stage(t) for t in order],
    }]
    return {"vendor_correlations": vendor_corr, "cross_vendor_correlations": cross_vendor}


def _sample_profile():
    now = datetime.utcnow().isoformat()
    return {
        "domain": DOMAIN,
        "timestamp": now,
        "company_info": {
            "domain": DOMAIN, "company_name": f"{LABEL} Sample Corp", "organization": "Sample Corp Ltd",
            "country": "United Kingdom", "mail_provider": "Microsoft 365",
            "ip_addresses": ["203.0.113.10", "203.0.113.11"],
        },
        "risk_score": 62,
        "recommended_groups": [GROUP, "APT41", "FIN13"],
        "recommended_techniques": [t[0] for t in TECHNIQUES],
        "osint": {"subdomains": ["mail.sample-corp.example", "vpn.sample-corp.example", "portal.sample-corp.example"],
                  "ip_addresses": ["203.0.113.10", "203.0.113.11"], "asns": ["AS64500"],
                  "hosting": ["United Kingdom"]},
        "breach_surface": {"breaches": 1, "exposed_accounts": 3},
        "exposed_services": {"per_ip": [], "ports": [25, 443], "cpes": [], "vulns": [], "hostnames": []},
        "detected_stack": {"web_server": "nginx"},
        "sample": True,
    }


def _seed_db(manifest, email):
    from shikari.database.db import SessionLocal
    from shikari.database.models import (ThreatTestCase, Assessment, AssessmentResult,
                                        LibraryDetection, DetectionType, VisibilityType)
    db = SessionLocal()
    try:
        user = _resolve_user(db, email or os.getenv("SHIKARI_EMAIL", ""))
        if not user:
            print("  database     skipped — no user found (create an account first)")
            return
        manifest["db_user_id"] = user.id
        tc_ids, res_ids, lib_ids = [], [], []

        test_cases = []
        for t in TECHNIQUES:
            tid, name, tactic, iocs = t[0], t[1], t[2], t[7]
            proc = f"{LABEL} {GROUP} procedure for {name}"
            tc = ThreatTestCase(
                user_id=user.id, signature=hashlib.sha1(f"{tid}|{proc}".encode()).hexdigest()[:40],
                technique_id=tid, technique_name=name, tactic=tactic, group_name=GROUP,
                procedure=proc, indicators=json.dumps(iocs), prevalence=3,
                source=f"{LABEL} group:{GROUP}")
            db.add(tc); db.flush(); tc_ids.append(tc.id); test_cases.append(tc)

        assessment = Assessment(user_id=user.id, name=f"{LABEL} Q4 Purple Team",
                                target=DOMAIN, operator="sample", run_date=datetime.utcnow().date().isoformat(),
                                notes=f"{LABEL} Example assessment — remove with shikari-cli test depopulate")
        db.add(assessment); db.flush()
        outcomes = [("executed", "alerted"), ("executed", "logged"), ("blocked", "prevented")]
        for tc, (red, blue) in zip(test_cases, outcomes):
            r = AssessmentResult(assessment_id=assessment.id, user_id=user.id, test_case_id=tc.id,
                                 technique_id=tc.technique_id, technique_name=tc.technique_name,
                                 tactic=tc.tactic, red_outcome=red, blue_outcome=blue)
            db.add(r); db.flush(); res_ids.append(r.id)

        # A couple of saved Library detections
        for tid, name, tactic, *_ in TECHNIQUES[:2]:
            lib = LibraryDetection(
                user_id=user.id, title=f"{LABEL} {name} ({tid})", detection_type=DetectionType.DETECTION,
                visibility=VisibilityType.PRIVATE,
                content=json.dumps({"technique_id": tid, "query": "sample", "platform": "mde"}),
                platform="mde", tags=json.dumps([LABEL, GROUP]))
            db.add(lib); db.flush(); lib_ids.append(lib.id)

        db.commit()
        manifest["db"] = {"threat_test_cases": tc_ids, "assessments": [assessment.id],
                          "assessment_results": res_ids, "library_detections": lib_ids}
        print(f"  database     {len(tc_ids)} test cases, 1 assessment, {len(lib_ids)} library detections "
              f"(user {user.email})  →  Build → Assessments, Detections → Library")
    except Exception as e:
        db.rollback()
        print(f"  database     skipped ({e})")
    finally:
        db.close()


# --------------------------------------------------------------------------- depopulate / status

def _load_manifest():
    try:
        with open(MANIFEST, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def depopulate():
    m = _load_manifest()
    if not m:
        print("No sample data manifest found — nothing to remove.")
        return 0
    removed = 0
    for path in m.get("files", []):
        try:
            os.remove(path); removed += 1
        except OSError:
            pass
    print(f"  removed {removed} file(s)")

    db_ids = m.get("db") or {}
    if any(db_ids.values()):
        from shikari.database.db import SessionLocal
        from shikari.database.models import (ThreatTestCase, Assessment, AssessmentResult, LibraryDetection)
        model = {"threat_test_cases": ThreatTestCase, "assessments": Assessment,
                 "assessment_results": AssessmentResult, "library_detections": LibraryDetection}
        db = SessionLocal()
        try:
            n = 0
            # results first (FK to assessments/test cases)
            for key in ("assessment_results", "library_detections", "assessments", "threat_test_cases"):
                for rid in db_ids.get(key, []):
                    row = db.get(model[key], rid)
                    if row:
                        db.delete(row); n += 1
            db.commit()
            print(f"  removed {n} database row(s)")
        except Exception as e:
            db.rollback(); print(f"  database removal error: {e}")
        finally:
            db.close()

    try:
        os.remove(MANIFEST)
    except OSError:
        pass
    print("Sample data removed.")
    return 0


def status():
    m = _load_manifest()
    if not m:
        print("No sample data present. Add it with `shikari-cli test populate`.")
        return 0
    files = [p for p in m.get("files", []) if os.path.exists(p)]
    db = m.get("db") or {}
    when = datetime.fromtimestamp(m.get("created_at", 0)).strftime("%Y-%m-%d %H:%M")
    print(f"Sample data present (created {when}):")
    print(f"  group:   {m.get('group')}")
    print(f"  company: {m.get('domain')}")
    print(f"  files:   {len(files)} present of {len(m.get('files', []))} recorded")
    print(f"  db rows: " + ", ".join(f"{k}={len(v)}" for k, v in db.items()) if db else "  db rows: none")
    print("Remove with `shikari-cli test depopulate`.")
    return 0


def state():
    """Structured presence summary for the web toggle (no printing)."""
    m = _load_manifest()
    if not m:
        return {"present": False, "group": GROUP, "domain": DOMAIN}
    files = m.get("files", [])
    db = m.get("db") or {}
    return {
        "present": True,
        "group": m.get("group", GROUP),
        "domain": m.get("domain", DOMAIN),
        "created_at": m.get("created_at"),
        "files_recorded": len(files),
        "files_present": sum(1 for p in files if os.path.exists(p)),
        "db_counts": {k: len(v) for k, v in db.items()},
        "db_user_id": m.get("db_user_id"),
    }


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(prog="shikari-cli test",
                                     description="Sample data for a guided tour of Shikari.")
    sub = parser.add_subparsers(dest="action")
    p = sub.add_parser("populate", help="seed the sample scenario")
    p.add_argument("--force", action="store_true", help="replace existing sample data")
    p.add_argument("--user", default="", help="email of the user to own the DB rows (default: an admin)")
    sub.add_parser("depopulate", help="remove everything populate created")
    sub.add_parser("status", help="show what sample data is present")
    args = parser.parse_args(argv)

    if args.action == "populate":
        return populate(force=args.force, email=args.user)
    if args.action == "depopulate":
        return depopulate()
    if args.action == "status":
        return status()
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

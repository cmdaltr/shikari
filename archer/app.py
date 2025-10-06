from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# -----------------------------------------------------------------------------
# Archer service - main FastAPI application
#
# This module wires up the web application, mounts static assets, loads
# MITRE ATT&CK data into `app.state` on startup, and exposes the public
# HTTP endpoints used by the front-end templates (index, generate,
# manual submission, draft saving/loading, and progress). Comments in
# this file explain the purpose of each handler and the shape of data
# passed between client and server.
# -----------------------------------------------------------------------------

# from archer.build import define_vectr_values
from archer.mitre import (
    get_stix_data,
    obtain_all_techniques,
    obtain_technique_descriptions,
)
from archer.mitre.enterprise import check_group_in_mitre
from archer.build.orchestrator import process_group
from archer.genai import process_genai
from datetime import datetime
import os
import json
import threading
from archer.build.progress import read_progress, write_progress


templates = Jinja2Templates(directory="templates")

app = FastAPI(title="Archer Threat Hunting Service")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Resetting latest.yaml to blank on startup
with open(os.path.join("data", "generate", "latest.yaml"), "w") as latest_yaml:
    latest_yaml.write("")


# Cache-busting token for static assets
@app.on_event("startup")
async def _set_asset_version():
    app.state.asset_version = datetime.now().strftime("%Y%m%d%H%M%S")


# Cleanup old drafts on startup (default: 30 days)
@app.on_event("startup")
def cleanup_old_drafts():
    """
    Remove draft files older than DRAFT_MAX_AGE_DAYS from data/drafts.

    This is a housekeeping task executed once during app startup. If the
    drafts directory doesn't exist we simply return. Any exceptions are
    caught and ignored because cleanup is non-fatal.
    """
    drafts_dir = os.path.join("data", "drafts")
    if not os.path.exists(drafts_dir):
        return
    try:
        max_age_days = int(os.environ.get("DRAFT_MAX_AGE_DAYS", "30"))
        cutoff = (
            datetime.utcnow() - __import__("datetime").timedelta(days=max_age_days)
        ).timestamp()
        for root, dirs, files in os.walk(drafts_dir):
            for fname in files:
                path = os.path.join(root, fname)
                try:
                    if os.path.getmtime(path) < cutoff:
                        os.remove(path)
                except Exception:
                    # If a single file can't be removed, continue
                    pass
    except Exception:
        # non-fatal: don't prevent the app from starting if cleanup fails
        pass


def get_mitre_lists():
    """
    Helper to return (tactics, techniques) used by templates.

    - tactics: ordered list of ATT&CK tactic names (filtered to an opinionated
      ordering defined by mitre_order).
    - techniques: cached list of technique display names stored in app.state
    """
    mitre_order = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command And Control",
        "Exfiltration",
        "Impact",
    ]
    bundle = getattr(app.state, "bundle", None)
    if bundle:
        tactics = [
            phase["phase_name"].title().replace("-", " ")
            for obj in getattr(bundle, "objects", [])
            if obj.get("type") == "attack-pattern" and "kill_chain_phases" in obj
            for phase in obj["kill_chain_phases"]
        ]
        tactics = list(dict.fromkeys(tactics))
        tactics = [t for t in mitre_order if t in tactics]
    else:
        tactics = []
    techniques = getattr(app.state, "techniques_to_choose", [])
    return tactics, techniques


# Load MITRE data on startup and cache in app.state
@app.on_event("startup")
def load_mitre_data():
    # Download the MITRE ATT&CK STIX bundle and cache useful indexes in
    # app.state so template handlers can access them without repeated network
    # calls. These calls are synchronous during startup to ensure the data
    # is available for user requests.
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    bundle = get_stix_data(url)
    app.state.bundle = bundle
    app.state.techniques_to_choose = obtain_all_techniques(bundle)
    app.state.technique_descriptions = obtain_technique_descriptions(bundle)


@app.get("/", response_class=HTMLResponse)
def read_form(request: Request):
    # Render the index page where the user can enter a group name. The
    # template expects a `request` object and optionally lists of
    # techniques; other placeholders are provided for future features.
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "techniques": getattr(app.state, "techniques_to_choose", []),
            "message": None,
            "actor_found": None,
            "wait_message": None,
            "js_script": None,
        },
    )


# POST handler for Generate button
from fastapi.responses import RedirectResponse, JSONResponse
import json
import os


@app.post("/generate")
async def generate(
    request: Request,
    group_name: str = Form(...),
    advanced_parsing: str = Form(None),
    semantic: str = Form(None),
    ai_generators: str = Form(None),
    local_llm: str = Form(None),
    run_correlation: str = Form(None),
    run_emulation: str = Form(None),
    emulation_mode: str = Form("simulate"),
    vectr_export: str = Form(None),
    vectr_campaign_name: str = Form(None),
):
    # Called when the user clicks Generate on the index page. We first
    # check whether the provided group name maps to a known MITRE actor.

    # Determine GENAI_MODE based on checkboxes (priority order)
    genai_mode = None
    if local_llm == "true":
        genai_mode = "local_llm"
    elif ai_generators == "true":
        genai_mode = "ai_generators"
    elif semantic == "true":
        genai_mode = "semantic"
    elif advanced_parsing == "true":
        genai_mode = "advanced_parsing"
    # If none selected, genai_mode remains None (uses default/heuristic)

    actor_found = check_group_in_mitre(app.state.bundle, group_name)
    if actor_found == "Y":
        # Known actor: kick off processing in a background thread and immediately return a JSON
        # payload containing a redirect URL so the front-end can navigate to the progress page.
        hypothesis = "Generated from form"

        def _bg():
            try:
                # Use the modified wrapper instead of direct process_group
                modified_process_group_wrapper(
                    group_name, hypothesis, manual_data=None, genai_mode=genai_mode,
                    run_correlation=(run_correlation == "true")
                )

                # Run emulation if requested
                if run_emulation == "true":
                    try:
                        from archer.config import EmulationConfig
                        from archer.emulation import AtomicRedTeam
                        from archer.emulation.enrich import enrich_from_group_emulation

                        if EmulationConfig.is_atomic_configured():
                            # Set execution mode
                            if emulation_mode == "live":
                                os.environ["EMULATION_EXECUTE_MODE"] = "live"
                            else:
                                os.environ["EMULATION_EXECUTE_MODE"] = "simulate"

                            # Run group emulation
                            atomic = AtomicRedTeam()
                            atomic.execute_threat_group(group_name)

                            # Enrich detections
                            enrich_from_group_emulation(group_name)
                    except Exception as e:
                        print(f"Emulation error: {e}")

                # Export to VECTR if requested
                if vectr_export == "true":
                    try:
                        from archer.config import VECTRConfig
                        from archer.vectr import export_to_vectr

                        if VECTRConfig.is_configured():
                            campaign_name = vectr_campaign_name if vectr_campaign_name else None
                            export_to_vectr(
                                threat_group=group_name,
                                campaign_name=campaign_name
                            )
                    except Exception as e:
                        print(f"VECTR export error: {e}")

            except Exception:
                try:
                    write_progress(group_name, {"status": "failed"})
                except Exception:
                    pass

        threading.Thread(target=_bg, daemon=True).start()
        # Initialize a progress file so the front-end has something to poll
        try:
            write_progress(
                group_name, {"status": "started", "stage": "queued", "created_yaml": 0}
            )
        except Exception:
            pass
        return JSONResponse({"redirect_url": f"/progress?group_name={group_name}"})
    else:
        return JSONResponse({"redirect_url": f"/manual?group_name={group_name}"})


# Progress page endpoint
@app.get("/progress", response_class=HTMLResponse)
async def progress(request: Request, group_name: str = ""):
    # Simple progress page shown while the orchestrator runs. Currently
    # the template only needs the request and the group_name to display.
    return templates.TemplateResponse(
        "progress.html",
        {"request": request, "group_name": group_name},
    )


@app.get("/manual", response_class=HTMLResponse)
def manual(request: Request, group_name: str = ""):
    tactics, techniques = get_mitre_lists()
    render_time = datetime.utcnow().isoformat() + "Z"
    return templates.TemplateResponse(
        "manual.html",
        {
            "request": request,
            "group_name": group_name,
            "tactics": tactics,
            "techniques": techniques,
            "render_time": render_time,
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/save_draft")
async def save_draft(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False}, status_code=400)
    # Expect payload to include a `draft_id` and optional `user_id`.
    # The payload is stored to disk for later retrieval by /load_draft.
    draft_id = payload.get("draft_id")
    user_id = payload.get("user_id")
    if not draft_id:
        return JSONResponse({"ok": False}, status_code=400)
    # If user_id present in payload, require X-USER-ID header to match.
    if user_id:
        header_uid = request.headers.get("X-USER-ID")
        if not header_uid or header_uid != str(user_id):
            return JSONResponse(
                {"ok": False, "error": "user_id header mismatch"}, status_code=403
            )
    drafts_dir = os.path.join("data", "drafts")
    if user_id:
        user_dir = os.path.join(drafts_dir, "users", user_id)
        os.makedirs(user_dir, exist_ok=True)
        path = os.path.join(user_dir, f"{draft_id}.json")
    else:
        os.makedirs(drafts_dir, exist_ok=True)
        path = os.path.join(drafts_dir, f"{draft_id}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return JSONResponse({"ok": True})


@app.get("/load_draft")
async def load_draft(draft_id: str = "", user_id: str = ""):
    if not draft_id:
        return JSONResponse({"ok": False}, status_code=400)

    # If user_id provided, only look under that user's drafts
    if user_id:
        user_path = os.path.join("data", "drafts", "users", user_id, f"{draft_id}.json")
        if not os.path.exists(user_path):
            # not found or access denied
            return JSONResponse({"ok": False, "entries": []}, status_code=403)
        try:
            with open(user_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return JSONResponse({"ok": True, "entries": data.get("entries", [])})
        except Exception:
            return JSONResponse({"ok": False}, status_code=500)

    # No user_id: only allow top-level drafts
    path = os.path.join("data", "drafts", f"{draft_id}.json")
    if not os.path.exists(path):
        return JSONResponse({"ok": True, "entries": []})
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return JSONResponse({"ok": True, "entries": data.get("entries", [])})
    except Exception:
        return JSONResponse({"ok": False}, status_code=500)


# Handler for manual submission of appended techniques
@app.post("/manual_submit")
async def manual_submit(
    request: Request,
    group_name: str = Form("manual"),
    group_desc: str = Form(""),
    technique_entries: str = Form(""),
):
    """
    Receive manual technique entries (JSON string), validate them,
    transform the client payload into the `manual_data` structure expected
    by the `process_group` orchestrator, persist a draft for auditing,
    then call the orchestrator and redirect to the progress page.

    Inputs (form fields):
    - group_name: the name supplied on the previous page
    - group_desc: optional description/hypothesis
    - technique_entries: JSON string of appended technique objects

    Returns: RedirectResponse to /progress on success, or re-renders the
    manual form with an error message on validation failure.
    """
    try:
        entries = json.loads(technique_entries) if technique_entries else []
    except Exception:
        entries = []

    # Server-side validation: require at least one entry and each must have technique and procedures
    if not entries:
        # Re-render manual page with an error message
        tactics, techniques = get_mitre_lists()
        render_time = datetime.utcnow().isoformat() + "Z"
        return templates.TemplateResponse(
            "manual.html",
            {
                "request": request,
                "group_name": group_name,
                "tactics": tactics,
                "techniques": techniques,
                "render_time": render_time,
                "error_message": "Please append at least one technique before submitting.",
            },
        )

    invalid = False
    for ent in entries:
        if not ent.get("technique") or not ent.get("procedures"):
            invalid = True
            break
    if invalid:
        tactics, techniques = get_mitre_lists()
        render_time = datetime.utcnow().isoformat() + "Z"
        return templates.TemplateResponse(
            "manual.html",
            {
                "request": request,
                "group_name": group_name,
                "tactics": tactics,
                "techniques": techniques,
                "render_time": render_time,
                "error_message": "Each appended technique must include a technique name and procedures.",
            },
        )

    # Group techniques by tactic to match process_group expected schema
    tactic_map = {}
    for ent in entries:
        tech = ent.get("technique")
        tactics = ent.get("tactics") or []
        procedures = ent.get("procedures", "")
        # If no tactics were selected, put under a generic 'Unknown' tactic
        if not tactics:
            tactics = ["Unknown"]
        for tac in tactics:
            tactic_map.setdefault(tac, []).append(
                {
                    "technique": tech,
                    "op_guidance": procedures,
                    "red_tool": "",
                    "detect_guidance": "",
                }
            )

    manual_data = []
    for tac, techs in tactic_map.items():
        manual_data.append({"tactic": tac, "techniques": techs})

    # Use the provided group_desc as hypothesis if present
    hypothesis = group_desc or "Manual submission"

    # Persist draft to data/drafts/{group_name}.json for auditing/debugging
    try:
        drafts_dir = os.path.join("data", "drafts")
        os.makedirs(drafts_dir, exist_ok=True)
        draft_path = os.path.join(drafts_dir, f"{group_name}.json")
        with open(draft_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "group_name": group_name,
                    "group_desc": group_desc,
                    "entries": entries,
                },
                fh,
                indent=2,
            )
    except Exception:
        # non-fatal: if we can't write the draft, continue processing
        pass

    # Call the orchestrator to process the manual data in background
    def _bg_manual():
        try:
            # Use the modified wrapper instead of direct process_group
            # Note: manual submissions don't currently pass genai_mode or run_correlation from UI
            modified_process_group_wrapper(
                group_name, hypothesis, manual_data=manual_data, genai_mode=None, run_correlation=False
            )
        except Exception:
            try:
                write_progress(group_name, {"status": "failed"})
            except Exception:
                pass

    threading.Thread(target=_bg_manual, daemon=True).start()
    try:
        write_progress(
            group_name, {"status": "started", "stage": "queued", "created_yaml": 0}
        )
    except Exception:
        pass

    # Redirect user to progress page
    return RedirectResponse(url=f"/progress?group_name={group_name}", status_code=303)


@app.get("/progress_status")
async def progress_status(group_name: str = "", include_latest_file: bool = False):
    # Return the JSON progress status for the given group_name so the
    # front-end can poll and update progress bars.
    if not group_name:
        return JSONResponse(
            {"ok": False, "error": "group_name required"}, status_code=400
        )
    data = read_progress(group_name)
    response = {"ok": True, "progress": data}

    # Add latest file info if requested
    if include_latest_file:
        try:
            latest_yaml_path = os.path.join("data", "generate", "latest.yaml")
            if os.path.exists(latest_yaml_path):
                with open(latest_yaml_path, "r") as file:
                    latest_file = file.read().strip()

                    # Format the path for cleaner display
                    # 1. Extract just the filename if it's a full path
                    if os.path.sep in latest_file:
                        filename = os.path.basename(latest_file)
                    else:
                        filename = latest_file

                    # 2. Remove any path prefixes like "data/generate/"
                    filename = filename.replace("data/generate/", "")

                    # 3. Format the display name like "DirectVolumeAccess (aws guardduty)"
                    name_parts = os.path.splitext(filename)[0].split("_")
                    if len(name_parts) > 1:
                        # Assume format like "ActionName_platform.yaml"
                        action_name = name_parts[0]
                        platform = "_".join(name_parts[1:])  # Define platform variable

                        # Convert CamelCase to spaced words if needed
                        action_display = action_name  # Define action_display variable

                        # Format platform - typically lowercase with spaces
                        platform_display = platform.replace("_", " ")

                        pretty_name = f"{action_display} ({platform_display})"
                    else:
                        # If no underscore, just use the filename without extension
                        pretty_name = os.path.splitext(filename)[0]

                    response["latest_file"] = latest_file  # Original path for reference
                    response["latest_filename"] = filename  # Just the filename
                    response["latest_file_pretty"] = (
                        pretty_name  # Formatted display name
                    )
            else:
                print(f"Latest YAML file not found at {latest_yaml_path}")
        except Exception as e:
            print(f"Error reading latest.yaml: {e}")

    return JSONResponse(response)


@app.get("/correlations/{group_name}.json")
async def correlations_json(group_name: str):
    path = os.path.join("data", "correlate", f"{group_name}.json")
    if not os.path.exists(path):
        return JSONResponse({"ok": False, "error": "not_found"}, status_code=404)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return JSONResponse({"ok": True, "results": data})
    except Exception:
        return JSONResponse({"ok": False}, status_code=500)


@app.get("/list_drafts")
async def list_drafts(user_id: str = ""):
    drafts_dir = os.path.join("data", "drafts")
    results = []
    if user_id:
        user_dir = os.path.join(drafts_dir, "users", user_id)
        if not os.path.exists(user_dir):
            return JSONResponse({"ok": True, "drafts": []})
        for fname in os.listdir(user_dir):
            if fname.endswith(".json"):
                path = os.path.join(user_dir, fname)
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        j = json.load(fh)
                    results.append(
                        {
                            "draft_id": fname[:-5],
                            "group_name": j.get("group_name", ""),
                            "mtime": os.path.getmtime(path),
                        }
                    )
                except Exception:
                    pass
        return JSONResponse({"ok": True, "drafts": results})

    # list top-level drafts
    if not os.path.exists(drafts_dir):
        return JSONResponse({"ok": True, "drafts": []})
    for fname in os.listdir(drafts_dir):
        if fname.endswith(".json"):
            path = os.path.join(drafts_dir, fname)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    j = json.load(fh)
                results.append(
                    {
                        "draft_id": fname[:-5],
                        "group_name": j.get("group_name", ""),
                        "mtime": os.path.getmtime(path),
                    }
                )
            except Exception:
                pass
    return JSONResponse({"ok": True, "drafts": results})


@app.get("/threat_groups")
async def get_threat_groups(query: str = ""):
    """
    Return a list of threat group names and aliases from MITRE ATT&CK
    that match the provided query string.
    """
    bundle = getattr(app.state, "bundle", None)
    if not bundle:
        return JSONResponse({"ok": False, "groups": []})

    groups = []
    query_lower = query.lower()

    for obj in bundle.objects:
        if obj.get("type") == "intrusion-set":
            name = obj.get("name", "")
            aliases = obj.get("aliases", [])

            # Add the primary name if it matches
            if query_lower in name.lower():
                groups.append({"name": name, "is_alias": False})

            # Add matching aliases
            for alias in aliases:
                if alias != name and query_lower in alias.lower():
                    groups.append({"name": alias, "is_alias": True, "primary": name})

    # Remove duplicates and sort
    seen = set()
    unique_groups = []
    for group in groups:
        if group["name"] not in seen:
            seen.add(group["name"])
            unique_groups.append(group)

    # Sort: primary names first, then aliases, alphabetically within each
    unique_groups.sort(key=lambda x: (x.get("is_alias", False), x["name"].lower()))

    # Limit results to 10 for performance
    return JSONResponse({"ok": True, "groups": unique_groups[:10]})


# Add this function to explicitly start the GenAI processing after YAML generation
def start_genai_processing(group_name):
    """
    Helper function to start GenAI processing explicitly after YAML generation completes.
    This ensures proper transition between phases.
    """
    # Update progress to mark YAML generation as complete
    progress_data = read_progress(group_name) or {}

    # Make sure created_yaml equals total_yaml to show 100% completion
    if "total_yaml" in progress_data and progress_data.get("total_yaml", 0) > 0:
        progress_data["created_yaml"] = progress_data["total_yaml"]
    else:
        # If total_yaml is not set, set both to ensure 100% progress
        progress_data["created_yaml"] = progress_data.get("created_yaml", 10)
        progress_data["total_yaml"] = progress_data.get("created_yaml", 10)

    # Mark status as transitioning to GenAI
    progress_data["status"] = "genai_starting"
    write_progress(group_name, progress_data)

    # Start the actual GenAI processing
    try:
        import importlib.util

        spec = importlib.util.find_spec("archer.build.genai")
        if spec:
            genai_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(genai_module)

            # Start GenAI processing in a new thread
            def _bg_genai():
                try:
                    # Call the appropriate GenAI processing function
                    if hasattr(genai_module, "process_genai"):
                        # This is where GenAI correlation starts (dynamically loaded)
                        genai_module.process_genai(group_name)
                    elif hasattr(genai_module, "process"):
                        # Alternative entry point for GenAI processing
                        genai_module.process(group_name)
                    else:
                        print(
                            f"Warning: GenAI module loaded but no process function found"
                        )
                        # Update progress to show GenAI is complete (fallback)
                        progress_data = read_progress(group_name) or {}
                        progress_data["status"] = "genai_complete"
                        write_progress(group_name, progress_data)
                except Exception as e:
                    print(f"Error in GenAI processing: {e}")
                    # Mark as failed
                    try:
                        progress_data = read_progress(group_name) or {}
                        progress_data["status"] = "failed"
                        write_progress(group_name, progress_data)
                    except:
                        pass

            threading.Thread(target=_bg_genai, daemon=True).start()
    except Exception as e:
        print(f"Error starting GenAI: {e}")


# Modify the orchestrator process to ensure completion
def modified_process_group_wrapper(
    group_name, hypothesis, manual_data=None, genai_mode=None, run_correlation=False
):
    """Wrapper for process_group to ensure proper completion and transition to GenAI."""

    # Set GENAI_MODE environment variable if provided
    if genai_mode:
        os.environ["GENAI_MODE"] = genai_mode

    try:
        # Call the original process_group with run_correlation parameter
        process_group(group_name, hypothesis, manual_data, run_correlation=run_correlation)

        # If correlation was requested and run via process_group, we're done
        if run_correlation:
            return

        # Otherwise, just mark as complete
        progress_data = read_progress(group_name) or {}
        if "total_yaml" in progress_data:
            progress_data["created_yaml"] = progress_data["total_yaml"]
        else:
            progress_data["created_yaml"] = progress_data.get("created_yaml", 10)
            progress_data["total_yaml"] = progress_data.get("created_yaml", 10)

        progress_data["status"] = "complete"
        write_progress(group_name, progress_data)

    except Exception as e:
        print(f"Error in process group: {e}")
        try:
            write_progress(group_name, {"status": "failed"})
        except:
            pass


# Add a new endpoint to handle completion signals from the frontend
@app.post("/complete_yaml")
async def complete_yaml(request: Request, group_name: str = ""):
    """Handle explicit completion signal from frontend when YAML progress reaches 100%."""
    if not group_name:
        return JSONResponse(
            {"ok": False, "error": "group_name required"}, status_code=400
        )

    # Fetch current progress
    progress_data = read_progress(group_name) or {}

    # Only proceed if we're not already in GenAI phase
    if progress_data.get("status") not in [
        "genai_started",
        "genai_starting",
        "genai_complete",
    ]:
        # Ensure YAML progress shows as complete
        if "total_yaml" in progress_data:
            progress_data["created_yaml"] = progress_data["total_yaml"]
        else:
            progress_data["created_yaml"] = progress_data.get("created_yaml", 10)
            progress_data["total_yaml"] = progress_data.get("created_yaml", 10)

        # Mark as ready for GenAI
        progress_data["status"] = "genai_starting"
        write_progress(group_name, progress_data)

        # Start GenAI processing in a background thread
        try:
            def _bg_genai():
                try:
                    print(
                        f"Starting GenAI correlation for {group_name} in background thread"
                    )
                    process_genai(group_name)
                    print(f"GenAI correlation for {group_name} completed")
                except Exception as e:
                    print(f"Error in GenAI processing: {e}")
                    try:
                        progress_data = read_progress(group_name) or {}
                        progress_data["status"] = "failed"
                        write_progress(group_name, progress_data)
                    except:
                        pass

            thread = threading.Thread(target=_bg_genai, daemon=True)
            thread.start()
            print(f"Started background thread for GenAI processing: {thread.name}")
        except Exception as e:
            print(f"Error starting GenAI: {e}")

    return JSONResponse({"ok": True})

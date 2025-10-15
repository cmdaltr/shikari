from fastapi import FastAPI, Form, Request, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from archer.security import sanitize_filename, sanitize_path_component, validate_safe_path, sanitize_group_name
from fastapi.staticfiles import StaticFiles
from pathlib import Path

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


@app.get("/how-it-works", response_class=HTMLResponse)
def how_it_works(request: Request):
    """Render the 'How Archer Works' documentation page."""
    return templates.TemplateResponse(
        "how_it_works.html",
        {"request": request},
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
    cross_vendor_correlation: str = Form(None),
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
                group_name, {
                    "status": "started",
                    "stage": "queued",
                    "created_yaml": 0,
                    "cross_vendor_enabled": (cross_vendor_correlation == "true")
                }
            )
        except Exception:
            pass
        return JSONResponse({"redirect_url": f"/progress?group_name={group_name}"})
    else:
        # Group not in ATT&CK - search blogs automatically
        print(f"Group '{group_name}' not found in ATT&CK, searching security blogs...")

        try:
            from archer.parsers.blog_analyzer import auto_search_blogs
            blog_result = auto_search_blogs(group_name)

            if blog_result.get("success"):
                # Found blog post - redirect to manual entry with pre-filled data
                print(f"Found blog post from {blog_result.get('source')}: {blog_result.get('source_url')}")

                # Store blog results in session or pass as query params
                # For now, redirect to manual with a message
                return JSONResponse({
                    "redirect_url": f"/manual?group_name={group_name}&blog_found=true&source={blog_result.get('source', '')}"
                })
        except Exception as e:
            print(f"Blog search failed: {e}")

        # Fallback to manual entry
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
        "genai_processing",
        "genai_complete",
    ]:
        # Ensure YAML progress shows as complete
        if "total_yaml" in progress_data:
            progress_data["created_yaml"] = progress_data["total_yaml"]
        else:
            progress_data["created_yaml"] = progress_data.get("created_yaml", 10)
            progress_data["total_yaml"] = progress_data.get("created_yaml", 10)

        # Mark as ready for GenAI (but preserve any existing GenAI progress fields)
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


@app.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    use_openai: str = Form(None),
    auto_generate: str = Form(None),
    run_correlation: str = Form(None),
):
    """
    Handle file upload for TTP/IOC extraction.

    Accepts threat intelligence files (PDF, TXT, JSON, CSV, YARA) and extracts
    TTPs and IOCs using GenAI, then optionally generates detection queries.
    """
    try:
        # SECURITY: Validate filename to prevent path traversal
        import os
        import re

        if not file.filename:
            return JSONResponse({
                "success": False,
                "error": "No filename provided"
            }, status_code=400)

        # Sanitize filename - remove path components and dangerous characters
        safe_filename = os.path.basename(file.filename)
        safe_filename = re.sub(r'[^\w\s\-\.]', '_', safe_filename)

        # Check file extension whitelist
        allowed_extensions = {'.pdf', '.txt', '.md', '.json', '.csv', '.xlsx', '.xls', '.docx', '.doc', '.yar', '.yara'}
        file_ext = os.path.splitext(safe_filename)[1].lower()

        if file_ext not in allowed_extensions:
            return JSONResponse({
                "success": False,
                "error": f"File type '{file_ext}' not allowed. Allowed types: {', '.join(allowed_extensions)}"
            }, status_code=400)

        # SECURITY: Limit file size to 50MB
        file_content = await file.read()
        max_size = 50 * 1024 * 1024  # 50MB

        if len(file_content) > max_size:
            return JSONResponse({
                "success": False,
                "error": f"File too large. Maximum size is {max_size // (1024*1024)}MB"
            }, status_code=413)

        # Import the file intelligence parser
        from archer.parsers.file_intelligence import parse_intelligence_file

        # Parse the file to extract TTPs and IOCs
        use_ai = use_openai == "true"
        result = parse_intelligence_file(
            file_path=safe_filename,
            file_content=file_content,
            use_openai=use_ai,
            use_local_llm=False
        )

        # Extract data
        ttps = result.get("ttps", [])
        iocs = result.get("iocs", {})

        # Create a synthetic group name for tracking
        import hashlib
        file_hash = hashlib.md5(file_content).hexdigest()[:8]
        base_name = os.path.splitext(safe_filename)[0]
        # SECURITY: Sanitize the group name to prevent path traversal
        synthetic_group_name = sanitize_group_name(f"Upload_{base_name}_{file_hash}")

        # Save extraction results to file for later use
        import json
        upload_dir = os.path.join("data", "uploads")
        os.makedirs(upload_dir, exist_ok=True)

        result_file = os.path.join(upload_dir, f"{synthetic_group_name}_extraction.json")
        with open(result_file, "w") as f:
            json.dump({
                "filename": safe_filename,
                "ttps": ttps,
                "iocs": iocs,
                "synthetic_group_name": synthetic_group_name,
                "use_openai": use_ai,
                "run_correlation": run_correlation == "true"
            }, f, indent=2)

        # Always return extraction results first for user review
        # The frontend will display these and give user option to proceed
        response_data = {
            "success": True,
            "show_extraction": True,
            "filename": safe_filename,
            "synthetic_group_name": synthetic_group_name,
            "ttps": ttps,
            "iocs": {k: v for k, v in iocs.items() if v},  # Only include non-empty
            "ttps_count": len(ttps),
            "iocs_count": sum(len(v) for v in iocs.values()),
            "auto_generate_requested": auto_generate == "true"
        }

        print(f"\n[DEBUG] Returning extraction results:")
        print(f"  - show_extraction: {response_data['show_extraction']}")
        print(f"  - filename: {response_data['filename']}")
        print(f"  - ttps_count: {response_data['ttps_count']}")
        print(f"  - iocs_count: {response_data['iocs_count']}")
        print(f"  - auto_generate_requested: {response_data['auto_generate_requested']}")

        return JSONResponse(response_data)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/upload/generate")
async def generate_from_upload(
    request: Request,
    synthetic_group_name: str = Form(...),
    selected_ttps: str = Form(None),
    selected_iocs: str = Form(None)
):
    """
    Generate detections from previously uploaded and extracted file.
    Called after user reviews extraction results and chooses to proceed.
    Now supports user-selected TTPs and IOCs.
    """
    try:
        import json
        import os

        # SECURITY: Sanitize group name to prevent path traversal
        safe_group_name = sanitize_group_name(synthetic_group_name)

        # Load the extraction results
        upload_dir = os.path.join("data", "uploads")
        result_file = os.path.join(upload_dir, f"{safe_group_name}_extraction.json")

        # SECURITY: Validate the path is within the expected directory
        safe_path = validate_safe_path(upload_dir, result_file)
        if not safe_path:
            return JSONResponse({
                "success": False,
                "error": "Invalid file path"
            }, status_code=400)

        result_file = safe_path

        if not os.path.exists(result_file):
            return JSONResponse({
                "success": False,
                "error": "Extraction results not found. Please upload the file again."
            }, status_code=404)

        with open(result_file, "r") as f:
            extraction_data = json.load(f)

        # Use selected TTPs/IOCs if provided, otherwise use all extracted data
        if selected_ttps:
            ttps = json.loads(selected_ttps)
        else:
            ttps = extraction_data.get("ttps", [])

        if selected_iocs:
            iocs = json.loads(selected_iocs)
        else:
            iocs = extraction_data.get("iocs", {})
        filename = extraction_data.get("filename", "unknown")
        use_ai = extraction_data.get("use_openai", False)
        run_correlation = extraction_data.get("run_correlation", False)

        # Build manual data structure for process_group
        manual_data = {
            "techniques": [],
            "identifiers": iocs,  # Use extracted IOCs
            "metadata": {
                "source": "file_upload",
                "filename": filename,
                "ttps_found": ttps
            }
        }

        # Add technique data for each TTP
        for ttp_id in ttps:
            # Try to get technique info from MITRE
            try:
                technique_info = _get_technique_info(ttp_id)
                if technique_info:
                    manual_data["techniques"].append(technique_info)
            except Exception:
                # If we can't find the technique, add minimal data
                manual_data["techniques"].append({
                    "tid": ttp_id,
                    "name": f"Technique {ttp_id}",
                    "tactic": "Unknown",
                    "description": f"Extracted from {filename}",
                    "software_used": [],
                    "platforms": ["windows", "linux", "macos"]
                })

        # Process in background thread
        def _bg():
            try:
                modified_process_group_wrapper(
                    synthetic_group_name,
                    f"Generated from uploaded file: {filename}",
                    manual_data=manual_data,
                    genai_mode="semantic" if not use_ai else "ai_generators",
                    run_correlation=run_correlation
                )
            except Exception as e:
                print(f"Error processing upload: {e}")
                try:
                    write_progress(synthetic_group_name, {"status": "failed", "error": str(e)})
                except Exception:
                    pass

        threading.Thread(target=_bg, daemon=True).start()

        # Initialize progress
        try:
            write_progress(synthetic_group_name, {
                "status": "processing",
                "current_step": "Generating detections from uploaded file",
                "ttps_found": len(ttps),
                "iocs_found": sum(len(v) for v in iocs.values())
            })
        except Exception:
            pass

        return JSONResponse({
            "success": True,
            "redirect": f"/progress?group_name={synthetic_group_name}",
            "ttps_found": len(ttps),
            "iocs_found": sum(len(v) for v in iocs.values())
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/analyze_blog")
async def analyze_blog(
    request: Request,
    url: str = Form(...),
    use_openai: str = Form(None),
    auto_generate: str = Form(None),
    run_correlation: str = Form(None),
):
    """
    Analyze a blog post or threat report URL and extract TTPs, procedures, and IOCs.

    Similar to file upload, can optionally auto-generate detection queries.
    """
    try:
        url = url.strip()

        if not url:
            return JSONResponse({
                "success": False,
                "message": "No URL provided"
            }, status_code=400)

        # Import the blog analyzer
        from archer.parsers.blog_analyzer import analyze_blog_post

        # Analyze the blog post
        print(f"\nAnalyzing blog post: {url}")
        result = analyze_blog_post(url)

        if not result.get("success"):
            return JSONResponse({
                "success": False,
                "message": result.get("error", "Failed to analyze blog post")
            }, status_code=500)

        # Extract data
        ttps = result.get("techniques", [])
        iocs = result.get("iocs", {})
        group_name = result.get("group_name", "")
        procedures = result.get("procedures", [])

        # Create a synthetic group name for tracking if not found
        import hashlib
        import json
        import os

        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        # SECURITY: Sanitize group name
        raw_group_name = group_name or f"BlogAnalysis_{url_hash}"
        synthetic_group_name = sanitize_group_name(raw_group_name)

        # Save extraction results to file for later use (like file upload)
        blog_dir = os.path.join("data", "blog_analysis")
        os.makedirs(blog_dir, exist_ok=True)

        result_file = os.path.join(blog_dir, f"{synthetic_group_name}_extraction.json")
        with open(result_file, "w") as f:
            json.dump({
                "url": url,
                "filename": url,  # Use URL as filename for consistency
                "group_name": group_name,
                "ttps": ttps,
                "iocs": iocs,
                "procedures": procedures,
                "synthetic_group_name": synthetic_group_name,
                "use_openai": use_openai == "true",
                "run_correlation": run_correlation == "true"
            }, f, indent=2)

        # Always return extraction results first for user review (same as file upload)
        return JSONResponse({
            "success": True,
            "show_extraction": True,
            "filename": f"Blog: {url[:50]}..." if len(url) > 50 else f"Blog: {url}",
            "synthetic_group_name": synthetic_group_name,
            "ttps": ttps,
            "iocs": {k: v for k, v in iocs.items() if v},  # Only include non-empty
            "ttps_count": len(ttps),
            "iocs_count": sum(len(v) for v in iocs.values()),
            "auto_generate_requested": auto_generate == "true"
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({
            "success": False,
            "message": f"Error analyzing blog: {str(e)}"
        }, status_code=500)


@app.post("/blog/generate")
async def generate_from_blog(
    request: Request,
    synthetic_group_name: str = Form(...),
    selected_ttps: str = Form(None),
    selected_iocs: str = Form(None)
):
    """
    Generate detections from previously analyzed blog post.
    Called after user reviews extraction results and chooses to proceed.
    Now supports user-selected TTPs and IOCs.
    """
    try:
        import json
        import os

        # SECURITY: Sanitize group name to prevent path traversal
        safe_group_name = sanitize_group_name(synthetic_group_name)

        # Load the extraction results
        blog_dir = os.path.join("data", "blog_analysis")
        result_file = os.path.join(blog_dir, f"{safe_group_name}_extraction.json")

        # SECURITY: Validate the path is within the expected directory
        safe_path = validate_safe_path(blog_dir, result_file)
        if not safe_path:
            return JSONResponse({
                "success": False,
                "error": "Invalid file path"
            }, status_code=400)

        result_file = safe_path

        if not os.path.exists(result_file):
            return JSONResponse({
                "success": False,
                "error": "Extraction results not found. Please analyze the blog post again."
            }, status_code=404)

        with open(result_file, "r") as f:
            extraction_data = json.load(f)

        # Use selected TTPs/IOCs if provided, otherwise use all extracted data
        if selected_ttps:
            ttps = json.loads(selected_ttps)
        else:
            ttps = extraction_data.get("ttps", [])

        if selected_iocs:
            iocs = json.loads(selected_iocs)
        else:
            iocs = extraction_data.get("iocs", {})
        url = extraction_data.get("url", "unknown")
        procedures = extraction_data.get("procedures", [])
        use_ai = extraction_data.get("use_openai", False)
        run_correlation = extraction_data.get("run_correlation", False)

        # Build manual data structure for process_group
        manual_data = {
            "techniques": [],
            "identifiers": iocs,  # Use extracted IOCs
            "metadata": {
                "source": "blog_analysis",
                "url": url,
                "ttps_found": ttps,
                "procedures": procedures
            }
        }

        # Add technique data for each TTP
        for ttp_id in ttps:
            # Try to get technique info from MITRE
            try:
                technique_info = _get_technique_info(ttp_id)
                if technique_info:
                    manual_data["techniques"].append(technique_info)
            except Exception:
                # If we can't find the technique, add minimal data
                manual_data["techniques"].append({
                    "tid": ttp_id,
                    "name": f"Technique {ttp_id}",
                    "tactic": "Unknown",
                    "description": f"Extracted from {url}",
                    "software_used": [],
                    "platforms": ["windows", "linux", "macos"]
                })

        # Process in background thread
        def _bg():
            try:
                modified_process_group_wrapper(
                    synthetic_group_name,
                    f"Generated from blog post: {url}",
                    manual_data=manual_data,
                    genai_mode="semantic" if not use_ai else "ai_generators",
                    run_correlation=run_correlation
                )
            except Exception as e:
                print(f"Error processing blog analysis: {e}")
                try:
                    write_progress(synthetic_group_name, {"status": "failed", "error": str(e)})
                except Exception:
                    pass

        threading.Thread(target=_bg, daemon=True).start()

        # Initialize progress
        try:
            write_progress(synthetic_group_name, {
                "status": "processing",
                "current_step": "Generating detections from blog post",
                "ttps_found": len(ttps),
                "iocs_found": sum(len(v) for v in iocs.values())
            })
        except Exception:
            pass

        return JSONResponse({
            "success": True,
            "redirect": f"/progress?group_name={synthetic_group_name}",
            "ttps_found": len(ttps),
            "iocs_found": sum(len(v) for v in iocs.values())
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({
            "success": False,
            "message": f"Error analyzing blog: {str(e)}"
        }, status_code=500)


@app.post("/emulate")
async def emulate_technique(
    request: Request,
    technique: str = Form(...),
    emulation_mode: str = Form("simulate"),
    remote_execution: str = Form(None),
    remote_hosts: str = Form(None),
):
    """
    Execute adversary emulation using Atomic Red Team.

    Supports both local simulation and live execution modes.
    Can execute on remote hosts if configured.
    """
    try:
        from archer.emulation.atomic import AtomicRedTeam

        # Parse technique or group name
        technique = technique.strip()

        # If it looks like a threat group, we need to map it to techniques
        if not technique.startswith("T"):
            # It's a group name - fetch techniques for the group
            bundle = getattr(app.state, "bundle", None)
            if bundle:
                # Find the group in the bundle
                group_obj = None
                for obj in bundle.get("objects", []):
                    if obj.get("type") == "intrusion-set":
                        if (obj.get("name", "").lower() == technique.lower() or
                            any(alias.lower() == technique.lower()
                                for alias in obj.get("aliases", []))):
                            group_obj = obj
                            break

                if group_obj:
                    # Get techniques used by this group
                    techniques = []
                    group_id = group_obj.get("id")
                    for obj in bundle.get("objects", []):
                        if obj.get("type") == "relationship":
                            if (obj.get("source_ref") == group_id and
                                obj.get("relationship_type") == "uses"):
                                target_id = obj.get("target_ref")
                                # Find the technique
                                for tech_obj in bundle.get("objects", []):
                                    if tech_obj.get("id") == target_id:
                                        if tech_obj.get("type") == "attack-pattern":
                                            ext_refs = tech_obj.get("external_references", [])
                                            for ref in ext_refs:
                                                if ref.get("source_name") == "mitre-attack":
                                                    techniques.append(ref.get("external_id"))
                                                    break

                    if not techniques:
                        return JSONResponse({
                            "success": False,
                            "error": f"No techniques found for group '{technique}'"
                        }, status_code=400)

                    # Use the first technique for now
                    technique = techniques[0]
                else:
                    return JSONResponse({
                        "success": False,
                        "error": f"Threat group '{technique}' not found in MITRE ATT&CK"
                    }, status_code=400)
            else:
                return JSONResponse({
                    "success": False,
                    "error": "MITRE ATT&CK data not loaded"
                }, status_code=500)

        # Initialize Atomic Red Team
        atomic = AtomicRedTeam()

        # Check if in simulate mode
        is_simulate = emulation_mode == "simulate"

        if is_simulate:
            # Simulate mode - just show what would be executed
            try:
                atomic_data = atomic.get_technique_atomics(technique)
                atomic_tests = atomic_data.get("atomic_tests", [])

                return JSONResponse({
                    "success": True,
                    "mode": "simulate",
                    "technique": technique,
                    "technique_name": atomic_data.get("display_name", ""),
                    "test_count": len(atomic_tests),
                    "tests": [
                        {
                            "name": test.get("name", ""),
                            "description": test.get("description", ""),
                            "executor": test.get("executor", {}).get("name", ""),
                            "platforms": test.get("supported_platforms", [])
                        }
                        for test in atomic_tests
                    ],
                    "message": "Simulation complete. Enable 'Live Execution' to actually run these tests."
                })
            except FileNotFoundError as e:
                return JSONResponse({
                    "success": False,
                    "error": str(e)
                }, status_code=404)
        else:
            # Live execution mode - actually run the tests
            # THIS IS DANGEROUS - only for controlled environments
            try:
                results = atomic.execute_technique(
                    technique_id=technique,
                    auto_cleanup=True
                )

                return JSONResponse({
                    "success": True,
                    "mode": "live",
                    "technique": technique,
                    "results": results,
                    "message": "Emulation executed successfully"
                })
            except Exception as e:
                import traceback
                traceback.print_exc()
                return JSONResponse({
                    "success": False,
                    "error": f"Emulation failed: {str(e)}"
                }, status_code=500)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/profile")
async def profile_company(
    request: Request,
    domain: str = Form(...),
    include_industry: str = Form(None),
    include_geography: str = Form(None),
    include_tech_stack: str = Form(None),
    include_supply_chain: str = Form(None),
    use_openai: str = Form(None),
    generate_detections: str = Form(None),
):
    """
    Profile a company based on their domain and generate threat intelligence.

    Analyzes:
    - Industry sector and targeted threat groups
    - Geographic location and nation-state threats
    - Technology stack and CVEs
    - Supply chain dependencies

    Returns profile data and optionally generates detection queries.
    """
    try:
        from archer.intelligence import profile_company as do_profile
        from archer.build.orchestrator import process_group

        # Clean domain input
        domain = domain.strip().lower()
        # Remove http:// or https:// if present
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]

        # Build options dict
        options = {
            'include_industry': include_industry == 'true',
            'include_geography': include_geography == 'true',
            'include_tech_stack': include_tech_stack == 'true',
            'include_supply_chain': include_supply_chain == 'true',
        }

        use_ai = use_openai == 'true'
        auto_generate = generate_detections == 'true'

        # Use domain as group_name for progress tracking
        group_name = domain.replace('.', '_').replace('/', '_')

        # Profile the company
        print(f"\nProfiling domain: {domain}")
        profile = do_profile(domain, options, use_openai=use_ai, group_name=group_name)

        # Save profile to data/profiles/
        profile_dir = Path("data") / "profiles"
        profile_dir.mkdir(parents=True, exist_ok=True)

        # Use domain as filename (sanitized)
        safe_domain = domain.replace('.', '_').replace('/', '_')
        profile_path = profile_dir / f"{safe_domain}_profile.json"

        with open(profile_path, 'w', encoding='utf-8') as f:
            json.dump(profile, f, indent=2)

        print(f"Profile saved to: {profile_path}")

        # Always return profile for user review first
        # User can then select which threat groups to generate detections for
        return JSONResponse({
            "success": True,
            "profile": profile,
            "message": "Company profile complete",
            "profile_path": str(profile_path),
            "recommended_groups": profile.get('recommended_groups', []),
            "show_selection": auto_generate  # Show selection UI if auto-generate was checked
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/api/technique_names")
async def get_technique_names(request: Request):
    """
    Get technique names for given technique IDs.

    Request body: {"technique_ids": ["T1059.001", "T1078", ...]}
    Returns: {"T1059.001": "PowerShell", "T1078": "Valid Accounts", ...}
    """
    try:
        import json
        from pathlib import Path

        body = await request.json()
        technique_ids = body.get("technique_ids", [])

        # Load MITRE ATT&CK data
        mitre_path = Path(__file__).parent / "data" / "cache" / "enterprise-attack.json"
        if not mitre_path.exists():
            return JSONResponse({
                "success": False,
                "error": "MITRE ATT&CK data not found"
            }, status_code=500)

        with open(mitre_path) as f:
            data = json.load(f)

        # Build mapping
        technique_names = {}
        for obj in data['objects']:
            if obj.get('type') == 'attack-pattern':
                ext_refs = obj.get('external_references', [])
                for ref in ext_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        tech_id = ref.get('external_id')
                        tech_name = obj.get('name')
                        if tech_id in technique_ids:
                            technique_names[tech_id] = tech_name

        return JSONResponse(technique_names)

    except Exception as e:
        print(f"Error getting technique names: {e}")
        return JSONResponse({
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/profile/generate-detections")
async def generate_detections_from_profile(
    request: Request,
    domain: str = Form(...),
    selected_groups: str = Form(...),  # Comma-separated list
    run_correlation: str = Form(None)
):
    """
    Generate detections for user-selected threat groups from a profile.

    This is called after the user reviews the profile and selects which
    threat groups they want to generate detections for.
    """
    try:
        from archer.build.orchestrator import process_group

        # Parse selected groups
        groups = [g.strip() for g in selected_groups.split(',') if g.strip()]

        if not groups:
            return JSONResponse({
                "success": False,
                "error": "No threat groups selected"
            }, status_code=400)

        should_correlate = run_correlation == 'true'

        print(f"\nGenerating detections for {len(groups)} selected threat groups from {domain} profile...")

        # Use the first group as primary (for progress tracking)
        primary_group = groups[0]

        # Start background generation for all selected groups
        def _generate_bg():
            try:
                for group in groups:
                    print(f"Generating detections for: {group}")
                    result = process_group(group, run_correlation=should_correlate)
                    print(f"Generated detections for {group}: {result}")
            except Exception as e:
                print(f"Error generating detections: {e}")
                import traceback
                traceback.print_exc()

        import threading
        threading.Thread(target=_generate_bg, daemon=True).start()

        # Return progress redirect
        group_list = ', '.join(groups[:3])  # Show first 3 groups
        if len(groups) > 3:
            group_list += f" and {len(groups) - 3} more"

        return JSONResponse({
            "success": True,
            "redirect_url": f"/progress?group_name={primary_group}",
            "message": f"Generating detections for: {group_list}",
            "groups": groups
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({
            "success": False,
            "error": str(e)
        }, status_code=500)


def _get_technique_info(ttp_id: str) -> dict:
    """Get technique information from MITRE ATT&CK bundle."""
    bundle = getattr(app.state, "bundle", None)
    if not bundle:
        return None

    # Search for technique in bundle
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            # Check external references for technique ID
            for ref in obj.get("external_references", []):
                if ref.get("external_id") == ttp_id:
                    # Extract tactic
                    tactics = []
                    for phase in obj.get("kill_chain_phases", []):
                        tactic_name = phase.get("phase_name", "").replace("-", " ").title()
                        tactics.append(tactic_name)

                    return {
                        "tid": ttp_id,
                        "name": obj.get("name", ttp_id),
                        "tactic": tactics[0] if tactics else "Unknown",
                        "description": obj.get("description", ""),
                        "software_used": [],
                        "platforms": obj.get("x_mitre_platforms", ["windows"])
                    }

    return None


# =============================================================================
# Results Page and Download API Routes
# =============================================================================

from fastapi.responses import FileResponse, StreamingResponse
import glob
import zipfile
import io
from datetime import timedelta


@app.get("/results", response_class=HTMLResponse)
def results_page(request: Request, group_name: str):
    """
    Render the results dashboard showing generated detections, correlations, and attack flows.
    """
    safe_group = sanitize_group_name(group_name)

    # Collect detection files by vendor
    generate_dir = os.path.join("data", "generate")
    detection_files = {}
    vendor_icons = {
        "splunk": "🔍",
        "mde": "🛡️",
        "microsoft": "🛡️",
        "elastic": "🔎",
        "qradar": "🎯",
        "sumo": "☁️",
        "chronicle": "📊"
    }

    vendor_display_names = {
        "splunk": "Splunk",
        "mde": "Microsoft Defender",
        "microsoft": "Microsoft Defender",
        "elastic": "Elastic",
        "qradar": "IBM QRadar",
        "sumo": "Sumo Logic",
        "chronicle": "Google Chronicle"
    }

    # Find all YAML files for this group
    if os.path.exists(generate_dir):
        for yaml_file in glob.glob(os.path.join(generate_dir, f"{safe_group}_*.yaml")):
            filename = os.path.basename(yaml_file)

            # Determine vendor from filename
            vendor = None
            for v in vendor_icons.keys():
                if f"_{v}_" in filename.lower() or f"_{v}." in filename.lower():
                    vendor = v
                    break

            if not vendor:
                vendor = "unknown"

            if vendor not in detection_files:
                detection_files[vendor] = []

            # Extract technique and title from filename
            # Format: groupname_vendor_technique_description.yaml
            parts = filename.replace(".yaml", "").split("_", 3)
            technique = parts[2] if len(parts) > 2 else "Unknown"
            title = parts[3].replace("_", " ").title() if len(parts) > 3 else filename

            # Read first few lines for description
            description = ""
            try:
                with open(yaml_file, 'r') as f:
                    lines = f.readlines()[:10]
                    for line in lines:
                        if line.strip().startswith("description:"):
                            description = line.split(":", 1)[1].strip().strip('"\'')
                            break
            except:
                pass

            detection_files[vendor].append({
                "file": filename,
                "title": title,
                "technique": technique.upper(),
                "description": description or f"Detection rule for {technique}"
            })

    # Build vendor list for template
    detections = []
    total_detections = 0
    for vendor, files in detection_files.items():
        detections.append({
            "name": vendor,
            "display_name": vendor_display_names.get(vendor, vendor.title()),
            "icon": vendor_icons.get(vendor, "📋"),
            "count": len(files),
            "detections": sorted(files, key=lambda x: x['technique'])
        })
        total_detections += len(files)

    detections.sort(key=lambda x: x['count'], reverse=True)

    # Load correlations
    correlations = []
    correlation_file = os.path.join("data", "correlate", f"{safe_group}.json")
    if os.path.exists(correlation_file):
        try:
            with open(correlation_file, 'r') as f:
                corr_data = json.load(f)
                for idx, corr in enumerate(corr_data.get("correlations", [])):
                    techniques = []
                    for tech in corr.get("techniques", []):
                        tech_id = tech if isinstance(tech, str) else tech.get("id", "Unknown")
                        tech_name = tech.get("name", "") if isinstance(tech, dict) else ""
                        techniques.append({"id": tech_id, "name": tech_name or tech_id})

                    correlations.append({
                        "techniques": techniques,
                        "description": corr.get("description", "Multi-stage attack sequence"),
                        "flow_file": f"{safe_group}_corr_{idx+1}.html"
                    })
        except:
            pass

    # Check if attack flow exists
    attack_flow_file = os.path.join("data", "attack_flows", f"{safe_group}_complete_flow.html")
    attack_flow_exists = os.path.exists(attack_flow_file)

    # Get unique technique count
    technique_set = set()
    for vendor_data in detections:
        for detection in vendor_data['detections']:
            technique_set.add(detection['technique'])

    # Calculate duration (if progress file exists)
    duration = "N/A"
    progress_file = os.path.join("data", "progress", f"{safe_group}.json")
    if os.path.exists(progress_file):
        try:
            with open(progress_file, 'r') as f:
                progress_data = json.load(f)
                # Estimate based on timestamps if available
                duration = "~3min"  # Placeholder
        except:
            pass

    # Get MITRE ID if available
    mitre_id = None
    if check_group_in_mitre(safe_group):
        # Try to find MITRE ID from STIX data
        mitre_id = safe_group  # Simplified

    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "group_name": safe_group,
            "mitre_id": mitre_id,
            "total_detections": total_detections,
            "vendor_count": len(detections),
            "correlation_count": len(correlations),
            "technique_count": len(technique_set),
            "duration": duration,
            "detections": detections,
            "correlations": correlations,
            "attack_flow_exists": attack_flow_exists,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    )


@app.get("/api/detection/{filename}")
def get_detection_content(filename: str):
    """
    Return the content of a detection YAML file.
    """
    safe_filename = sanitize_filename(filename)
    file_path = os.path.join("data", "generate", safe_filename)

    if not os.path.exists(file_path):
        return {"error": "File not found"}, 404

    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return content
    except Exception as e:
        return {"error": str(e)}, 500


@app.get("/api/download/detection/{filename}")
def download_detection(filename: str):
    """
    Download a single detection YAML file.
    """
    safe_filename = sanitize_filename(filename)
    file_path = os.path.join("data", "generate", safe_filename)

    if not os.path.exists(file_path):
        return {"error": "File not found"}, 404

    return FileResponse(
        file_path,
        media_type="application/x-yaml",
        filename=safe_filename
    )


@app.get("/api/download/all/{group_name}")
def download_all_detections(group_name: str):
    """
    Download all detections, correlations, and attack flows for a group as a ZIP file.
    """
    safe_group = sanitize_group_name(group_name)

    # Create in-memory ZIP file
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Add detection YAMLs
        generate_dir = os.path.join("data", "generate")
        if os.path.exists(generate_dir):
            for yaml_file in glob.glob(os.path.join(generate_dir, f"{safe_group}_*.yaml")):
                filename = os.path.basename(yaml_file)
                zip_file.write(yaml_file, f"detections/{filename}")

        # Add correlation JSON
        corr_file = os.path.join("data", "correlate", f"{safe_group}.json")
        if os.path.exists(corr_file):
            zip_file.write(corr_file, f"correlations/{safe_group}.json")

        # Add attack flows
        flow_dir = os.path.join("data", "attack_flows")
        if os.path.exists(flow_dir):
            for flow_file in glob.glob(os.path.join(flow_dir, f"{safe_group}_*.json")):
                filename = os.path.basename(flow_file)
                zip_file.write(flow_file, f"attack_flows/{filename}")

            for flow_file in glob.glob(os.path.join(flow_dir, f"{safe_group}_*.html")):
                filename = os.path.basename(flow_file)
                zip_file.write(flow_file, f"attack_flows/{filename}")

    zip_buffer.seek(0)

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={safe_group}_results.zip"}
    )


@app.get("/api/attack-flow/{filename}")
def view_attack_flow(filename: str):
    """
    Serve an attack flow HTML file for viewing.
    """
    safe_filename = sanitize_filename(filename)
    file_path = os.path.join("data", "attack_flows", safe_filename)

    if not os.path.exists(file_path):
        return {"error": "Attack flow not found"}, 404

    return FileResponse(file_path, media_type="text/html")


@app.get("/api/download/flow/{filename}")
def download_attack_flow(filename: str):
    """
    Download an attack flow JSON file.
    """
    safe_filename = sanitize_filename(filename)
    file_path = os.path.join("data", "attack_flows", safe_filename)

    if not os.path.exists(file_path):
        return {"error": "File not found"}, 404

    return FileResponse(
        file_path,
        media_type="application/json",
        filename=safe_filename
    )

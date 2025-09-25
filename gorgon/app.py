from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse

from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# Recommended: keep absolute imports for clarity

from gorgon.build import define_vectr_values, construct_yaml
from gorgon.mitre import (
    get_stix_data,
    obtain_all_techniques,
    obtain_technique_descriptions,
)
from gorgon.mitre import (
    retrieve_group,
    retrieve_techniques,
    retrieve_procedures,
)
from archer import process_group


templates = Jinja2Templates(directory="templates")

app = FastAPI(title="Archer Threat Hunting Service")
app.mount("/static", StaticFiles(directory="static"), name="static")


# Load MITRE data on startup and cache in app.state
@app.on_event("startup")
def load_mitre_data():
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    bundle = get_stix_data(url)
    app.state.bundle = bundle
    app.state.techniques_to_choose = obtain_all_techniques(bundle)
    app.state.technique_descriptions = obtain_technique_descriptions(bundle)


@app.get("/", response_class=HTMLResponse)
def read_form(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "techniques": getattr(app.state, "techniques_to_choose", []),
        },
    )


# POST handler for Generate button
@app.post("/generate")
async def generate(request: Request, group_name: str = Form(...)):
    # You can add more form fields as needed
    hypothesis = "Generated from form"  # Replace with actual form field if needed
    # Call process_group with cached technique_descriptions
    process_group(
        group_name,
        hypothesis,
        manual_data=None,  # Extend to parse more form data if needed
    )
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "techniques": getattr(app.state, "techniques_to_choose", []),
            "message": f"Processed group: {group_name}",
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}

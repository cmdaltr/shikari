from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

import yaml


# Initialize the FastAPI app
app = FastAPI()


# A basic health check endpoint. You can hit /health in a browser or curl to confirm the service is alive.
@app.get("/health")
def health():
    return {"status": "ok"}


# Define a /generate endpoint that responds to POST requests.
# Inside, we build a Python dictionary (hunt) that represents your detection content.
# We convert it to YAML (yaml.safe_dump) and return it as plain text.
# So whenever n8n (or you) calls /generate, you get back a YAML-structured hunt definition.
@app.post("/generate", response_class=PlainTextResponse)
def generate():
    # Open and return the contents of a YAML file
    with open("hunts/base64_github.yaml", "r") as f:
        yaml_content = f.read()
    return yaml_content

import os
from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.get("/latest_yaml_file")
async def get_latest_yaml_file():
    """
    Returns the path to the latest YAML file from the latest.yaml tracker file.
    """
    try:
        latest_yaml_path = os.path.join("data", "queries", "latest.yaml")
        if os.path.exists(latest_yaml_path):
            with open(latest_yaml_path, "r") as file:
                latest_file = file.read().strip()
                return {"latest_file": latest_file}
        else:
            return {"error": "No latest.yaml file found"}
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error reading latest.yaml: {str(e)}"
        )

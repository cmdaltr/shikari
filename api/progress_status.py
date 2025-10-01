import os
from typing import Dict, Any, Optional
from fastapi import APIRouter, Query, Request, Depends
from pathlib import Path

router = APIRouter()


def get_base_dir() -> Path:
    """Get the base directory for the application."""
    return Path(__file__).parent.parent


@router.get("/progress_status")
async def progress_status(
    request: Request,
    group_name: str = Query(..., description="Group name to get progress for"),
    include_latest_file: bool = Query(
        False, description="Include latest YAML file path"
    ),
) -> Dict[str, Any]:
    """
    Return progress status for a group, optionally including latest file information.
    """
    # Call existing progress_status implementation
    # Get existing progress_status data from the request scope or context
    original_handler = request.app.routes[-1].endpoint
    if original_handler.__name__ != "progress_status":
        original_handler = None
        for route in request.app.routes:
            if (
                getattr(route, "path", "") == "/progress_status"
                and route.endpoint.__name__ == "progress_status"
            ):
                original_handler = route.endpoint
                break

    # If we can't get the original handler, just create an empty response
    if not original_handler or original_handler == progress_status:
        response = {"progress": {}}
    else:
        # Call the original handler
        response = await original_handler(request)

    # Add latest file info if requested
    if include_latest_file:
        try:
            base_dir = get_base_dir()
            latest_yaml_path = os.path.join(base_dir, "data", "queries", "latest.yaml")
            if os.path.exists(latest_yaml_path):
                with open(latest_yaml_path, "r") as file:
                    latest_file = file.read().strip()
                    response["latest_file"] = latest_file
                    print(f"Loaded latest file info: {latest_file}")
            else:
                print(f"latest.yaml not found at {latest_yaml_path}")
        except Exception as e:
            print(f"Error reading latest.yaml: {e}")

    return response

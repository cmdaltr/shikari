import os
import time
from datetime import datetime
from pathlib import Path
from flask import Blueprint, jsonify, request, current_app, abort

yaml_files_bp = Blueprint("yaml_files", __name__)


def get_base_dir():
    """Get the base directory for the application."""
    # Adjust this path to match your application's structure
    return Path(current_app.root_path).parent


@yaml_files_bp.route("/api/yaml_files", methods=["GET"])
def list_yaml_files():
    """List all YAML files in the specified directory."""
    directory = request.args.get("directory", "data/queries")

    # Validate and sanitize the directory path to prevent directory traversal
    base_dir = get_base_dir()
    target_dir = (base_dir / directory).resolve()

    # Ensure the target directory is within the allowed base path
    if not str(target_dir).startswith(str(base_dir)):
        abort(403, description="Access to this directory is forbidden")

    # Check if the directory exists
    if not target_dir.exists() or not target_dir.is_dir():
        abort(404, description=f"Directory not found: {directory}")

    # List files in the directory
    yaml_files = []

    try:
        for file_path in target_dir.glob("*.y*ml"):
            if file_path.is_file() and file_path.suffix.lower() in [".yaml", ".yml"]:
                stats = file_path.stat()
                rel_path = file_path.relative_to(base_dir)
                yaml_files.append(
                    {
                        "name": file_path.name,
                        "path": str(rel_path).replace(
                            "\\", "/"
                        ),  # Normalize path for URLs
                        "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                        "size": stats.st_size,
                    }
                )
    except Exception as e:
        abort(500, description=f"Error accessing directory: {str(e)}")

    # Sort files by modification time, newest first
    yaml_files.sort(key=lambda x: x["modified"], reverse=True)

    return jsonify({"files": yaml_files})


# Register this blueprint in your Flask app
# In your app.py or __init__.py:
# from api.yaml_files import yaml_files_bp
# app.register_blueprint(yaml_files_bp)
from api.yaml_files import router as yaml_router

# Add to your FastAPI app
app.include_router(yaml_router)

# Import and register the latest file router
from api.latest_file import router as latest_file_router

app.include_router(latest_file_router)

# Optional: Add the debug router to help troubleshoot API registration
from api.endpoint_debug import router as debug_router

app.include_router(debug_router)

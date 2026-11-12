FROM python:3.11-slim

WORKDIR /app

# Install git (required for cloning OSINT repos)
RUN apt-get update && \
    apt-get install -y git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
# CPU-only torch: from PyPI, torch on Linux brings about 2.5 GB of CUDA wheels that no Shikari server
# uses (the embeddings run on the CPU), as in the desktop workflow
ENV PIP_EXTRA_INDEX_URL=https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY shikari/ ./shikari/
COPY templates/ ./templates/
COPY static/ ./static/
COPY scripts/ ./scripts/
COPY data/ ./data/

# Make Python entrypoint executable
RUN chmod +x scripts/deployment/docker_entrypoint.py

# Expose port
EXPOSE 32453

# Use Python entrypoint to initialize OSINT repos before starting app (cross-platform)
ENTRYPOINT ["python", "scripts/deployment/docker_entrypoint.py"]

# Run the FastAPI application. No --reload: a server restarting on any file change under its bind
# mounts drops requests and hunts in flight. SHIKARI_RELOAD=1 turns it on for development.
CMD ["uvicorn", "shikari.app:app", "--host", "0.0.0.0", "--port", "32453"]
FROM python:3.11-slim

WORKDIR /app

# Install git (required for cloning OSINT repos)
RUN apt-get update && \
    apt-get install -y git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY archer/ ./archer/
COPY templates/ ./templates/
COPY static/ ./static/
COPY scripts/ ./scripts/
COPY data/ ./data/

# Make Python entrypoint executable
RUN chmod +x scripts/deployment/docker_entrypoint.py

# Expose port
EXPOSE 8000

# Use Python entrypoint to initialize OSINT repos before starting app (cross-platform)
ENTRYPOINT ["python", "scripts/deployment/docker_entrypoint.py"]

# Run the FastAPI application
CMD ["uvicorn", "archer.app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
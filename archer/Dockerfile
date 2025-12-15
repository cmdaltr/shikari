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
COPY archer.py .

# Make Python entrypoint executable
<<<<<<< HEAD
RUN chmod +x scripts/deployment/docker_entrypoint.py
=======
RUN chmod +x scripts/docker_entrypoint.py
>>>>>>> 534dbed55db820eea689f7a2b6dc4330fafc6b07

# Expose port
EXPOSE 8000

# Use Python entrypoint to initialize OSINT repos before starting app (cross-platform)
<<<<<<< HEAD
ENTRYPOINT ["python", "scripts/deployment/docker_entrypoint.py"]
=======
ENTRYPOINT ["python", "scripts/docker_entrypoint.py"]
>>>>>>> 534dbed55db820eea689f7a2b6dc4330fafc6b07

# Run the FastAPI application
CMD ["uvicorn", "archer.app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
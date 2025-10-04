FROM python:3.11-slim

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY gorgon/ ./gorgon/
COPY templates/ ./templates/
COPY static/ ./static/
COPY data/ ./data/
COPY cli.py .

# Expose port
EXPOSE 8000

# Run the FastAPI application
CMD ["uvicorn", "gorgon.app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
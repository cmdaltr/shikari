# Dockerfile for archer FastAPI service
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the archer package code
COPY archer/ ./archer/

# Expose FastAPI port
EXPOSE 8000

# Command to run FastAPI
CMD ["uvicorn", "archer.app:app", "--host", "0.0.0.0", "--port", "8000"]
# AI Model Configuration Guide for Archer

This guide explains how to configure AI models in Archer for detection generation, correlation analysis, and threat report generation.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Web Application Setup](#web-application-setup)
- [Configuration Methods](#configuration-methods)
  - [1. Cloud API Configuration](#1-cloud-api-configuration)
  - [2. Local Model Configuration (Ollama)](#2-local-model-configuration-ollama)
  - [3. Advanced Local Configuration](#3-advanced-local-configuration)
- [Supported Providers](#supported-providers)
- [Model Selection Guide](#model-selection-guide)
- [Training Configuration](#training-configuration)
- [Backend Comparison](#backend-comparison)
- [Troubleshooting](#troubleshooting)
- [Cost Optimization](#cost-optimization)

---

## Overview

Archer supports multiple AI model backends for different use cases:

- **Cloud APIs**: OpenAI GPT, Anthropic Claude, Google Gemini
- **Local Models**: Ollama (recommended), llama.cpp, Transformers
- **Training**: LoRA fine-tuning for custom detections

**Recommended Setup**: Start with **Anthropic Claude** for best quality, or **Ollama** for privacy/cost savings.

---

## Quick Start

### Option 1: Cloud API (Fastest Setup)

1. **Copy environment template**:
   ```bash
   cp .env.example .env
   ```

2. **Configure provider** (edit `.env`):
   ```bash
   # For Claude (Best Quality)
   LLM_PROVIDER=anthropic
   ANTHROPIC_API_KEY=sk-ant-your-api-key-here

   # OR for GPT (Fast Response)
   LLM_PROVIDER=openai
   OPENAI_API_KEY=sk-your-openai-key-here

   # OR for Gemini (Lowest Cost)
   LLM_PROVIDER=google
   GOOGLE_API_KEY=AIza-your-google-key-here
   ```

3. **Start Archer**:

   **For Web Application**:
   ```bash
   # Using Docker (Recommended)
   docker-compose up --build

   # OR using local Python
   uvicorn archer.app:app --reload

   # Access at http://localhost:8000
   # Login: admin@archer.app / £missary_0f_the_G0rg0nite$
   ```

   **For CLI**:
   ```bash
   python -m archer.cli
   ```

### Option 2: Local Ollama (Privacy-Focused)

1. **Install Ollama**:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```

2. **Start Ollama server**:
   ```bash
   ollama serve
   ```

3. **Pull a model**:
   ```bash
   # Recommended: Llama 3.1 70B (4-bit quantized)
   ollama pull llama3.1:70b-instruct-q4_K_M

   # Or lighter: Llama 3.1 8B
   ollama pull llama3.1:8b-instruct-q4_K_M
   ```

4. **Configure Archer** (edit `.env`):
   ```bash
   LLM_PROVIDER=ollama
   LLM_MODEL=llama3.1:70b-instruct-q4_K_M
   ```

5. **Start Archer**:

   **For Web Application**:
   ```bash
   # Using Docker (Recommended)
   docker-compose up --build

   # OR using local Python
   uvicorn archer.app:app --reload

   # Access at http://localhost:8000
   ```

   **For CLI**:
   ```bash
   python -m archer.cli
   ```

---

## Web Application Setup

The Archer web application is built with **FastAPI** and uses **Uvicorn** as the ASGI server. It automatically loads AI model configuration from environment variables.

### Starting the Web App

**Option 1: Docker (Recommended)**
```bash
# Start with Docker Compose
docker-compose up --build

# Access at http://localhost:8000
# Default login: admin@archer.app / £missary_0f_the_G0rg0nite$
```

**Option 2: Local Python**
```bash
# Requires Python 3.11 (requirements.txt pins torch==2.2.2, incompatible with 3.12+)
pyenv install 3.11.15
pyenv local 3.11.15

# Install dependencies
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Start the web server
uvicorn archer.app:app --reload

# Access at http://localhost:8000
```

### Environment Configuration

The web app loads configuration from `.env` file in the project root:

```bash
# Create .env file
cp .env.example .env
```

**Example .env for Cloud API**:
```bash
# LLM Provider Configuration
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your-api-key-here
LLM_MODEL=claude-sonnet-4-5-20250929

# Correlation Settings
CORRELATION_MIN_RELEVANCE=0.75
CORRELATION_MAX_LIMIT=250

# Database (optional)
DATABASE_PATH=data/archer.db
```

**Example .env for Local Ollama**:
```bash
# LLM Provider Configuration
LLM_PROVIDER=ollama
LLM_MODEL=llama3.1:70b-instruct-q4_K_M
OLLAMA_BASE_URL=http://localhost:11434

# Correlation Settings
CORRELATION_MIN_RELEVANCE=0.75
CORRELATION_MAX_LIMIT=250
```

### Docker Compose Configuration

**For Local Ollama on Host Machine**:
```yaml
# docker-compose.yml
version: "3.8"

services:
  archer:
    build:
      context: .
      dockerfile: archer/Dockerfile
    ports:
      - "8000:8000"
    environment:
      - PYTHONUNBUFFERED=1
      - LLM_PROVIDER=ollama
      - LLM_MODEL=llama3.1:70b-instruct-q4_K_M
      - OLLAMA_BASE_URL=http://host.docker.internal:11434
    volumes:
      - ./archer:/app/archer
      - ./templates:/app/templates
      - ./static:/app/static
      - ./data:/app/data
    restart: unless-stopped
```

**For Ollama in Docker (Fully Containerized)**:
```yaml
# docker-compose.yml
version: "3.8"

services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    environment:
      - OLLAMA_HOST=0.0.0.0:11434
    # Optional: GPU support for NVIDIA
    # deploy:
    #   resources:
    #     reservations:
    #       devices:
    #         - driver: nvidia
    #           count: 1
    #           capabilities: [gpu]

  archer:
    build:
      context: .
      dockerfile: archer/Dockerfile
    ports:
      - "8000:8000"
    environment:
      - PYTHONUNBUFFERED=1
      - LLM_PROVIDER=ollama
      - LLM_MODEL=llama3.1:70b-instruct-q4_K_M
      - OLLAMA_BASE_URL=http://ollama:11434
      - CORRELATION_MIN_RELEVANCE=0.75
      - CORRELATION_MAX_LIMIT=250
    depends_on:
      - ollama
    volumes:
      - ./archer:/app/archer
      - ./templates:/app/templates
      - ./static:/app/static
      - ./data:/app/data
    restart: unless-stopped

volumes:
  ollama_data:
```

**Pull models into Ollama container**:
```bash
# After starting docker-compose up
docker exec -it archer-ollama-1 ollama pull llama3.1:70b-instruct-q4_K_M
docker exec -it archer-ollama-1 ollama pull llama3.1:8b-instruct-q4_K_M
```

### How the Web App Loads Configuration

The web application (`archer/app.py`) loads configuration through `archer/config.py`:

```python
# From archer/config.py
import os

# LLM Provider Configuration
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")
LLM_MODEL = os.getenv("LLM_MODEL")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Correlation Configuration
CORRELATION_MIN_RELEVANCE = float(os.getenv("CORRELATION_MIN_RELEVANCE", "0.75"))
CORRELATION_MAX_LIMIT = int(os.getenv("CORRELATION_MAX_LIMIT", "250"))
```

### Verifying Configuration

Once the web app is running:

1. **Access the application**: Navigate to `http://localhost:8000`
2. **Login**: Use default credentials (change immediately!)
   - Email: `admin@archer.app`
   - Password: `£missary_0f_the_G0rg0nite$`
3. **Test AI generation**:
   - Navigate to **Generate** page
   - Select a threat group or technique
   - Click **Generate Detections**
   - The configured LLM provider will be used for generation

### Monitoring Logs

**Docker**:
```bash
# View logs
docker-compose logs -f archer

# View Ollama logs (if using Docker)
docker-compose logs -f ollama
```

**Local Python**:
```bash
# Uvicorn logs are displayed in terminal
# Look for startup messages like:
# INFO:     Application startup complete.
# INFO:     Uvicorn running on http://127.0.0.1:8000
```

---

## Configuration Methods

### 1. Cloud API Configuration

Cloud APIs require no local model setup—just API keys.

#### Anthropic Claude (Recommended for Quality)

**Step 1**: Get API key from https://console.anthropic.com/

**Step 2**: Configure `.env`:
```bash
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-api01-your-key-here

# Optional: Specify model (defaults to claude-sonnet-4-5-20250929)
LLM_MODEL=claude-sonnet-4-5-20250929
```

**Pricing**:
- Claude Sonnet 4.5: $3/M input tokens, $15/M output tokens
- Claude Opus 4: $15/M input tokens, $75/M output tokens

**Best For**: High-quality detection generation, complex correlation analysis

#### OpenAI GPT (Recommended for Speed)

**Step 1**: Get API key from https://platform.openai.com/

**Step 2**: Install OpenAI package:
```bash
pip install openai
```

**Step 3**: Configure `.env`:
```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-openai-key-here

# Optional: Specify model (defaults to gpt-4o)
LLM_MODEL=gpt-4o
```

**Pricing**:
- GPT-4o: $2.50/M input tokens, $10/M output tokens
- GPT-4 Turbo: $10/M input tokens, $30/M output tokens

**Best For**: Fast response times, general-purpose detection generation

#### Google Gemini (Recommended for Cost)

**Step 1**: Get API key from https://aistudio.google.com/

**Step 2**: Install Google AI package:
```bash
pip install google-generativeai
```

**Step 3**: Configure `.env`:
```bash
LLM_PROVIDER=google
GOOGLE_API_KEY=AIza-your-google-key-here

# Optional: Specify model (defaults to gemini-2.0-flash-exp)
LLM_MODEL=gemini-2.0-flash-exp
```

**Pricing**:
- Gemini 2.0 Flash: $0.075/M input tokens, $0.30/M output tokens
- Gemini Pro: $0.50/M input tokens, $1.50/M output tokens

**Best For**: Cost-effective detection generation, high-volume usage

---

### 2. Local Model Configuration (Ollama)

Ollama provides the easiest local model setup with no API costs.

#### Installation

**macOS**:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Linux**:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Windows**:
Download from https://ollama.com/download

#### Starting Ollama

```bash
# Start server (runs on http://localhost:11434)
ollama serve

# Or run as background service
ollama serve &
```

#### Model Selection

**For Detection Generation** (Recommended):
```bash
# Best quality (requires ~40GB RAM)
ollama pull llama3.1:70b-instruct-q4_K_M

# Good quality (requires ~8GB RAM)
ollama pull llama3.1:8b-instruct-q4_K_M

# Alternative: Qwen 2.5 (excellent for code/queries)
ollama pull qwen2.5:72b-instruct-q4_K_M
```

**For Correlation Analysis**:
```bash
# Best for multi-step reasoning
ollama pull mixtral:8x7b-instruct-v0.1-q4_K_M

# Lightweight alternative
ollama pull mistral:7b-instruct-q4_K_M
```

**For CVE Analysis** (lightweight tasks):
```bash
ollama pull llama3.1:8b-instruct-q4_K_M
```

#### Configure Archer for Ollama

**Method 1: Using .env file** (for local Python):
```bash
# Edit .env
LLM_PROVIDER=ollama
LLM_MODEL=llama3.1:70b-instruct-q4_K_M

# Optional: Custom Ollama endpoint
# OLLAMA_ENDPOINT=http://localhost:11434
```

**Method 2: Using Docker Compose** (for Docker deployment):
```yaml
# Edit docker-compose.yml
version: "3.8"

services:
  archer:
    build:
      context: .
      dockerfile: archer/Dockerfile
    ports:
      - "8000:8000"
    environment:
      - PYTHONUNBUFFERED=1
      - LLM_PROVIDER=ollama
      - LLM_MODEL=llama3.1:70b-instruct-q4_K_M
      - OLLAMA_BASE_URL=http://host.docker.internal:11434  # For Ollama on host
    volumes:
      - ./archer:/app/archer
      - ./templates:/app/templates
      - ./static:/app/static
      - ./data:/app/data
    restart: unless-stopped
```

**Method 3: Ollama in Docker** (fully containerized):
```yaml
# docker-compose.yml with Ollama service
version: "3.8"

services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    environment:
      - OLLAMA_HOST=0.0.0.0:11434

  archer:
    build:
      context: .
      dockerfile: archer/Dockerfile
    ports:
      - "8000:8000"
    environment:
      - PYTHONUNBUFFERED=1
      - LLM_PROVIDER=ollama
      - LLM_MODEL=llama3.1:70b-instruct-q4_K_M
      - OLLAMA_BASE_URL=http://ollama:11434  # Reference Docker service name
    depends_on:
      - ollama
    volumes:
      - ./archer:/app/archer
      - ./templates:/app/templates
      - ./static:/app/static
      - ./data:/app/data
    restart: unless-stopped

volumes:
  ollama_data:
```

#### Verify Setup

```bash
# Test Ollama is running
curl http://localhost:11434/api/tags

# Test model generation
ollama run llama3.1:70b-instruct-q4_K_M "Generate a KQL query to detect PowerShell downloads"
```

#### Start Archer Web Application

```bash
# Using Docker
docker-compose up --build

# OR using local Python (ensure .env is configured)
uvicorn archer.app:app --reload

# Access the web app at http://localhost:8000
# Default login: admin@archer.app / £missary_0f_the_G0rg0nite$
```

---

### 3. Advanced Local Configuration

For advanced users wanting more control over model deployment.

#### vLLM (High-Throughput Production)

**Use Case**: Production deployments with high query volume

**Requirements**:
- CUDA GPU with 24GB+ VRAM
- Linux system

**Installation**:
```bash
pip install vllm
```

**Start vLLM Server**:
```bash
python -m vllm.entrypoints.openai.api_server \
    --model meta-llama/Llama-3.1-70B-Instruct \
    --tensor-parallel-size 2 \
    --port 8000
```

**Configure Archer** (edit `archer/ai/training/config.py`):
```python
MODEL_CONFIG = {
    "backends": {
        "vllm": {
            "enabled": True,
            "endpoint": "http://localhost:8000",
            "tensor_parallel_size": 2
        }
    }
}
```

#### llama.cpp (CPU-Only Systems)

**Use Case**: Systems without GPU, resource-constrained environments

**Installation**:
```bash
pip install llama-cpp-python
```

**Download Model**:
```bash
# Download GGUF format model
wget https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF/resolve/main/llama-2-7b-chat.Q4_K_M.gguf
```

**Configure Archer** (edit `archer/ai/training/config.py`):
```python
MODEL_CONFIG = {
    "backends": {
        "llama_cpp": {
            "enabled": True,
            "model_path": "/path/to/llama-2-7b-chat.Q4_K_M.gguf",
            "n_ctx": 8192,
            "n_gpu_layers": 0  # Set to 0 for CPU-only
        }
    }
}
```

#### Transformers (For Fine-Tuning)

**Use Case**: Model training and fine-tuning

**Requirements**:
- CUDA GPU with 16GB+ VRAM (or Apple Silicon with Metal)
- PyTorch

**Installation**:
```bash
pip install transformers accelerate bitsandbytes peft
```

**Configure Archer** (edit `archer/ai/training/config.py`):
```python
MODEL_CONFIG = {
    "backends": {
        "transformers": {
            "enabled": True,
            "device": "cuda",  # or "mps" for Apple Silicon
            "load_in_8bit": True,  # Use 8-bit quantization
            "load_in_4bit": False  # Or use 4-bit for lower memory
        }
    }
}
```

---

## Supported Providers

### Provider Comparison

| Provider | Setup Difficulty | Cost | Privacy | Quality | Speed |
|----------|-----------------|------|---------|---------|-------|
| **Anthropic Claude** | Easy | Medium | Cloud | Excellent | Fast |
| **OpenAI GPT** | Easy | Medium | Cloud | Excellent | Very Fast |
| **Google Gemini** | Easy | Low | Cloud | Good | Fast |
| **Ollama** | Easy | Free | Local | Excellent | Medium |
| **vLLM** | Hard | Free | Local | Excellent | Very Fast |
| **llama.cpp** | Medium | Free | Local | Good | Slow |
| **Transformers** | Hard | Free | Local | Excellent | Medium |

### Default Models by Provider

Configured in `archer/ai/llm/providers.py`:

- **Anthropic**: `claude-sonnet-4-5-20250929`
- **OpenAI**: `gpt-4o`
- **Google**: `gemini-2.0-flash-exp`
- **Ollama**: `llama2` (configure to use better models)

### Task-Specific Model Recommendations

From `archer/ai/training/config.py`:

**Detection Generation**:
- Primary: `llama3.1:70b-instruct-q4_K_M`
- Alternative: `qwen2.5:72b-instruct-q4_K_M`
- Cloud: `claude-sonnet-4-5-20250929`

**Correlation Generation**:
- Primary: `mixtral:8x7b-instruct-v0.1-q4_K_M`
- Alternative: `llama3.1:70b-instruct-q4_K_M`
- Cloud: `gpt-4o`

**Report Generation**:
- Primary: `llama3.1:70b-instruct-q4_K_M`
- Cloud: `claude-opus-4-20241120`

**CVE Analysis**:
- Primary: `llama3.1:8b-instruct-q4_K_M`
- Cloud: `gemini-2.0-flash-exp`

---

## Model Selection Guide

### By Use Case

**Best Quality (Security-Critical Detections)**:
```bash
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-5-20250929
```

**Best Cost (High Volume)**:
```bash
LLM_PROVIDER=google
LLM_MODEL=gemini-2.0-flash-exp
```

**Best Privacy (Air-Gapped/Classified)**:
```bash
LLM_PROVIDER=ollama
LLM_MODEL=llama3.1:70b-instruct-q4_K_M
```

**Best Speed (Real-Time)**:
```bash
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
```

### By Resource Availability

**High Memory (64GB+ RAM)**:
- Ollama: `llama3.1:70b-instruct-q4_K_M`
- Ollama: `qwen2.5:72b-instruct-q4_K_M`

**Medium Memory (16-32GB RAM)**:
- Ollama: `llama3.1:8b-instruct-q4_K_M`
- Ollama: `mistral:7b-instruct-q4_K_M`

**Low Memory (8-16GB RAM)**:
- Cloud APIs (no local model)
- Ollama: `llama2:7b-chat-q4_K_M`

**GPU Available (24GB+ VRAM)**:
- vLLM: `meta-llama/Llama-3.1-70B-Instruct`
- Transformers: 8-bit quantization

**CPU Only**:
- llama.cpp with small models
- Cloud APIs (recommended)

---

## Training Configuration

### Configuration File

Edit `archer/ai/training/config.py`:

```python
MODEL_CONFIG = {
    # Backend selection
    "backends": {
        "ollama": {
            "enabled": True,
            "endpoint": "http://localhost:11434",
            "models": [
                "llama3.1:70b-instruct-q4_K_M",
                "llama3.1:8b-instruct-q4_K_M",
                "mixtral:8x7b-instruct-v0.1-q4_K_M"
            ]
        }
    },

    # Task-specific models
    "default_models": {
        "detection_generation": "llama3.1:70b-instruct-q4_K_M",
        "correlation_generation": "mixtral:8x7b-instruct-v0.1-q4_K_M",
        "report_generation": "llama3.1:70b-instruct-q4_K_M",
        "cve_analysis": "llama3.1:8b-instruct-q4_K_M"
    },

    # Generation parameters
    "generation_params": {
        "temperature": 0.7,
        "top_p": 0.9,
        "max_tokens": 4096,
        "frequency_penalty": 0.0,
        "presence_penalty": 0.0
    }
}

TRAINING_CONFIG = {
    "epochs": 3,
    "batch_size": 4,
    "learning_rate": 2e-5,
    "max_seq_length": 8192,

    # LoRA configuration
    "lora": {
        "r": 16,
        "alpha": 32,
        "dropout": 0.05,
        "target_modules": ["q_proj", "v_proj"]
    },

    # Quantization
    "quantization": {
        "load_in_8bit": False,
        "load_in_4bit": True
    }
}
```

### Training Commands

**Basic LoRA Training**:
```bash
python -m archer.ai.training.pipelines.training \
    --data archer/ai/training/datasets/hunting_queries/ \
    --model llama3.1:70b \
    --epochs 5 \
    --lora \
    --lora-rank 16 \
    --learning-rate 2e-4 \
    --batch-size 4
```

**Memory-Efficient (4-bit)**:
```bash
python -m archer.ai.training.pipelines.training \
    --data archer/ai/training/datasets/ \
    --model llama3.1:70b \
    --epochs 3 \
    --lora \
    --quantization 4bit \
    --batch-size 2 \
    --gradient-accumulation-steps 8
```

---

## Backend Comparison

### Performance Benchmarks

Based on detection generation tasks:

| Backend | Setup Time | Inference Speed | Quality | Memory | Cost |
|---------|------------|----------------|---------|--------|------|
| **Claude API** | 5 min | 2-3 sec | 9.5/10 | 0 GB | $3-15/M tokens |
| **GPT-4o API** | 5 min | 1-2 sec | 9/10 | 0 GB | $2.50-10/M tokens |
| **Gemini API** | 5 min | 2-3 sec | 8/10 | 0 GB | $0.08-0.30/M tokens |
| **Ollama (70B)** | 15 min | 5-10 sec | 9/10 | 40 GB | Free |
| **Ollama (8B)** | 10 min | 2-3 sec | 7.5/10 | 8 GB | Free |
| **vLLM (70B)** | 2 hours | 1-2 sec | 9/10 | 48 GB VRAM | Free |
| **llama.cpp (7B)** | 30 min | 20-30 sec | 7/10 | 6 GB | Free |

### Recommendations by Scenario

**Enterprise Production**:
- Primary: Anthropic Claude (quality + support)
- Backup: OpenAI GPT (speed)
- Local: vLLM with Llama 3.1 70B (privacy)

**Startup/SMB**:
- Primary: Google Gemini (cost-effective)
- Local: Ollama with Llama 3.1 8B (privacy)

**Air-Gapped/Classified**:
- Only: Ollama or vLLM with local models

**Development/Testing**:
- Fast: Ollama with Llama 3.1 8B
- Budget: Google Gemini

---

## Troubleshooting

### Ollama Issues

**Issue**: Connection refused to Ollama
```bash
# Solution: Start Ollama server
ollama serve

# Verify it's running
curl http://localhost:11434/api/tags
```

**Issue**: Model not found
```bash
# Solution: Pull the model first
ollama pull llama3.1:70b-instruct-q4_K_M

# List available models
ollama list
```

**Issue**: Out of memory
```bash
# Solution: Use smaller model
ollama pull llama3.1:8b-instruct-q4_K_M

# Update .env
LLM_MODEL=llama3.1:8b-instruct-q4_K_M
```

### API Issues

**Issue**: Invalid API key
```bash
# Solution: Check .env file has correct key format
# Anthropic: sk-ant-api01-...
# OpenAI: sk-...
# Google: AIza...
```

**Issue**: Rate limit exceeded
```bash
# Solution: Add retry logic or switch to local model temporarily
# Or upgrade API plan
```

**Issue**: API timeout
```bash
# Solution: Increase timeout in config or use faster model
# For OpenAI: Use gpt-4o instead of gpt-4-turbo
```

### Training Issues

**Issue**: CUDA out of memory
```bash
# Solution: Enable 4-bit quantization
python -m archer.ai.training.pipelines.training \
    --quantization 4bit \
    --batch-size 1 \
    --gradient-accumulation-steps 16
```

**Issue**: Model not loading
```bash
# Solution: Check model path and format
# For Ollama: Ensure model is pulled
# For Transformers: Use HuggingFace model ID
```

---

## Cost Optimization

### Strategies

1. **Use Gemini for high-volume tasks**: 40x cheaper than Claude
2. **Cache API responses**: Implement caching for repeated queries
3. **Use smaller models for simple tasks**: CVE analysis doesn't need 70B models
4. **Batch requests**: Reduce API overhead
5. **Local models for development**: Use Ollama during testing
6. **Tier your models**:
   - Critical detections: Claude Sonnet
   - Standard detections: Gemini Flash
   - Bulk processing: Local Ollama

### Cost Comparison (1M tokens generated)

| Provider | Model | Input Cost | Output Cost | Total (1M gen) |
|----------|-------|------------|-------------|----------------|
| **Google** | Gemini Flash | $0.075 | $0.30 | $0.38 |
| **OpenAI** | GPT-4o | $2.50 | $10.00 | $12.50 |
| **Anthropic** | Claude Sonnet | $3.00 | $15.00 | $18.00 |
| **Anthropic** | Claude Opus | $15.00 | $75.00 | $90.00 |
| **Ollama** | Any model | $0.00 | $0.00 | $0.00 |

### Hybrid Configuration

For optimal cost/quality balance:

```bash
# .env configuration for hybrid setup
LLM_PROVIDER=google
LLM_MODEL=gemini-2.0-flash-exp
GOOGLE_API_KEY=AIza-your-key-here

# Use local Ollama for development
# LLM_PROVIDER=ollama
# LLM_MODEL=llama3.1:8b-instruct-q4_K_M
```

Then override for critical tasks in code:
```python
# Use Claude for high-value detections
from archer.ai.llm.providers import LLMFactory

claude = LLMFactory.create_provider("anthropic")
response = claude.generate(prompt, max_tokens=2000)
```

---

## Additional Resources

- [Training Data Collection Guide](TRAIN_AI.md)
- [LLM Detection Generation Documentation](LLM_DETECTION_GENERATION.md)
- [AI Training Architecture](AI_TRAINING.md)
- [Ollama Documentation](https://ollama.com/docs)
- [Anthropic API Reference](https://docs.anthropic.com/)
- [OpenAI API Reference](https://platform.openai.com/docs/)
- [Google AI Studio](https://aistudio.google.com/)

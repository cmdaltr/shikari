# Shikari AI Documentation

Complete guide to AI-powered detection generation, model configuration, and training in Shikari.

## Quick Start

### 1. Configure an AI Model

**Option A: Cloud API (Fastest)**
```bash
# Edit .env file
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

**Option B: Local LLM (Privacy-focused)**
```bash
# Automated setup based on your system RAM
python scripts/ai/setup_local_llm.py
```

See **[MODEL_CONFIGURATION.md](MODEL_CONFIGURATION.md)** for complete setup guide.

### 2. Start Using AI Features

```bash
# Start Shikari
docker-compose up --build
# or
uvicorn shikari.app:app --reload

# Access at http://localhost:8000
# Navigate to Generate → Select technique → AI-powered generation
```

---

## Documentation Guide

### For Getting Started

**[MODEL_CONFIGURATION.md](MODEL_CONFIGURATION.md)** - Start here
- How to configure AI models (cloud or local)
- Provider comparison (Anthropic, OpenAI, Google, Ollama)
- Web application setup
- Quick start guides
- Troubleshooting

**Recommended for**: First-time setup, choosing a model provider

### For Training Custom Models

**[TRAIN_AI.md](TRAIN_AI.md)** - Training data collection
- Collecting CVE data
- Converting threat reports
- Extracting OSINT rules
- **Adding custom high-fidelity queries**
- Training workflows

**Recommended for**: Security teams with proprietary detections

### For Understanding the Architecture

**[LLM_DETECTION_GENERATION.md](LLM_DETECTION_GENERATION.md)** - Technical deep-dive
- Detection generation architecture
- Multi-backend support (Ollama, vLLM, llama.cpp, Transformers)
- Training data formats (JSONL)
- Inference pipelines
- Model benchmarks

**Recommended for**: Developers, advanced users

### For Advanced Training

**[AI_TRAINING.md](AI_TRAINING.md)** - Complete implementation guide
- Three-tiered training approach
- Few-shot learning
- Fine-tuning with LoRA
- Database schema for feedback
- API endpoints
- Frontend components

**Recommended for**: Organizations implementing continuous learning

---

## Use Cases

### Use Case 1: Basic Setup (Cloud API)

**Goal**: Get AI-powered detection generation working quickly

**Steps**:
1. Read [MODEL_CONFIGURATION.md](MODEL_CONFIGURATION.md) → Quick Start
2. Choose a provider (Anthropic recommended for quality)
3. Add API key to `.env`
4. Start Shikari

**Time**: 5 minutes

---

### Use Case 2: Privacy-Focused Setup (Local LLM)

**Goal**: Run AI entirely on-premise

**Steps**:
1. Run automated setup: `python scripts/ai/setup_local_llm.py`
2. Script auto-selects model based on your RAM
3. Start Shikari

**Time**: 15-30 minutes (depending on model download)

**Documentation**:
- [MODEL_CONFIGURATION.md](MODEL_CONFIGURATION.md) → Local Ollama section
- [scripts/ai/LOCAL_LLM.md](../../scripts/ai/LOCAL_LLM.md) → Setup scripts

---

### Use Case 3: Train on Custom Detections

**Goal**: Train AI on your organization's proprietary detection queries

**Steps**:
1. Read [TRAIN_AI.md](TRAIN_AI.md) → Custom High-Fidelity Queries section
2. Create JSONL training data with your queries
3. Run training: `python scripts/ai/train_ai.py custom --import-dir custom_queries/`
4. Fine-tune model: `python -m shikari.ai.training.pipelines.training`

**Time**: 2-4 hours (setup + training)

**Documentation**:
- [TRAIN_AI.md](TRAIN_AI.md) → Complete guide
- [TRAIN_AI.md](TRAIN_AI.md) → Training Data Format Specification

---

### Use Case 4: Enterprise Deployment

**Goal**: Production deployment with local LLM and custom training

**Steps**:
1. Set up Ollama with appropriate model (see [MODEL_CONFIGURATION.md](MODEL_CONFIGURATION.md))
2. Configure Docker Compose for production
3. Collect custom training data ([TRAIN_AI.md](TRAIN_AI.md))
4. Implement feedback loop ([AI_TRAINING.md](AI_TRAINING.md))
5. Fine-tune model quarterly

**Time**: 1-2 days initial setup, ongoing maintenance

**Documentation**:
- [MODEL_CONFIGURATION.md](MODEL_CONFIGURATION.md) → Docker Compose setup
- [AI_TRAINING.md](AI_TRAINING.md) → Complete implementation
- [LLM_DETECTION_GENERATION.md](LLM_DETECTION_GENERATION.md) → Architecture

---

## File Reference

| File | Purpose | Audience | Length |
|------|---------|----------|--------|
| **[MODEL_CONFIGURATION.md](MODEL_CONFIGURATION.md)** | AI model setup and configuration | All users | ~1000 lines |
| **[TRAIN_AI.md](TRAIN_AI.md)** | Training data collection and custom queries | Security analysts | ~680 lines |
| **[LLM_DETECTION_GENERATION.md](LLM_DETECTION_GENERATION.md)** | Technical architecture and implementation | Developers | ~830 lines |
| **[AI_TRAINING.md](AI_TRAINING.md)** | Advanced training and feedback loops | Organizations | ~1270 lines |

---

## Supported AI Providers

### Cloud APIs

| Provider | Default Model | Cost (per 1M tokens) | Best For |
|----------|---------------|----------------------|----------|
| **Anthropic Claude** | claude-sonnet-4-5 | $3 in / $15 out | Best quality |
| **OpenAI GPT** | gpt-4o | $2.50 in / $10 out | Fast response |
| **Google Gemini** | gemini-2.0-flash | $0.075 in / $0.30 out | Cost-effective |

### Local Models (via Ollama)

| Model | RAM Required | Size | Quality |
|-------|--------------|------|---------|
| **llama3.1:70b** | 64GB+ | ~40GB | Excellent |
| **qwen2.5:32b** | 32GB+ | ~20GB | Excellent |
| **llama3.1:8b** | 16GB+ | ~5GB | Good |
| **mistral:7b** | 8GB+ | ~4GB | Moderate |

**Setup**: `python scripts/ai/setup_local_llm.py` (auto-selects based on your RAM)

---

## Common Tasks

### Change AI Provider

```bash
# Edit .env
LLM_PROVIDER=ollama  # or anthropic, openai, google
LLM_MODEL=llama3.1:70b-instruct-q4_K_M

# Restart Shikari
docker-compose restart
```

### Update OSINT Training Data

```bash
python scripts/ai/train_ai.py osint --all
```

### Add Custom Detection Queries

```bash
# Create queries.json with your detections
python scripts/ai/train_ai.py custom --import queries.json

# Train model
python -m shikari.ai.training.pipelines.training \
    --data shikari/ai/training/datasets/hunting_queries/ \
    --model llama3.1:70b \
    --epochs 5 --lora
```

### Test Model Configuration

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Test model via CLI
ollama run llama3.1:70b "Generate a KQL query to detect PowerShell downloads"

# Check Shikari logs
docker-compose logs -f shikari
```

---

## Troubleshooting

### "Connection refused" to Ollama

```bash
# Start Ollama server
ollama serve

# Verify it's running
curl http://localhost:11434/api/tags
```

### "Invalid API key"

Check your `.env` file has the correct format:
- Anthropic: `ANTHROPIC_API_KEY=sk-ant-api01-...`
- OpenAI: `OPENAI_API_KEY=sk-...`
- Google: `GOOGLE_API_KEY=AIza...`

### "Out of memory" with local model

```bash
# Use smaller model
python scripts/ai/setup_local_llm.py --ram 16  # Forces 8B model

# Or manually switch
# Edit .env: LLM_MODEL=llama3.1:8b-instruct-q4_K_M
```

### Training fails

```bash
# Validate training data format
python scripts/ai/train_ai.py custom --validate shikari/ai/training/datasets/

# Check you have enough examples (minimum 20-50 recommended)
```

---

## Related Documentation

### In This Directory
- [MODEL_CONFIGURATION.md](MODEL_CONFIGURATION.md) - Setup guide
- [TRAIN_AI.md](TRAIN_AI.md) - Training data collection
- [LLM_DETECTION_GENERATION.md](LLM_DETECTION_GENERATION.md) - Architecture
- [AI_TRAINING.md](AI_TRAINING.md) - Advanced training

### Scripts
- [scripts/ai/](../../scripts/ai/) - AI setup scripts
- [scripts/ai/setup_local_llm.py](../../scripts/ai/setup_local_llm.py) - Automated local LLM setup
- [scripts/ai/train_ai.py](../../scripts/ai/train_ai.py) - Training data collection

### Other Documentation
- [Getting Started](../../GETTING_STARTED.md) - Shikari setup
- [Usage Guide](../USAGE.md) - How to use Shikari
- [Architecture](../architecture/ARCHITECTURE.md) - System architecture

---

## Getting Help

1. **Check documentation**: Start with [MODEL_CONFIGURATION.md](MODEL_CONFIGURATION.md)
2. **Review examples**: See each doc's "Quick Examples" section
3. **Check logs**: `docker-compose logs -f shikari`
4. **Test components**:
   - Ollama: `curl http://localhost:11434/api/tags`
   - Model: `ollama run <model-name> "test prompt"`
5. **GitHub Issues**: Report bugs or request features

---

## Contributing

To add new AI documentation:
1. Follow existing structure and format
2. Include practical examples
3. Add entry to this README
4. Update cross-references
5. Test all commands

---

*Last Updated: 2024-11-14*

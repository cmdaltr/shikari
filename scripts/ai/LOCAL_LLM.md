# Local LLM Setup Scripts

Automated scripts to configure Archer with a local LLM (Ollama) based on your system resources.

## Quick Start

### Python Script (Recommended - Cross-Platform)

```bash
# Auto-detect RAM and configure everything automatically
python scripts/ai/setup_local_llm.py

# Specify RAM manually (useful for servers/VMs)
python scripts/ai/setup_local_llm.py --ram 32

# Skip confirmation prompts (for automation)
python scripts/ai/setup_local_llm.py --yes
```

## What This Script Does

1. **Detect System RAM**: Auto-detects available RAM or allows manual input
2. **Recommend Best Model**: Selects optimal model based on resources
3. **Install Ollama**: Installs Ollama if not already present (Linux/macOS)
4. **Download Model**: Pulls the selected model from Ollama registry
5. **Configure Archer**: Updates `.env` file with local LLM settings
6. **Verify Setup**: Tests the installation and model functionality

## Model Recommendations by RAM

| RAM Available | Model Selected | Size | Description |
|---------------|----------------|------|-------------|
| **64GB+** | `llama3.1:70b-instruct-q4_K_M` | ~40GB | Best quality - perfect for detection engineering |
| **32-63GB** | `qwen2.5:32b-instruct-q4_K_M` | ~20GB | Excellent quality - great for code/query generation |
| **16-31GB** | `llama3.1:8b-instruct-q4_K_M` | ~5GB | Good quality - balanced performance |
| **8-15GB** | `mistral:7b-instruct-q4_K_M` | ~4GB | Lightweight - suitable for basic tasks |
| **4-7GB** | `phi3:mini` | ~2GB | Minimal - very basic LLM capabilities |

## Usage Examples

### Example 1: Default Setup (Auto-detect)

```bash
$ python scripts/ai/setup_local_llm.py

═══════════════════════════════════════════════════════════════
  Archer Local LLM Setup
═══════════════════════════════════════════════════════════════

This script will set up a local LLM (Ollama) for Archer based on your system resources.

ℹ Detected RAM: 32GB
Is this correct? (y/n, or enter custom value in GB): y

═══════════════════════════════════════════════════════════════
  Recommended Configuration
═══════════════════════════════════════════════════════════════
  System RAM:    32GB
  Model:         qwen2.5:32b-instruct-q4_K_M
  Model Size:    ~20GB
  Description:   Excellent Quality - Great for code/query generation

Proceed with this configuration? (y/n): y
```

### Example 2: Specify RAM Manually

```bash
# For a server with 64GB RAM
python scripts/ai/setup_local_llm.py --ram 64

# For a laptop with 16GB RAM
python scripts/ai/setup_local_llm.py --ram 16
```

### Example 3: Automated/Non-Interactive

```bash
# Useful for scripts or automation
python scripts/ai/setup_local_llm.py --ram 32 --yes
```

## What Gets Configured

### `.env` File

The script updates your `.env` file with:

```bash
LLM_PROVIDER=ollama
LLM_MODEL=llama3.1:70b-instruct-q4_K_M  # or appropriate model for your RAM
OLLAMA_BASE_URL=http://localhost:11434
```

### Ollama Server

- Starts Ollama server on `http://localhost:11434`
- Downloads the selected model
- Verifies model is working

## After Setup

Once the script completes, you can start Archer:

### Using Docker

```bash
docker-compose up --build
```

Access at: `http://localhost:8000`

### Using Local Python

```bash
uvicorn archer.app:app --reload
```

Access at: `http://localhost:8000`

### Default Login

```
Email: admin@archer.app
Password: £missary_0f_the_G0rg0nite$
```

## Troubleshooting

### Issue: "Ollama is not installed"

**Windows users**: Download Ollama from https://ollama.com/download/windows

**Linux/macOS users**: The script will attempt to install automatically

### Issue: "Failed to start Ollama server"

```bash
# Check if Ollama is already running
curl http://localhost:11434/api/tags

# Manually start Ollama
ollama serve

# Check logs (if using script)
tail -f /tmp/ollama.log
```

### Issue: "Out of memory" when running model

Your system doesn't have enough RAM for the selected model. Re-run with a smaller model:

```bash
# Use smaller model
python scripts/ai/setup_local_llm.py --ram 8  # Will select mistral:7b-instruct-q4_K_M
```

### Issue: "Model download is slow"

This is normal. Large models (40GB+) can take 30+ minutes on slower connections. The script will wait.

### Issue: "Connection refused" when testing

Wait a few seconds for Ollama to fully start, then retry.

## Manual Configuration

If you prefer manual setup, follow these steps:

### 1. Install Ollama

```bash
# Linux/macOS
curl -fsSL https://ollama.com/install.sh | sh

# Windows
# Download from https://ollama.com/download/windows
```

### 2. Start Ollama

```bash
ollama serve
```

### 3. Pull a Model

```bash
# For 64GB+ RAM
ollama pull llama3.1:70b-instruct-q4_K_M

# For 32GB RAM
ollama pull qwen2.5:32b-instruct-q4_K_M

# For 16GB RAM
ollama pull llama3.1:8b-instruct-q4_K_M

# For 8GB RAM
ollama pull mistral:7b-instruct-q4_K_M
```

### 4. Configure Archer

Create or edit `.env`:

```bash
LLM_PROVIDER=ollama
LLM_MODEL=llama3.1:70b-instruct-q4_K_M
OLLAMA_BASE_URL=http://localhost:11434
```

### 5. Start Archer

```bash
# Docker
docker-compose up --build

# OR Local Python
uvicorn archer.app:app --reload
```

## Advanced Options

### Using Different Models

You can override the recommended model:

1. Run the setup script to configure everything
2. Manually pull a different model:
   ```bash
   ollama pull codellama:13b  # Example: CodeLlama for code generation
   ```
3. Update `.env`:
   ```bash
   LLM_MODEL=codellama:13b
   ```

### Docker Deployment with Local Ollama

If Archer runs in Docker but Ollama is on the host:

```yaml
# docker-compose.yml
environment:
  - LLM_PROVIDER=ollama
  - LLM_MODEL=llama3.1:70b-instruct-q4_K_M
  - OLLAMA_BASE_URL=http://host.docker.internal:11434
```

### GPU Acceleration

Ollama automatically uses GPU if available (NVIDIA CUDA or Apple Silicon Metal). No additional configuration needed.

## Monitoring

### Check Ollama Status

```bash
# List running models
ollama list

# Check server status
curl http://localhost:11434/api/tags

# Test model
ollama run llama3.1:70b-instruct-q4_K_M "Generate a KQL query to detect PowerShell"
```

### Check Archer Logs

```bash
# Docker
docker-compose logs -f archer

# Local Python
# Logs appear in terminal where uvicorn is running
```

## Uninstalling

### Remove Models

```bash
# List models
ollama list

# Remove a specific model
ollama rm llama3.1:70b-instruct-q4_K_M
```

### Stop Ollama

```bash
# Linux/macOS
killall ollama

# Windows
# Close Ollama from system tray or Task Manager
```

### Uninstall Ollama

```bash
# Linux
sudo rm -rf /usr/local/bin/ollama
sudo rm -rf ~/.ollama

# macOS
brew uninstall ollama  # If installed via Homebrew
# OR
sudo rm -rf /usr/local/bin/ollama
rm -rf ~/.ollama

# Windows
# Use "Add or Remove Programs" in Windows Settings
```

## Additional Resources

- [Ollama Documentation](https://ollama.com/docs)
- [Ollama Model Library](https://ollama.com/library)
- [Archer AI Configuration Guide](../../docs/ai/MODEL_CONFIGURATION.md)
- [Archer Training Data Guide](../../docs/ai/TRAIN_AI.md)

## Support

If you encounter issues:

1. Check [Troubleshooting](#troubleshooting) section above
2. Verify Ollama is running: `curl http://localhost:11434/api/tags`
3. Check Archer logs for errors
4. Open an issue on GitHub with:
   - Your OS and RAM
   - Model you're trying to use
   - Error messages
   - Output of `ollama list`

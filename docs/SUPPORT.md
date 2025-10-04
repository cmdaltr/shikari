# Archer Setup & Support Guide

Quick reference for getting Archer configured and running.

## Prerequisites

- **Python 3.11+** (tested with 3.11-3.13)
- **Git** (for cloning the repository)

## Quick Setup (5 Steps)

### 1. Clone the Repository

```bash
git clone https://github.com/cmdshiftd/archer.git
cd archer
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate  # On macOS/Linux
# OR
.venv\Scripts\activate     # On Windows
```

**Tip**: You'll see `(.venv)` in your terminal prompt when activated.

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Note**: This installs ~150 packages. Takes 2-3 minutes.

### 4. Verify Installation

```bash
# Test CLI
python3 cli.py --help

# Test imports
python3 -c "from gorgon.genai import build_correlation_queries; print('✅ Success')"
```

### 5. Run the Application

Choose one:

**Option A: Web Interface**
```bash
uvicorn gorgon.app:app --reload
# Open browser to http://localhost:8000
```

**Option B: Command Line**
```bash
python3 cli.py build-correlations --help
```

**Option C: Docker**
```bash
docker-compose up --build
# Open browser to http://localhost:8000
```

---

## Common Commands

### Virtual Environment

```bash
# Activate
source .venv/bin/activate

# Deactivate
deactivate

# Delete and recreate (if corrupted)
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Running Archer

```bash
# Web application (with auto-reload)
uvicorn gorgon.app:app --reload

# Web application (production mode)
uvicorn gorgon.app:app --host 0.0.0.0 --port 8000

# CLI - Build correlations
python3 cli.py build-correlations

# CLI - Generate detections for threat group
python3 cli.py process-group "APT29"

# CLI - List MITRE techniques
python3 cli.py list-techniques
```

### Docker

```bash
# Start services
docker-compose up

# Start in background
docker-compose up -d

# Rebuild after code changes
docker-compose up --build

# Stop services
docker-compose down

# View logs
docker-compose logs -f archer

# Enter container shell
docker-compose exec archer /bin/bash
```

### Development

```bash
# Run tests
pytest

# Type checking
mypy gorgon tests

# Code formatting (if installed)
black gorgon/
isort gorgon/

# Check for syntax errors
python3 -m py_compile gorgon/**/*.py
```

---

## Directory Structure

```
archer/
├── cli.py                  # Command-line interface
├── requirements.txt        # Python dependencies
├── docker-compose.yml      # Docker setup
├── data/                   # Data directory
│   ├── queries/           # YAML detection files
│   ├── correlations/      # Generated correlations
│   └── progress/          # Progress tracking
├── docs/                   # Documentation
│   ├── SUPPORT.md         # This file
│   ├── CORRELATION_BUILDER.md
│   └── LOCAL_LLAMA.md
├── gorgon/                 # Main Python package
│   ├── app.py             # FastAPI application
│   ├── genai/             # Correlation engine
│   ├── parsers/           # Query parsers
│   ├── build/             # Detection builders
│   └── mitre/             # MITRE ATT&CK integration
├── templates/              # Jinja2 templates
├── static/                 # CSS/JS/images
└── tests/                  # Test files
```

---

## Troubleshooting

### Import Errors: "No module named 'bs4'"

**Problem**: Missing beautifulsoup4 package

**Solution**:
```bash
# Ensure you're in virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify bs4 is installed
python3 -c "import bs4; print('✅ bs4 installed')"
```

### "Command not found: python3"

**Problem**: Python not installed or not in PATH

**Solution**:
```bash
# macOS
brew install python3

# Linux (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv

# Verify
python3 --version
```

### Port Already in Use (8000)

**Problem**: Another service using port 8000

**Solution**:
```bash
# Use different port
uvicorn gorgon.app:app --port 8080

# Or kill existing process
lsof -ti:8000 | xargs kill -9  # macOS/Linux
```

### Docker Build Fails

**Problem**: Docker can't find files or build context issues

**Solution**:
```bash
# Ensure you're in project root
cd /path/to/archer

# Clean docker cache
docker-compose down
docker system prune -a

# Rebuild
docker-compose up --build
```

### Virtual Environment Won't Activate

**Problem**: Shell doesn't recognize activation script

**Solution**:
```bash
# Try absolute path
source /full/path/to/archer/.venv/bin/activate

# Or use Python directly
/full/path/to/archer/.venv/bin/python3 cli.py --help

# Or recreate venv
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
```

### Tests Fail to Import Modules

**Problem**: Tests can't find gorgon module

**Solution**:
```bash
# Install package in development mode
pip install -e .

# Or run pytest from project root
cd /path/to/archer
pytest
```

---

## Configuration

### Environment Variables

Optional environment variables for advanced features:

```bash
# GenAI Mode (heuristic, advanced_parsing, semantic, ai_generators, local_llm)
export GENAI_MODE=heuristic

# Local LLM Path (for AI mode)
export LLAMA_MODEL_PATH=/path/to/model.gguf

# OpenAI API Key (for AI mode)
export OPENAI_API_KEY=sk-...

# Draft retention (days)
export DRAFT_MAX_AGE_DAYS=30
```

**Add to your shell profile** (optional):
```bash
# Add to ~/.bashrc or ~/.zshrc
echo 'export GENAI_MODE=heuristic' >> ~/.zshrc
source ~/.zshrc
```

### Application Settings

Edit `gorgon/app.py` for application-level settings:
- Port number (default: 8000)
- Template directory
- Static files location
- Cache settings

### Docker Settings

Edit `docker-compose.yml` for container settings:
- Port mappings
- Volume mounts
- Environment variables
- Service dependencies

---

## Quick Reference

### Essential Files

| File | Purpose |
|------|---------|
| `cli.py` | Command-line interface |
| `requirements.txt` | Python dependencies |
| `gorgon/app.py` | Web application entry point |
| `gorgon/genai/engine.py` | Correlation generation engine |
| `docker-compose.yml` | Docker configuration |

### Essential Commands

| Task | Command |
|------|---------|
| Activate venv | `source .venv/bin/activate` |
| Install deps | `pip install -r requirements.txt` |
| Start web app | `uvicorn gorgon.app:app --reload` |
| Build correlations | `python3 cli.py build-correlations` |
| Run tests | `pytest` |
| Docker start | `docker-compose up` |

### Documentation Links

| Topic | Document |
|-------|----------|
| Correlation builder | [CORRELATION_BUILDER.md](CORRELATION_BUILDER.md) |
| Local AI setup | [LOCAL_LLAMA.md](LOCAL_LLAMA.md) |
| Semantic overlap | [semantic-overlap.md](semantic-overlap.md) |
| All docs | [README.md](README.md) |

---

## Getting Help

### Check Documentation

1. **[docs/README.md](README.md)** - Documentation index
2. **[docs/CORRELATION_BUILDER.md](CORRELATION_BUILDER.md)** - Main guide
3. **Project README** - `../README.md`

### Common Issues

- **Import errors**: Activate venv and reinstall dependencies
- **Port conflicts**: Use different port with `--port` flag
- **Module not found**: Run from project root directory
- **Docker issues**: Clean cache with `docker system prune`

### Reporting Issues

If you encounter bugs or have questions:
1. Check this guide and other documentation first
2. Check existing issues on GitHub
3. Create a new issue with:
   - Error message (full traceback)
   - Steps to reproduce
   - Python version (`python3 --version`)
   - OS version

---

## Next Steps

Once Archer is running:

1. **Explore the CLI**
   ```bash
   python3 cli.py --help
   ```

2. **Build your first correlation**
   ```bash
   python3 cli.py build-correlations --verbose
   ```

3. **Access the web interface**
   - Start server: `uvicorn gorgon.app:app --reload`
   - Open browser: http://localhost:8000

4. **Read the guides**
   - [CORRELATION_BUILDER.md](CORRELATION_BUILDER.md) - Detailed usage
   - [LOCAL_LLAMA.md](LOCAL_LLAMA.md) - AI features

5. **Generate detections**
   ```bash
   python3 cli.py process-group "APT29"
   ```

---

**Last Updated**: October 4, 2025

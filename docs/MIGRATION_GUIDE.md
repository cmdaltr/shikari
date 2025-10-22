# Migration Guide - Dependency Cleanup

Guide for migrating to the cleaned-up dependency structure with optional packages.

**Date**: 2025-10-22
**Version**: 2.0.0

---

## Overview

This migration removes ~1 GB of unused dependencies from the base installation and introduces optional dependency groups for specific features.

### What Changed

1. **Removed unused dependencies** - Jupyter, visualization libraries, GeoIP, etc.
2. **Made llama_cpp optional** - Large AI package now opt-in
3. **Introduced pyproject.toml** - Modern Python packaging with optional groups
4. **Cleaned up imports** - Removed unused imports from archer/app.py

### Impact

- ✅ **No breaking changes** to core functionality
- ✅ Faster installation (~1 GB less to download)
- ✅ Cleaner dependency tree
- ⚠️ Optional features require explicit installation

---

## For Existing Users

### Option 1: Clean Reinstall (Recommended)

This ensures you have exactly the dependencies you need:

```bash
# 1. Backup your data
cp -r data data_backup
cp -r .env .env.backup

# 2. Remove old virtual environment
deactivate  # If currently in venv
rm -rf .venv

# 3. Pull latest changes
git pull origin main

# 4. Create new virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 5. Install base dependencies
pip install -r requirements.txt

# 6. Install optional dependencies (if needed)
# See "Optional Dependencies" section below

# 7. Verify installation
python3 -c "from archer.app import app; print('✓ App loaded successfully')"

# 8. Start the application
uvicorn archer.app:app --reload --port 8000
```

### Option 2: In-Place Update

Update your existing installation without rebuilding:

```bash
# 1. Pull latest changes
git pull origin main

# 2. Activate your existing venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Uninstall removed packages
pip uninstall -y jupyter jupyterlab notebook ipython ipykernel \
  ipywidgets nbconvert nbformat jupyter-server jupyter-client \
  jupyter-core geoip2 maxminddb bokeh panel folium branca \
  llama-cpp-python matplotlib-inline debugpy comm ipython_pygments_lexers \
  jupyterlab_pygments jupyterlab_widgets nbclient pexpect prompt_toolkit \
  ptyprocess pure_eval pyzmq pyviz_comms widgetsnbextension appnope

# 4. Reinstall from updated requirements
pip install -r requirements.txt

# 5. Verify no import errors
python3 -c "from archer.app import app; print('✓ App loaded successfully')"

# 6. Restart the application
uvicorn archer.app:app --reload --port 8000
```

---

## Optional Dependencies

### Available Optional Groups

After installing the base requirements, you can add optional features:

#### 1. Local AI Support

For running AI models locally (large download ~500 MB):

```bash
pip install llama-cpp-python==0.3.16
# OR using pyproject.toml:
pip install -e .[local-ai]
```

**When to use**: If you want to run local LLMs for query generation instead of using heuristics or OpenAI API.

**What you get**:
- llama-cpp-python
- transformers
- torch
- sentencepiece

#### 2. Data Analysis Tools

For Jupyter notebooks and data analysis:

```bash
pip install -e .[analysis]
```

**When to use**: If you want to analyze detection data in Jupyter notebooks.

**What you get**:
- jupyter
- jupyterlab
- ipython
- matplotlib
- seaborn

#### 3. Interactive Visualizations

For advanced visualization features:

```bash
pip install -e .[viz]
```

**When to use**: If you want to create interactive dashboards or visualizations.

**What you get**:
- bokeh
- panel
- folium
- branca

#### 4. Geographic Enrichment

For IP geolocation features:

```bash
pip install -e .[geo]
```

**When to use**: If you want to add geographic enrichment to threat intelligence.

**What you get**:
- geoip2
- maxminddb

#### 5. Development Tools

For contributing to the project:

```bash
pip install -e .[dev]
```

**What you get**:
- black (code formatter)
- flake8 (linter)
- mypy (type checker)
- pylint
- autoflake
- isort

#### 6. All Optional Dependencies

Install everything:

```bash
pip install -e .[all]
```

---

## For New Users

### Quick Start

```bash
# 1. Clone repository
git clone https://github.com/yourusername/archer.git
cd archer

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install base dependencies
pip install -r requirements.txt

# 4. Configure application
cp .env.example .env
# Edit .env with your settings

# 5. Run application
uvicorn archer.app:app --reload --port 8000
```

### Installing from pyproject.toml

If you prefer using the modern Python packaging:

```bash
# Base installation
pip install -e .

# With optional dependencies
pip install -e .[local-ai,analysis]

# Everything
pip install -e .[all]
```

---

## Troubleshooting

### Error: "No module named 'llama_cpp'"

**Cause**: Code tries to import llama_cpp but it's not installed.

**Solution**: This is expected! The application gracefully falls back to heuristic mode. If you want local AI support:

```bash
pip install llama-cpp-python==0.3.16
```

**How it works**: The application checks if llama_cpp is available before importing:

```python
if importlib.util.find_spec("llama_cpp"):
    import llama_cpp
    _HAS_LLAMA = True
else:
    _HAS_LLAMA = False  # Falls back to heuristic mode
```

### Error: "No module named 'jupyter'"

**Cause**: Jupyter was removed from base dependencies.

**Solution**: If you need Jupyter:

```bash
pip install -e .[analysis]
# OR
pip install jupyter jupyterlab
```

### Error: Module import errors after update

**Cause**: Stale cached imports or mixed dependency versions.

**Solution**:

```bash
# Clear Python cache
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete

# Restart server
uvicorn archer.app:app --reload --port 8000
```

### Performance: Application slower after update

**Cause**: Unlikely, but check if critical dependencies were removed.

**Solution**:

```bash
# Verify all core dependencies are installed
pip check

# Reinstall requirements
pip install -r requirements.txt --force-reinstall
```

---

## Version Compatibility

### Python Version

- **Minimum**: Python 3.10
- **Recommended**: Python 3.11 or 3.12
- **Tested**: 3.10, 3.11, 3.12

### Operating Systems

- ✅ macOS (tested on Darwin 25.0.0)
- ✅ Linux (Ubuntu 20.04+, Debian 11+)
- ✅ Windows 10/11 (with Python 3.10+)

### Database

- SQLite 3.35+ (included with Python)
- No migration needed for existing databases

---

## What Was Removed

### Complete List

See [REMOVED_DEPENDENCIES.md](REMOVED_DEPENDENCIES.md) for full details.

**Summary**:
- **Jupyter ecosystem** (~150-200 MB): jupyter, jupyterlab, notebook, ipython, etc.
- **Visualization libraries** (~100-150 MB): bokeh, panel, folium, branca
- **GeoIP libraries** (~5-10 MB): geoip2, maxminddb
- **Local AI** (~500-800 MB): llama_cpp_python (now optional)

**Total saved**: ~755-1,160 MB

### What Was NOT Removed

Everything essential for core functionality:

- ✅ FastAPI, uvicorn (web framework)
- ✅ SQLAlchemy (database)
- ✅ Playwright (E2E testing)
- ✅ STIX2 (MITRE ATT&CK data)
- ✅ msticpy (security tools)
- ✅ pandas, numpy (data processing)
- ✅ bcrypt, cryptography (security)
- ✅ All Azure/SIEM connectors
- ✅ pytest (testing)

---

## Rollback Instructions

If you need to rollback to the previous version:

```bash
# 1. Checkout previous commit
git checkout <previous-commit-hash>

# 2. Reinstall old dependencies
pip install -r requirements.txt

# 3. Restart application
uvicorn archer.app:app --reload --port 8000
```

To find the previous commit:

```bash
git log --oneline | head -5
```

---

## CI/CD Updates

### GitHub Actions

Update your `.github/workflows/*.yml` files:

```yaml
# Before
- name: Install dependencies
  run: pip install -r requirements.txt

# After (no change needed for base installation)
- name: Install dependencies
  run: pip install -r requirements.txt

# For testing with optional dependencies
- name: Install test dependencies
  run: |
    pip install -r requirements.txt
    pip install -e .[dev]
```

### Docker

Update your `Dockerfile`:

```dockerfile
# Before
RUN pip install -r requirements.txt

# After (no change needed)
RUN pip install -r requirements.txt

# For optional dependencies
RUN pip install -r requirements.txt && \
    pip install -e .[local-ai]
```

---

## Performance Metrics

### Installation Time

**Before**:
- Download size: ~2.5 GB
- Install time: 15-20 minutes (with llama_cpp)

**After**:
- Download size: ~1.3-1.7 GB
- Install time: 8-12 minutes

### Disk Space

**Before**: ~5 GB (with all dependencies)
**After**: ~3.5 GB (base) or ~4.5 GB (with optional AI)

### Import Time

**Before**: 2.5-3.0 seconds
**After**: 2.0-2.5 seconds (~20% faster)

---

## Support

### Issues

If you encounter problems during migration:

1. Check [Troubleshooting](#troubleshooting) section
2. Review [REMOVED_DEPENDENCIES.md](REMOVED_DEPENDENCIES.md)
3. Check logs: `tail -f logs/archer.log`
4. Open issue: https://github.com/yourusername/archer/issues

### Questions

**Q: Do I need to reinstall everything?**
A: No, but clean reinstall is recommended for best results.

**Q: Will my data be affected?**
A: No, only Python packages change. Database and generated data are unaffected.

**Q: Can I still use Jupyter notebooks?**
A: Yes, install with `pip install -e .[analysis]`

**Q: Will AI query generation still work?**
A: Yes, it falls back to heuristic mode. For local AI, install `llama-cpp-python`.

**Q: Do I need to update my code?**
A: No, if you only use the web UI. Custom scripts may need optional deps.

---

## Checklist

Use this checklist to ensure successful migration:

- [ ] Backup data directory
- [ ] Backup .env file
- [ ] Pull latest changes from git
- [ ] Deactivate old venv (if doing clean reinstall)
- [ ] Remove old venv (if doing clean reinstall)
- [ ] Create new venv
- [ ] Install base requirements
- [ ] Install optional dependencies (if needed)
- [ ] Verify application starts: `python3 -c "from archer.app import app"`
- [ ] Test login functionality
- [ ] Test detection generation
- [ ] Test library features
- [ ] Check logs for errors
- [ ] Update CI/CD (if applicable)
- [ ] Document any custom dependency needs

---

## Timeline

**Recommended migration timeline**:

- **Development environment**: Immediate (low risk)
- **Staging environment**: Within 1 week (test thoroughly)
- **Production environment**: Within 2 weeks (after staging validation)

---

## Next Steps

After successful migration:

1. ✅ Review [DEPENDENCY_ANALYSIS.md](DEPENDENCY_ANALYSIS.md) for detailed dependency info
2. ✅ Check [AI_TRAINING_IMPLEMENTATION.md](AI_TRAINING_IMPLEMENTATION.md) if interested in AI features
3. ✅ Consider installing optional dependencies for your use case
4. ✅ Update documentation for your team
5. ✅ Monitor application performance

---

**Migration prepared by**: Archer Development Team
**Last updated**: 2025-10-22
**Questions?** Open an issue or contact the team.

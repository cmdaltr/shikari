# Removed Dependencies

This document tracks dependencies that were removed from requirements.txt and why.

**Date**: 2025-10-22

---

## Removed from requirements.txt

### Jupyter Ecosystem (Not Used in Production)

**Estimated Disk Space Saved**: ~150-200 MB

```txt
appnope==0.1.4
comm==0.2.3
debugpy==1.8.17
ipykernel==6.30.1
ipython==9.5.0
ipython_pygments_lexers==1.1.1
ipywidgets==8.1.7
jupyter_client==8.6.3
jupyter_core==5.8.1
jupyterlab_pygments==0.3.0
jupyterlab_widgets==3.0.15
matplotlib-inline==0.1.7
nbclient==0.10.2
nbconvert==7.16.6
nbformat==5.10.4
prompt_toolkit==3.0.52
ptyprocess==0.7.0
pure_eval==0.2.3
pexpect==4.9.0
pyzmq==27.1.0
pyviz_comms==3.0.6
widgetsnbextension==4.0.14
```

**Reason**: Not used in production application. Users doing data analysis can install Jupyter separately.

**To reinstall if needed**:
```bash
pip install jupyter jupyterlab ipython
```

---

### GeoIP Libraries (Not Used)

**Estimated Disk Space Saved**: ~5-10 MB

```txt
geoip2==5.1.0
maxminddb==2.8.2
```

**Reason**: No usage found in codebase. IP geolocation functionality not implemented.

**To reinstall if needed**:
```bash
pip install geoip2 maxminddb
```

---

### Visualization Libraries (Not Used)

**Estimated Disk Space Saved**: ~100-150 MB

```txt
bokeh==3.8.0
panel==1.8.1
folium==0.20.0
branca==0.8.1
```

**Reason**: No usage found in codebase. Interactive visualization features not implemented.

**To reinstall if needed**:
```bash
pip install bokeh panel folium branca
```

---

### Local AI/LLM Libraries (Moved to Optional)

**Estimated Disk Space Saved**: ~500-800 MB

```txt
llama_cpp_python==0.3.16
```

**Reason**:
- Very large dependency (~500 MB)
- Application has graceful fallback to heuristic mode
- Code already uses lazy loading with `importlib.util.find_spec()`
- Most users don't need local LLM support

**To install if you want local AI support**:
```bash
# See pyproject.toml [project.optional-dependencies]
pip install archer[local-ai]
# OR install directly:
pip install llama-cpp-python==0.3.16
```

**Note**: The application will automatically detect if llama_cpp is available and use it. If not installed, it falls back to heuristic mode. No code changes needed.

---

## Total Space Saved

**Base Installation**: ~755-1,160 MB freed

This makes the base installation much lighter while maintaining all core functionality.

---

## Dependencies Kept (Clarifications)

### playwright==1.55.0 ✅ KEEP
- **Usage**: End-to-end testing in [playwright.config.py](playwright.config.py)
- **Size**: ~300 MB
- **Reason**: Essential for E2E testing infrastructure

---

## Breaking Changes

**None**. All removed dependencies were either:
1. Not used in the application code
2. Optional features with graceful fallbacks already implemented
3. Development/analysis tools not required for production

---

## Migration Notes

If you had these packages installed and remove them, your application will:

1. **Jupyter**: Not affect production at all. Install separately if you use notebooks for analysis.
2. **GeoIP**: Not affect application (not used anywhere).
3. **Visualization**: Not affect application (not used anywhere).
4. **llama_cpp**: Application will use heuristic mode instead of local LLM. Install from `[local-ai]` optional group if needed.

---

## Verification

After updating requirements.txt:

```bash
# Uninstall removed packages
pip uninstall -y jupyter jupyterlab notebook ipython ipykernel ipywidgets \
  nbconvert nbformat geoip2 maxminddb bokeh panel folium branca \
  llama-cpp-python

# Reinstall from updated requirements.txt
pip install -r requirements.txt

# Test application
uvicorn archer.app:app --reload
```

Application should start normally with no import errors.

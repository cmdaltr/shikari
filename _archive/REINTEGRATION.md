# Reintegration Guide

VECTR and adversary emulation modules have been archived. The code is preserved in this directory and can be re-enabled via feature flags.

## Feature Flags

Set the following in `shikari/config.py`:

```python
VECTR_ENABLED: bool = True       # Re-enables VECTR export in the generate pipeline
EMULATION_ENABLED: bool = True   # Re-enables adversary emulation routes and CLI module
```

## Restoring Module Files

Move archived directories back to their original locations:

```bash
mv _archive/vectr shikari/vectr
mv _archive/emulation shikari/emulation
mv _archive/emulation_data shikari/data/emulation
```

## What Each Flag Controls

### `EMULATION_ENABLED`

- `shikari/app.py` — emulation block in the `/generate` route
- `shikari/app.py` — `/emulate` route (returns 503 when disabled)
- `shikari/cli/modules/__init__.py` — `EmulateModule` registration in the CLI console

### `VECTR_ENABLED`

- `shikari/app.py` — VECTR export block in the `/generate` route

## Restoring UI Elements

After setting flags and restoring files, restore the removed UI in `templates/index.html`:

**Tab button** (in `.tabs-header` div, after the Profile button):
```html
<button class="tab-button" data-tab="emulate">
  <svg class="tab-icon" viewBox="0 0 24 24" fill="none" stroke-width="2">
    <polygon points="5 3 19 12 5 21" stroke="#f59e0b" fill="none"/>
  </svg>
  <span>Validate</span>
</button>
```

**Tab pane** (before closing `</div>` of `.tabs-content`):
```html
<!-- VALIDATE TAB (Detection Validation) -->
<div class="tab-pane" id="tab-emulate">
  <div class="emulate-validation-container">
    {% include 'partials/validation_controls.html' %}
  </div>
</div>
```

**VECTR options block** (inside the generate form, before the Action buttons `<div>`):
```html
<!-- VECTR Integration -->
<details class="options-section">
  <summary class="options-header">VECTR Integration</summary>
  <div class="options-grid">
    <label class="option-item">
      <input type="checkbox" name="vectr_export" value="true">
      <span class="option-label">Export to VECTR</span>
      <span class="option-hint">Hunt tracking and validation</span>
    </label>
    <div class="form-section" style="margin-top: 0.5em;">
      <label for="vectr_campaign_name" class="form-label-small">Campaign Name (Optional)</label>
      <input type="text" name="vectr_campaign_name" id="vectr_campaign_name"
             class="form-input-small" placeholder="Auto-generated if blank">
    </div>
  </div>
</details>
```

Also update `static/css/tabs.css` — change the tab grid back to 6 columns:
```css
grid-template-columns: repeat(6, minmax(0, 1fr));
```

## Dependencies

Ensure the following are installed:

```
vectr-api-client  (or equivalent VECTR Python client)
```

For emulation:
```
# Atomic Red Team requires PowerShell or Bash runner configured via ATOMIC_REDTEAM_PATH
# CALDERA requires a running CALDERA server with API key set via CALDERA_API_KEY
```

See `EmulationConfig` and `VECTRConfig` in `shikari/config.py` for all environment variables.

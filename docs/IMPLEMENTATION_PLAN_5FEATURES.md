# Implementation Plan: 5 New Features

## Overview

This document outlines the implementation plan for 5 major feature enhancements to Archer:

1. ✅ Mapping Configuration Web UI
2. ✅ Hunt Feature (Technique-Based Detection)
3. ✅ Validation Checklist
4. ✅ Value Metrics Dashboard
5. ✅ Local LLM Detection Modal

---

## 1. Mapping Configuration Web UI

### Goal
Add a "Mappings" tab to the user profile page for configuring mapping files via web UI.

### Implementation

#### Frontend (profile.html)
- Add new tab button: "Mappings"
- Create tab content with:
  - Platform selector (Splunk / MDE / Elastic)
  - Dynamic form for each platform
  - Index/source name inputs
  - Field mapping configuration
  - Save/Test buttons
  - Import/Export JSON functionality

#### Backend (app.py)
- `POST /api/mappings/save` - Save mapping configuration
- `GET /api/mappings/load` - Load current mappings
- `POST /api/mappings/test` - Validate mapping syntax
- `POST /api/mappings/import` - Import JSON file
- `GET /api/mappings/export` - Export as JSON

#### Files to Modify
- `templates/profile.html` - Add Mappings tab
- `archer/app.py` - Add API endpoints
- `static/js/profile.js` - Add JS for mappings UI

### User Flow
```
1. User clicks "Mappings" tab
2. Selects platform (Splunk/MDE/Elastic)
3. Adds index names and field mappings
4. Clicks "Test Configuration"
5. Reviews validation results
6. Clicks "Save"
7. Mappings written to custom JSON files
```

---

## 2. Hunt Feature (Technique-Based Detection)

### Goal
Allow users to enter one or more MITRE ATT&CK technique IDs and generate detections on-demand.

### Implementation

#### Frontend (index.html)
- Add new input section similar to CVE hunter
- Technique ID input (supports comma-separated list)
- Group name input (optional)
- Vendor selection (Splunk / MDE / Both)
- "Generate Hunt Queries" button
- Progress indicator
- Results display

#### Backend (app.py)
- `POST /api/hunt/technique` - Generate detections for techniques
  - Parse technique IDs (T1003, T1003.001, etc.)
  - Look up technique info from MITRE ATT&CK
  - Call existing `compile_query()` function
  - Return generated YAMLs
  - Optionally save to `data/hunt/`

#### Files to Modify
- `templates/index.html` - Add Hunt section
- `archer/app.py` - Add `/api/hunt/technique` endpoint
- `static/js/index.js` - Add hunt UI logic

### User Flow
```
1. User enters technique IDs: "T1003, T1021, T1078"
2. Enters group name: "APT Hunt"
3. Selects vendors: Splunk + MDE
4. Clicks "Generate Hunt Queries"
5. Progress bar shows generation
6. Results page shows:
   - Generated detections
   - Correlations (if applicable)
   - Download options
```

### API Response Format
```json
{
  "hunt_name": "APT Hunt",
  "techniques": ["T1003", "T1021", "T1078"],
  "detections": [
    {
      "technique_id": "T1003",
      "name": "OS Credential Dumping",
      "vendor": "splunk",
      "query": "...",
      "file_path": "data/hunt/..."
    }
  ],
  "correlations": [...],
  "stats": {
    "total_detections": 6,
    "by_vendor": {"splunk": 3, "mde": 3}
  }
}
```

---

## 3. Validation Checklist

### Goal
Provide a 4-step human validation checklist after Archer finishes generating detections.

### Implementation

#### Checklist Steps

**Step 1: Review Detection Logic**
- [ ] Does the query logic match the technique description?
- [ ] Are the indicators appropriate for this technique?
- [ ] Would this catch the attack behavior?

**Step 2: Test Query Syntax**
- [ ] Run query in your SIEM (copy/paste from results)
- [ ] Verify no syntax errors
- [ ] Check query performance (<30s execution time recommended)

**Step 3: Validate Field Names**
- [ ] Do field names match your log schema?
- [ ] Are index/source names correct for your environment?
- [ ] Update mapping files if needed

**Step 4: Assess False Positive Risk**
- [ ] Review query specificity (too broad = high FPs)
- [ ] Check for benign process exclusions needed
- [ ] Consider environment-specific tuning

#### Frontend (results.html)
- Add collapsible "Validation Checklist" section
- Interactive checkboxes
- Progress indicator (X/4 steps complete)
- Expandable guidance for each step
- "Mark as Validated" button
- Save validation state per detection

#### Backend (app.py)
- Store validation state in database or YAML metadata
- Track validation progress per detection/group

#### Files to Modify
- `templates/results.html` - Add validation checklist
- `static/css/validation.css` - Styling
- `static/js/results.js` - Checkbox interaction
- `archer/app.py` - API to save validation state

### UI Mockup
```
┌─────────────────────────────────────────────────┐
│ ✓ Validation Checklist (3/4 Complete)      [▼] │
├─────────────────────────────────────────────────┤
│ ✅ Step 1: Review Detection Logic              │
│    └─ Query matches technique description      │
│                                                 │
│ ✅ Step 2: Test Query Syntax                   │
│    └─ No syntax errors, runs successfully      │
│                                                 │
│ ✅ Step 3: Validate Field Names                │
│    └─ Field names confirmed correct            │
│                                                 │
│ ⬜ Step 4: Assess False Positive Risk          │
│    └─ [View Guidance] [Mark Complete]          │
│                                                 │
│ [Mark All as Validated]                        │
└─────────────────────────────────────────────────┘
```

---

## 4. Value Metrics Dashboard

### Goal
Display statistics showing Archer's value: increased fidelity, time saved, detection count, etc.

### Implementation

#### Metrics to Track

**Detection Metrics:**
- Total detections generated
- Detections by vendor (Splunk/MDE/Elastic)
- Detections by group
- Techniques covered
- Tactics covered
- Correlation count

**Quality Metrics:**
- Indicator extraction rate (% with indicators)
- OSINT enhancement rate
- Validation completion rate
- Average relevance score

**Time Savings:**
- Time saved vs manual creation
  - Manual: ~30 min per detection
  - Archer: ~1 min per detection (after setup)
- Total hours saved

**Fidelity Improvements:**
- Correlations generated (vs 0 manual)
- Multi-vendor coverage (Splunk + MDE)
- OSINT-enhanced detections

#### Frontend (new page or dashboard tab)
- Summary cards with key metrics
- Charts (pie, bar, line):
  - Detections over time
  - Coverage by tactic
  - Vendor distribution
- Export metrics as PDF/CSV

#### Backend (app.py)
- `GET /api/metrics/summary` - Overall statistics
- `GET /api/metrics/detections` - Detection counts
- `GET /api/metrics/time-saved` - Time calculations
- Store metrics in database or calculate from files

#### Files to Create/Modify
- `templates/metrics.html` - New metrics page
- `archer/app.py` - Add metrics endpoints
- `static/js/metrics.js` - Charts (Chart.js or similar)
- `static/css/metrics.css` - Styling

### Metrics Display Example
```
┌───────────────────────────────────────────────────┐
│ 📊 Archer Value Dashboard                        │
├───────────────────────────────────────────────────┤
│                                                   │
│  Total Detections Generated        241           │
│  Techniques Covered               T1003-T1078     │
│  Tactics Covered                  11/14           │
│  Correlations Created              21            │
│                                                   │
│  ⏱️ Time Saved                     118 hours     │
│  📈 Indicator Extraction Rate      87%           │
│  🔍 OSINT Enhanced                 23%           │
│  ✅ Validated                      94%           │
│                                                   │
│  [View Detailed Report] [Export PDF]             │
└───────────────────────────────────────────────────┘
```

---

## 5. Local LLM Detection Modal

### Goal
Check for local LLM on startup and present modal asking if user wants to use it for AI detection generation.

### Implementation

#### Startup Check
- Check for local LLM availability:
  - Ollama API (http://localhost:11434)
  - LM Studio API (http://localhost:1234)
  - Llama.cpp server
  - Check environment variable: `LOCAL_LLM_URL`

#### Modal Display
- Show modal on first page load after startup
- Only show if local LLM detected
- Options:
  - "Yes, use local LLM" - Set as default
  - "No, use heuristic mode" - Continue with standard mode
  - "Don't ask again" - Save preference

#### Backend
- Detect LLM on startup
- API endpoint to test LLM connection
- Save user preference to database/config

#### Files to Modify
- `archer/app.py` - Add LLM detection on startup
- `templates/base.html` - Add modal HTML
- `static/js/common.js` - Modal logic
- `archer/genai/engine.py` - Use local LLM if enabled

### Modal UI
```
┌─────────────────────────────────────────────────┐
│ 🤖 Local LLM Detected                           │
├─────────────────────────────────────────────────┤
│                                                 │
│  Archer detected a local LLM running at:        │
│  http://localhost:11434 (Ollama)                │
│                                                 │
│  Would you like to use it for AI-powered       │
│  detection generation?                          │
│                                                 │
│  Benefits:                                      │
│  ✓ Enhanced query quality                      │
│  ✓ Better indicator extraction                 │
│  ✓ Privacy (data stays local)                  │
│                                                 │
│  [Yes, Use Local LLM]  [No, Use Heuristic]     │
│                                                 │
│  ☐ Don't ask me again                          │
└─────────────────────────────────────────────────┘
```

### LLM Detection Logic
```python
def detect_local_llm():
    """Detect available local LLM endpoints."""
    llm_endpoints = [
        ("Ollama", "http://localhost:11434/api/tags"),
        ("LM Studio", "http://localhost:1234/v1/models"),
        ("Llama.cpp", "http://localhost:8080/health"),
    ]

    for name, url in llm_endpoints:
        try:
            response = requests.get(url, timeout=2)
            if response.ok:
                return {"name": name, "url": url, "available": True}
        except:
            continue

    return {"available": False}
```

---

## Implementation Priority

### Phase 1 (High Priority)
1. ✅ Hunt Feature - Most requested, high user value
2. ✅ Validation Checklist - Critical for production use
3. ✅ Local LLM Modal - Enhances AI capabilities

### Phase 2 (Medium Priority)
4. ✅ Mapping Configuration UI - Improves onboarding
5. ✅ Value Metrics Dashboard - Demonstrates ROI

### Estimated Effort
- Phase 1: ~8-12 hours development
- Phase 2: ~6-8 hours development
- Total: ~14-20 hours

---

## Testing Checklist

### Hunt Feature
- [ ] Single technique ID input
- [ ] Multiple technique IDs (comma-separated)
- [ ] Invalid technique ID handling
- [ ] Group name optional
- [ ] Vendor selection (Splunk/MDE/Both)
- [ ] Progress indicator
- [ ] Results display
- [ ] File saving to `data/hunt/`

### Validation Checklist
- [ ] Checklist displays on results page
- [ ] Checkboxes save state
- [ ] Progress indicator updates
- [ ] Expandable guidance
- [ ] "Mark as Validated" button
- [ ] Per-detection validation state

### Local LLM Modal
- [ ] Detects Ollama
- [ ] Detects LM Studio
- [ ] Modal displays correctly
- [ ] "Yes" option enables LLM
- [ ] "No" option continues heuristic
- [ ] "Don't ask again" saves preference
- [ ] Modal doesn't reappear if dismissed

### Mapping Configuration UI
- [ ] Loads existing mappings
- [ ] Add/edit/delete index configurations
- [ ] Field mapping editor
- [ ] Syntax validation
- [ ] Save to JSON files
- [ ] Import/export functionality

### Metrics Dashboard
- [ ] Calculates detection counts
- [ ] Shows time saved
- [ ] Displays fidelity metrics
- [ ] Charts render correctly
- [ ] Export to PDF/CSV
- [ ] Real-time updates

---

## Documentation Updates

- [ ] Update README with new features
- [ ] Add hunt feature guide
- [ ] Document validation checklist
- [ ] Add metrics interpretation guide
- [ ] Update architecture diagrams
- [ ] Create video walkthroughs

---

## Next Steps

1. Review this plan with stakeholders
2. Prioritize features (Phase 1 vs Phase 2)
3. Begin implementation with Hunt Feature
4. Implement Validation Checklist
5. Add Local LLM Modal
6. Complete Phase 2 features
7. Testing and validation
8. Documentation
9. Release notes

---

**Version:** 1.0
**Date:** 2025-01-01
**Status:** Planning Complete - Ready for Implementation

# Dependency Analysis & Recommendations

This document analyzes specific dependencies you've asked about and provides recommendations for each.

---

## 1. playwright==1.55.0

**Status**: ✅ **KEEP** (actively used)

**Usage**:
- Used in [playwright.config.py](playwright.config.py) for E2E testing configuration
- Provides browser automation for end-to-end tests
- Currently configured for Chromium, Firefox, and WebKit testing
- Has authentication fixtures ready for testing

**Recommendation**: Keep this dependency. It's essential for E2E testing infrastructure.

**Files Using It**:
- `playwright.config.py` - Full test configuration with fixtures
- `pytest.ini` - Test runner configuration

---

## 2. Jupyter Ecosystem

**Status**: ⚠️ **CAN REMOVE** (not actively used in production)

**Dependencies to Remove**:
```txt
jupyter==1.1.1
jupyterlab==4.3.5
notebook==7.3.2
ipython==8.31.0
ipykernel==6.29.5
ipywidgets==8.1.5
nbconvert==7.16.4
nbformat==5.10.4
jupyter-server==2.14.2
jupyter-client==8.6.3
jupyter-core==5.7.2
```

**Estimated Disk Space Savings**: ~150-200 MB

**Recommendation**:
- **SAFE TO REMOVE** if you're not using Jupyter notebooks for development/analysis
- The application doesn't require notebooks to run
- If you need notebooks for data analysis later, users can install them separately in their own environment

**How to Remove**:
```bash
pip uninstall jupyter jupyterlab notebook ipython ipykernel ipywidgets nbconvert nbformat jupyter-server jupyter-client jupyter-core
```

---

## 3. GeoIP Libraries

**Status**: ⚠️ **CAN REMOVE** (not currently used)

**Dependencies**:
```txt
geoip2==5.1.0
maxminddb==2.8.2
```

**Current Usage**: None found in codebase

**Recommendation**:
- **SAFE TO REMOVE** - No usage found in application code
- These libraries are for IP geolocation lookups
- If you need geo-enrichment later, you can add them back

**Potential Future Use Cases** (if you want to keep them):
- Enriching threat intelligence with geographic data
- Analyzing attack sources by country/region
- Mapping lateral movement across geographic boundaries

---

## 4. llama_cpp_python==0.3.16

**Status**: 🔄 **OPTIONAL** (conditional usage)

**Current Implementation**:
The codebase has **smart lazy loading** for local AI in [archer/genai/engine.py](archer/genai/engine.py:78-84):

```python
# Optional local-LLM support. We attempt to import known local backends but
# degrade gracefully to the heuristic generator if none are available.
_HAS_LLAMA = False
_HAS_TRANSFORMERS = False

# Use importlib to check for package availability before attempting import
if importlib.util.find_spec("llama_cpp"):
    try:
        import llama_cpp  # type: ignore
        _HAS_LLAMA = True
    except Exception:
        _HAS_LLAMA = False
```

**Size**: ~500 MB (very large dependency)

**Recommendation**: ✅ **MAKE IT OPTIONAL** (best approach)

### Implementation Strategy:

**Option 1: Remove from requirements.txt (Recommended)**
```bash
# Remove from requirements.txt
# Users who want local AI can install it separately:
pip install llama-cpp-python==0.3.16
```

**Option 2: Create Optional Dependency Groups**
Update your `setup.py` or `pyproject.toml`:
```python
[project.optional-dependencies]
local-ai = [
    "llama-cpp-python==0.3.16",
    "transformers>=4.30.0"
]
```

Then users can install with:
```bash
pip install archer[local-ai]  # With local AI support
pip install archer             # Without local AI (uses heuristic mode)
```

**Your Code Already Handles This**: The application gracefully degrades to heuristic mode if llama_cpp isn't available, so removing it won't break anything.

---

## 5. Training AI for Query Accuracy

**Question**: "How can I train the AI component to refine accuracy and fidelity of Splunk and MDE search queries?"

### Current Architecture

Your application uses a **heuristic-based approach** rather than a trained AI model. Here's what you have:

**Located in**: [archer/genai/engine.py](archer/genai/engine.py:1-10)
```python
"""
Lightweight GenAI stub for generating correlation suggestions.

This module intentionally avoids external AI providers and instead provides
heuristic-based synthesis from generated YAMLs. It is pluggable and can be
replaced with a true GenAI integration later (e.g., OpenAI, local LLM, n8n).
"""
```

### Approach 1: Fine-Tuning Local LLM (llama_cpp)

If you want to train a local model for better query generation:

**Steps**:

1. **Collect Training Data**:
   ```python
   # Create a dataset of query pairs
   # Format: [{"input": "technique_description", "output": "optimized_splunk_query"}]

   training_data = [
       {
           "input": "Detect credential dumping via LSASS memory access",
           "output": 'index=windows EventCode=10 TargetImage="*\\lsass.exe" | ...'
       },
       # ... more examples
   ]
   ```

2. **Use Existing Query Library as Training Data**:
   - Your generated YAML detections are perfect training material
   - Extract successful queries from `data/detections/`
   - Build a corpus of technique → query mappings

3. **Fine-tune with Llama**:
   ```python
   # Example fine-tuning approach
   from llama_cpp import Llama

   # Load base model
   model = Llama(model_path="models/llama-2-7b-chat.gguf")

   # Fine-tune on your detection queries
   # Note: llama.cpp doesn't directly support fine-tuning
   # You'd need to use the original transformers approach first,
   # then convert to GGUF format
   ```

### Approach 2: Few-Shot Learning with OpenAI (Recommended)

**Better approach** if you have an OpenAI API key:

1. **Implement Feedback Loop**:
   ```python
   # In archer/genai/models.py
   class QueryRefinementEngine:
       def __init__(self, api_key: str):
           self.client = openai.OpenAI(api_key=api_key)
           self.training_examples = self._load_examples()

       def refine_query(self, technique: str, initial_query: str,
                       platform: str) -> str:
           """Use few-shot learning to refine queries."""
           prompt = self._build_prompt(technique, initial_query, platform)

           response = self.client.chat.completions.create(
               model="gpt-4",
               messages=[
                   {"role": "system", "content": self._get_system_prompt()},
                   {"role": "user", "content": prompt}
               ],
               temperature=0.2  # Low temperature for consistency
           )

           return response.choices[0].message.content

       def _get_system_prompt(self) -> str:
           return """You are a security detection engineer specializing in
           writing high-fidelity Splunk SPL and Microsoft Defender KQL queries.

           Your queries should:
           1. Minimize false positives
           2. Use efficient search patterns
           3. Include proper field extractions
           4. Add relevant enrichment
           5. Follow security best practices

           Examples of good queries:
           {self._format_examples()}
           """

       def add_feedback(self, query_id: str, was_accurate: bool,
                       notes: str = None):
           """Collect feedback to improve future generations."""
           # Store in database for continuous improvement
           pass
   ```

2. **Implement Active Learning**:
   - Track which queries users edit/modify
   - Store user improvements as training examples
   - Periodically retrain or update few-shot examples

### Approach 3: Reinforcement Learning from Human Feedback (RLHF)

**Advanced approach** for long-term accuracy:

```python
# Create feedback collection in UI
class QueryFeedback:
    def __init__(self, db):
        self.db = db

    def record_feedback(self, user_id: int, query_id: str,
                       rating: int, edited_query: str = None):
        """
        rating: 1-5 stars
        edited_query: User's improved version
        """
        self.db.execute("""
            INSERT INTO query_feedback
            (user_id, query_id, rating, edited_query, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, query_id, rating, edited_query, datetime.now()))

    def get_training_data(self) -> List[Dict]:
        """Extract high-rated queries for training."""
        return self.db.execute("""
            SELECT technique_id, original_query, edited_query,
                   AVG(rating) as avg_rating
            FROM query_feedback
            WHERE edited_query IS NOT NULL
            GROUP BY technique_id
            HAVING avg_rating >= 4
        """).fetchall()
```

### Recommended Implementation Plan

**Phase 1: Data Collection** (Immediate)
1. Add rating system to Library feature
2. Track which detections users save/export
3. Allow users to submit improved queries
4. Store feedback in `query_feedback` table

**Phase 2: Few-Shot Learning** (Short-term)
1. Integrate OpenAI API with user's key
2. Use top-rated queries as few-shot examples
3. Implement query refinement endpoint
4. Add "Improve with AI" button in UI

**Phase 3: Fine-Tuning** (Long-term)
1. Collect 1000+ query examples with ratings
2. Fine-tune smaller model (Llama 7B or Mistral 7B)
3. Deploy as optional local AI component
4. Fall back to heuristic mode if not available

**Code Location for Implementation**:
- Query refinement: [archer/genai/models.py](archer/genai/models.py)
- Feedback collection: [archer/app.py](archer/app.py) (add new API endpoints)
- Database schema: [archer/database/models.py](archer/database/models.py)

---

## 6. Visualization Libraries

**Dependencies**:
```txt
bokeh==3.8.0
panel==1.8.1
folium==0.20.0
branca==0.8.1
```

**Status**: ❌ **NOT USED** (can remove)

**Current Usage**: No usage found in application code

**What They're For**:
- **bokeh**: Interactive data visualization library
- **panel**: Dashboard creation framework
- **folium**: Interactive map visualizations
- **branca**: Utilities for folium (HTML/CSS/JS generation)

**Estimated Disk Space**: ~100-150 MB

**Recommendation**: **SAFE TO REMOVE**

These were likely included for potential dashboard/visualization features but aren't currently used.

**If You Want to Use Them** (future enhancement ideas):
- **folium**: Map attack paths geographically
- **bokeh**: Interactive timeline of attack progression
- **panel**: Create admin dashboard for user analytics

**To Remove**:
```bash
pip uninstall bokeh panel folium branca
```

---

## 7. Unused Import Analysis

### `from archer.security import sanitize_path_component`

**Status**: ❌ **UNUSED IN ARCHER/APP.PY**

**Found in**:
- [archer/security/validation.py](archer/security/validation.py) - Implementation
- [archer/security/__init__.py](archer/security/__init__.py) - Export
- [archer/app.py](archer/app.py) - Import but NOT USED

**Recommendation**: Remove from archer/app.py

```python
# REMOVE THIS LINE from archer/app.py:
from archer.security import sanitize_path_component
```

### `from archer.auth import get_current_user`

**Status**: ❌ **UNUSED IN ARCHER/APP.PY**

**Found in**:
- [archer/auth/session.py](archer/auth/session.py) - Implementation
- [archer/auth/__init__.py](archer/auth/__init__.py) - Export
- [archer/app.py](archer/app.py) - Import but NOT USED

**Recommendation**: Remove from archer/app.py

```python
# REMOVE THIS LINE from archer/app.py:
from archer.auth import get_current_user
```

**Note**: These functions ARE used elsewhere in the codebase, just not in app.py where they're imported.

---

## Summary of Actions

### 🔴 Safe to Remove Immediately:
```bash
# Visualization libraries (not used)
pip uninstall bokeh panel folium branca

# Jupyter ecosystem (unless you use notebooks)
pip uninstall jupyter jupyterlab notebook ipython ipykernel ipywidgets nbconvert nbformat jupyter-server jupyter-client jupyter-core

# GeoIP libraries (not used)
pip uninstall geoip2 maxminddb
```

**Estimated Total Savings**: 250-350 MB

### 🟡 Make Optional:
```bash
# Move to optional dependencies
# Remove from requirements.txt, keep as optional install
llama-cpp-python==0.3.16  # ~500 MB
transformers              # ~300 MB
```

### 🟢 Keep:
```bash
playwright==1.55.0  # Used for E2E testing
```

### ⚙️ Code Cleanup:
Remove these unused imports from [archer/app.py](archer/app.py):
```python
from archer.security import sanitize_path_component  # Line ??? - find and remove
from archer.auth import get_current_user            # Line ??? - find and remove
```

---

## Next Steps

Would you like me to:

1. **Remove the unused dependencies** and update requirements.txt?
2. **Remove the unused imports** from archer/app.py?
3. **Implement the AI training feedback system** (database schema + API endpoints)?
4. **Create optional dependency groups** in setup.py/pyproject.toml?
5. **Create a migration guide** for users who want local AI support?

Let me know which actions you'd like me to take!

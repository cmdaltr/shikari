# AI Training & Query Refinement System

> **Status (2026-10-16):** some of what this document names was never built: the fine-tuning and deployment scripts (`fine_tune_llama.py`, `deploy_model.py`, `export_training_data.py`), the training-table migration and `config/ai_models.json`; local models are configured in Profile → API Keys instead. What exists: `scripts/config/` (`setup_knowledge_base.py`, `import_community_rules.py`, `build_embeddings.py`, `search_similar_detections.py`, `validate_detections.py`, `quickstart_rag.py`), `scripts/ai/` (`setup_local_llm.py`, `train_ai.py`), `scripts/data/` and `scripts/validation/`: see [SCRIPTS.md](../SCRIPTS.md).

Complete implementation guide for training the AI component to improve Splunk and MDE query accuracy.

---

## Table of Contents

1. [Overview](#overview)
2. [Current Architecture](#current-architecture)
3. [Proposed Implementation](#proposed-implementation)
4. [Database Schema](#database-schema)
5. [Backend APIs](#backend-apis)
6. [Frontend UI Components](#frontend-ui-components)
7. [Training Approaches](#training-approaches)
8. [Implementation Phases](#implementation-phases)
9. [Code Examples](#code-examples)
10. [Next Steps](#next-steps)
11. [Installation & Setup](#installation--setup)
    - [Option 1: OpenAI API](#option-1-openai-api-few-shot-learning---recommended)
    - [Option 2: Local AI (Llama)](#option-2-local-ai-llamatransformers---offline)
    - [Option 3: Hybrid Approach](#option-3-hybrid-approach-recommended)
    - [Model Comparison](#model-comparison)
    - [Troubleshooting](#troubleshooting-installation)
    - [Quick Start Examples](#quick-start-examples)
    - [Performance Optimization](#performance-optimization)

---

## Overview

### Problem Statement

The current detection generation uses **heuristic-based** correlation rather than AI-trained models. To improve query accuracy and fidelity:

1. Collect user feedback on generated queries
2. Learn from user improvements/edits
3. Use successful queries as training examples
4. Continuously improve query generation over time

### Goals

- **Collect feedback**: Track which queries are good/bad
- **Learn patterns**: Identify what makes queries high-quality
- **Improve accuracy**: Generate better queries over time
- **Reduce false positives**: Learn from user corrections
- **Platform-specific optimization**: Splunk vs MDE differences

---

## Current Architecture

### Location: [shikari/ai/genai/engine.py](../../shikari/ai/genai/engine.py)

Current system:
```python
"""
Lightweight GenAI stub for generating correlation suggestions.

This module intentionally avoids external AI providers and instead provides
heuristic-based synthesis from generated YAMLs. It is pluggable and can be
replaced with a true GenAI integration later (e.g., OpenAI, local LLM).
"""
```

**Key characteristics**:
- Uses heuristic rules, not AI
- Graceful fallback if LLM unavailable
- Already has optional llama_cpp support
- Modular and pluggable design

---

## Proposed Implementation

### Three-Tiered Approach

1. **Phase 1**: Feedback Collection (Immediate)
2. **Phase 2**: Few-Shot Learning (Short-term)
3. **Phase 3**: Fine-Tuning (Long-term)

---

## Database Schema

### New Tables

Add these models to [shikari/database/models.py](../../shikari/database/models.py):

```python
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
import enum


class QueryRatingEnum(enum.Enum):
    """Query quality rating"""
    EXCELLENT = 5
    GOOD = 4
    ACCEPTABLE = 3
    POOR = 2
    UNUSABLE = 1


class QueryPlatform(enum.Enum):
    """Detection platform"""
    SPLUNK = "splunk"
    MDE = "mde"
    SENTINEL = "sentinel"
    SECOPS = "secops"


class QueryFeedback(Base):
    """
    User feedback on generated queries.

    Tracks user ratings and improvements to queries for training purposes.
    """
    __tablename__ = "query_feedback"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Query details
    technique_id = Column(String(20), nullable=False, index=True)  # e.g., "T1003.001"
    platform = Column(Enum(QueryPlatform), nullable=False, index=True)
    original_query = Column(Text, nullable=False)
    edited_query = Column(Text, nullable=True)  # User's improved version

    # Feedback
    rating = Column(Integer, nullable=False)  # 1-5 scale
    feedback_text = Column(Text, nullable=True)  # Optional user comments

    # Metadata
    generation_method = Column(String(50), nullable=True)  # "heuristic", "llm", "few-shot"
    context = Column(Text, nullable=True)  # JSON: {threat_group, use_case, etc.}

    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", backref="query_feedback")

    def __repr__(self):
        return f"<QueryFeedback(id={self.id}, technique={self.technique_id}, rating={self.rating})>"


class QueryTrainingExample(Base):
    """
    Curated training examples for query generation.

    High-quality examples extracted from feedback and manual curation.
    Used for few-shot learning and fine-tuning.
    """
    __tablename__ = "query_training_examples"

    id = Column(Integer, primary_key=True, index=True)

    # Example details
    technique_id = Column(String(20), nullable=False, index=True)
    platform = Column(Enum(QueryPlatform), nullable=False, index=True)
    query = Column(Text, nullable=False)

    # Context for the example
    technique_description = Column(Text, nullable=False)
    attack_scenario = Column(Text, nullable=True)
    expected_detections = Column(Text, nullable=True)

    # Quality metrics
    avg_rating = Column(Float, nullable=True)  # From feedback
    usage_count = Column(Integer, default=0)  # How many times used in few-shot
    success_rate = Column(Float, nullable=True)  # % of users who rated subsequent queries highly

    # Metadata
    source = Column(String(50), nullable=False)  # "user_feedback", "manual", "expert_review"
    tags = Column(Text, nullable=True)  # JSON array: ["persistence", "windows", "registry"]

    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    def __repr__(self):
        return f"<QueryTrainingExample(id={self.id}, technique={self.technique_id}, platform={self.platform.value})>"


class QueryGenerationLog(Base):
    """
    Log of all query generation attempts.

    Tracks which method was used, success/failure, and performance metrics.
    """
    __tablename__ = "query_generation_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Generation details
    technique_id = Column(String(20), nullable=False, index=True)
    platform = Column(Enum(QueryPlatform), nullable=False)
    method = Column(String(50), nullable=False)  # "heuristic", "few-shot", "fine-tuned"

    # Performance
    generation_time_ms = Column(Integer, nullable=True)
    success = Column(Integer, nullable=False)  # 1 = success, 0 = failure
    error_message = Column(Text, nullable=True)

    # Context
    model_version = Column(String(50), nullable=True)  # e.g., "gpt-4", "llama-2-7b"
    num_examples_used = Column(Integer, nullable=True)  # For few-shot learning

    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<QueryGenerationLog(id={self.id}, method={self.method}, success={self.success})>"
```

### Migration Script

Create shikari/database/migrations/add_ai_training_tables.py:

```python
"""
Add AI training tables for query feedback and training examples.
"""
from sqlalchemy import create_engine
from shikari.database.models import Base, QueryFeedback, QueryTrainingExample, QueryGenerationLog

def upgrade(db_path: str = "data/shikari.db"):
    """Create new tables for AI training."""
    engine = create_engine(f"sqlite:///{db_path}")

    # Create only the new tables
    QueryFeedback.__table__.create(engine, checkfirst=True)
    QueryTrainingExample.__table__.create(engine, checkfirst=True)
    QueryGenerationLog.__table__.create(engine, checkfirst=True)

    print("✓ AI training tables created successfully")

if __name__ == "__main__":
    upgrade()
```

---

## Backend APIs

### Add to [shikari/app.py](../../shikari/app.py)

```python
from shikari.database.models import QueryFeedback, QueryTrainingExample, QueryGenerationLog, QueryPlatform

# ============================================================================
# Query Feedback APIs
# ============================================================================

@app.post("/api/query-feedback")
async def submit_query_feedback(
    request: Request,
    technique_id: str = Form(...),
    platform: str = Form(...),
    original_query: str = Form(...),
    rating: int = Form(...),
    edited_query: str = Form(None),
    feedback_text: str = Form(None),
    generation_method: str = Form(None),
    context: str = Form(None),
    session_id: str = Cookie(None)
):
    """
    Submit feedback on a generated query.

    Args:
        technique_id: MITRE technique (e.g., "T1003.001")
        platform: "splunk", "mde", etc.
        original_query: The query that was generated
        rating: 1-5 stars
        edited_query: User's improved version (optional)
        feedback_text: User comments (optional)
        generation_method: How it was generated
        context: JSON context data
    """
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = get_user_from_session_id(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session")

    db = next(get_db())
    try:
        feedback = QueryFeedback(
            user_id=user.id,
            technique_id=technique_id,
            platform=QueryPlatform[platform.upper()],
            original_query=original_query,
            edited_query=edited_query,
            rating=rating,
            feedback_text=feedback_text,
            generation_method=generation_method,
            context=context
        )
        db.add(feedback)
        db.commit()

        # If rating is 4 or 5 and user provided edits, create training example
        if rating >= 4 and edited_query:
            await _create_training_example(
                db, technique_id, platform, edited_query, user.id, rating
            )

        return {"status": "success", "feedback_id": feedback.id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@app.get("/api/query-feedback/{technique_id}")
async def get_query_feedback(
    technique_id: str,
    platform: str = None,
    session_id: str = Cookie(None)
):
    """
    Get feedback statistics for a technique.

    Returns average rating, count, and top-rated examples.
    """
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = get_user_from_session_id(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session")

    db = next(get_db())
    try:
        query = db.query(QueryFeedback).filter(
            QueryFeedback.technique_id == technique_id
        )

        if platform:
            query = query.filter(
                QueryFeedback.platform == QueryPlatform[platform.upper()]
            )

        feedback_items = query.all()

        if not feedback_items:
            return {"count": 0, "avg_rating": None, "examples": []}

        avg_rating = sum(f.rating for f in feedback_items) / len(feedback_items)

        # Get top-rated examples with edits
        top_examples = [
            {
                "query": f.edited_query or f.original_query,
                "rating": f.rating,
                "platform": f.platform.value,
                "created_at": f.created_at.isoformat()
            }
            for f in sorted(feedback_items, key=lambda x: x.rating, reverse=True)[:5]
            if f.edited_query or f.rating >= 4
        ]

        return {
            "count": len(feedback_items),
            "avg_rating": round(avg_rating, 2),
            "examples": top_examples
        }
    finally:
        db.close()


# ============================================================================
# Query Refinement with AI
# ============================================================================

@app.post("/api/query-refine")
async def refine_query(
    request: Request,
    technique_id: str = Form(...),
    platform: str = Form(...),
    original_query: str = Form(...),
    use_ai: bool = Form(True),
    session_id: str = Cookie(None)
):
    """
    Refine a query using AI and feedback data.

    Uses few-shot learning with top-rated examples.
    """
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = get_user_from_session_id(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session")

    db = next(get_db())
    start_time = time.time()

    try:
        # Get training examples for this technique
        examples = db.query(QueryTrainingExample).filter(
            QueryTrainingExample.technique_id == technique_id,
            QueryTrainingExample.platform == QueryPlatform[platform.upper()],
            QueryTrainingExample.avg_rating >= 4.0
        ).order_by(QueryTrainingExample.avg_rating.desc()).limit(3).all()

        if not use_ai or not examples:
            # Return original if no AI or no examples
            return {
                "refined_query": original_query,
                "method": "original",
                "confidence": 0.5
            }

        # Use few-shot learning to refine
        refined_query = await _refine_with_few_shot(
            technique_id, platform, original_query, examples
        )

        # Log generation
        generation_time = int((time.time() - start_time) * 1000)
        log = QueryGenerationLog(
            user_id=user.id,
            technique_id=technique_id,
            platform=QueryPlatform[platform.upper()],
            method="few-shot",
            generation_time_ms=generation_time,
            success=1,
            num_examples_used=len(examples)
        )
        db.add(log)
        db.commit()

        return {
            "refined_query": refined_query,
            "method": "few-shot",
            "num_examples": len(examples),
            "confidence": 0.8 if len(examples) >= 3 else 0.6
        }

    except Exception as e:
        db.rollback()
        # Log failure
        log = QueryGenerationLog(
            user_id=user.id,
            technique_id=technique_id,
            platform=QueryPlatform[platform.upper()],
            method="few-shot",
            generation_time_ms=int((time.time() - start_time) * 1000),
            success=0,
            error_message=str(e)
        )
        db.add(log)
        db.commit()

        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


# ============================================================================
# Helper Functions
# ============================================================================

async def _create_training_example(db, technique_id, platform, query, user_id, rating):
    """Create or update a training example from user feedback."""
    # Check if example already exists
    existing = db.query(QueryTrainingExample).filter(
        QueryTrainingExample.technique_id == technique_id,
        QueryTrainingExample.platform == QueryPlatform[platform.upper()],
        QueryTrainingExample.query == query
    ).first()

    if existing:
        # Update rating
        if existing.avg_rating:
            existing.avg_rating = (existing.avg_rating + rating) / 2
        else:
            existing.avg_rating = float(rating)
        existing.usage_count += 1
    else:
        # Get technique description from MITRE
        technique_desc = _get_technique_description(technique_id)

        example = QueryTrainingExample(
            technique_id=technique_id,
            platform=QueryPlatform[platform.upper()],
            query=query,
            technique_description=technique_desc,
            avg_rating=float(rating),
            source="user_feedback",
            created_by=user_id
        )
        db.add(example)

    db.commit()


async def _refine_with_few_shot(technique_id, platform, original_query, examples):
    """
    Use few-shot learning to refine a query.

    If OpenAI API available, use GPT-4. Otherwise use heuristics.
    """
    # Check for OpenAI API key
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        # Fall back to heuristic improvements
        return _heuristic_refinement(original_query, platform)

    # Build few-shot prompt
    from openai import OpenAI
    client = OpenAI(api_key=api_key)

    examples_text = "\n\n".join([
        f"Example {i+1}:\n{ex.query}"
        for i, ex in enumerate(examples)
    ])

    prompt = f"""You are a security detection engineer. Refine the following {platform} query
to be more accurate and reduce false positives, based on these high-quality examples:

{examples_text}

Original Query:
{original_query}

Provide ONLY the refined query, no explanation."""

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are an expert security detection engineer."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2,
        max_tokens=500
    )

    return response.choices[0].message.content.strip()


def _heuristic_refinement(query, platform):
    """Basic heuristic-based query improvements."""
    # Add common refinements based on platform
    if platform.lower() == "splunk":
        # Add time range if missing
        if "earliest=" not in query.lower():
            query = query.strip() + " | head 1000"
    elif platform.lower() == "mde":
        # Add time filter if missing
        if "timestamp" not in query.lower() and "ago" not in query.lower():
            query = query.strip() + "\n| where Timestamp > ago(24h)"

    return query


def _get_technique_description(technique_id):
    """Get MITRE technique description."""
    # This function should integrate with your existing MITRE data
    # For now, return placeholder
    return f"Detection for MITRE technique {technique_id}"
```

---

## Frontend UI Components

### Add Rating Component to Library

Update [templates/library.html](../../templates/library.html) or create new template sections:

```html
<!-- Rating Component -->
<div class="query-rating" data-technique-id="{{ technique_id }}" data-platform="{{ platform }}">
    <div class="rating-stars">
        <span class="star" data-rating="1">★</span>
        <span class="star" data-rating="2">★</span>
        <span class="star" data-rating="3">★</span>
        <span class="star" data-rating="4">★</span>
        <span class="star" data-rating="5">★</span>
    </div>
    <div class="rating-feedback hidden">
        <textarea placeholder="Optional: Provide your improved version of the query"
                  id="edited-query"></textarea>
        <textarea placeholder="Additional feedback (optional)"
                  id="feedback-text"></textarea>
        <button onclick="submitFeedback()">Submit Feedback</button>
    </div>
</div>

<script>
// JavaScript for rating interaction
document.querySelectorAll('.star').forEach(star => {
    star.addEventListener('click', function() {
        const rating = this.getAttribute('data-rating');
        const parent = this.closest('.query-rating');

        // Highlight stars
        parent.querySelectorAll('.star').forEach((s, i) => {
            s.classList.toggle('active', i < rating);
        });

        // Show feedback form for ratings 3 and below
        if (rating <= 3) {
            parent.querySelector('.rating-feedback').classList.remove('hidden');
        }

        // Store rating
        parent.setAttribute('data-current-rating', rating);
    });
});

async function submitFeedback() {
    const container = event.target.closest('.query-rating');
    const rating = container.getAttribute('data-current-rating');
    const techniqueId = container.getAttribute('data-technique-id');
    const platform = container.getAttribute('data-platform');
    const originalQuery = document.querySelector('#query-content').textContent;
    const editedQuery = document.querySelector('#edited-query').value;
    const feedbackText = document.querySelector('#feedback-text').value;

    const formData = new FormData();
    formData.append('technique_id', techniqueId);
    formData.append('platform', platform);
    formData.append('original_query', originalQuery);
    formData.append('rating', rating);
    if (editedQuery) formData.append('edited_query', editedQuery);
    if (feedbackText) formData.append('feedback_text', feedbackText);

    const response = await fetch('/api/query-feedback', {
        method: 'POST',
        body: formData
    });

    if (response.ok) {
        alert('Thank you for your feedback!');
        container.querySelector('.rating-feedback').classList.add('hidden');
    } else {
        alert('Failed to submit feedback. Please try again.');
    }
}
</script>

<style>
.star {
    font-size: 24px;
    color: #ddd;
    cursor: pointer;
    transition: color 0.2s;
}

.star:hover,
.star.active {
    color: #ffd700;
}

.rating-feedback {
    margin-top: 15px;
}

.rating-feedback.hidden {
    display: none;
}

.rating-feedback textarea {
    width: 100%;
    margin: 10px 0;
    padding: 10px;
    font-family: monospace;
}

.rating-feedback button {
    background: #0066cc;
    color: white;
    padding: 10px 20px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
</style>
```

---

## Training Approaches

### 1. Few-Shot Learning (Recommended Start)

**How it works**:
- Collect top-rated queries as examples
- Send 3-5 examples to OpenAI GPT-4 with new query
- GPT-4 learns pattern from examples
- Generates improved query

**Pros**:
- No fine-tuning needed
- Works immediately with small dataset
- Easy to update examples
- Low cost (~$0.03 per query)

**Cons**:
- Requires OpenAI API key
- Slower than local model
- Privacy concerns (sending data to OpenAI)

**Implementation**: Already included in code above

### 2. Fine-Tuning Local LLM

**How it works**:
- Collect 500+ training examples
- Fine-tune Llama-2-7B or Mistral-7B
- Deploy fine-tuned model locally
- Generate queries offline

**Pros**:
- No ongoing API costs
- Runs offline
- Data stays private
- Faster generation

**Cons**:
- Requires large dataset (500+ examples)
- GPU needed for training
- More complex deployment
- Maintenance overhead

**Implementation Steps**:

```python
# 1. Export training data
python scripts/export_training_data.py --min-rating 4 --output training_data.jsonl

# 2. Fine-tune model (requires GPU)
python scripts/fine_tune_llama.py --data training_data.jsonl --model llama-2-7b

# 3. Deploy fine-tuned model
python scripts/deploy_model.py --model models/fine-tuned-llama-2-7b.gguf
```

### 3. Reinforcement Learning from Human Feedback (RLHF)

**Advanced approach** - recommended for future:

1. Generate query
2. User rates it
3. If edited, compute similarity to original
4. Reward model based on user satisfaction
5. Retrain periodically

**Best for**: Long-term continuous improvement

---

## Implementation Phases

### Phase 1: Foundation (Week 1)

**Tasks**:
- [x] Add database tables
- [ ] Implement feedback APIs
- [ ] Add rating UI to library
- [ ] Create migration script

**Deliverables**:
- Users can rate queries 1-5 stars
- Users can submit improved versions
- Feedback stored in database

### Phase 2: Few-Shot Learning (Week 2-3)

**Tasks**:
- [ ] Implement query refinement API
- [ ] Integrate OpenAI GPT-4
- [ ] Add "Improve with AI" button
- [ ] Display confidence scores

**Deliverables**:
- AI-powered query refinement
- Learning from top-rated examples
- Visual feedback on improvements

### Phase 3: Analytics & Monitoring (Week 4)

**Tasks**:
- [ ] Create admin dashboard for training data
- [ ] Show query success metrics
- [ ] Export training dataset
- [ ] A/B test heuristic vs AI

**Deliverables**:
- Admin insights into query quality
- Ability to curate training examples
- Performance metrics

### Phase 4: Advanced Training (Future)

**Tasks**:
- [ ] Collect 500+ training examples
- [ ] Fine-tune local Llama model
- [ ] Deploy fine-tuned model
- [ ] Implement RLHF loop

**Deliverables**:
- Fully offline AI training
- Continuous improvement
- Platform-specific optimization

---

## Code Examples

### Example: Submit Feedback via cURL

```bash
curl -X POST http://localhost:8000/api/query-feedback \
  -H "Cookie: session_id=your-session-id" \
  -F "technique_id=T1003.001" \
  -F "platform=splunk" \
  -F "original_query=index=windows EventCode=4688" \
  -F "rating=4" \
  -F "edited_query=index=windows EventCode=4688 Image=*lsass.exe* | stats count by Computer" \
  -F "feedback_text=Added specificity for LSASS"
```

### Example: Refine Query

```bash
curl -X POST http://localhost:8000/api/query-refine \
  -H "Cookie: session_id=your-session-id" \
  -F "technique_id=T1003.001" \
  -F "platform=mde" \
  -F "original_query=DeviceProcessEvents | where ProcessCommandLine contains 'lsass'" \
  -F "use_ai=true"
```

Response:
```json
{
  "refined_query": "DeviceProcessEvents\n| where ProcessCommandLine has_any ('lsass.exe', 'lsass.dmp')\n| where Timestamp > ago(24h)\n| where ActionType == 'ProcessCreated'\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine",
  "method": "few-shot",
  "num_examples": 3,
  "confidence": 0.8
}
```

---

## Next Steps

**To implement this system**:

1. **Review this document** - Understand the architecture
2. **Decide on approach** - Few-shot vs fine-tuning vs both
3. **Run migration** - Add database tables
4. **Implement Phase 1** - Basic feedback collection
5. **Test with users** - Collect initial feedback
6. **Implement Phase 2** - AI refinement (if OpenAI available)
7. **Monitor results** - Track improvement metrics
8. **Iterate** - Continuous improvement

**Questions to answer before implementation**:

1. Do you have OpenAI API key? (for few-shot learning)
2. Do you want offline-only solution? (requires fine-tuning)
3. What's your target accuracy improvement? (to measure success)
4. How many users will provide feedback? (to estimate dataset size)
5. Which platform is priority? (Splunk vs MDE vs both)

---

## Installation & Setup

### Prerequisites

Choose your AI approach and install the required dependencies:

#### Option 1: OpenAI API (Few-Shot Learning) - Recommended

**Best for**: Quick start, small datasets, cloud-based solution

**Requirements**:
- OpenAI API key
- Internet connection
- No GPU needed

**Installation**:
```bash
# No additional packages needed - uses requests (already in requirements.txt)
# Just set your API key
export OPENAI_API_KEY="sk-your-api-key-here"

# Or add to .env file
echo "OPENAI_API_KEY=sk-your-api-key-here" >> .env
```

**Cost**: ~$0.03 per query refinement (GPT-4)

---

#### Option 2: Local AI (Llama/Transformers) - Offline

**Best for**: Privacy-focused, offline deployment, high query volume

**Requirements**:
- GPU recommended (8GB+ VRAM for 7B models, 16GB+ for 13B)
- CPU-only possible but slower
- 10-20 GB disk space for models

**Installation**:

##### Step 1: Install Local AI Dependencies

```bash
# Using pyproject.toml (recommended)
pip install -e .[local-ai]

# OR install packages directly
pip install llama-cpp-python==0.3.16 transformers torch sentencepiece
```

**Note**: On macOS with Apple Silicon (M1/M2/M3), llama-cpp-python will automatically use Metal for GPU acceleration.

##### Step 2: Download Model Files

**Option A: Llama 2 (Recommended for Production)**

```bash
# Create models directory
mkdir -p models

# Download Llama-2-7B-Chat GGUF (quantized, ~4 GB)
# From HuggingFace
cd models
wget https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF/resolve/main/llama-2-7b-chat.Q4_K_M.gguf

# OR download via Python
python3 << 'EOF'
from huggingface_hub import hf_hub_download

hf_hub_download(
    repo_id="TheBloke/Llama-2-7B-Chat-GGUF",
    filename="llama-2-7b-chat.Q4_K_M.gguf",
    local_dir="models"
)
EOF
```

**Option B: Mistral 7B (Alternative, Good Performance)**

```bash
cd models
wget https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf
```

**Option C: Smaller Models (For Limited Resources)**

```bash
# TinyLlama 1.1B (~600 MB) - Fast, lower quality
cd models
wget https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
```

##### Step 3: Configure Model Path

Create config/ai_models.json:

```json
{
  "local_llm": {
    "enabled": true,
    "model_type": "llama-cpp",
    "model_path": "models/llama-2-7b-chat.Q4_K_M.gguf",
    "n_ctx": 2048,
    "n_gpu_layers": 35,
    "temperature": 0.2,
    "max_tokens": 500
  },
  "cache_dir": "data/ai_cache",
  "cache_ttl": 86400
}
```

**GPU Configuration**:
- `n_gpu_layers`: Number of layers to offload to GPU
  - CPU only: `0`
  - 8GB VRAM: `20-25`
  - 16GB VRAM: `35-40` (full model)
  - Apple Silicon: `35-40` (Metal acceleration)

##### Step 4: Test Installation

```bash
# Test llama-cpp installation
python3 << 'EOF'
import importlib.util

if importlib.util.find_spec("llama_cpp"):
    from llama_cpp import Llama

    # Load model
    llm = Llama(
        model_path="models/llama-2-7b-chat.Q4_K_M.gguf",
        n_ctx=2048,
        n_gpu_layers=35,
        verbose=False
    )

    # Test query
    output = llm("Q: What is 2+2? A:", max_tokens=32)
    print("✓ Llama model loaded successfully!")
    print(f"Test output: {output['choices'][0]['text']}")
else:
    print("✗ llama-cpp-python not installed")
EOF
```

Expected output:
```
✓ Llama model loaded successfully!
Test output:  4
```

---

#### Option 3: Hybrid Approach (Recommended)

Use both OpenAI and local AI with automatic fallback:

```bash
# 1. Install local AI dependencies
pip install -e .[local-ai]

# 2. Download a model (as above)
# 3. Set OpenAI API key
export OPENAI_API_KEY="sk-your-key"

# 4. Configure priority in config/ai_models.json
```

**Configuration**:
```json
{
  "query_refinement": {
    "primary": "openai",
    "fallback": "local_llm",
    "local_llm": {
      "enabled": true,
      "model_path": "models/llama-2-7b-chat.Q4_K_M.gguf"
    },
    "openai": {
      "enabled": true,
      "model": "gpt-4",
      "use_if_available": true
    }
  }
}
```

The application will:
1. Try OpenAI first (if API key available)
2. Fall back to local LLM (if installed)
3. Fall back to heuristic mode (always available)

---

### Verify Installation

Test that the AI system detects available backends:

```bash
# Run detection test
python3 << 'EOF'
from shikari.ai.genai.engine import _HAS_LLAMA, _HAS_TRANSFORMERS
import os

print("=== AI Backend Detection ===")
print(f"Llama (llama-cpp): {'✓ Available' if _HAS_LLAMA else '✗ Not installed'}")
print(f"Transformers: {'✓ Available' if _HAS_TRANSFORMERS else '✗ Not installed'}")
print(f"OpenAI API Key: {'✓ Set' if os.getenv('OPENAI_API_KEY') else '✗ Not set'}")

if _HAS_LLAMA:
    print("\n→ Will use local LLM for query refinement")
elif os.getenv('OPENAI_API_KEY'):
    print("\n→ Will use OpenAI API for query refinement")
else:
    print("\n→ Will use heuristic mode (no AI)")
EOF
```

---

### Model Comparison

| Model | Size | VRAM | Speed | Quality | Use Case |
|-------|------|------|-------|---------|----------|
| **TinyLlama 1.1B** | 600 MB | 2 GB | Very Fast | Good | Testing, CPU-only |
| **Llama 2 7B (Q4)** | 4 GB | 6-8 GB | Fast | Excellent | Production |
| **Mistral 7B (Q4)** | 4 GB | 6-8 GB | Fast | Excellent | Production |
| **Llama 2 13B (Q4)** | 7 GB | 12-16 GB | Medium | Best | High accuracy |
| **GPT-4 (OpenAI)** | N/A | N/A | Medium | Best | Cloud, no GPU |

**Recommendation**:
- **Development**: TinyLlama or OpenAI API
- **Production (offline)**: Llama 2 7B or Mistral 7B
- **Production (cloud)**: OpenAI GPT-4
- **High accuracy**: Llama 2 13B or GPT-4

---

### Troubleshooting Installation

#### Error: "No module named 'llama_cpp'"

**Solution**: This is expected if you haven't installed local AI dependencies. The app will use heuristic mode.

To fix:
```bash
pip install -e .[local-ai]
```

#### Error: "Failed to load model: cannot open file"

**Solution**: Model file not found or path incorrect.

```bash
# Check model exists
ls -lh models/*.gguf

# Update path in config/ai_models.json
```

#### Error: "CUDA not available" or "Metal not available"

**Solution**: GPU acceleration not detected.

```bash
# Test GPU
python3 -c "import torch; print('CUDA:', torch.cuda.is_available())"

# On macOS, llama-cpp-python uses Metal automatically
# On Linux/Windows, ensure CUDA is installed
```

For CPU-only mode:
```json
{
  "n_gpu_layers": 0  # Disable GPU
}
```

#### Error: "Out of memory"

**Solution**: Model too large for available VRAM.

**Options**:
1. Use smaller model (TinyLlama instead of Llama 2)
2. Reduce `n_gpu_layers` in config
3. Use quantized model (Q4_K_M instead of Q8)

```bash
# Switch to smaller model
cd models
rm llama-2-7b-chat.Q4_K_M.gguf
wget https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
```

#### Slow Generation (~1 token/second)

**Causes**:
- Running on CPU only
- Model too large for hardware
- Not using GPU acceleration

**Solutions**:
1. Check GPU configuration: `n_gpu_layers` should be > 0
2. Use smaller/faster model
3. Ensure Metal/CUDA is available

---

### Quick Start Examples

#### Example 1: Test Few-Shot Learning with OpenAI

```bash
# 1. Set API key
export OPENAI_API_KEY="sk-your-key"

# 2. Start server
uvicorn shikari.app:app --reload

# 3. Test refinement
curl -X POST http://localhost:8000/api/query-refine \
  -H "Cookie: session_id=your-session" \
  -F "technique_id=T1003.001" \
  -F "platform=splunk" \
  -F "original_query=index=windows EventCode=4688" \
  -F "use_ai=true"
```

#### Example 2: Test Local Llama Model

```bash
# 1. Install and download model (as above)

# 2. Test model directly
python3 << 'EOF'
from llama_cpp import Llama

llm = Llama(model_path="models/llama-2-7b-chat.Q4_K_M.gguf", n_gpu_layers=35)
result = llm("Refine this Splunk query: index=windows EventCode=4688", max_tokens=200)
print(result['choices'][0]['text'])
EOF
```

---

### Performance Optimization

#### For Maximum Speed

```json
{
  "local_llm": {
    "n_ctx": 1024,           // Smaller context
    "n_gpu_layers": 40,      // All layers on GPU
    "n_threads": 8,          // CPU threads
    "n_batch": 512,          // Larger batches
    "temperature": 0.1,      // Lower = faster, more deterministic
    "max_tokens": 300        // Limit output length
  }
}
```

#### For Maximum Quality

```json
{
  "local_llm": {
    "n_ctx": 4096,           // Larger context
    "temperature": 0.3,      // Higher creativity
    "top_p": 0.95,           // Nucleus sampling
    "repeat_penalty": 1.1,   // Reduce repetition
    "max_tokens": 1000       // Longer outputs
  }
}
```

---

### Next Steps After Installation

1. ✓ Dependencies installed
2. ✓ Model downloaded (if using local AI)
3. ✓ Configuration file created
4. → Proceed to [Implementation Phases](#implementation-phases)
5. → Start with Phase 1: Database migration
6. → Implement feedback collection APIs
7. → Test query refinement

**Ready to implement?** Start with Phase 1 in the implementation guide above!

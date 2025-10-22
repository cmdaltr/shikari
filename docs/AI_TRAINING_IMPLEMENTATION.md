# AI Training & Query Refinement System

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

### Location: [archer/genai/engine.py](../archer/genai/engine.py)

Current system:
```python
"""
Lightweight GenAI stub for generating correlation suggestions.

This module intentionally avoids external AI providers and instead provides
heuristic-based synthesis from generated YAMLs. It is pluggable and can be
replaced with a true GenAI integration later (e.g., OpenAI, local LLM, n8n).
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

Add these models to [archer/database/models.py](../archer/database/models.py):

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
    CHRONICLE = "chronicle"


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

Create [archer/database/migrations/add_ai_training_tables.py](../archer/database/migrations/add_ai_training_tables.py):

```python
"""
Add AI training tables for query feedback and training examples.
"""
from sqlalchemy import create_engine
from archer.database.models import Base, QueryFeedback, QueryTrainingExample, QueryGenerationLog

def upgrade(db_path: str = "data/archer.db"):
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

### Add to [archer/app.py](../archer/app.py)

```python
from archer.database.models import QueryFeedback, QueryTrainingExample, QueryGenerationLog, QueryPlatform

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

Update [templates/library.html](../templates/library.html) or create new template sections:

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

Let me know when you're ready to implement, and I'll help with the specific phase you want to start with!

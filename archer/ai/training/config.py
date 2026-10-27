"""
AI Training Configuration

Centralized configuration for LLM training and inference.
"""

import os
from pathlib import Path
from archer import paths

# Base directories
BASE_DIR = Path(__file__).parent
DATA_DIR = paths.DATA
AI_DATA_DIR = DATA_DIR / "ai_training"

# Dataset directories
DATASETS_DIR = BASE_DIR / "datasets"
HUNTING_QUERIES_DIR = DATASETS_DIR / "hunting_queries"
CORRELATIONS_DIR = DATASETS_DIR / "correlations"
THREAT_INTEL_DIR = DATASETS_DIR / "threat_intelligence"
THREAT_REPORTS_DIR = DATASETS_DIR / "threat_reports"
BLOG_POSTS_DIR = DATASETS_DIR / "blog_posts"
CVE_DATA_DIR = DATASETS_DIR / "cve_data"
OSINT_SAMPLES_DIR = DATASETS_DIR / "osint_samples"

# Model directories
MODELS_DIR = BASE_DIR / "models"
CHECKPOINTS_DIR = MODELS_DIR / "checkpoints"
FINE_TUNED_DIR = MODELS_DIR / "fine_tuned"
ADAPTERS_DIR = MODELS_DIR / "adapters"

# Prompt directories
PROMPTS_DIR = BASE_DIR / "prompts"
SYSTEM_PROMPTS_DIR = PROMPTS_DIR / "system"
DETECTION_PROMPTS_DIR = PROMPTS_DIR / "detection"
CORRELATION_PROMPTS_DIR = PROMPTS_DIR / "correlation"
REPORT_PROMPTS_DIR = PROMPTS_DIR / "reports"

# Pipeline directories
PIPELINES_DIR = BASE_DIR / "pipelines"
PREPROCESSING_DIR = PIPELINES_DIR / "preprocessing"
TRAINING_DIR = PIPELINES_DIR / "training"
INFERENCE_DIR = PIPELINES_DIR / "inference"

# Evaluation directories
EVALUATION_DIR = BASE_DIR / "evaluation"
BENCHMARKS_DIR = EVALUATION_DIR / "benchmarks"
METRICS_DIR = EVALUATION_DIR / "metrics"
VALIDATION_DIR = EVALUATION_DIR / "validation"

# Output directories
OUTPUT_DIR = AI_DATA_DIR / "outputs"
GENERATED_DETECTIONS_DIR = OUTPUT_DIR / "detections"
GENERATED_CORRELATIONS_DIR = OUTPUT_DIR / "correlations"
GENERATED_REPORTS_DIR = OUTPUT_DIR / "reports"

# Model configuration
MODEL_CONFIG = {
    # Supported local LLM backends
    "backends": {
        "ollama": {
            "enabled": True,
            "endpoint": "http://localhost:11434",
            "models": [
                "llama3.1:70b",
                "llama3.1:8b",
                "mistral:7b",
                "mixtral:8x7b",
                "codellama:34b",
                "deepseek-coder:33b",
            ]
        },
        "vllm": {
            "enabled": False,
            "endpoint": "http://localhost:8000",
            "tensor_parallel_size": 1,
        },
        "llama_cpp": {
            "enabled": False,
            "n_ctx": 8192,
            "n_gpu_layers": 35,
        },
        "transformers": {
            "enabled": True,
            "device": "cuda",  # or "mps" for Apple Silicon
            "load_in_8bit": True,
            "load_in_4bit": False,
        }
    },

    # Default model for each task
    "default_models": {
        "detection_generation": "llama3.1:70b",
        "correlation_generation": "mixtral:8x7b",
        "report_generation": "llama3.1:70b",
        "threat_analysis": "deepseek-coder:33b",
        "cve_analysis": "llama3.1:8b",
    },

    # Generation parameters
    "generation": {
        "temperature": 0.7,
        "top_p": 0.9,
        "top_k": 40,
        "max_tokens": 4096,
        "repetition_penalty": 1.1,
        "stop_sequences": ["</detection>", "</correlation>", "</report>"],
    },

    # Training parameters
    "training": {
        "epochs": 3,
        "batch_size": 4,
        "learning_rate": 2e-5,
        "warmup_steps": 100,
        "gradient_accumulation_steps": 4,
        "max_seq_length": 8192,
        "lora_r": 16,
        "lora_alpha": 32,
        "lora_dropout": 0.05,
        "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj"],
    }
}

# Data preprocessing configuration
PREPROCESSING_CONFIG = {
    "chunk_size": 2048,
    "overlap": 256,
    "min_quality_score": 0.7,
    "deduplication": True,
    "normalization": True,
}

# Evaluation metrics
EVALUATION_CONFIG = {
    "metrics": [
        "detection_accuracy",
        "false_positive_rate",
        "coverage_score",
        "query_validity",
        "correlation_relevance",
        "report_coherence",
    ],
    "validation_split": 0.2,
    "test_split": 0.1,
}

# Create directories on import
def create_directories():
    """Create all necessary directories for AI training"""
    directories = [
        DATASETS_DIR, HUNTING_QUERIES_DIR, CORRELATIONS_DIR,
        THREAT_INTEL_DIR, THREAT_REPORTS_DIR, BLOG_POSTS_DIR,
        CVE_DATA_DIR, OSINT_SAMPLES_DIR, MODELS_DIR, CHECKPOINTS_DIR,
        FINE_TUNED_DIR, ADAPTERS_DIR, PROMPTS_DIR, SYSTEM_PROMPTS_DIR,
        DETECTION_PROMPTS_DIR, CORRELATION_PROMPTS_DIR, REPORT_PROMPTS_DIR,
        PIPELINES_DIR, PREPROCESSING_DIR, TRAINING_DIR, INFERENCE_DIR,
        EVALUATION_DIR, BENCHMARKS_DIR, METRICS_DIR, VALIDATION_DIR,
        OUTPUT_DIR, GENERATED_DETECTIONS_DIR, GENERATED_CORRELATIONS_DIR,
        GENERATED_REPORTS_DIR, AI_DATA_DIR,
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

# Auto-create directories
create_directories()

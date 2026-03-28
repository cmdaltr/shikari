# LLM-Based Detection Generation

## Overview

Archer's LLM-based detection generation infrastructure enables training and deploying local Large Language Models (LLMs) to automatically generate high-fidelity detection rules, correlations, and threat reports. This system replaces the traditional heuristic regex-based detection generation with AI-powered generation trained on curated security datasets.

### Key Capabilities

- **Detection Generation**: Create platform-specific detection rules from MITRE ATT&CK techniques
- **Correlation Rules**: Generate multi-stage attack correlations and behavioral analytics
- **Threat Reports**: Produce comprehensive threat intelligence reports with executive summaries
- **Continuous Learning**: Improve detection quality through fine-tuning on curated datasets
- **Multi-Platform Support**: Generate detections for Splunk, Microsoft Defender, Elastic, Google Chronicle

### Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                   Archer LLM Detection Pipeline                   │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│   ┌──────────────┐      ┌──────────────┐      ┌───────────────┐   │
│   │   Training   │      │  Inference   │      │  Evaluation   │   │
│   │   Pipeline   │─────▶│   Pipeline   │─────▶│   Pipeline    │   │
│   └──────────────┘      └──────────────┘      └───────────────┘   │
│          │                     │                      │           │
│          │                     │                      │           │
│   ┌──────▼──────┐      ┌───────▼────────┐    ┌────────▼───────┐   │
│   │  Datasets   │      │  LLM Backends  │    │  Benchmarks    │   │
│   │             │      │                │    │                │   │
│   │ • Hunting   │      │ • Ollama       │    │ • Accuracy     │   │
│   │ • Threat    │      │ • vLLM         │    │ • Coverage     │   │
│   │ • CVEs      │      │ • llama.cpp    │    │ • Quality      │   │
│   │ • OSINT     │      │ • Transformers │    │ • Performance  │   │
│   └─────────────┘      └────────────────┘    └────────────────┘   │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Install Dependencies

```bash
# Core AI training dependencies
pip install transformers>=4.35.0
pip install datasets>=2.14.0
pip install peft>=0.7.0
pip install bitsandbytes>=0.41.0
pip install accelerate>=0.24.0
pip install torch>=2.1.0
pip install sentencepiece>=0.1.99
pip install tensorboard>=2.15.0
```

### 2. Set Up LLM Backend

#### Option A: Ollama (Recommended)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull recommended models
ollama pull llama3.1:70b-instruct-q4_K_M  # For detection generation
ollama pull llama3.1:70b-instruct-q4_K_M  # For correlation generation
ollama pull llama3.1:70b-instruct-q4_K_M  # For report generation

# Verify installation
ollama list
```

#### Option B: vLLM (For High-Performance)

```bash
# Install vLLM
pip install vllm

# Start vLLM server
python -m vllm.entrypoints.openai.api_server \
    --model meta-llama/Llama-3.1-70B-Instruct \
    --tensor-parallel-size 2 \
    --port 8000
```

### 3. Configure Backend

Edit `archer/ai/training/config.py`:

```python
MODEL_CONFIG = {
    "backends": {
        "ollama": {
            "enabled": True,
            "endpoint": "http://localhost:11434",
            "models": ["llama3.1:70b-instruct-q4_K_M"],
        }
    },
    "default_backend": "ollama",
}
```

### 4. Test Inference

```python
from archer.ai.training.pipelines.llm_inference import LLMInference

# Initialize inference client
llm = LLMInference(backend="ollama")

# Test detection generation
detection = llm.generate_detection(
    technique_id="T1003.001",
    technique_name="OS Credential Dumping: LSASS Memory",
    technique_description="Adversaries may attempt to access credential material stored in LSASS memory...",
    platforms=["Windows"],
)

print(detection)
```

## Directory Structure

```
archer/ai/training/
├── __init__.py                    # Module initialization
├── config.py                      # Configuration for backends and training
│
├── datasets/                      # Training data
│   ├── README.md                 # Dataset format documentation
│   ├── hunting_queries/          # High-fidelity hunting queries
│   ├── correlations/             # Multi-stage detection logic
│   ├── threat_intelligence/      # Threat intel documents
│   ├── threat_reports/           # Vendor threat reports
│   ├── blog_posts/               # Security research
│   ├── cve_data/                 # CVE data and exploits
│   └── osint_samples/            # Sigma, Elastic, Splunk rules
│
├── models/                        # Trained models
│   ├── checkpoints/              # Training checkpoints
│   ├── fine_tuned/               # Fine-tuned models
│   └── adapters/                 # LoRA adapters
│
├── prompts/                       # System prompts
│   ├── system/                   # System prompts for personas
│   │   ├── detection_engineer.txt
│   │   └── threat_analyst.txt
│   ├── detection/                # Detection generation prompts
│   ├── correlation/              # Correlation generation prompts
│   └── reports/                  # Report generation prompts
│
├── pipelines/                     # Core pipelines
│   ├── llm_inference.py          # LLM inference pipeline
│   ├── training.py               # Fine-tuning pipeline
│   ├── preprocessing/            # Data preprocessing
│   └── inference/                # Inference utilities
│
└── evaluation/                    # Model evaluation
    ├── benchmarks/               # Test sets
    ├── metrics/                  # Quality metrics
    └── validation/               # Validation logic
```

## Training Data Format

All training data must be in **JSONL format** (one JSON object per line).

### Detection Generation Format

```json
{
  "task": "detection_generation",
  "input": {
    "technique_id": "T1003.001",
    "technique_name": "OS Credential Dumping: LSASS Memory",
    "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS)...",
    "platforms": ["Windows"],
    "threat_intel": "Observed in APT29 campaigns. Common tools: Mimikatz, Procdump.",
    "related_cves": []
  },
  "output": {
    "detections": [
      {
        "platform": "splunk",
        "query": "index=windows_logs sourcetype=WinEventLog:Security EventCode=10 TargetImage=*lsass.exe* | where GrantedAccess IN (\"0x1010\", \"0x1410\") | stats count by SourceImage, TargetImage",
        "confidence": "high",
        "false_positive_rate": "low",
        "data_sources": ["Windows Security Logs", "Sysmon Event ID 10"]
      }
    ],
    "indicators": {
      "cmd": ["mimikatz", "procdump"],
      "sw": ["lsass.exe"],
      "evt": ["10", "4688"]
    }
  }
}
```

### Correlation Generation Format

```json
{
  "task": "correlation_generation",
  "input": {
    "techniques": [
      {"technique_id": "T1003.001", "technique_name": "LSASS Memory Dumping"},
      {"technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares"}
    ],
    "group": "APT29",
    "hypothesis": "Credential theft followed by lateral movement",
    "context": "Observed 10-30 minute window between LSASS access and lateral movement"
  },
  "output": {
    "correlation": {
      "name": "APT29 Credential Theft and Lateral Movement Chain",
      "description": "Detects credential dumping followed by lateral movement",
      "platform": "splunk",
      "query": "index=windows_logs (EventCode=10 TargetImage=*lsass.exe*) OR (EventCode=4624 LogonType=3) | transaction host maxspan=30m",
      "time_window": "30m",
      "confidence": "high"
    }
  }
}
```

### Report Generation Format

```json
{
  "task": "report_generation",
  "input": {
    "group": "Scattered Spider",
    "detections": [
      {"technique_id": "T1566.002", "platform": "splunk", "confidence": "high"}
    ],
    "correlations": [
      {"name": "Phishing to Cloud Access Chain", "stages": 3}
    ],
    "metrics": {
      "technique_coverage": 0.85,
      "avg_confidence": "high"
    }
  },
  "output": {
    "executive_summary": "Comprehensive detection coverage developed for Scattered Spider...",
    "technical_analysis": "Scattered Spider is a sophisticated threat actor...",
    "recommendations": ["Implement MFA", "Enable conditional access"]
  }
}
```

## Data Collection

### CVE Enrichment Pipeline

The CVE enrichment pipeline combines technical CVE data with real-world blog posts, security research, and exploit analyses to create comprehensive training examples for ITW (In-The-Wild) exploits and POCs (Proof-of-Concept).

#### How CVE Enrichment Works

1. **Fetch CVE Data**: Pull CVE information from NVD including description, CVSS score, affected products
2. **Search Related Content**: Find security blog posts, threat reports, and exploit analyses
3. **Extract Technical Indicators**: Parse commands, file paths, registry keys, network indicators
4. **Map to MITRE ATT&CK**: Identify relevant techniques based on CVE behavior
5. **Build Detection Context**: Create comprehensive context for LLM training

#### Enrich Specific CVEs

```bash
# Enrich specific CVEs with full context
python scripts/train_ai.py cve --cves CVE-2024-1234 CVE-2024-5678

# Output:
# ✓ Enriched CVE-2024-1234 → archer/ai/training/datasets/cve_data/enriched/CVE-2024-1234.json
# ✓ Generated training example → archer/ai/training/datasets/cve_data/training_examples/CVE-2024-1234_training.json
```

#### Enrich by Year and Severity

```bash
# Enrich high-severity CVEs from 2024
python scripts/train_ai.py cve --year 2024 --min-cvss 7.0 --limit 50

# Enrich only CVEs with known ITW exploitation
python scripts/train_ai.py cve --year 2024 --itw-only --min-cvss 8.0

# Enrich from file
python scripts/train_ai.py cve --file priority_cves.txt
```

#### Enrichment Sources

The pipeline searches multiple sources for technical analysis:

- **ExploitDB**: POC exploit code and descriptions
- **GitHub**: Public exploit repositories
- **Security Blogs**: Technical analysis from:
  - Google Project Zero
  - Microsoft Security Response Center (MSRC)
  - Recorded Future
  - Mandiant
  - CrowdStrike
  - Rapid7
  - Tenable
  - Qualys
- **Threat Reports**: Vendor reports mentioning the CVE
- **Local Cache**: Previously saved blog posts and research

#### Enriched CVE Structure

```json
{
  "cve_id": "CVE-2024-1234",
  "cve_data": {
    "description": "Buffer overflow in XYZ service allows remote code execution...",
    "cvss_score": 9.8,
    "affected_products": ["cpe:2.3:a:vendor:product:*"]
  },
  "related_content": {
    "exploits": [
      {
        "source": "exploitdb",
        "code": "import socket...",
        "description": "POC for CVE-2024-1234"
      }
    ],
    "blog_posts": [
      {
        "source": "project_zero",
        "url": "https://...",
        "content": "Technical analysis of the vulnerability..."
      }
    ]
  },
  "indicators": {
    "cmd": ["nc -e /bin/sh", "powershell -enc"],
    "file": ["C:\\Windows\\Temp\\exploit.exe"],
    "reg": ["HKLM\\Software\\..."],
    "net": ["192.168.1.1:4444"],
    "proc": ["svchost.exe"]
  },
  "attack_techniques": [
    {
      "technique_id": "T1210",
      "technique_name": "Exploitation of Remote Services",
      "tactic": "Lateral Movement",
      "confidence": "high"
    }
  ],
  "detection_context": {
    "severity": "critical",
    "exploit_available": true,
    "itw_exploitation": true,
    "technical_analysis": [...]
  }
}
```

#### Training Example Generation

The enriched CVE is converted to a training example:

```json
{
  "task": "detection_generation",
  "input": {
    "technique_id": "T1210",
    "technique_name": "Exploitation of Remote Services",
    "description": "CVE-2024-1234 - Buffer overflow...\n\nSeverity: CRITICAL (CVSS: 9.8)\n⚠️ PUBLIC EXPLOIT AVAILABLE\n⚠️ IN-THE-WILD EXPLOITATION OBSERVED\n\nSource: project_zero\nTechnical deep-dive into the memory corruption vulnerability...",
    "platforms": ["Windows"],
    "threat_intel": "Public exploit code available. Active in-the-wild exploitation observed.",
    "related_cves": ["CVE-2024-1234"]
  },
  "output": {
    "detections": [],
    "indicators": {
      "cmd": ["nc -e /bin/sh", "powershell -enc"],
      "file": ["C:\\Windows\\Temp\\exploit.exe"]
    },
    "metadata": {
      "cve_id": "CVE-2024-1234",
      "cvss_score": 9.8,
      "exploit_available": true,
      "itw_exploitation": true
    }
  }
}
```

### Convert Threat Reports

```bash
# Convert single PDF threat report to JSON
python scripts/train_ai.py reports --pdf threat_report.pdf

# Batch convert all PDFs in directory
python scripts/train_ai.py reports --dir archer/ai/training/datasets/threat_reports/

# Specify custom output directory
python scripts/train_ai.py reports --dir reports/ --output custom_output/
```

**Requirements**: `pip install pdfplumber`

### Extract OSINT Samples

```bash
# Extract Sigma rules
python scripts/train_ai.py osint --source sigma

# Extract Elastic detection rules
python scripts/train_ai.py osint --source elastic

# Extract Splunk security content
python scripts/train_ai.py osint --source splunk

# Extract from all sources
python scripts/train_ai.py osint --all

# Use custom repository
python scripts/train_ai.py osint --source sigma --repo https://github.com/custom/sigma-fork
```

**Requirements**: `pip install pyyaml toml`

## Fine-Tuning Pipeline

### Basic Fine-Tuning

```python
from archer.ai.training.pipelines.training import DetectionEngineeringTrainer

# Initialize trainer
trainer = DetectionEngineeringTrainer(
    base_model="meta-llama/Llama-3.1-70B-Instruct",
    use_lora=True,
    use_4bit=True,  # QLoRA for memory efficiency
)

# Load model with quantization
trainer.load_model()

# Load training datasets (auto-discovers all .jsonl files)
trainer.load_datasets(
    train_files=None,  # Auto-discover
    val_split=0.1,
)

# Start training
trainer.train(
    epochs=3,
    batch_size=4,
    learning_rate=2e-5,
    save_steps=500,
)
```

### Advanced Configuration

```python
from archer.ai.training.pipelines.training import DetectionEngineeringTrainer
from pathlib import Path

# Initialize with specific datasets
trainer = DetectionEngineeringTrainer(
    base_model="meta-llama/Llama-3.1-70B-Instruct",
    output_dir=Path("archer/ai/training/models/fine_tuned/llama3.1-detection-v1"),
    use_lora=True,
    use_4bit=True,
)

trainer.load_model()

# Specify exact training files
train_files = [
    Path("archer/ai/training/datasets/hunting_queries/internal_soc.jsonl"),
    Path("archer/ai/training/datasets/osint_samples/sigma_rules.jsonl"),
]

trainer.load_datasets(train_files=train_files)

# Train with custom parameters
trainer.train(
    epochs=5,
    batch_size=2,
    learning_rate=1e-5,
    warmup_steps=200,
)
```

## Inference Pipeline

### Detection Generation

```python
from archer.ai.training.pipelines.llm_inference import LLMInference

# Initialize with Ollama backend
llm = LLMInference(backend="ollama")

# Generate detection for a technique
detection = llm.generate_detection(
    technique_id="T1003.001",
    technique_name="OS Credential Dumping: LSASS Memory",
    technique_description="Adversaries may attempt to access credential material stored in LSASS memory...",
    platforms=["Windows"],
    threat_intel={
        "groups": ["APT29", "APT28"],
        "tools": ["Mimikatz", "Procdump"],
    },
)

print(detection["detections"][0]["query"])
```

### Correlation Generation

```python
# Generate multi-stage correlation
correlation = llm.generate_correlation(
    techniques=[
        {"technique_id": "T1003.001", "technique_name": "LSASS Memory Dumping"},
        {"technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares"},
    ],
    group_name="APT29",
    hypothesis="Credential theft followed by lateral movement",
    context="10-30 minute window observed",
)

print(correlation["correlation"]["query"])
```

### Report Generation

```python
# Generate comprehensive threat report
report = llm.generate_report(
    group_name="Scattered Spider",
    detections=[...],
    correlations=[...],
    metrics={"technique_coverage": 0.85},
)

print(report["executive_summary"])
```

## LLM Backend Configuration

### Ollama Backend

**Recommended for**: Easy setup, good performance

```python
MODEL_CONFIG = {
    "backends": {
        "ollama": {
            "enabled": True,
            "endpoint": "http://localhost:11434",
            "models": ["llama3.1:70b-instruct-q4_K_M"],
        }
    },
}
```

**Pros**:
- Easy installation
- Automatic model management
- Low memory with quantization
- Good performance

**Cons**:
- Single model per instance
- Slower for batch processing

### vLLM Backend

**Recommended for**: High-throughput production

```python
MODEL_CONFIG = {
    "backends": {
        "vllm": {
            "enabled": True,
            "endpoint": "http://localhost:8000",
            "model": "meta-llama/Llama-3.1-70B-Instruct",
            "tensor_parallel_size": 2,
        }
    },
}
```

**Pros**:
- Fastest inference
- Efficient batching
- Multi-GPU support

**Cons**:
- Complex setup
- Higher GPU memory

### llama.cpp Backend

**Recommended for**: CPU-only systems

```python
MODEL_CONFIG = {
    "backends": {
        "llama_cpp": {
            "enabled": True,
            "endpoint": "http://localhost:8080",
            "model_path": "/path/to/model.gguf",
            "n_gpu_layers": 0,
        }
    },
}
```

**Pros**:
- Runs on CPU
- Very low memory
- Portable

**Cons**:
- Slower inference
- GGUF format only

## Recommended Models

### Detection Generation

| Model | Size | Hardware | Quality | Speed |
|-------|------|----------|---------|-------|
| Llama 3.1 70B Instruct (Q4) | 40GB | 1x A100 80GB | Excellent | Medium |
| Llama 3.1 8B Instruct (Q4) | 5GB | 1x RTX 4090 | Good | Fast |
| Mistral 7B Instruct (Q5) | 5GB | 1x RTX 3090 | Good | Fast |
| Qwen2.5 72B Instruct (Q4) | 42GB | 1x A100 80GB | Excellent | Medium |

### Correlation Generation

| Model | Size | Hardware | Quality | Speed |
|-------|------|----------|---------|-------|
| Llama 3.1 70B Instruct (Q4) | 40GB | 1x A100 80GB | Excellent | Medium |
| Qwen2.5 72B Instruct (Q4) | 42GB | 1x A100 80GB | Excellent | Medium |
| Mixtral 8x7B Instruct (Q4) | 26GB | 1x A100 40GB | Very Good | Fast |

## Integration with Archer

The LLM pipeline integrates with Archer's existing workflow:

```python
# In archer/core/orchestrator.py

from archer.ai.training.pipelines.llm_inference import LLMInference

class OrchestrationManager:
    def __init__(self, use_ai=False):
        self.use_ai = use_ai
        if use_ai:
            self.llm = LLMInference(backend="ollama")

    def generate_detections(self, technique_data):
        if self.use_ai:
            # AI-powered generation
            return self.llm.generate_detection(
                technique_id=technique_data["id"],
                technique_name=technique_data["name"],
                technique_description=technique_data["description"],
                platforms=technique_data["platforms"],
            )
        else:
            # Traditional regex-based generation
            return self._regex_based_detection(technique_data)
```

## Command-Line Interface

```bash
# Generate detections using AI
python -m archer.cli generate \
    --technique T1003.001 \
    --use-ai \
    --backend ollama \
    --output detections/

# Generate correlations
python -m archer.cli correlate \
    --group APT29 \
    --techniques T1003.001,T1021.002,T1078.003 \
    --use-ai \
    --output correlations/

# Generate report
python -m archer.cli report \
    --group "Scattered Spider" \
    --detections detections/ \
    --use-ai \
    --output reports/
```

## Data Privacy and Security

### Training Data Guidelines

⚠️ **CRITICAL**: Never include sensitive data in training datasets

- **Sanitize all examples**: Remove customer data, internal IPs, credentials
- **Anonymize organizations**: Replace real company names
- **Remove PII**: Strip names, emails, phone numbers
- **Review queries**: Ensure no information disclosure
- **Validate sources**: Only use publicly available or approved data

### Model Security

- **Local deployment**: All models run locally
- **Data retention**: Training data never leaves infrastructure
- **Access control**: Restrict model endpoint access
- **Audit logging**: Log all inference requests
- **Model versioning**: Track versions and provenance

## Troubleshooting

### Out of Memory During Training

```
RuntimeError: CUDA out of memory
```

**Solutions**:
1. Reduce batch size: `batch_size=1`
2. Use 4-bit quantization: `use_4bit=True`
3. Reduce sequence length: `max_seq_length=2048`
4. Increase gradient accumulation: `gradient_accumulation_steps=8`

### Ollama Connection Refused

```
requests.exceptions.ConnectionError
```

**Solutions**:
1. Check Ollama: `ollama list`
2. Verify endpoint: `curl http://localhost:11434/api/tags`
3. Restart: `systemctl restart ollama`

### Poor Detection Quality

**Solutions**:
1. Increase epochs: `epochs=5`
2. Add more training data
3. Use larger model (70B instead of 7B)
4. Lower temperature: `temperature=0.3`
5. Fine-tune with curated examples

## Performance Benchmarks

### Inference Speed

| Backend | Model | Hardware | Tokens/sec | Latency |
|---------|-------|----------|------------|---------|
| Ollama | Llama 3.1 70B Q4 | A100 80GB | 35 | ~15s |
| vLLM | Llama 3.1 70B | A100 80GB | 120 | ~5s |
| llama.cpp | Llama 3.1 8B Q4 | CPU 32 cores | 25 | ~20s |

### Training Time

| Dataset | Model | Hardware | Epochs | Time |
|---------|-------|----------|--------|------|
| 10k examples | Llama 3.1 70B | A100 80GB | 3 | ~6h |
| 10k examples | Llama 3.1 8B | RTX 4090 | 3 | ~2h |
| 50k examples | Llama 3.1 70B | A100 80GB | 5 | ~30h |

## Comparison: LLM vs Heuristic Generation

### LLM-Based Generation

**Advantages**:
- Higher detection quality
- Learns from real-world examples
- Adapts to new threats
- Context-aware generation
- Platform-specific optimization

**Disadvantages**:
- Requires GPU for training
- Initial dataset collection effort
- Model deployment complexity
- Higher inference cost

### Heuristic-Based Generation

**Advantages**:
- Fast and deterministic
- No GPU required
- Simple deployment
- Low resource usage

**Disadvantages**:
- Fixed patterns
- Limited context awareness
- Manual rule updates
- Generic output

## Roadmap

### Planned Features

- [ ] Active learning for low-confidence detections
- [ ] Multi-model ensemble
- [ ] Synthetic data generation
- [ ] Continuous fine-tuning
- [ ] Model distillation
- [ ] Feedback loop from SOC analysts
- [ ] Cross-platform optimization
- [ ] Adversarial testing

## References

### Documentation

- [Transformers Training Guide](https://huggingface.co/docs/transformers/training)
- [LoRA Fine-Tuning](https://huggingface.co/docs/peft/conceptual_guides/lora)
- [Ollama Documentation](https://github.com/ollama/ollama/blob/main/docs/README.md)
- [vLLM Documentation](https://docs.vllm.ai/en/latest/)

### Research Papers

- "LoRA: Low-Rank Adaptation of Large Language Models" (Hu et al., 2021)
- "QLoRA: Efficient Finetuning of Quantized LLMs" (Dettmers et al., 2023)

### MITRE Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/)

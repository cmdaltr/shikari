"""
LLM Fine-Tuning Pipeline

Provides infrastructure for fine-tuning local LLMs on detection engineering tasks.
"""

import json
import torch
from pathlib import Path
from typing import Dict, List, Optional
from datasets import load_dataset, Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling,
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training,
    TaskType,
)

from ..config import MODEL_CONFIG, DATASETS_DIR, CHECKPOINTS_DIR, FINE_TUNED_DIR


class DetectionEngineeringTrainer:
    """
    Fine-tune LLMs for detection engineering tasks using LoRA/QLoRA.
    """

    def __init__(
        self,
        base_model: str,
        output_dir: Optional[Path] = None,
        use_lora: bool = True,
        use_4bit: bool = False,
        use_8bit: bool = True,
    ):
        """
        Initialize trainer.

        Args:
            base_model: Base model name or path (e.g., "meta-llama/Llama-2-70b-hf")
            output_dir: Output directory for checkpoints
            use_lora: Use LoRA for parameter-efficient fine-tuning
            use_4bit: Use 4-bit quantization (QLoRA)
            use_8bit: Use 8-bit quantization
        """
        self.base_model = base_model
        self.output_dir = output_dir or FINE_TUNED_DIR / base_model.split("/")[-1]
        self.use_lora = use_lora
        self.use_4bit = use_4bit
        self.use_8bit = use_8bit

        self.tokenizer = None
        self.model = None
        self.train_dataset = None
        self.eval_dataset = None

    def load_model(self):
        """Load base model with quantization if specified"""
        print(f"Loading model: {self.base_model}")

        # Load tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.base_model,
            trust_remote_code=True,
        )
        self.tokenizer.pad_token = self.tokenizer.eos_token
        self.tokenizer.padding_side = "right"

        # Quantization config
        quantization_config = None
        if self.use_4bit:
            from transformers import BitsAndBytesConfig
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.bfloat16,
                bnb_4bit_use_double_quant=True,
            )
        elif self.use_8bit:
            quantization_config = {"load_in_8bit": True}

        # Load model
        self.model = AutoModelForCausalLM.from_pretrained(
            self.base_model,
            quantization_config=quantization_config,
            device_map="auto",
            trust_remote_code=True,
        )

        # Prepare for training
        if self.use_4bit or self.use_8bit:
            self.model = prepare_model_for_kbit_training(self.model)

        # Apply LoRA
        if self.use_lora:
            lora_config = LoraConfig(
                task_type=TaskType.CAUSAL_LM,
                r=MODEL_CONFIG["training"]["lora_r"],
                lora_alpha=MODEL_CONFIG["training"]["lora_alpha"],
                lora_dropout=MODEL_CONFIG["training"]["lora_dropout"],
                target_modules=MODEL_CONFIG["training"]["target_modules"],
                bias="none",
            )
            self.model = get_peft_model(self.model, lora_config)
            self.model.print_trainable_parameters()

        print("Model loaded successfully")

    def load_datasets(
        self,
        train_files: Optional[List[Path]] = None,
        eval_files: Optional[List[Path]] = None,
        val_split: float = 0.1,
    ):
        """
        Load and preprocess training datasets.

        Args:
            train_files: List of training data files (JSONL)
            eval_files: List of evaluation data files (JSONL)
            val_split: Validation split ratio if eval_files not provided
        """
        print("Loading datasets...")

        if train_files is None:
            # Auto-discover training files
            train_files = list(DATASETS_DIR.rglob("*.jsonl"))

        if not train_files:
            raise ValueError("No training files found")

        # Load datasets
        data_files = {"train": [str(f) for f in train_files]}
        if eval_files:
            data_files["eval"] = [str(f) for f in eval_files]

        dataset = load_dataset("json", data_files=data_files)

        # Split if no eval set
        if "eval" not in dataset:
            dataset = dataset["train"].train_test_split(test_size=val_split)

        # Preprocess
        self.train_dataset = dataset["train"].map(
            self._preprocess_function,
            batched=True,
            remove_columns=dataset["train"].column_names,
        )

        eval_key = "eval" if "eval" in dataset else "test"
        self.eval_dataset = dataset[eval_key].map(
            self._preprocess_function,
            batched=True,
            remove_columns=dataset[eval_key].column_names,
        )

        print(f"Loaded {len(self.train_dataset)} training examples")
        print(f"Loaded {len(self.eval_dataset)} evaluation examples")

    def _preprocess_function(self, examples):
        """Preprocess examples for training"""
        # Format examples into instruction-response pairs
        formatted_examples = []

        for i in range(len(examples["task"])):
            task = examples["task"][i]
            input_data = examples["input"][i]
            output_data = examples["output"][i]

            # Build prompt based on task type
            if task == "detection_generation":
                prompt = self._format_detection_prompt(input_data)
                response = self._format_detection_response(output_data)
            elif task == "correlation_generation":
                prompt = self._format_correlation_prompt(input_data)
                response = self._format_correlation_response(output_data)
            elif task == "report_generation":
                prompt = self._format_report_prompt(input_data)
                response = self._format_report_response(output_data)
            else:
                continue

            # Combine into training format
            formatted = f"<|user|>\n{prompt}\n<|assistant|>\n{response}<|endoftext|>"
            formatted_examples.append(formatted)

        # Tokenize
        tokenized = self.tokenizer(
            formatted_examples,
            truncation=True,
            max_length=MODEL_CONFIG["training"]["max_seq_length"],
            padding="max_length",
        )

        return tokenized

    def train(
        self,
        epochs: int = 3,
        batch_size: int = 4,
        learning_rate: float = 2e-5,
        warmup_steps: int = 100,
        save_steps: int = 500,
        logging_steps: int = 10,
    ):
        """
        Fine-tune the model.

        Args:
            epochs: Number of training epochs
            batch_size: Training batch size
            learning_rate: Learning rate
            warmup_steps: Warmup steps
            save_steps: Save checkpoint every N steps
            logging_steps: Log metrics every N steps
        """
        if self.model is None:
            raise ValueError("Model not loaded. Call load_model() first.")

        if self.train_dataset is None:
            raise ValueError("Datasets not loaded. Call load_datasets() first.")

        print("Starting training...")

        # Training arguments
        training_args = TrainingArguments(
            output_dir=str(self.output_dir),
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            gradient_accumulation_steps=MODEL_CONFIG["training"]["gradient_accumulation_steps"],
            learning_rate=learning_rate,
            warmup_steps=warmup_steps,
            logging_steps=logging_steps,
            save_steps=save_steps,
            eval_steps=save_steps,
            save_total_limit=3,
            load_best_model_at_end=True,
            report_to="tensorboard",
            fp16=torch.cuda.is_available(),
            gradient_checkpointing=True,
            optim="paged_adamw_32bit" if self.use_4bit else "adamw_torch",
        )

        # Data collator
        data_collator = DataCollatorForLanguageModeling(
            tokenizer=self.tokenizer,
            mlm=False,
        )

        # Trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=self.train_dataset,
            eval_dataset=self.eval_dataset,
            data_collator=data_collator,
        )

        # Train
        trainer.train()

        # Save final model
        trainer.save_model(str(self.output_dir / "final"))
        self.tokenizer.save_pretrained(str(self.output_dir / "final"))

        print(f"Training complete. Model saved to: {self.output_dir}")

    def _format_detection_prompt(self, input_data: Dict) -> str:
        """Format detection generation prompt"""
        return f"""Generate detection rules for the following MITRE ATT&CK technique:

Technique ID: {input_data['technique_id']}
Technique Name: {input_data['technique_name']}
Description: {input_data['description']}
Platforms: {', '.join(input_data['platforms'])}

Generate detection queries for: Splunk, Microsoft Defender, Elastic, Google Chronicle

Include:
- High-fidelity detection logic
- Required data sources
- False positive considerations
- Performance optimizations"""

    def _format_detection_response(self, output_data: Dict) -> str:
        """Format detection generation response"""
        return json.dumps(output_data, indent=2)

    def _format_correlation_prompt(self, input_data: Dict) -> str:
        """Format correlation generation prompt"""
        techniques = "\n".join([
            f"- {t['technique_id']}: {t['technique_name']}"
            for t in input_data['techniques']
        ])

        return f"""Generate correlation rules for the following attack scenario:

Threat Group: {input_data['group']}
Hypothesis: {input_data['hypothesis']}

Techniques:
{techniques}

Generate multi-stage detection correlations with time windows and logic."""

    def _format_correlation_response(self, output_data: Dict) -> str:
        """Format correlation generation response"""
        return json.dumps(output_data, indent=2)

    def _format_report_prompt(self, input_data: Dict) -> str:
        """Format report generation prompt"""
        return f"""Generate a comprehensive threat detection report:

Threat Group: {input_data['group']}
Detections Generated: {len(input_data['detections'])}
Correlations Generated: {len(input_data['correlations'])}

Include:
- Executive summary
- Technical analysis
- Coverage assessment
- Recommendations"""

    def _format_report_response(self, output_data: Dict) -> str:
        """Format report generation response"""
        return json.dumps(output_data, indent=2)

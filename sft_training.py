import os
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"
import json
import torch
from datasets import load_dataset
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import LoraConfig, get_peft_model
from trl import SFTConfig, SFTTrainer

# Basic parameters
model_name = "/data/upftfg31/fxarrie/devstral-small-2507"
max_seq_length = 4096

# Held-out test groups (same for SFT and GRPO; defined once here, mirrored in training.py)
TEST_GROUP_IDS = {"cve-2016-0736", "prestashop-CVE4"}

# 1. Load tokenizer and base model
tokenizer = AutoTokenizer.from_pretrained(model_name)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForCausalLM.from_pretrained(
    model_name,
    dtype=torch.bfloat16,
    device_map="auto",
)
model.gradient_checkpointing_enable()
model.enable_input_require_grads()

# 2. Apply LoRA via PEFT (config identical to training.py so adapters are interoperable)
lora_config = LoraConfig(
    r=16,
    lora_alpha=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.0,
    bias="none",
    task_type="CAUSAL_LM",
)
model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# 3. Helpers for SFT target resolution and completion construction

def get_sft_target_path(entry):
    """Resolve the SFT target file for an entry by (group_id, verdict).
    Tries paired pattern first (e.g. 'cve-2010-2057-vuln.py'), falls back to
    standalone (e.g. 'cryptopals-17.py')."""
    gid = entry["group_id"]
    verdict = entry["test_case_outputs"]["verdict"]
    suffix = "vuln" if verdict == "VULNERABLE" else "safe"
    ext = "py" if verdict == "VULNERABLE" else "txt"
    for candidate in [
        f"data/sft_targets/{gid}-{suffix}.{ext}",
        f"data/sft_targets/{gid}.{ext}",
    ]:
        if os.path.exists(candidate):
            return candidate
    raise FileNotFoundError(
        f"No SFT target for group_id={gid}, verdict={verdict}"
    )


def build_completion(entry):
    """Construct the supervised target the model must learn to predict.

    For VULNERABLE entries: 'VULNERABLE.\\n\\n```python\\n<exploit>\\n```'
      - The verdict preamble teaches the model to announce its judgment first,
        matching what the GRPO reward function's regex expects.
      - The fenced code block matches the format the dataset prompts ask for.

    For NOT_VULNERABLE entries: the safe.txt file is used as-is, since these
      files already contain a verdict announcement and reasoning about the
      structural fix (HMAC, AEAD, etc.).
    """
    target_path = get_sft_target_path(entry)
    with open(target_path) as f:
        target_content = f.read().rstrip("\n")
    if entry["test_case_outputs"]["verdict"] == "VULNERABLE":
        return f"VULNERABLE.\n\n```python\n{target_content}\n```"
    return target_content


# 4. Load dataset, filter to train split, format as prompt+completion pairs
raw_dataset = load_dataset("json", data_files="dataset.json", split="train")

train_dataset = raw_dataset.filter(lambda e: e["group_id"] not in TEST_GROUP_IDS)
print(f"Dataset: {len(raw_dataset)} total, {len(train_dataset)} in train split "
      f"(test groups held out: {sorted(TEST_GROUP_IDS)})")


def to_sft_pair(example):
    """Wrap the raw prompt in Devstral's chat template and attach the
    constructed completion. SFTTrainer auto-detects {prompt, completion}
    columns and masks the prompt tokens from the loss."""
    return {
        "prompt": tokenizer.apply_chat_template(
            [{"role": "user", "content": example["prompt"]}],
            tokenize=False,
            add_generation_prompt=True,
        ),
        "completion": build_completion(example),
    }


# Drop the original columns so only {prompt, completion} remain — SFTTrainer
# is strict about column names when in prompt+completion mode.
train_dataset = train_dataset.map(
    to_sft_pair,
    remove_columns=raw_dataset.column_names,
)

# 5. Configure SFT training
# Smoke-test values: max_steps=2 confirms the machinery runs end-to-end.
# For real training, comment out max_steps and uncomment num_train_epochs.
sft_config = SFTConfig(
    output_dir="outputs_sft",
    max_steps=2,                       # SMOKE TEST. For real training: use num_train_epochs=3 below
    # num_train_epochs=3,
    per_device_train_batch_size=1,
    gradient_accumulation_steps=4,
    learning_rate=2e-4,                # standard LoRA SFT rate (QLoRA paper, HF defaults)
    bf16=True,
    logging_steps=1,
    report_to="none",
    warmup_ratio=0.1,
    max_length=max_seq_length,
    save_strategy="no",                # smoke test: don't save intermediate checkpoints
)

# 6. Initialize trainer
trainer = SFTTrainer(
    model=model,
    args=sft_config,
    train_dataset=train_dataset,
    processing_class=tokenizer,
)

# 7. Train
print("Starting SFT training...")
trainer.train()

# 8. Save resulting LoRA adapter
model.save_pretrained("devstral-sft-lora")
tokenizer.save_pretrained("devstral-sft-lora")
print("SFT training complete and saved to devstral-sft-lora/")

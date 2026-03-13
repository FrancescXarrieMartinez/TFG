import os
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"
import re
import json
import tempfile
import subprocess
import torch
from datasets import load_dataset
from unsloth import FastLanguageModel, PatchFastRL
from trl import GRPOConfig, GRPOTrainer

# 1. Patch Unsloth to optimize RL (required for TRL)
PatchFastRL("GRPO", FastLanguageModel)

# Basic parameters
model_name = "./devstral-small-2" # Change this to the real path
max_seq_length = 4096  # Increased to accommodate long code-embedding prompts

# 2. Load the base model and Tokenizer with Unsloth
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=model_name,
    max_seq_length=max_seq_length,
    dtype=torch.bfloat16, # Key for H100s!
    load_in_4bit=True,    # 4-bit quantization to save VRAM (optional but recommended)
)

# 3. Apply LoRA with Unsloth (integrated PEFT)
model = FastLanguageModel.get_peft_model(
    model,
    r=16, # LoRA rank
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_alpha=16,
    lora_dropout=0, # Unsloth recommends 0 for higher speed
    bias="none",
    use_gradient_checkpointing="unsloth", # Saves a lot of memory
)

# 4. Prepare your Dataset
# The dataset must have a 'prompt' column. The model will generate the response.
dataset = load_dataset("json", data_files="dataset.json", split="train")

# 5. Define your Reward function (Verifiable / RLVR)
# TRL passes 'prompts', 'completions', and the remaining JSON columns as kwargs.

def _extract_python_code(text):
    """Return the first ```python ... ``` block in text, or None."""
    match = re.search(r'```python\s*\n(.*?)```', text, re.DOTALL)
    return match.group(1).strip() if match else None

def _states_vulnerable(text):
    """True if text explicitly claims VULNERABLE (and not NOT VULNERABLE)."""
    lower = text.lower()
    if re.search(r'\bnot\s+vulnerable\b', lower):
        return False
    return bool(re.search(r'\bvulnerable\b', lower))

_NOT_VULN_REASONING_KEYWORDS = {"hmac", "mac", "authenticate", "integrity", "tamper"}

def _score_not_vulnerable(text):
    """
    Full credit (1.0) for correct verdict + MAC/HMAC reasoning.
    Partial credit (0.5) for correct verdict without detailed reasoning.
    """
    lower = text.lower()
    if not re.search(r'\bnot\s+vulnerable\b', lower):
        return 0.0
    keyword_hits = sum(1 for kw in _NOT_VULN_REASONING_KEYWORDS if kw in lower)
    return 1.0 if keyword_hits >= 2 else 0.5

def verifiable_reward_function(prompts, completions, test_case_inputs, test_case_outputs, **kwargs):
    rewards = []

    for i in range(len(completions)):
        completion    = completions[i]
        generated_text = completion[0]['content'] if isinstance(completion, list) else completion

        inputs  = test_case_inputs[i]
        outputs = test_case_outputs[i]

        php_bin     = inputs["php_bin"]
        oracle_path = inputs["oracle_path"]
        key         = inputs["key"]
        plaintext   = inputs["plaintext"]
        verdict     = outputs["verdict"]

        # --- NOT VULNERABLE: reward based on correct identification + reasoning ---
        if verdict == "NOT_VULNERABLE":
            rewards.append(_score_not_vulnerable(generated_text))
            continue

        # --- VULNERABLE: require correct verdict, then verify the exploit runs ---
        if not _states_vulnerable(generated_text):
            rewards.append(0.0)
            continue

        # Partial credit for correctly identifying the vulnerability
        score = 0.2

        exploit_code = _extract_python_code(generated_text)
        if exploit_code:
            tmp_path = None
            try:
                # Step 1: Encrypt the known plaintext to obtain a test ciphertext
                enc = subprocess.run(
                    [php_bin, oracle_path, "encrypt", plaintext, key],
                    capture_output=True, text=True, timeout=10,
                )
                ciphertext = json.loads(enc.stdout)["ciphertext"]

                # Step 2: Write the exploit to a temp file
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".py", delete=False, dir="/tmp"
                ) as f:
                    f.write(exploit_code)
                    tmp_path = f.name

                # Step 3: Run the exploit — expect it to print the plaintext to stdout
                # Generous timeout: a single-block CBC padding oracle needs ~4096 queries
                result = subprocess.run(
                    ["python3", tmp_path, oracle_path, key, ciphertext],
                    capture_output=True, text=True, timeout=300,
                )

                if plaintext in result.stdout.strip():
                    score = 1.0

            except (subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, OSError):
                pass  # Keep partial credit; exploit present but failed/timed out
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    os.unlink(tmp_path)

        rewards.append(score)

    return rewards

# 6. Configure RL training (GRPO)
training_args = GRPOConfig(
    output_dir="outputs_rlvr",
    learning_rate=5e-6,           # Typically lower in RL than in SFT
    per_device_train_batch_size=1, # Start at 1. Adjust based on available VRAM.
    gradient_accumulation_steps=4,
    max_prompt_length=4096,    # Prompts embed full PHP source code
    max_completion_length=2048, # Enough for analysis + exploit code
    num_generations=4,            # How many responses to generate per prompt for comparison
    bf16=True,                    # Key for H100
    logging_steps=10,
    max_steps=500,                # Adjust based on your dataset
)

# 7. Initialize the TRL Trainer
trainer = GRPOTrainer(
    model=model,
    processing_class=tokenizer,
    reward_funcs=[verifiable_reward_function], # Pass your function here
    args=training_args,
    train_dataset=dataset,
)

# 8. Start training!
print("Starting RLVR training...")
trainer.train()

# 9. Save the resulting LoRA weights
model.save_pretrained("devstral-rlvr-lora")
tokenizer.save_pretrained("devstral-rlvr-lora")
print("Training complete and saved!")

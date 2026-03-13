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

# ── Static helpers ─────────────────────────────────────────────────────────────

def _extract_python_code(text):
    """Return the first ```python … ``` block, or None."""
    m = re.search(r'```python\s*\n(.*?)```', text, re.DOTALL)
    return m.group(1).strip() if m else None

def _states_vulnerable(text):
    """True iff the text asserts VULNERABLE (not overridden by NOT VULNERABLE)."""
    lower = text.lower()
    if re.search(r'\bnot\s+vulnerable\b', lower):
        return False
    return bool(re.search(r'\bvulnerable\b', lower))

def _check_syntax(code):
    """True if the code has no SyntaxError."""
    try:
        compile(code, '<string>', 'exec')
        return True
    except SyntaxError:
        return False

_ORACLE_API_SIGNALS = [
    r'plaintext_b64',              # reads the key oracle response field
    r'\bsys\.argv\b|\bargparse\b', # accepts CLI arguments
    r'[\^]|\bxor\b',               # XOR for byte manipulation
    r'\brange\(256\)',             # brute-force loop over all byte values
]

def _check_oracle_api(code):
    """True if ≥3 of the oracle-API signals are present (static analysis)."""
    hits = sum(1 for p in _ORACLE_API_SIGNALS if re.search(p, code))
    return hits >= 3

_NOT_VULN_KEYWORDS = {"hmac", "mac", "authenticate", "integrity", "tamper"}

def _score_not_vulnerable(text):
    """
    1.0 — correct verdict + ≥2 MAC/HMAC reasoning keywords
    0.5 — correct verdict only
    0.0 — claims vulnerable
    """
    lower = text.lower()
    if not re.search(r'\bnot\s+vulnerable\b', lower):
        return 0.0
    hits = sum(1 for kw in _NOT_VULN_KEYWORDS if kw in lower)
    return 1.0 if hits >= 2 else 0.5

# ── Log analysis helpers ───────────────────────────────────────────────────────

def _count_log_calls(log_path):
    """Number of oracle calls recorded in the log."""
    try:
        with open(log_path) as f:
            return sum(1 for line in f if line.strip())
    except FileNotFoundError:
        return 0

def _log_has_valid_padding(log_path):
    """True if at least one oracle call returned valid padding (response-based oracles)."""
    try:
        with open(log_path) as f:
            return any(json.loads(line).get('valid') for line in f if line.strip())
    except (FileNotFoundError, json.JSONDecodeError):
        return False

# ── Main reward function ───────────────────────────────────────────────────────

def verifiable_reward_function(prompts, completions, test_case_inputs, test_case_outputs, **kwargs):
    """
    Reward shaping — cumulative tiers for VULNERABLE prompts:

      0.0  Wrong verdict, no code, or SyntaxError.
      0.1  Code has no SyntaxError.
      0.2  Static: ≥3 oracle-API signals (plaintext_b64, sys.argv, XOR, range(256)).
             OR dynamic fallback: exploit triggers ≥200 oracle calls.
      0.5  Dynamic: exploit issues ≥256 oracle calls AND at least one valid-padding
             response is observed in the log (response-based oracles only).
      1.0  Exploit prints the full known plaintext to stdout.

    The exploit is invoked as: <exploit> <oracle_path> <key> <ciphertext>
    The oracle receives ORACLE_LOG in its environment and is responsible for
    appending one JSON log line per call (fields: "valid", "elapsed_ms").

    NOT_VULNERABLE prompts:
      0.0  Claims vulnerable.
      0.5  Correct verdict, no reasoning.
      1.0  Correct verdict + cites MAC/HMAC as the protection mechanism.
    """
    rewards = []

    for i in range(len(completions)):
        completion     = completions[i]
        generated_text = completion[0]['content'] if isinstance(completion, list) else completion

        inputs  = test_case_inputs[i]
        outputs = test_case_outputs[i]

        php_bin     = inputs["php_bin"]
        oracle_path = inputs["oracle_path"]
        key         = inputs["key"]
        plaintext   = inputs["plaintext"]
        verdict     = outputs["verdict"]

        # ── NOT VULNERABLE branch ──────────────────────────────────────────────
        if verdict == "NOT_VULNERABLE":
            rewards.append(_score_not_vulnerable(generated_text))
            continue

        # ── VULNERABLE branch ──────────────────────────────────────────────────
        if not _states_vulnerable(generated_text):
            rewards.append(0.0)
            continue

        exploit_code = _extract_python_code(generated_text)
        if not exploit_code:
            rewards.append(0.0)
            continue

        # Level 1 (+0.1): syntax check
        if not _check_syntax(exploit_code):
            rewards.append(0.0)
            continue
        score = 0.1

        # Level 2 (+0.2): oracle API understanding (static)
        if _check_oracle_api(exploit_code):
            score = 0.2

        # Dynamic levels — run exploit directly against the real oracle
        tmp_exploit = tmp_log = None
        try:
            # Obtain a structurally valid ciphertext from the real oracle
            enc = subprocess.run(
                [php_bin, oracle_path, "encrypt", plaintext, key],
                capture_output=True, text=True, timeout=10,
            )
            ciphertext = json.loads(enc.stdout)["ciphertext"]

            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, dir='/tmp') as f:
                f.write(exploit_code)
                tmp_exploit = f.name

            tmp_log = tempfile.mktemp(suffix='_oracle.log', dir='/tmp')

            # Invoke: python3 <exploit> <oracle_path> <key> <ciphertext>
            # The oracle reads ORACLE_LOG from its environment and logs there.
            run_stdout = ''
            try:
                r = subprocess.run(
                    ['python3', tmp_exploit, oracle_path, key, ciphertext],
                    env={**os.environ, 'ORACLE_LOG': tmp_log},
                    capture_output=True, text=True, timeout=180,
                )
                run_stdout = r.stdout
            except subprocess.TimeoutExpired as exc:
                run_stdout = (exc.stdout or b'').decode(errors='replace') if isinstance(exc.stdout, bytes) else (exc.stdout or '')

            total_calls = _count_log_calls(tmp_log)
            found_valid = _log_has_valid_padding(tmp_log)

            if plaintext in run_stdout.strip():
                score = 1.0                          # Full plaintext recovered
            elif total_calls >= 256 and found_valid:
                score = max(score, 0.5)              # ≥1 byte correctly recovered
            elif total_calls >= 200:
                score = max(score, 0.2)              # Making oracle calls (dynamic fallback)

        except (json.JSONDecodeError, KeyError, OSError, subprocess.TimeoutExpired):
            pass  # Keep whatever partial score was reached
        finally:
            for path in [tmp_exploit, tmp_log]:
                if path and os.path.exists(path):
                    os.unlink(path)

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

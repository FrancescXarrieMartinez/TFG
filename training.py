import os
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"
import re
import json
import tempfile
import subprocess
import torch
from datasets import load_dataset
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import LoraConfig, get_peft_model, PeftModel
from trl import GRPOConfig, GRPOTrainer

model_name = "/data/upftfg31/fxarrie/devstral-small-2507"

# Held-out test groups (mirrored from sft_training.py so SFT and GRPO see the same train set)
TEST_GROUP_IDS = {"cve-2016-0736", "prestashop-CVE4"}

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

lora_config = LoraConfig(
    r=16,
    lora_alpha=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.0,
    bias="none",
    task_type="CAUSAL_LM",
)
sft_adapter_path = os.environ.get("SFT_ADAPTER_PATH", None)
if sft_adapter_path:
    # Config D: SFT then GRPO — start GRPO from the SFT'd LoRA adapter
    print(f"Loading SFT adapter from {sft_adapter_path} (Config D: SFT then GRPO)")
    model = PeftModel.from_pretrained(model, sft_adapter_path, is_trainable=True)
else:
    # Config C: GRPO only — apply fresh LoRA on top of base model
    print("No SFT_ADAPTER_PATH set; using fresh LoRA (Config C: GRPO only)")
    model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

dataset = load_dataset("json", data_files="dataset.json", split="train")
dataset = dataset.filter(lambda e: e["group_id"] not in TEST_GROUP_IDS)
print(f"Dataset: filtered to {len(dataset)} train entries (held out: {sorted(TEST_GROUP_IDS)})")

def _to_chat_prompt(example):
    example["prompt"] = tokenizer.apply_chat_template(
        [{"role": "user", "content": example["prompt"]}],
        tokenize=False,
        add_generation_prompt=True,
    )
    return example

dataset = dataset.map(_to_chat_prompt)

def _extract_python_code(text):
    m = re.search(r'```python\s*\n(.*?)```', text, re.DOTALL)
    return m.group(1).strip() if m else None

def _states_vulnerable(text):
    lower = text.lower()
    if re.search(r'\bnot\s+vulnerable\b', lower):
        return False
    return bool(re.search(r'\bvulnerable\b', lower))

def _check_syntax(code):
    try:
        compile(code, '<string>', 'exec')
        return True
    except SyntaxError:
        return False

_ORACLE_API_SIGNALS = [
    r'plaintext_b64',
    r'\bsys\.argv\b|\bargparse\b',
    r'[\^]|\bxor\b',
    r'\brange\(256\)',
]

def _check_oracle_api(code):
    hits = sum(1 for p in _ORACLE_API_SIGNALS if re.search(p, code))
    return hits >= 3

# Distinct integrity concepts; hmac and mac collapse to one concept via \bh?mac\b.
_NOT_VULN_CONCEPTS = [
    r'\bh?mac\b',
    r'\bauthenticat\w*\b',
    r'\bintegrity\b',
    r'\btamper\w*\b',
]

def _score_not_vulnerable(text):
    lower = text.lower()
    if not re.search(r'\bnot\s+vulnerable\b', lower):
        return 0.0
    hits = sum(1 for p in _NOT_VULN_CONCEPTS if re.search(p, lower))
    return 1.0 if hits >= 2 else 0.5

def _count_log_calls(log_path):
    try:
        with open(log_path) as f:
            return sum(1 for line in f if line.strip())
    except FileNotFoundError:
        return 0

def _log_has_valid_padding(log_path):
    try:
        with open(log_path) as f:
            return any(json.loads(line).get('valid') for line in f if line.strip())
    except (FileNotFoundError, json.JSONDecodeError):
        return False

def verifiable_reward_function(prompts, completions, test_case_inputs, test_case_outputs, **kwargs):
    rewards = []
    for i in range(len(completions)):
        completion = completions[i]
        generated_text = completion[0]['content'] if isinstance(completion, list) else completion
        inputs = test_case_inputs[i]
        outputs = test_case_outputs[i]
        php_bin = inputs["php_bin"]
        oracle_path = inputs["oracle_path"]
        key = inputs["key"]
        plaintext = inputs["plaintext"]
        verdict = outputs["verdict"]
        if verdict == "NOT_VULNERABLE":
            rewards.append(_score_not_vulnerable(generated_text))
            continue
        if not _states_vulnerable(generated_text):
            rewards.append(0.0)
            continue
        exploit_code = _extract_python_code(generated_text)
        if not exploit_code:
            rewards.append(0.0)
            continue
        if not _check_syntax(exploit_code):
            rewards.append(0.0)
            continue
        score = 0.1
        if _check_oracle_api(exploit_code):
            score = 0.2
        tmp_exploit = tmp_log = None
        try:
            enc = subprocess.run([php_bin, oracle_path, "encrypt", plaintext, key], capture_output=True, text=True, timeout=10)
            ciphertext = json.loads(enc.stdout)["ciphertext"]
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, dir='/tmp') as f:
                f.write(exploit_code)
                tmp_exploit = f.name
            tmp_log = tempfile.mktemp(suffix='_oracle.log', dir='/tmp')
            run_stdout = ''
            try:
                r = subprocess.run(['python3', tmp_exploit, oracle_path, key, ciphertext],
                                   env={**os.environ, 'ORACLE_LOG': tmp_log},
                                   capture_output=True, timeout=180)
                # Decode stdout manually with errors='replace' so non-UTF-8 bytes
                # from arbitrary exploit code don't crash the reward function.
                run_stdout = r.stdout.decode('utf-8', errors='replace') if r.stdout else ''
            except subprocess.TimeoutExpired as exc:
                run_stdout = (exc.stdout or b'').decode('utf-8', errors='replace') if isinstance(exc.stdout, bytes) else (exc.stdout or '')
            total_calls = _count_log_calls(tmp_log)
            found_valid = _log_has_valid_padding(tmp_log)
            if plaintext in run_stdout.strip() and total_calls >= 256:
                score = 1.0
            elif plaintext in run_stdout.strip():
                # recovered plaintext but without real oracle interaction -> reward
                # hacking; cap at the dynamic-effort tier, do not grant 1.0
                score = max(score, 0.2)
            elif total_calls >= 256 and found_valid:
                score = max(score, 0.5)
            elif total_calls >= 200:
                score = max(score, 0.2)
        except Exception as e:
            # Catch-all so a single bad exploit can't crash a multi-hour training run.
            # WARNING lines are logged so we can review what failed after each run.
            print(f"WARNING: reward function caught {type(e).__name__}: {e}", flush=True)
            pass
        finally:
            for path in [tmp_exploit, tmp_log]:
                if path and os.path.exists(path):
                    os.unlink(path)
        rewards.append(score)
    return rewards

training_args = GRPOConfig(
    output_dir="outputs_rlvr",
    learning_rate=5e-6,
    per_device_train_batch_size=1,
    gradient_accumulation_steps=4,
    seed=42,
    max_prompt_length=4096,
    max_completion_length=1024,
    num_generations=4,
    bf16=True,
    logging_steps=10,
    report_to="none",
    max_steps=200,
)

trainer = GRPOTrainer(
    model=model,
    processing_class=tokenizer,
    reward_funcs=[verifiable_reward_function],
    args=training_args,
    train_dataset=dataset,
)

print("Starting RLVR training...")
trainer.train()

output_dir = os.environ.get("RLVR_OUTPUT_DIR", "devstral-rlvr-lora")
model.save_pretrained(output_dir)
tokenizer.save_pretrained(output_dir)
print(f"Saved adapter to {output_dir}")
print("Training complete and saved!")

import os
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"
import torch
from datasets import load_dataset
from unsloth import FastLanguageModel, PatchFastRL
from trl import GRPOConfig, GRPOTrainer

# 1. Patch Unsloth to optimize RL (required for TRL)
PatchFastRL("GRPO", FastLanguageModel)

# Basic parameters
model_name = "./devstral-small-2" # Change this to the real path
max_seq_length = 2048

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
# TRL passes the 'prompt', 'completions' (model generations) and the rest of the JSON
def verifiable_reward_function(prompts, completions, test_case_inputs, test_case_outputs, **kwargs):
    rewards = []

    # Evaluate each generated response
    for i in range(len(completions)):
        generated_code = completions[i][0]['content'] if isinstance(completions[i], list) else completions[i]

        # Get the specific tests for THIS prompt
        expected_inputs = test_case_inputs[i]
        expected_outputs = test_case_outputs[i]

        # -------------------------------------------------------------------
        # USE THE INPUTS/OUTPUTS HERE TO TEST THE GENERATED CODE
        # (e.g.: Run the generated_code passing the expected_inputs
        # and check if the result matches the expected_outputs)
        # -------------------------------------------------------------------

        score = 0.0
        # Imaginary test logic:
        # if passes_tests(generated_code, expected_inputs, expected_outputs):
        #     score = 1.0

        rewards.append(score)

    return rewards

# 6. Configure RL training (GRPO)
training_args = GRPOConfig(
    output_dir="outputs_rlvr",
    learning_rate=5e-6,           # Typically lower in RL than in SFT
    per_device_train_batch_size=1, # Start at 1. Adjust based on available VRAM.
    gradient_accumulation_steps=4,
    max_prompt_length=512,
    max_completion_length=1024,
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

#!/bin/bash
# Submit Config D: SFT then GRPO (starts from devstral-sft-lora/)
#
#SBATCH --account=upftfg31_normal
#SBATCH --job-name=rlvr_d_devstral
#SBATCH --output=logs/rlvr_d_%j.out
#SBATCH --error=logs/rlvr_d_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h100:1
#SBATCH --time=24:00:00

module load conda
conda activate unsloth_env
module load java/23.0.1
export SFT_ADAPTER_PATH=devstral-sft-lora
python training.py

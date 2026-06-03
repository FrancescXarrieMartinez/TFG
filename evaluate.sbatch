#!/bin/bash
# Usage:
#   sbatch evaluate.sbatch A   # base model
#   sbatch evaluate.sbatch B   # SFT
#   sbatch evaluate.sbatch C   # GRPO only
#   sbatch evaluate.sbatch D   # SFT then GRPO
#
#SBATCH --account=upftfg31_normal
#SBATCH --job-name=eval_devstral
#SBATCH --output=logs/eval_%j.out
#SBATCH --error=logs/eval_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h100:1
#SBATCH --time=01:00:00

module load conda
conda activate unsloth_env
module load java/23.0.1

CONFIG=${1:-A}
echo "Evaluating Configuration $CONFIG"
python evaluate.py --config $CONFIG

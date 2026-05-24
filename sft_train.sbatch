#!/bin/bash
# Usage:
#   Submit job:       sbatch sft_train.sbatch
#   Check status:     squeue -u $USER
#   Cancel job:       scancel <job_id>
#
#SBATCH --account=upftfg31_normal
#SBATCH --job-name=sft_devstral
#SBATCH --output=logs/sft_%j.out
#SBATCH --error=logs/sft_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h100:1
#SBATCH --time=24:00:00

module load conda
conda activate unsloth_env
module load java/23.0.1
python sft_training.py
